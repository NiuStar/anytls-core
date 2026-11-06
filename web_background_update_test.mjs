// SYNTHETIC_VM: actual app/runtime, controlled clock/transport; no lifecycle writes.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {harness} from './web_status_lifecycle_test.mjs';

const root=process.env.WEB_ROOT||new URL('./web_assets/',import.meta.url).pathname;
const good={
 current:'v2026-11-06-02',installed:'v2026-11-06-02',latest:'v2026-11-07-01',
 status:'UPDATE_AVAILABLE',available:true,sourceOnly:false,updated:false,restartRequired:false,
};
const flush=async()=>{for(let i=0;i<60;i++)await Promise.resolve();};
function setup(runtime=true){
 const h=harness();
 h.run('addEventListener=window.addEventListener;window=globalThis;navigator={onLine:true};isSecureContext=false;currentView="update";Date.now=()=>1800000000000;');
 if(runtime)h.run(fs.readFileSync(root+'runtime.js','utf8'));
 return h;
}
async function advance(h,ms){
 h.run(`Date.now=()=>${h.run('Date.now()')+ms}`);
 const due=[...h.timers].filter(([,t])=>t.ms<=ms);
 for(const [,t]of h.timers)t.ms-=ms;
 for(const [id,t]of due)if(h.timers.delete(id))t.fn();
 await flush();
}
async function login(h){
 h.respond({availability:'AVAILABLE',version:good.current});h.respond({available:false});
 await h.run('enterConsole({csrf:"LOGIN"})');
}
const count=h=>h.requests.filter(r=>r.path==='/api/v1/update-check').length;
const observation=h=>JSON.parse(h.run('AnyTLSRuntime.summary()')).versions.installed;

test('authenticated direct settings login schedules one background read and hourly success, never status-loop reads',async()=>{
 const h=setup();await login(h);h.respond(good);await advance(h,0);
 assert.equal(count(h),1);assert.equal(h.run('busy'),false);assert.equal(h.run('updateAvailable'),true);
 assert.equal(observation(h).value,good.installed);
 for(let i=0;i<5;i++)h.emit('visibilitychange');
 await advance(h,3599999);assert.equal(count(h),1);
 h.respond(good);await advance(h,1);assert.equal(count(h),2);
 assert.ok(h.requests.every(r=>!r.method||r.method==='GET'));
});

test('manual and debug join the active auto owner; route changes retain it and save feedback survives',async()=>{
 const h=setup();await login(h);const release=h.hold();await advance(h,0);
 h.run('savedFeedback({changed:true,apply_status:"SAVED_STOPPED"});currentView="nodes"');
 const notice=h.get('notice').textContent;
 const manual=h.run('updateOperation(false)'),debug=h.run('AnyTLSRuntime.check()');
 assert.equal(count(h),1);assert.equal(h.run('busy'),false);
 release(good);await Promise.all([manual,debug]);
 assert.equal(h.get('notice').textContent,notice);
 assert.match(h.get('update-result').textContent,/发现可用更新/);
});

test('failure retains last observation, disables installation and backs off 15 minutes',async()=>{
 const h=setup();h.respond(good);await h.run('checkUpdate()');const before=observation(h);
 h.respond({error:'UPDATE_CHECK_FAILED'},503);await h.run('checkUpdate()');
 assert.equal(h.run('updateAvailable'),false);const after=observation(h);
 assert.equal(after.value,before.value);assert.equal(after.observedAt,before.observedAt);
 assert.equal(after.refreshStatus,'FAILED');
 await advance(h,899999);assert.equal(count(h),2);
 h.respond(good);await advance(h,1);assert.equal(count(h),3);
});

test('offline skips, online resumes due only; hiding aborts logical owner and stale 401 cannot log out',async()=>{
 const h=setup();h.run('navigator.onLine=false');await login(h);await advance(h,0);
 assert.equal(count(h),0);h.run('navigator.onLine=true');
 let release;
 h.queue.push(()=>new Promise(resolve=>release=()=>resolve({ok:false,status:401,json:async()=>({error:'AUTH_REQUIRED'})})));
 h.emit('online');await advance(h,0);assert.equal(count(h),1);
 h.document.hidden=true;h.emit('visibilitychange');assert.equal(h.requests.at(-1).signal.aborted,true);
 h.document.hidden=false;h.respond(good);h.emit('visibilitychange');await advance(h,0);
 release();await flush();assert.equal(h.run('csrf'),'LOGIN');assert.equal(h.run('updateAvailable'),true);
});

test('fetch and body hangs settle within 35s even when AbortSignal is ignored',async()=>{
 for(const body of [false,true]){
  const h=setup();let release;
  if(body)h.queue.push(async()=>({ok:true,status:200,json:()=>new Promise(r=>release=r)}));
  else release=h.hold();
  const pending=h.run('checkUpdate()');await flush();await advance(h,35000);await pending;
  assert.equal(h.run('updateCheckOwner'),null);assert.equal(h.run('busy'),false);
  assert.equal(h.run('updateAvailable'),false);assert.match(h.get('update-result').textContent,/检查未完成/);
  h.respond(good);await h.run('checkUpdate()');release(good);await flush();
  assert.equal(h.run('updateAvailable'),true);
 }
});

test('all versions and boolean/status combinations validate atomically before installation is enabled',async()=>{
 for(const patch of [
  {current:'SECRET'},{installed:'<script>'},{latest:'https://evil'},{available:'true'},
  {status:'UP_TO_DATE',available:true},{status:'RESTART_REQUIRED',restartRequired:false},
 ]){
  const h=setup(false);h.respond({...good,...patch});await h.run('checkUpdate()');
  assert.equal(h.run('updateAvailable'),false);assert.equal(h.get('run-update').disabled,true);
  assert.doesNotMatch(h.get('update-result').textContent,/SECRET|evil|<script>/);
 }
});

test('source-only and restart-required remain honest states and checks never write',async()=>{
 for(const data of [
  {...good,sourceOnly:true},
  {...good,status:'RESTART_REQUIRED',installed:good.latest,available:false,restartRequired:true},
 ]){
  const h=setup();h.respond(data);await h.run('checkUpdate()');
  assert.equal(h.run('updateAvailable'),false);
  assert.match(h.get('update-result').textContent,data.sourceOnly?/不能安装/:/需重启控制台/);
  assert.equal(h.requests.length,1);assert.equal(h.requests[0].path,'/api/v1/update-check');
 }
});

test('cancel before deferred fetch never issues an old-session read or unhandled rejection',async()=>{
 const h=setup();const old=h.run('checkUpdate()');h.run('showLogin()');await old;
 assert.equal(count(h),0);assert.equal(h.run('updateCheckOwner'),null);
});

test('pagehide cancels timer and active owner; pageshow resumes due, not every route',async()=>{
 const h=setup();h.respond(good);await h.run('checkUpdate()');
 h.emit('pagehide');assert.equal(h.timers.size,0);
 h.emit('pageshow');await advance(h,3599999);assert.equal(count(h),1);
 const release=h.hold();await advance(h,1);assert.equal(count(h),2);
 h.emit('pagehide');assert.equal(h.requests.at(-1).signal.aborted,true);
 release(good);await flush();assert.equal(h.timers.size,0);
});

test('background checks run during unrelated operation without changing its controls or APPLIED notice',async()=>{
 const h=setup();h.run('busy=true;savedFeedback({changed:true,apply_status:"APPLIED"})');
 const before=h.get('notice').textContent;h.respond(good);await h.run('checkUpdate()');
 assert.equal(h.run('busy'),true);assert.equal(h.get('notice').textContent,before);
 assert.equal(h.get('run-update').disabled,true);
});

test('logout/new session fences body-delayed 401 and old finally cannot release successor',async()=>{
 const h=setup();let release;
 h.queue.push(async()=>({ok:false,status:401,json:()=>new Promise(r=>release=r)}));
 const old=h.run('checkUpdate()');await flush();h.run('showLogin();csrf="NEW"');
 const releaseNew=h.hold(),next=h.run('checkUpdate()'),owner=h.run('updateCheckOwner');
 release({error:'AUTH_REQUIRED'});await old;
 assert.equal(h.run('csrf'),'NEW');assert.equal(h.run('updateCheckOwner'),owner);
 releaseNew(good);await next;assert.equal(h.run('updateAvailable'),true);
});

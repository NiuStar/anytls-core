// SYNTHETIC_VM: real app handlers + runtime; reuse lifecycle harness (7 inherited tests).
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {harness} from './web_status_lifecycle_test.mjs';
const root=process.env.WEB_ROOT||new URL('./web_assets/',import.meta.url).pathname;
function full(){const h=harness();h.run('window=globalThis;isSecureContext=false;navigator={};addEventListener=()=>{};currentView="update";');h.run(fs.readFileSync(root+'runtime.js','utf8'));return h;}
const disk={installed:'v2026-11-03-01',current:'v2026-11-02-02',latest:'v2026-11-03-01',status:'RESTART_REQUIRED',available:false,sourceOnly:false,updated:false,restartRequired:true};
const read=h=>JSON.parse(h.run('AnyTLSRuntime.summary()')).versions.installed;
const flush=async()=>{for(let i=0;i<40;i++)await Promise.resolve();};
async function seed(h){h.respond(disk);await h.get('check-update').onclick();return read(h);}
const fixed='安装版本检查失败；保留上次观察，不代表实时磁盘状态。';
for(const failure of ['503','throw','invalid','invalid-version'])test(`update page ${failure} after success marks FAILED and retains value/time`,async()=>{
 const h=full(),before=await seed(h);
 if(failure==='503')h.respond({error:'UPDATE_CHECK_FAILED'},503);
 if(failure==='throw')h.queue.push(async()=>{throw Error('SECRET /private/config');});
 if(failure==='invalid')h.respond({...disk,available:'SECRET'});
 if(failure==='invalid-version')h.respond({...disk,installed:'SECRET /private/config'});
 await h.get('check-update').onclick();const after=read(h);
 assert.equal(after.refreshStatus,'FAILED');assert.equal(after.value,before.value);assert.equal(after.observedAt,before.observedAt);assert.equal(after.evidence,before.evidence);assert.equal(h.get('runtime-error').textContent,fixed);assert.match(h.get('update-result').textContent,/检查未完成/);
 h.respond(disk);await h.get('check-update').onclick();assert.equal(read(h).refreshStatus,'NOT_FAILED');assert.equal(h.get('runtime-error').textContent,'');
});
for(const boundary of ['hidden-visible','new-session','new-epoch'])test(`late update-page 401 after ${boundary} cannot revoke session or mark newer observation failed`,async()=>{
 const h=full();await seed(h);let release;h.queue.push(()=>new Promise(resolve=>release=()=>resolve({ok:false,status:401,json:async()=>({error:'AUTH_REQUIRED'})})));const old=h.get('check-update').onclick();
 await flush();if(boundary==='hidden-visible'){h.document.hidden=true;h.emit('visibilitychange');h.document.hidden=false;h.emit('visibilitychange');}
 if(boundary==='new-session')h.run('showLogin();csrf="NEW_SESSION";currentView="update";');
 h.run(`AnyTLSRuntime.acceptCheck(${JSON.stringify({...disk,installed:'v2026-11-04-01'})},AnyTLSRuntime.checkToken())`);
 const before=read(h),session=h.run('csrf');release();await old;
 assert.equal(h.run('csrf'),session);assert.deepEqual(read(h),before);assert.equal(read(h).refreshStatus,'NOT_FAILED');
});
for(const failure of ['503','throw'])test(`update-page and panel coalesce ${failure}, then manual retry replaces failed observation`,async()=>{
 const h=full();await seed(h);let release;h.queue.push(()=>new Promise((resolve,reject)=>release=()=>failure==='throw'?reject(Error('SECRET')):resolve({ok:false,status:503,json:async()=>({error:'UPDATE_CHECK_FAILED'})})));
 const old=h.get('check-update').onclick();await flush();const joined=h.run('AnyTLSRuntime.check()');assert.equal(h.requests.length,2,'manual/debug share the current owner');release();await Promise.all([old,joined]);assert.equal(read(h).refreshStatus,'FAILED');h.respond({...disk,installed:'v2026-11-04-01'});await h.run('AnyTLSRuntime.check()');assert.equal(read(h).value,'v2026-11-04-01');assert.equal(read(h).refreshStatus,'NOT_FAILED');assert.equal(h.run('csrf'),'session');
});
test('hidden-visible alone fences late update failure without any newer check',async()=>{
 const h=full();await seed(h);let release;h.queue.push(()=>new Promise(resolve=>release=()=>resolve({ok:false,status:503,json:async()=>({error:'UPDATE_CHECK_FAILED'})})));
 const before=read(h),old=h.get('check-update').onclick();await flush();h.document.hidden=true;h.emit('visibilitychange');h.document.hidden=false;h.emit('visibilitychange');release();await old;assert.deepEqual(read(h),before);assert.equal(h.run('csrf'),'session');
});
test('current update-page 401 still invalidates the authenticated session',async()=>{
 const h=full();await seed(h);h.respond({error:'AUTH_REQUIRED'},401);await h.get('check-update').onclick();assert.equal(h.run('csrf'),'');assert.equal(read(h).value,null);
});
test('panel own check failure preserves observation/time and SAVED_STOPPED authority',async()=>{
 const h=full();await seed(h);const before=read(h);h.run('savedFeedback({changed:true,apply_status:"SAVED_STOPPED"})');const notice=h.get('notice').textContent;
 h.respond({error:'SECRET'},503);await h.run('AnyTLSRuntime.check()');assert.equal(read(h).refreshStatus,'FAILED');assert.equal(read(h).value,before.value);assert.equal(read(h).observedAt,before.observedAt);assert.equal(h.get('runtime-error').textContent,fixed);assert.equal(h.get('notice').textContent,notice);
});
test('failed install does not replace or fail disk observation, nor invent a runtime update',async()=>{
 const h=full();await seed(h);const before=read(h);h.run('updateAvailable=true;');h.respond({error:'UPDATE_CHECK_FAILED'},503);await h.get('run-update').onclick();assert.deepEqual(read(h),before);assert.equal(JSON.parse(h.run('AnyTLSRuntime.summary()')).versions.coreCurrent.value,null);
});

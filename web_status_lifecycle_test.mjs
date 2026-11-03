// Reuse the existing real-app VM harness; synthetic DOM/HTTP, not browser acceptance.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {test} from 'node:test';
let source=fs.readFileSync(new URL('./web_rules_list_only_test.mjs',import.meta.url),'utf8').split('const base=')[0];
source=source.replace('const requests=[], queue=[];','const requests=[], queue=[], intervals=[], timers=new Map(), listeners=new Map();let timerID=0;');
source=source.replace('addEventListener(){}};','addEventListener(name,fn){listeners.set(name,[...(listeners.get(name)||[]),fn]);}};');
source=source.replace('setInterval(){},clearInterval(){},setTimeout(){},clearTimeout(){}','window:{addEventListener(name,fn){listeners.set(name,[...(listeners.get(name)||[]),fn]);}},setInterval(fn){intervals.push(fn);},clearInterval(){},setTimeout(fn,ms){timers.set(++timerID,{fn,ms});return timerID;},clearTimeout(id){timers.delete(id);}');
source=source.replace('return {get,requests,respond,hold,run};','return {get,requests,respond,hold,run,document,queue,intervals,timers,emit:name=>(listeners.get(name)||[]).forEach(fn=>fn())};');
// A data URL has no relative file base: explicitly supply the real asset root.
process.env.WEB_ROOT ||= new URL('./web_assets/',import.meta.url).pathname;
source+='\nexport {harness};';
export const {harness}=await import('data:text/javascript;base64,'+Buffer.from(source).toString('base64'));
const state={availability:'AVAILABLE',running:false,loaded:false,version:'fixture'};
const flush=async()=>{for(let i=0;i<40;i++)await Promise.resolve();};

test('explicit save refresh reads status from config view and preserves actual YAML result',async()=>{
 const h=harness();h.run('currentView="config";etag=\'"v1"\'');
 h.respond({saved:true,changed:true,apply_status:'APPLIED',etag:'"v2"'});h.respond(state);h.respond({available:false});
 await h.get('save-config').onclick();assert.equal(h.requests.length,3);assert.equal(h.requests[1].path,'/api/v1/status');
 assert.match(h.get('notice').textContent,/配置已保存并自动生效/);assert.equal(h.run('serviceState.version'),'fixture');
});
test('single owner and hidden event abort both late status and helper body',async()=>{
 for(const helper of [false,true]){
  const h=harness();if(helper)h.respond(state);const release=h.hold();const pending=h.run('status()');await flush();
  h.run('status();status()');assert.equal(h.requests.length,helper?2:1);
  const signal=h.requests.at(-1).signal;h.document.hidden=true;h.emit('visibilitychange');
  assert.equal(signal.aborted,true);const before=h.get('helper-detail').textContent;release(helper?{available:true}:state);await pending;
  assert.equal(h.requests.length,helper?2:1);assert.equal(h.get('helper-detail').textContent,before);
  if(!helper)assert.equal(h.run('serviceState'),null);
 }
});
test('off-view late read is fenced and visibility return resumes overview only',async()=>{
 const h=harness(),release=h.hold();const pending=h.run('status()');h.run('currentView="config"');release(state);await pending;
 assert.equal(h.run('serviceState'),null);assert.equal(h.requests.length,1);
 h.emit('visibilitychange');await flush();assert.equal(h.requests.length,1);
 h.run('currentView="overview"');h.respond(state);h.respond({available:false});h.emit('visibilitychange');await flush();
 assert.equal(h.requests.length,3);assert.equal(h.run('serviceState.version'),'fixture');
});
test('pagehide aborts and fences the current read',async()=>{
 const h=harness(),release=h.hold();const pending=h.run('status()');h.emit('pagehide');assert.equal(h.requests[0].signal.aborted,true);
 release(state);await pending;assert.equal(h.run('serviceState'),null);assert.equal(h.requests.length,1);
});
test('old status/helper 401 after JSON cannot revoke a newer session',async()=>{
 for(const helper of [false,true]){
  const h=harness();let body;h.queue.push(async()=>({ok:false,status:401,json:()=>new Promise(resolve=>body=resolve)}));
  if(helper)h.queue.unshift(async()=>({ok:true,status:200,json:async()=>state}));
  const pending=h.run('status()');await flush();assert.equal(typeof body,'function');h.run('showLogin();csrf="NEW"');
  body({error:'AUTH_REQUIRED'});await pending;assert.equal(h.run('csrf'),'NEW');
 }
});
test('logout invalidation and old finally cannot release the new status owner',async()=>{
 const h=harness(),release=h.hold();const pending=h.run('status()');h.run('showLogin();csrf="NEW"');assert.equal(h.requests[0].signal.aborted,true);
 const releaseNew=h.hold();const newer=h.run('status()');const owner=h.run('polling');release(state);await pending;
 assert.equal(h.run('polling'),owner);h.run('status()');assert.equal(h.requests.length,2);
 h.respond({available:false});releaseNew({...state,version:'new'});await newer;assert.equal(h.run('serviceState.version'),'new');
});
test('hung read timeout settles, releases owner and late response cannot win',async()=>{
 const h=harness(),release=h.hold();const pending=h.run('status()');assert.equal(h.timers.size,1);
 const [{fn,ms}]=h.timers.values();assert.equal(ms,5000);fn();await pending;
 assert.equal(h.requests[0].signal.aborted,true);assert.equal(h.run('polling'),false);assert.equal(h.get('header-status').textContent,'状态未知');
 h.respond({...state,version:'fresh'});h.respond({available:false});await h.run('status()');release(state);await flush();
 assert.equal(h.run('serviceState.version'),'fresh');assert.equal(h.requests.length,3);
});

// SYNTHETIC_VM: real runtime component, synthetic DOM/HTTP; no native helper.
import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import test from 'node:test';
const root=process.env.WEB_ROOT||new URL('./web_assets/',import.meta.url).pathname;
function harness(){
 const nodes=new Map(),listeners={};
 const get=id=>{if(!nodes.has(id))nodes.set(id,{textContent:'',value:'',hidden:false,disabled:false,open:false,focus(){this.focused=true;},select(){this.selected=true;},addEventListener(k,f){this[k]=f;}});return nodes.get(id);};
 const ctx={console,Date,JSON,AbortController,URLSearchParams,setTimeout,clearTimeout,isSecureContext:false,navigator:{},sessionGeneration:1,csrf:'synthetic',currentView:'overview',busy:false,showLogin(){ctx.loggedOut=true;ctx.sessionGeneration++;ctx.csrf='';},document:{hidden:false,getElementById:get,addEventListener(k,f){listeners[k]=f;}},addEventListener(k,f){listeners[k]=f;}};
 ctx.window=ctx;vm.createContext(ctx);
 if(fs.existsSync(root+'runtime.js'))vm.runInContext(fs.readFileSync(root+'runtime.js','utf8'),ctx);
 return {ctx,get,listeners};
}
test('four-layer contract: no disk check or current-core join means UNKNOWN, not healthy',()=>{
 const {ctx,get}=harness();
 assert.ok(ctx.AnyTLSRuntime,'B1/B2 public projection contract must exist');
 ctx.AnyTLSRuntime.publish('status',{version:'v2026-11-02-02',availability:'UNAVAILABLE',running:false,loaded:false,pendingKnown:false,pendingReload:false});
 const s=JSON.parse(ctx.AnyTLSRuntime.summary());
 assert.equal(s.versions.installed.value,null);
 assert.equal(s.versions.installed.freshness,'UNKNOWN');
 assert.equal(s.versions.webui.value,'v2026-11-02-02');
 assert.equal(s.versions.coreCurrent.value,null);
 assert.equal(s.versions.coreCurrent.reason,'CURRENT_CORE_PROVENANCE_JOIN_UNAVAILABLE');
 assert.equal(s.health.service.running,null);
 assert.equal(s.health.network,'NOT_OBSERVED');
 assert.match(get('runtime-core').textContent,/UNKNOWN/);
});
const disk=(installed='v2026-11-03-01')=>({installed,current:'v2026-11-02-02',latest:installed,status:'RESTART_REQUIRED',available:false,sourceOnly:false,updated:false,restartRequired:true});
const response=(data,status=200)=>({status,ok:status===200,json:async()=>data});
const read=ctx=>JSON.parse(ctx.AnyTLSRuntime.summary());
const helper={available:true,status:{ok:true,code:'',loaded:true,running:true,config_identity:'c'.repeat(64),helper_version:'v2026-11-01-01',helper_sha256:'a'.repeat(64),message:'SECRET /private/config.yaml'}};
test('explicit disk check is single inflight; error retains last observation without notice mutation',async()=>{
 const {ctx,get}=harness();let calls=0,resolve;
 ctx.fetch=()=>{calls++;return new Promise(r=>resolve=r);};
 const p=ctx.AnyTLSRuntime.check();await ctx.AnyTLSRuntime.check();assert.equal(calls,1);
 resolve(response(disk()));await p;
 assert.equal(read(ctx).versions.installed.value,'v2026-11-03-01');
 assert.equal(read(ctx).versions.installed.evidence,'DISK_CHECK');
 const at=read(ctx).versions.installed.observedAt;get('notice').textContent='配置已保存并自动生效。';
 ctx.fetch=async()=>response({error:'SECRET'},503);await ctx.AnyTLSRuntime.check();
 assert.equal(read(ctx).versions.installed.observedAt,at);assert.match(get('runtime-installed').textContent,/本次读取失败/);
 assert.equal(get('notice').textContent,'配置已保存并自动生效。');
});
test('authenticated helper is independent of custom console config; SHA never claims mapping or enters summary',()=>{
 const {ctx}=harness();ctx.AnyTLSRuntime.publish('helper',helper);const h=read(ctx).versions.helper;
 assert.equal(h.value,'v2026-11-01-01');assert.equal(h.available,true);assert.equal(h.shaKind,'FILE_BYTES');assert.equal(h.executionMapping,'NOT_ATTESTED');assert.equal(h.configBinding,'NOT_VERIFIED');
 assert.equal(ctx.AnyTLSRuntime.summary().includes('a'.repeat(64)),false);
 for(const p of [{available:false,code:'HELPER_CONFIG_MISMATCH',status:helper.status},{available:'true',status:helper.status},{available:true,status:{...helper.status,ok:false}},{available:true,status:{...helper.status,config_identity:'path'}}]){ctx.AnyTLSRuntime.publish('helper',p);assert.equal(read(ctx).versions.helper.value,null);}
});
test('version/status secrets, HTML, free messages, node IPs and identifiers are not projected',()=>{
 const {ctx,get}=harness();const attack='<img src=x onerror=alert(1)> SECRET /private/config.yaml 192.0.2.1';
 ctx.AnyTLSRuntime.publish('status',{version:attack,availability:attack,loaded:false,running:false,pendingKnown:false,pendingReload:true,yaml:attack});
 ctx.AnyTLSRuntime.publish('helper',{available:false,code:attack,message:attack});
 ctx.AnyTLSRuntime.publish('history',{version:attack,startedAt:attack,result:attack,observation:attack});
 ctx.AnyTLSRuntime.publish('dns',{availability:attack,state:attack,ageNS:attack,gap:attack,events:[attack]});
 const text=ctx.AnyTLSRuntime.summary();for(const s of ['SECRET','private','192.0.2.1','<img','events','config_identity'])assert.equal(text.includes(s),false,s);
 assert.equal(read(ctx).health.pending.reload,null);assert.equal(read(ctx).versions.webui.value,null);assert.equal(get('runtime-helper').textContent.includes('<img'),false);
});
test('fresh DNS plus stale startup never produces current core identity or network green',()=>{
 const {ctx}=harness();ctx.AnyTLSRuntime.publish('history',{version:'v2026-10-01-01',startedAt:'2026-11-03T00:00:00Z',observation:'STALE',result:'SUCCEEDED'});
 ctx.AnyTLSRuntime.publish('dns',{availability:'OBSERVED',state:'LOADED',ageNS:'1',gap:false});
 assert.equal(read(ctx).health.dns.availability,'OBSERVED');assert.equal(read(ctx).lastStartup.observation,'STALE');assert.equal(read(ctx).versions.coreCurrent.value,null);assert.equal(read(ctx).health.network,'NOT_OBSERVED');ctx.AnyTLSRuntime.cancel(true);
});
test('DNS missing age, STARTING, CLOSED, stale age and malformed projection are not observed',()=>{
 const {ctx}=harness();for(const p of [{state:'STARTING',ageNS:'1'},{state:'CLOSED',ageNS:'1'},{state:'LOADED',ageNS:'2500000001'},{state:'LOADED',ageNS:null},{state:'LOADED',ageNS:'01'}]){ctx.AnyTLSRuntime.publish('dns',{availability:'OBSERVED',gap:false,...p});assert.notEqual(read(ctx).health.dns.availability,'OBSERVED');}
});
test('DNS and historical snapshot expire locally without extra fetch',()=>{
 const {ctx}=harness();const timers=[];ctx.setTimeout=(f,ms)=>{timers.push({f,ms});return timers.length;};ctx.clearTimeout=()=>{};
 ctx.fetch=()=>assert.fail('must not poll');ctx.AnyTLSRuntime.publish('dns',{availability:'OBSERVED',state:'LOADED',ageNS:'2000000000',gap:true});
 ctx.AnyTLSRuntime.publish('history',{version:'v2026-11-01-01',startedAt:'2026-11-03T00:00:00Z',observation:'OBSERVED',ageNS:'1000000000',result:'SUCCEEDED'});
 assert.equal(timers[0].ms,500);assert.equal(timers[1].ms,500);timers.forEach(t=>t.f());assert.equal(read(ctx).health.dns.availability,'STALE');assert.equal(read(ctx).lastStartup.observation,'STALE');
});
test('late old 401/finally cannot log out or unlock newer owner',async()=>{
 const {ctx,get}=harness();let resolveOld,resolveNew;
 ctx.fetch=()=>new Promise(r=>resolveOld=r);const old=ctx.AnyTLSRuntime.check();ctx.AnyTLSRuntime.cancel(true);ctx.sessionGeneration++;ctx.csrf='new';
 ctx.fetch=()=>new Promise(r=>resolveNew=r);const fresh=ctx.AnyTLSRuntime.check();resolveOld(response({error:'AUTH_REQUIRED'},401));await old;
 assert.equal(ctx.loggedOut,undefined);assert.equal(get('runtime-check').disabled,true);assert.equal(read(ctx).versions.installed.value,null);
 resolveNew(response(disk()));await fresh;assert.equal(get('runtime-check').disabled,false);assert.equal(read(ctx).versions.installed.value,'v2026-11-03-01');
});
test('hidden cancellation discards delayed response even if abort is ignored',async()=>{
 const {ctx,listeners}=harness();let resolve;ctx.fetch=()=>new Promise(r=>resolve=r);const p=ctx.AnyTLSRuntime.check();ctx.document.hidden=true;listeners.visibilitychange();ctx.document.hidden=false;listeners.visibilitychange();resolve(response(disk()));await p;assert.equal(read(ctx).versions.installed.value,null);
});
test('hung body timeout is bounded and preserves save notice',async()=>{
 const {ctx,get}=harness();let fire;ctx.setTimeout=f=>{fire=f;return 1;};ctx.clearTimeout=()=>{};
 ctx.fetch=async()=>({ok:true,status:200,json:()=>new Promise(()=>{})});get('notice').textContent='配置已保存；VPN 未运行，下次启动时生效。';const p=ctx.AnyTLSRuntime.check();await Promise.resolve();fire();await p;
 assert.match(get('runtime-error').textContent,/检查失败/);assert.equal(get('runtime-check').disabled,false);assert.match(get('notice').textContent,/VPN 未运行/);
});
test('clipboard denied/manual fallback selects only strict summary; late completion cannot cross logout',async()=>{
 const {ctx,get}=harness();await get('runtime-copy').click();assert.equal(get('runtime-summary').selected,true);assert.match(get('runtime-copy-status').textContent,/未复制/);
 ctx.isSecureContext=true;ctx.navigator.clipboard={writeText:async()=>{throw Error('SECRET');}};await get('runtime-copy').click();assert.match(get('runtime-copy-status').textContent,/未复制/);
 let copied;ctx.navigator.clipboard={writeText:async text=>copied=text};await get('runtime-copy').click();assert.equal(copied,ctx.AnyTLSRuntime.summary());assert.match(get('runtime-copy-status').textContent,/已复制/);
 let done;ctx.navigator.clipboard={writeText:()=>new Promise(r=>done=r)};const p=get('runtime-copy').click();ctx.AnyTLSRuntime.cancel(true);ctx.sessionGeneration++;done();await p;assert.equal(get('runtime-copy-status').textContent,'');
});
test('status failure does not replace APPLIED or SAVED_STOPPED notice',()=>{
 const {ctx,get}=harness();for(const text of ['配置已保存并自动生效。','配置已保存；VPN 未运行，下次启动时生效。']){get('notice').textContent=text;ctx.AnyTLSRuntime.publish('statusError');assert.equal(get('notice').textContent,text);assert.equal(read(ctx).health.service.running,null);}
});
test('explicit update-page projection is epoch/session fenced and supersedes older panel check',async()=>{
 const {ctx}=harness();let resolve;ctx.fetch=()=>new Promise(r=>resolve=r);const old=ctx.AnyTLSRuntime.check();
 const token=ctx.AnyTLSRuntime.checkToken();assert.equal(ctx.AnyTLSRuntime.acceptCheck(disk('v2026-11-04-01'),token),true);
 resolve(response(disk()));await old;assert.equal(read(ctx).versions.installed.value,'v2026-11-04-01');
 ctx.AnyTLSRuntime.cancel();assert.equal(ctx.AnyTLSRuntime.acceptCheck(disk(),token),false);
 const next=ctx.AnyTLSRuntime.checkToken();ctx.sessionGeneration++;assert.equal(ctx.AnyTLSRuntime.acceptCheck(disk(),next),false);
});
test('service availability gates stopped/running and unknown pending never means applied',()=>{
 const {ctx,get}=harness();for(const running of [false,true]){
  ctx.AnyTLSRuntime.publish('status',{availability:'AVAILABLE',loaded:running,running,version:'v2026-11-02-02',pendingKnown:false,pendingReload:false});
  assert.equal(read(ctx).health.service.running,running);assert.equal(read(ctx).health.pending.reload,null);assert.equal(read(ctx).health.network,'NOT_OBSERVED');assert.match(get('runtime-service').textContent,running?/运行中/:/未加载/);
 }
 ctx.AnyTLSRuntime.publish('status',{availability:'AVAILABLE',loaded:false,running:'true'});assert.equal(read(ctx).health.service.running,null);
});
test('failure hook preserves observation and rejects stale epoch/session/visibility tokens',()=>{
 const {ctx,get,listeners}=harness();const first=ctx.AnyTLSRuntime.checkToken();ctx.AnyTLSRuntime.acceptCheck(disk(),first);const before=read(ctx).versions.installed;
 const failed=ctx.AnyTLSRuntime.checkToken();assert.equal(ctx.AnyTLSRuntime.checkFailure(failed),true);const after=read(ctx).versions.installed;
 assert.deepEqual({...after,refreshStatus:'NOT_FAILED'},before);assert.equal(after.refreshStatus,'FAILED');assert.match(get('runtime-error').textContent,/安装版本检查失败/);
 const fresh=ctx.AnyTLSRuntime.checkToken();ctx.AnyTLSRuntime.acceptCheck(disk('v2026-11-04-01'),fresh);assert.equal(ctx.AnyTLSRuntime.checkFailure(failed),false);
 const hidden=ctx.AnyTLSRuntime.checkToken();ctx.document.hidden=true;listeners.visibilitychange();ctx.document.hidden=false;listeners.visibilitychange();assert.equal(ctx.AnyTLSRuntime.checkFailure(hidden),false);
 const session=ctx.AnyTLSRuntime.checkToken();ctx.sessionGeneration++;assert.equal(ctx.AnyTLSRuntime.checkFailure(session),false);assert.equal(read(ctx).versions.installed.refreshStatus,'NOT_FAILED');
});
export {harness};

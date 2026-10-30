// Real app.js execution in Node VM. DOM/HTTP/clock are synthetic, not browser or Mac acceptance.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import {test} from 'node:test';
import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
const root=process.env.WEB_ROOT?pathToFileURL(resolve(process.env.WEB_ROOT)+'/'):new URL('../web_assets/',import.meta.url);
const source=fs.readFileSync(new URL('app.js',root),'utf8');
const html=fs.readFileSync(new URL('index.html',root),'utf8');
const bootstrap="(async()=>{try{await enterConsole(await api('/session'));}catch{showLogin();}})();";
assert.ok(source.trimEnd().endsWith(bootstrap),'remove only session bootstrap');
const oldVersion='v2026-10-22-06',target='v2026-10-30-01';
const installed={status:'UPDATED',current:oldVersion,installed:target,latest:target,available:false,sourceOnly:false,updated:true,restartRequired:true,restartScheduled:true};
const available={...installed,status:'UPDATE_AVAILABLE',installed:oldVersion,available:true,updated:false,restartRequired:false,restartScheduled:false,restartManaged:true};
const flush=async()=>{for(let i=0;i<40;i++)await Promise.resolve();};
function harness(storage=new Map()){
 class Element {
  constructor(tag='div',id=''){Object.assign(this,{tag,id,children:[],dataset:{},style:{},hidden:false,disabled:false,value:'',textContent:'',isConnected:true,listeners:{}});const classes=new Set();this.classList={toggle:(k,on)=>on?classes.add(k):classes.delete(k),contains:k=>classes.has(k),remove:k=>classes.delete(k)};}
  append(...children){this.children.push(...children);} replaceChildren(...children){this.children=[...children];}
  querySelectorAll(){return [];} setAttribute(){} removeAttribute(){} focus(){} reset(){} addEventListener(name,fn){this.listeners[name]=fn;}
 }
 const nodes=new Map([...html.matchAll(/<([a-z][\w-]*)\b[^>]*\bid="([^"]+)"/g)].map(([,tag,id])=>[id,new Element(tag,id)]));
 const get=id=>{assert.ok(nodes.has(id),'real HTML missing #'+id);return nodes.get(id);};
 const document={hidden:false,body:new Element(),getElementById:get,createElement:tag=>new Element(tag),querySelectorAll:s=>s==='button'?[...nodes.values()].filter(n=>n.tag==='button'):[],querySelector:()=>new Element(),addEventListener(){}};
 let now=1800000000000,nextTimer=0;const timers=new Map(),requests=[],queue=[],confirmations=[];
 const setTimeout=(fn,delay=0)=>{const id=++nextTimer;timers.set(id,{fn,at:now+delay});return id;};
 class ClockDate extends Date {constructor(...args){super(...(args.length?args:[now]));}static now(){return now;}}
 const fetch=(path,options)=>{requests.push({path,...options});assert.ok(queue.length,'unexpected fetch '+path);return queue.shift()(path,options);};
 const sessionStorage={getItem:k=>storage.get(k)??null,setItem:(k,v)=>storage.set(k,String(v)),removeItem:k=>storage.delete(k)};
 const context=vm.createContext({document,fetch,Headers,console,URL,AbortController,Date:ClockDate,sessionStorage,location:{origin:'http://127.0.0.1:18089',reload(){assert.fail('must verify memory version without blind reload');}},setInterval(){},clearInterval(){},setTimeout,clearTimeout:id=>timers.delete(id),confirm:text=>{confirmations.push(text);return true;}});
 vm.runInContext(source.slice(0,source.lastIndexOf(bootstrap)),context,{filename:'app.js'});
 const run=code=>vm.runInContext(code,context);run("csrf='session';updateAvailable=true;");
 const respond=(data,status=200)=>queue.push(async()=>({ok:status<400,status,json:async()=>structuredClone(data)}));
 const hold=()=>{let release;queue.push(()=>new Promise(resolve=>release=(data,status=200)=>resolve({ok:status<400,status,json:async()=>structuredClone(data)})));return (...args)=>{assert.ok(release,'held request not started');release(...args);};};
 const tick=async()=>{await flush();const timer=[...timers.entries()].sort((a,b)=>a[1].at-b[1].at)[0];assert.ok(timer,'expected bounded timer');timers.delete(timer[0]);now=timer[1].at;timer[1].fn();await flush();};
 const drain=async(promise)=>{let done=false;promise.finally(()=>done=true);for(let i=0;i<250&&!done;i++){await flush();if(!done)await tick();}assert.ok(done,'operation did not settle within bounded timer steps');await promise;};
 return {get,requests,queue,respond,hold,run,storage,timers,tick,drain,confirmations,advance:ms=>now+=ms,now:()=>now};
}

test('managed install waits for authenticated exact memory version, not disk publication',async()=>{
 const h=harness();h.respond(installed);const release=h.hold();const update=h.run('updateOperation(true)');await flush();
 // A scheduled restart is not yet a running-version success.
 assert.match(h.get('update-result').textContent,/等待.*控制台|控制台.*等待/);
 assert.doesNotMatch(h.get('update-result').textContent,/已确认.*运行|已恢复，/);
 if(h.requests.length===1)await h.tick();
 assert.equal(h.requests[1].path,'/api/v1/version');
 release({version:target});await h.drain(update);
 assert.match(h.get('update-result').textContent,/已确认.*运行.*v2026-10-30-01/);
 assert.match(h.get('update-result').textContent,/VPN 未重载/);
 assert.equal(h.run('busy'),false);
 assert.equal(h.requests.filter(r=>r.method==='POST').length,1);
 assert.equal(h.storage.size,0);
});

test('401 is not success: require real login then verify memory version',async()=>{
 const h=harness();h.respond(installed);h.respond({error:'AUTH_REQUIRED'},401);
 const update=h.run('updateOperation(true)');await flush();
 assert.equal(h.get('console-view').hidden,true);
 assert.equal(h.get('login-view').hidden,false);
 assert.match(h.get('login-error').textContent,/重新登录/);
 assert.match(h.get('login-error').textContent,/尚未.*确认/);
 assert.equal(h.storage.size,1,'retain only expected version receipt');
 const record=JSON.parse([...h.storage.values()][0]);assert.equal(record.target,target);
 assert.deepEqual(Object.keys(record).sort(),['createdAt','tag','target']);
 await h.drain(update);
 h.respond({csrf:'new-session',username:'admin'});h.respond({availability:'AVAILABLE',version:target});h.respond({available:false});h.respond({version:target});
 await h.get('login-form').listeners.submit({preventDefault(){},submitter:{disabled:false}});
 assert.equal(h.requests[2].path,'/api/v1/login');
 assert.equal(h.requests.at(-1).path,'/api/v1/version');
 assert.match(h.get('update-result').textContent,/已确认.*运行.*v2026-10-30-01/);
 assert.equal(h.storage.size,0);
 assert.equal(h.get('login-view').hidden,true);
});

test('confirmation distinguishes verified managed control from legacy/manual control',async()=>{
 for(const managed of [true,false,undefined]){
  const h=harness();h.respond({...available,restartManaged:managed});
  if(managed===undefined)h.queue[0]=async()=>({ok:true,status:200,json:async()=>{const data={...available};delete data.restartManaged;return data;}});
  await h.run('updateOperation(false)');h.respond({...installed,restartScheduled:false});await h.run('updateOperation(true)');
  const text=h.confirmations[0];assert.match(text,/VPN.*不.*重载|不.*重载.*VPN/);
  assert.match(text,managed?/自动重启 Web 控制台/:/手动重启 Web 控制台/);
  assert.equal(h.requests.length,2,'manual and legacy mode never poll');
 }
});

test('logout immediately aborts pending version read and late success cannot alter login',async()=>{
 const h=harness();h.respond(installed);const release=h.hold();const update=h.run('updateOperation(true)');await flush();
 assert.ok(h.requests[1],'scheduled update must start version verification');const signal=h.requests[1].signal;assert.equal(h.get('logout').disabled,false,'waiting must not trap user in session');
 h.respond({ok:true});await h.get('logout').listeners.click();await h.drain(update);
 assert.equal(signal.aborted,true);assert.equal(h.get('login-view').hidden,false);assert.equal(h.storage.size,0);
 const before=h.get('update-result').textContent;release({version:target});await flush();
 assert.equal(h.get('update-result').textContent,before);assert.equal(h.run('busy'),false);
 assert.equal(h.timers.size,0);
});

test('old memory version and network interruption never pass; exact target alone completes',async()=>{
 const h=harness();h.respond(installed);h.respond({version:oldVersion});h.queue.push(async()=>{throw new TypeError('offline');});h.respond({version:target});
 const update=h.run('updateOperation(true)');await flush();assert.doesNotMatch(h.get('update-result').textContent,/已确认当前运行/);
 await h.drain(update);assert.equal(h.requests.length,4);assert.match(h.get('update-result').textContent,/已确认当前运行/);
 for(const request of h.requests.slice(1)){assert.equal(request.path,'/api/v1/version');assert.equal(request.credentials,'same-origin');assert.equal(request.cache,'no-store');assert.equal(request.redirect,'error');assert.ok(request.signal);}
});

test('wrong version polling ends within 30 reads and releases controls without install retry',async()=>{
 const h=harness();h.respond(installed);for(let i=0;i<30;i++)h.respond({version:oldVersion});
 await h.drain(h.run('updateOperation(true)'));
 assert.equal(h.requests.length,31);assert.equal(h.run('busy'),false);assert.equal(h.get('run-update').disabled,true);
 assert.match(h.get('update-result').textContent,/磁盘.*已安装/);
 assert.match(h.get('update-result').textContent,/尚未确认/);assert.match(h.get('update-result').textContent,/手动刷新/);
 assert.doesNotMatch(h.get('update-result').textContent,/已确认当前运行/);assert.equal(h.timers.size,0);
});

test('hung reads time out, abort and stop within 90 seconds even when transport ignores abort',async()=>{
 const h=harness();h.respond(installed);for(let i=0;i<30;i++)h.queue.push(()=>new Promise(()=>{}));
 const start=h.now();await h.drain(h.run('updateOperation(true)'));
 assert.ok(h.now()-start<=90000,'total waiting deadline includes hung fetches');assert.ok(h.requests.length<=31);assert.ok(h.requests.slice(1).every(r=>r.signal.aborted));
 assert.match(h.get('update-result').textContent,/尚未确认/);assert.equal(h.run('busy'),false);assert.equal(h.timers.size,0);
});

for(const mutate of [d=>delete d.restartScheduled,d=>d.restartScheduled=false])test('legacy or unscheduled installation stays manual: '+mutate.toString(),async()=>{
 const h=harness(),data={...installed};mutate(data);h.respond(data);await h.run('updateOperation(true)');
 assert.equal(h.requests.length,1);assert.match(h.get('update-result').textContent,/手动重启/);assert.equal(h.storage.size,0);
});

for(const [key,value] of [['status','UP_TO_DATE'],['updated',false],['restartRequired',false],['installed','https://evil.test/'],['installed',' '+target],['latest',oldVersion],['restartScheduled','true']])test('invalid scheduled response never polls or stores target: '+key+'='+value,async()=>{
 const h=harness();h.respond({...installed,[key]:value});await h.run('updateOperation(true)');
 assert.equal(h.requests.length,1);assert.equal(h.storage.size,0);assert.match(h.get('update-result').textContent,/待核对/);assert.equal(h.run('busy'),false);
});

test('scheduled target must use the same canonical stable version grammar as CLI',async()=>{
 for(const target of ['v01.2.3','v2026-02-30-01','v0000-01-01-01','v2026-10-30-1','v2026-10-30-001','v1.2.3-beta','v1.2.3\n']){
  const h=harness();h.respond({...installed,installed:target,latest:target});for(let i=0;i<30;i++)h.respond({version:target});await h.drain(h.run('updateOperation(true)'));
  assert.equal(h.requests.length,1,'reject malformed version '+JSON.stringify(target));assert.equal(h.storage.size,0);
 }
});

test('restart scheduling error is fixed generic manual guidance, never raw data',async()=>{
 const h=harness();h.respond({...installed,restartScheduled:false,restartError:'<script>secret path</script>'});await h.run('updateOperation(true)');
 assert.match(h.get('update-result').textContent,/未能安排自动重启/);assert.doesNotMatch(h.get('update-result').textContent,/secret|script/);assert.equal(h.requests.length,1);
});

test('stale install response after logout cannot poll or persist a target',async()=>{
 const h=harness(),release=h.hold();const update=h.run('updateOperation(true)');await flush();
 h.run('showLogin()');release(installed);await update;
 assert.equal(h.requests.length,1);assert.equal(h.storage.size,0);assert.equal(h.get('update-result').textContent,'尚未检查。');
});

test('new login supersedes old version polling and rejects late 401',async()=>{
 const h=harness();h.respond(installed);const release=h.hold();const old=h.run('updateOperation(true)');await flush();
 const signal=h.requests[1].signal;h.respond({availability:'AVAILABLE',version:target});h.respond({available:false});h.respond({version:target});
 await h.run("enterConsole({csrf:'new-session'})");await h.drain(old);release({error:'AUTH_REQUIRED'},401);await flush();
 assert.equal(signal.aborted,true);assert.equal(h.get('login-view').hidden,true);assert.match(h.get('update-result').textContent,/已确认当前运行/);assert.equal(h.run('busy'),false);
});

test('target persists across page instance only until authenticated target verification',async()=>{
 const a=harness();a.respond(installed);a.respond({error:'AUTH_REQUIRED'},401);await a.drain(a.run('updateOperation(true)'));
 const h=harness(a.storage);h.respond({availability:'AVAILABLE',version:target});h.respond({available:false});h.respond({version:target});
 await h.run("enterConsole({csrf:'real-session'})");assert.equal(h.requests.at(-1).path,'/api/v1/version');assert.equal(h.storage.size,0);
 const n=h.requests.length;h.respond({availability:'AVAILABLE',version:target});h.respond({available:false});await h.run("enterConsole({csrf:'another-real-session'})");
 assert.equal(h.requests.length,n+2,'no target redirect or verification loop after success');
});

test('expired, malformed and future receipts are discarded without network version probe',async()=>{
 for(const data of ['bad JSON',JSON.stringify({tag:'WEBUI_UPDATE_TARGET',target,createdAt:0}),JSON.stringify({tag:'WEBUI_UPDATE_TARGET',target,createdAt:9999999999999}),JSON.stringify({tag:'WRONG',target,createdAt:1800000000000}),JSON.stringify({tag:'WEBUI_UPDATE_TARGET',target:'https://evil.test/',createdAt:1800000000000})]){
  const h=harness(new Map([['anytls.webui.update-target.v1',data]]));h.respond({availability:'AVAILABLE'});h.respond({available:false});await h.run("enterConsole({csrf:'real-login'})");
  assert.equal(h.requests.length,2);assert.equal(h.storage.size,0);
 }
});

test('non-200, malformed and wrong-version responses are never success',async()=>{
 for(const [payload,status] of [[{version:target},202],[{version:target},503],[{},200],[{version:oldVersion},200]]){
  const h=harness();h.respond(installed);for(let i=0;i<30;i++)h.respond(payload,status);await h.drain(h.run('updateOperation(true)'));
  assert.match(h.get('update-result').textContent,/尚未确认/);assert.doesNotMatch(h.get('update-result').textContent,/已确认当前运行/);assert.equal(h.requests.length,31);
 }
});

test('response body hangs are also bounded and abortable',async()=>{
 const h=harness();h.respond(installed);for(let i=0;i<30;i++)h.queue.push(async()=>({ok:true,status:200,json:()=>new Promise(()=>{})}));
 await h.drain(h.run('updateOperation(true)'));assert.match(h.get('update-result').textContent,/尚未确认/);assert.equal(h.timers.size,0);
});

test('old polling finally cannot release a newer operation',async()=>{
 const h=harness();h.respond(installed);const release=h.hold();const update=h.run('updateOperation(true)');await flush();
 h.run("showLogin();csrf='fresh';windowNew=operation('new',()=>new Promise(resolve=>releaseNew=resolve));");release({version:target});await update;
 assert.equal(h.run('busy'),true);assert.equal(h.get('notice').textContent,'new，请稍候…');
 h.run('releaseNew()');await h.run('windowNew');assert.equal(h.run('busy'),false);
});

test('manual login submission invalidates polling before its response arrives',async()=>{
 const h=harness();h.respond(installed);const releaseVersion=h.hold();const update=h.run('updateOperation(true)');await flush();
 const signal=h.requests[1].signal,releaseLogin=h.hold();const login=h.get('login-form').listeners.submit({preventDefault(){},submitter:{disabled:false}});await flush();
 assert.equal(signal.aborted,true);releaseVersion({error:'AUTH_REQUIRED'},401);await flush();
 h.respond({availability:'AVAILABLE'});h.respond({available:false});h.respond({version:target});releaseLogin({csrf:'new-session',username:'admin'});await login;await h.drain(update);
 assert.equal(h.get('login-view').hidden,true);assert.match(h.get('update-result').textContent,/已确认当前运行/);
});

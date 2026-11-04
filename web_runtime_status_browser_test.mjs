// BROWSER_SYNTHETIC: real candidate assets + Chromium, local synthetic HTTP only.
// NOT Go/static-route/native-helper acceptance: runtime.js is served by this
// fixture; source manifest checks below are not compiled HTTP acceptance.
import {createRequire} from 'node:module';
import http from 'node:http';
import fs from 'node:fs';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
const require=createRequire(import.meta.url);
const {chromium}=require(process.env.PLAYWRIGHT_CORE||'/home/hermeswebui/.hermes/node/lib/node_modules/@askjo/camofox-browser/node_modules/playwright-core');
const root=process.env.WEB_ROOT||new URL('./web_assets/',import.meta.url).pathname;
const out=process.env.WEB_EVIDENCE||'/workspace/anytls-performance-ux-evidence-r1/b1-b2-impl-r1/browser';fs.mkdirSync(out,{recursive:true});
const id='a'.repeat(32),epoch='b'.repeat(32),identity='c'.repeat(64),wall='2026-11-03T00:00:00Z';
const binding={instance_id:'d'.repeat(32),generation:'e'.repeat(32),manifest_id:'f'.repeat(64),runtime_sha256:'1'.repeat(64)};
function trace(){const stream={role:'CORE',clock_id:'2'.repeat(32),origin_at:wall,elapsed_ns:'0',provenance:{version:'v2026-10-01-01',git_revision:null,dirty:null,sha256:null,sha_kind:'UNKNOWN',execution_mapping:'NOT_ATTESTED'},current:null,events:[],generated_events:'0',dropped_events:'0',first_missing_seq:null,gap:false,retained_ranges:[],terminal:{result:'SUCCEEDED',at:wall,elapsed_ns:'0'}};return {timeline_schema:1,code:'OK',helper_epoch:epoch,config_identity:identity,operation_id:id,trace:{authority:'AUXILIARY_NOT_AUTHORITY',operation_id:id,helper_epoch:epoch,config_identity:identity,operation:'START',source:'MANUAL_START',started_at:wall,finished_at:wall,state:'FINISHED',lifecycle_result:'SUCCEEDED',helper_return:'SUCCEEDED',web_return:'SUCCEEDED',receipt_result:'WRITTEN',diagnostics:null,streams:[stream],core_observation:{availability:'STALE',captured_at:wall,helper_receive_elapsed_ns:'0',age_ns:'2000000000',clock_id:stream.clock_id,phase:null,gap:false},gap:false}};}
function dns(){return {dns_schema:1,code:'OK',helper_epoch:epoch,config_identity:identity,binding,received_at:wall,age_ns:'1',availability:'OBSERVED',snapshot:{revision:'1',captured_at:wall,elapsed_ns:'1',state:'LOADED',policy:{source:'DECODED_INSTANCE_AND_FACTORY',final:'SUPPORTED',transports:[],capture:'NOT_OBSERVED'},events:[],coverage:{scope:'HTTPS_TRANSPORT_COMPLETION',missing:'CAPTURE_CACHE_COALESCING_HTTP_STATUS_FRESH_TLS_CONCRETE_DETOUR_QUERY_JOIN_NOT_OBSERVED',gap:false,dropped_events:'0',counter_saturated:false}}};}
const defaultStatus=()=>({availability:'AVAILABLE',running:true,loaded:true,version:'v2026-11-02-02',pendingReload:false,pendingKnown:false,transport:'loopback-http'});
const defaultHelper=()=>({available:true,status:{ok:true,code:'',message:'SECRET_SENTINEL /private/config.yaml 192.0.2.1',loaded:true,running:true,helper_version:'v2026-11-01-01',helper_sha256:'3'.repeat(64),config_identity:identity}});
const disk=()=>({installed:'v2026-11-03-01',current:'v2026-11-02-02',latest:'v2026-11-03-01',status:'RESTART_REQUIRED',available:false,sourceOnly:false,updated:false,restartRequired:true});
let statusData=defaultStatus(),helperData=defaultHelper(),dnsData=dns(),statusFail=false,checkFail=false,requests=[];
const staticNames=new Set(['index.html','app.js','runtime.js','startup.js','dns.js','style.css','product.js','product.css']);
const server=http.createServer((req,res)=>{
 const u=new URL(req.url,'http://localhost');requests.push({path:u.pathname,query:u.search,method:req.method});
 if(!u.pathname.startsWith('/api/')){const file=u.pathname==='/'?'index.html':u.pathname.slice(1);if(!staticNames.has(file)){res.writeHead(404);res.end();return;}res.setHeader('Content-Type',file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':'text/html');res.end(fs.readFileSync(root+file));return;}
 let data={},code=200;
 switch(u.pathname){
 case '/api/v1/session':case '/api/v1/login':data={csrf:'SYNTHETIC_CSRF'};break;
 case '/api/v1/status':data=statusFail?{error:'SECRET_SENTINEL'}:statusData;code=statusFail?503:200;break;
 case '/api/v1/helper/status':data=helperData;break;
 case '/api/v1/startup-trace':data=trace();break;
 case '/api/v1/update-check':data=checkFail?{error:'SECRET_SENTINEL'}:disk();code=checkFail?503:200;break;
 case '/api/v1/dns-runtime':data=u.search?dnsData:{...dnsData,binding,availability:'UNAVAILABLE',snapshot:null,age_ns:null,received_at:null};break;
 case '/api/v1/profiles':data={profiles:[],etag:'"synthetic"',active_id:'',switch_version:'switch-v1-'+'1'.repeat(64)};break;
 case '/api/v1/subscription':data={configured:false};break;
 case '/api/v1/logout':data={ok:true};break;
 default:code=404;data={error:'SYNTHETIC_NOT_IMPLEMENTED'};
 }
 res.writeHead(code,{'Content-Type':'application/json'});res.end(JSON.stringify(data));
});
await new Promise(r=>server.listen(0,'127.0.0.1',r));const origin='http://127.0.0.1:'+server.address().port;
const browser=await chromium.launch({executablePath:process.env.CHROMIUM||'/home/hermeswebui/.cache/ms-playwright/chromium_headless_shell-1248/chrome-headless-shell-linux64/chrome-headless-shell',headless:true,args:['--no-sandbox'],env:{...process.env,FONTCONFIG_FILE:process.env.FONTCONFIG_FILE||'/workspace/anytls-r10-product-evidence-r2/fonts.conf',LD_LIBRARY_PATH:process.env.BROWSER_LIBS||'/workspace/browser-libs/extracted/usr/lib/x86_64-linux-gnu'}});
const results=[];
try{
 for(const width of [1280,390]){
  statusData=defaultStatus();helperData=defaultHelper();dnsData=dns();statusFail=false;checkFail=false;requests=[];
  const context=await browser.newContext({viewport:{width,height:1100}}),page=await context.newPage(),errors=[];
  page.on('pageerror',e=>errors.push(String(e)));
  await page.route('**/*',route=>route.request().url().startsWith(origin+'/')?route.continue():route.abort());
  const go=async route=>{await page.evaluate(r=>location.hash=r,route);await page.waitForTimeout(100);};
  await page.goto(origin+'/#debug/versions');await page.waitForFunction(()=>document.getElementById('runtime-helper').textContent.includes('v2026-11-01-01'));await go('debug/operations');
  await page.waitForFunction(()=>document.getElementById('runtime-history').textContent.includes('v2026-10-01-01'));await go('debug/versions');
  const summary=()=>page.evaluate(()=>JSON.parse(AnyTLSRuntime.summary()));
  const overflow=async()=>assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,'no horizontal overflow');
  assert.equal((await summary()).versions.installed.value,null);assert.equal((await summary()).versions.coreCurrent.value,null);assert.equal((await summary()).health.network,'NOT_OBSERVED');
  await page.evaluate(async()=>{await status();await status();});assert.equal(requests.filter(r=>r.path.endsWith('/update-check')).length,0);assert.equal(requests.filter(r=>r.path.endsWith('/dns-runtime')).length,0);
  await overflow();await page.locator('#runtime-panel').screenshot({path:out+`/initial-${width}.png`});
  await page.locator('#runtime-check').click();await page.waitForFunction(()=>document.getElementById('runtime-installed').textContent.includes('v2026-11-03-01'));
  assert.equal(requests.filter(r=>r.path.endsWith('/update-check')).length,1);assert.match(await page.locator('#runtime-difference').textContent(),/版本标签不同/);
  // SPEC-02: use the real update-page click handler, then read overview summary.
  await go('settings/update');await page.locator('#check-update').click();await page.waitForFunction(()=>document.getElementById('update-result').textContent.includes('已安装新版'));
  const beforeUpdateFailure=(await summary()).versions.installed;checkFail=true;
  await page.locator('#check-update').click();await page.waitForFunction(()=>document.getElementById('update-result').textContent.includes('检查未完成'));assert.match(await page.locator('#runtime-error').textContent(),/安装版本检查失败/);
  await go('debug/versions');await page.waitForFunction(()=>JSON.parse(AnyTLSRuntime.summary()).versions.installed.refreshStatus==='FAILED');
  const afterUpdateFailure=(await summary()).versions.installed;assert.equal(afterUpdateFailure.value,beforeUpdateFailure.value);assert.equal(afterUpdateFailure.observedAt,beforeUpdateFailure.observedAt);assert.match(await page.locator('#runtime-installed').textContent(),/本次读取失败/);
  await overflow();await page.locator('#runtime-panel').screenshot({path:out+`/update-page-failed-${width}.png`});fs.writeFileSync(out+`/update-page-failed-${width}.json`,JSON.stringify({before:beforeUpdateFailure,after:afterUpdateFailure},null,2));checkFail=false;
  assert.equal((await summary()).versions.webui.value,'v2026-11-02-02');assert.equal((await summary()).versions.helper.value,'v2026-11-01-01');
  await go('debug/dns');await page.locator('#dns-evidence-refresh').click();await page.waitForFunction(()=>JSON.parse(AnyTLSRuntime.summary()).health.dns.availability==='OBSERVED');
  const dnsRequests=requests.filter(r=>r.path.endsWith('/dns-runtime'));assert.equal(dnsRequests.length,2);assert.equal(dnsRequests[0].query,'');assert.ok(dnsRequests[1].query.includes('instance_id='));
  assert.equal((await summary()).versions.coreCurrent.value,null);assert.equal((await summary()).lastStartup.observation,'STALE');
  await go('debug/versions');await overflow();await page.locator('#runtime-panel').screenshot({path:out+`/observed-${width}.png`});await go('debug/dns');
  await page.waitForFunction(()=>JSON.parse(AnyTLSRuntime.summary()).health.dns.availability==='STALE');assert.equal(requests.filter(r=>r.path.endsWith('/dns-runtime')).length,2);
  // Real two-step mismatch cannot project fresh evidence.
  dnsData={...dns(),binding:{...binding,generation:'9'.repeat(32)}};await page.locator('#dns-evidence-refresh').click();await page.waitForFunction(()=>JSON.parse(AnyTLSRuntime.summary()).health.dns.availability==='UNAVAILABLE');dnsData=dns();
  helperData={available:false,code:'HELPER_CONFIG_MISMATCH',message:'SECRET_SENTINEL'};statusData={...defaultStatus(),availability:'UNAVAILABLE',running:false,loaded:false};await go('debug/versions');await page.evaluate(()=>status(()=>true,{explicit:true}));
  assert.equal((await summary()).versions.helper.value,null);assert.equal((await summary()).health.service.running,null);assert.match(await page.locator('#runtime-service').textContent(),/UNKNOWN/);
  await overflow();await page.locator('#runtime-panel').screenshot({path:out+`/unknown-${width}.png`});
  statusFail=true;checkFail=true;await page.evaluate(()=>{savedFeedback({changed:true,apply_status:'APPLIED'});});const noticeBefore=await page.locator('#notice').textContent();await page.evaluate(()=>status());assert.equal(await page.locator('#notice').textContent(),noticeBefore);
  await page.locator('#runtime-check').click();await page.waitForFunction(()=>document.getElementById('runtime-error').textContent.includes('检查失败'));assert.equal((await summary()).versions.installed.value,'v2026-11-03-01');assert.equal(await page.locator('#notice').textContent(),noticeBefore);
  await overflow();await page.locator('#runtime-panel').screenshot({path:out+`/error-${width}.png`});
  await page.evaluate(()=>{runtimePublish('status',{version:'<img src=x onerror=alert(1)> SECRET_SENTINEL /private/config.yaml 192.0.2.1',availability:'SECRET_SENTINEL',loaded:false,running:false,pendingKnown:false});notice('SECRET_SENTINEL /private/config.yaml 192.0.2.1');Object.defineProperty(window,'isSecureContext',{configurable:true,value:false});});
  await page.locator('#runtime-copy').click();assert.match(await page.locator('#runtime-copy-status').textContent(),/未复制/);
  const text=await page.locator('#runtime-summary').inputValue();assert.equal(await page.locator('#runtime-summary').evaluate(e=>e.selectionEnd-e.selectionStart),text.length);
  for(const secret of ['SECRET_SENTINEL','/private','192.0.2.1','config_identity',binding.instance_id,'3'.repeat(64),'<img'])assert.equal(text.includes(secret),false,secret);
  assert.equal(await page.locator('#runtime-panel img').count(),0);
  await page.evaluate(()=>{Object.defineProperty(window,'isSecureContext',{configurable:true,value:true});Object.defineProperty(navigator,'clipboard',{configurable:true,value:{writeText:async text=>{window.copied=text;}}});});await page.locator('#runtime-copy').click();assert.equal(await page.evaluate(()=>copied),await page.locator('#runtime-summary').inputValue());
  await page.evaluate(()=>Object.defineProperty(navigator,'clipboard',{configurable:true,value:{writeText:async()=>{throw Error('denied');}}}));await page.locator('#runtime-copy').click();assert.match(await page.locator('#runtime-copy-status').textContent(),/未复制/);await overflow();
  // Actual app session transitions, ignored-abort old 401 and finally/new-owner.
  const race=await page.evaluate(async()=>{
   const original=fetch;let oldResolve,newResolve;
   window.fetch=(...args)=>String(args[0]).endsWith('/update-check')?new Promise(r=>oldResolve=r):original(...args);
   const old=AnyTLSRuntime.check();showLogin();csrf='SYNTHETIC_NEW';sessionGeneration++;$('console-view').hidden=false;$('login-view').hidden=true;
   window.fetch=(...args)=>String(args[0]).endsWith('/update-check')?new Promise(r=>newResolve=r):original(...args);
   const fresh=AnyTLSRuntime.check();oldResolve(new Response('{"error":"AUTH_REQUIRED"}',{status:401}));await old;
   const retained=csrf==='SYNTHETIC_NEW'&&!$('console-view').hidden&&$('runtime-check').disabled;
   newResolve(new Response(JSON.stringify({installed:'v2026-11-03-01',status:'UP_TO_DATE',available:false,sourceOnly:false,updated:false,restartRequired:false})));await fresh;window.fetch=original;
   return retained&&!$('runtime-check').disabled&&JSON.parse(AnyTLSRuntime.summary()).versions.installed.value==='v2026-11-03-01';
  });assert.equal(race,true);
  const hidden=await page.evaluate(async()=>{const original=fetch;let resolve;window.fetch=()=>new Promise(r=>resolve=r);const p=AnyTLSRuntime.check();Object.defineProperty(document,'hidden',{configurable:true,value:true});document.dispatchEvent(new Event('visibilitychange'));Object.defineProperty(document,'hidden',{configurable:true,value:false});document.dispatchEvent(new Event('visibilitychange'));resolve(new Response(JSON.stringify({installed:'v2099-01-01-01',status:'UP_TO_DATE',available:false,sourceOnly:false,updated:false,restartRequired:false})));await p;window.fetch=original;return JSON.parse(AnyTLSRuntime.summary()).versions.installed.value!=='v2099-01-01-01';});assert.equal(hidden,true);
  assert.deepEqual(errors,[]);fs.writeFileSync(out+`/requests-${width}.json`,JSON.stringify(requests,null,2));fs.writeFileSync(out+`/summary-${width}.json`,text);
  results.push({width,mode:'BROWSER_SYNTHETIC',states:['initial','observed','update-page-failed','unknown','error'],updatePageFailureSummarySync:true,updatePageOldValueTimePreserved:true,realCandidateDOM:true,noOverflow:true,noAutomaticDNSOrUpdate:true,manualDNSTwoStep:true,coreAlwaysUnknown:true,summaryAllowlist:true,clipboardInjectedSuccessDeniedAndManual:true,actualAppSaveNoticePreserved:true,old401AndFinallyGuard:true,hiddenCancellation:true,pageErrors:errors});await context.close();
 }
 const staticSource=fs.readFileSync(new URL('./web_static.go',import.meta.url),'utf8');
 assert.match(staticSource,/\{"\/runtime\.js", "runtime\.js", "text\/javascript; charset=utf-8"\}/,'runtime asset must be in the source store manifest');
 const staticAllowlist=/case ([^\n]+):/.exec(staticSource)?.[1]||'';for(const asset of ['/','/app.js','/startup.js','/dns.js','/runtime.js','/style.css','/product.js','/product.css'])assert.ok(staticAllowlist.includes('"'+asset+'"'),'exact asset remains in source allowlist: '+asset);
 const report={mode:'BROWSER_SYNTHETIC',nativePreview:false,goStaticRuntimeRoute:'SOURCE_MANIFEST_ADDED_NOT_COMPILED_OR_HTTP_VERIFIED',results};fs.writeFileSync(out+'/results.json',JSON.stringify(report,null,2));console.log(JSON.stringify(report,null,2));
}finally{await browser.close();await new Promise(r=>server.close(r));}

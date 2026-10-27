import {createRequire} from 'node:module';
import fs from 'node:fs';
import http from 'node:http';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
const require=createRequire(import.meta.url);
const {chromium}=require('/home/hermeswebui/.hermes/node/lib/node_modules/@askjo/camofox-browser/node_modules/playwright-core');
const root=new URL('./web_assets/',import.meta.url).pathname;
const dir=process.env.ST1_BROWSER_EVIDENCE;
assert.ok(dir);fs.mkdirSync(dir,{recursive:true});
const input=process.env.ST1_ACTUAL_HTTP_PREFIX;assert.ok(input);
const files=Object.fromEntries(['preflight','open-sink','rollback'].map(n=>[n,fs.readFileSync(input+n+'.json')]));
const hashes=Object.fromEntries(Object.entries(files).map(([n,b])=>[n,crypto.createHash('sha256').update(b).digest('hex')]));
let selected='preflight';const reads=[];
// Trace bytes below are original authenticated Mac ServeHTTP responses, not
// reconstructed DTOs. Other API responses are explicitly synthetic shell-only
// fixtures: this browser phase does not claim native helper authentication.
const server=http.createServer((req,res)=>{
 const path=new URL(req.url,'http://localhost').pathname;
 if(path==='/api/v1/startup-trace'){reads.push({selected,url:req.url,origin:req.headers['x-anytls-origin']});res.setHeader('Content-Type','application/json');res.end(files[selected]);return;}
 if(path.startsWith('/api/')){
  const value=path.endsWith('/session')?{csrf:'shell-only-fixture'}:path.endsWith('/status')?{availability:'AVAILABLE',running:false,loaded:false,version:'shell-only',pendingReload:false,pendingKnown:true}:path.endsWith('/subscription')?{configured:false}:path.endsWith('/profiles')?{profiles:[],etag:'"v1"'}:path.endsWith('/config')?{yaml:'nodes: []\nrules: ["MATCH,DIRECT"]',etag:'"v1"'}:{available:false};
  res.setHeader('Content-Type','application/json');res.end(JSON.stringify(value));return;
 }
 const name=path==='/'?'index.html':path.slice(1);if(!['index.html','app.js','startup.js','style.css'].includes(name)){res.writeHead(404);res.end();return;}
 res.setHeader('Content-Type',name.endsWith('.js')?'text/javascript':name.endsWith('.css')?'text/css':'text/html');res.end(fs.readFileSync(root+name));
});
await new Promise(r=>server.listen(0,'127.0.0.1',r));
const origin=`http://127.0.0.1:${server.address().port}`;
const browser=await chromium.launch({executablePath:'/home/hermeswebui/.cache/ms-playwright/chromium_headless_shell-1248/chrome-headless-shell-linux64/chrome-headless-shell',headless:true,args:['--no-sandbox'],env:{...process.env,LD_LIBRARY_PATH:'/workspace/browser-libs/extracted/usr/lib/x86_64-linux-gnu'}});
const results=[];
try{
 for(const width of [1280,390]){
  selected='preflight';const context=await browser.newContext({viewport:{width,height:960},permissions:['clipboard-read','clipboard-write']});const page=await context.newPage();const errors=[];page.on('pageerror',e=>errors.push(String(e)));
  await page.goto(origin);await page.waitForFunction(()=>!document.getElementById('startup-copy').disabled);
  for(const name of ['preflight','open-sink','rollback']){
   selected=name;
   await page.evaluate(()=>{startupCancel();startupResume();});
   const expected=JSON.parse(files[name]);
   await page.waitForFunction(expected=>{const v=document.getElementById('startup-text').value;try{return JSON.stringify(JSON.parse(v.split('[完整固定 DTO]\n')[1]))===JSON.stringify(expected);}catch{return false;}},expected);
   const text=await page.locator('#startup-text').inputValue();
   assert.deepEqual(JSON.parse(text.split('[完整固定 DTO]\n')[1]),expected);
   assert.match(text,/AUXILIARY_NOT_AUTHORITY/);
   await page.locator('#startup-copy').click();
   const clipboard=await page.evaluate(()=>navigator.clipboard.readText());assert.equal(clipboard,text,'real Chromium clipboard must equal actual trace page text');
   assert.match(await page.locator('#startup-copy-status').textContent(),/已复制/);
   if(name==='preflight')assert.match(text,/HELPER_PREFLIGHT_CAPTURE/);
   if(name==='open-sink')assert.match(text,/CORE_OPEN_SINK/);
   if(name==='rollback'){for(const stage of ['CORE_START','CORE_CLOSE','SNAPSHOT_REMOVE','RECEIPT_WRITE','WEB_FINISH'])assert.match(text,new RegExp(stage));assert.equal(expected.trace.web_return,'FAILED');}
   fs.writeFileSync(`${dir}/copy-${width}-${name}.txt`,text);
   results.push({width,phase:name,actualAuthenticatedMacHTTP:hashes[name],copySHA256:crypto.createHash('sha256').update(text).digest('hex'),realChromiumClipboard:true,shellAPIsSynthetic:true,installedHelperAcceptance:false});
  }
  assert.deepEqual(errors,[]);assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);await context.close();
 }
 fs.writeFileSync(dir+'/results.json',JSON.stringify({results,reads,inputSHA256:hashes},null,2));console.log(JSON.stringify(results));
}finally{await browser.close();await new Promise(r=>server.close(r));}

// SYNTHETIC_API_FRONTEND: completed interval averages; no VPN or external calls.
import fs from 'node:fs';
import http from 'node:http';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import vm from 'node:vm';
import {createRequire} from 'node:module';
const root=process.env.WEB_ROOT||new URL('./web_assets/',import.meta.url).pathname;
const out=process.env.DASHBOARD_EVIDENCE;assert.ok(out);fs.mkdirSync(out,{recursive:true});
const hash=p=>crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
const pins=()=>Object.fromEntries(['app.js','runtime.js','startup.js','dns.js','product.js','style.css','product.css','index.html'].map(n=>[n,hash(root+n)]));
const before=pins(),checks=[],shots=[],errors=[];
const check=(name,ok,detail)=>checks.push({name,status:ok?'PASS':'FAIL',detail});
const interval=(start,end,down,up)=>({start_ns:String(start),end_ns:String(end),download_bytes:String(down),upload_bytes:String(up)});
const fixture=()=>({traffic_schema:1,availability:'OBSERVED',snapshot:{traffic_schema:1,header:{schema_version:1,config_identity:'a'.repeat(64),instance_id:'b'.repeat(32),generation:'c'.repeat(32),manifest_id:'d'.repeat(64),runtime_sha256:'e'.repeat(64),created_at:'2026-11-04T00:00:00Z',previous_binding:null},source:'SDK_ROUTED_PAYLOAD',state:'RUNNING',sampled_at:new Date().toISOString(),elapsed_ns:'205000000000',upload_bytes:'438750',download_bytes:'1453125',saturated:false,rate:null,history:[interval(0n,60000000000n,375000,202500),interval(60000000000n,125000000000n,853125,146250),interval(125000000000n,185000000000n,225000,90000)]}});
const source=fs.readFileSync(root+'product.js','utf8');
const ctx=vm.createContext({Date,BigInt,Object,Array,Number});
vm.runInContext(source.slice(source.indexOf(' const exact='),source.indexOf(' function clearTraffic')),ctx);
const valid=t=>{ctx.dto=t;return vm.runInContext('validTraffic(dto)',ctx);};
check('valid delayed 65s interval averages',valid(fixture()));
for(const [name,mutate]of [['subminute',s=>s.history[0].end_ns='59999999999'],['sum overflow',s=>s.download_bytes='1'],['uint64 overflow',s=>s.download_bytes='18446744073709551616'],['overlap',s=>s.history[1].start_ns='59999999999']]){const t=fixture();mutate(t.snapshot);check('reject '+name,!valid(t));}
const max=fixture();max.snapshot.download_bytes='18446744073709551615';max.snapshot.history=[interval(0n,60000000001n,max.snapshot.download_bytes,0)];check('max uint64 + duration jitter accepted',valid(max));
ctx.i=max.snapshot.history[0];check('BigInt actual ns Mbps preserved',vm.runInContext("mbps(i,'download_bytes')",ctx)===Number(18446744073709551615n*8000000n/60000000001n)/1000);
const {chromium}=createRequire(import.meta.url)(process.env.ANYTLS_PLAYWRIGHT_MODULE||'/home/hermeswebui/.hermes/node/lib/node_modules/@askjo/camofox-browser/node_modules/playwright-core');
let traffic=fixture();
const server=http.createServer((req,res)=>{const path=new URL(req.url,'http://localhost').pathname;
const send=d=>{res.setHeader('Content-Type','application/json');res.end(JSON.stringify(d));};
if(!path.startsWith('/api/')){const n=path==='/'?'index.html':path.slice(1);if(!Object.hasOwn(before,n))return res.writeHead(404).end();res.setHeader('Content-Type',n.endsWith('.js')?'text/javascript':n.endsWith('.css')?'text/css':'text/html');return res.end(fs.readFileSync(root+n));}
if(path.endsWith('/session'))return send({csrf:'SYNTHETIC'});
if(path.endsWith('/status'))return send({availability:'AVAILABLE',running:true,loaded:true,version:'v2026-11-06-02',transport:'loopback-http',pendingKnown:true,pendingReload:false});
if(path.endsWith('/traffic')){traffic.snapshot.sampled_at=new Date().toISOString();return send(traffic);}
if(path.endsWith('/metrics'))return send({schema_version:1,traffic:{quality:'NOT_OBSERVED',download_bps:null,upload_bps:null,recorded_download_bytes:null,recorded_upload_bytes:null},network:{state:'NOT_OBSERVED',latency_ms:null,attempts:0,succeeded:0,sample_success_ratio:null,availability_24h:null},bins:Array.from({length:288},()=>({attempts:0,succeeded:0,traffic_quality:'NOT_OBSERVED',download_bytes:null,upload_bytes:null}))});
res.statusCode=503;send({error:'UNAVAILABLE'});
});
await new Promise(r=>server.listen(0,'127.0.0.1',r));const origin='http://127.0.0.1:'+server.address().port;
const browser=await chromium.launch({executablePath:process.env.ANYTLS_CHROMIUM||'/home/hermeswebui/.cache/ms-playwright/chromium_headless_shell-1248/chrome-headless-shell-linux64/chrome-headless-shell',headless:true,args:['--no-sandbox'],env:{...process.env,FONTCONFIG_FILE:process.env.FONTCONFIG_FILE||'/workspace/anytls-r10-product-evidence-r2/fonts.conf',LD_LIBRARY_PATH:process.env.LD_LIBRARY_PATH||'/workspace/browser-libs/extracted/usr/lib/x86_64-linux-gnu'}});
try{for(const width of [1440,390]){
const context=await browser.newContext({viewport:{width,height:1000}}),p=await context.newPage();p.on('pageerror',e=>errors.push(String(e)));await p.route('**/*',r=>r.request().url().startsWith(origin)?r.continue():r.abort());
const render=async(name,change=()=>{})=>{traffic=fixture();change(traffic.snapshot);check(width+' valid '+name,valid(traffic));await p.goto(origin);await p.waitForFunction(()=>globalThis.AnyTLSProduct&&!document.querySelector('#console-view').hidden&&document.querySelector('[data-metric="traffic-total"]').textContent!=='—');await p.evaluate(()=>document.fonts.ready);
const data=await p.locator('.plot').evaluate(e=>{const svg=e.querySelector('svg'),overlay=e.querySelector('.emptyoverlay');return {hidden:getComputedStyle(overlay).display==='none',aria:svg.getAttribute('aria-label'),lines:[...svg.querySelectorAll('line')].map(l=>l.outerHTML),curves:svg.querySelectorAll('path').length,points:[...svg.querySelectorAll('circle')].map(c=>({kind:c.dataset.kind,series:c.dataset.series,x:+c.getAttribute('cx'),y:+c.getAttribute('cy'),width:c.getBoundingClientRect().width,stroke:getComputedStyle(c).stroke,strokeWidth:parseFloat(getComputedStyle(c).strokeWidth),title:c.querySelector('title')?.textContent})),polylines:[...svg.querySelectorAll('polyline')].map(l=>({series:l.dataset.series,points:[...l.points].map(p=>[p.x,p.y]),width:l.getBoundingClientRect().width,fill:l.getAttribute('fill')}))};});
check(width+' no invented smoothing '+name,data.curves===0);check(width+' no overflow '+name,await p.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
const cdp=await context.newCDPSession(p);await cdp.send('DOM.enable');await cdp.send('CSS.enable');const {root:d}=await cdp.send('DOM.getDocument'),{nodeId}=await cdp.send('DOM.querySelector',{nodeId:d.nodeId,selector:'#route-heading'}),{fonts}=await cdp.send('CSS.getPlatformFontsForNode',{nodeId});check(width+' CJK '+name,fonts.some(f=>/Noto.*CJK/i.test(f.familyName)&&f.glyphCount>0));await cdp.detach();
const file=out+'/'+name+'-'+width+'.png';await p.screenshot({path:file,fullPage:true});shots.push({file,sha256:hash(file)});return data;};
let d=await render('three-history');
check(width+' completed averages connected',d.polylines.length===2&&d.polylines.every(l=>l.points.length===3&&l.width>100&&l.fill==='none')&&d.lines.length===0,d);
check(width+' midpoint actual ns geometry',d.points.length===6&&d.points.slice(0,3).every((p,i)=>Math.abs(p.x-[40+30/205*958,40+92.5/205*958,40+155/205*958][i])<.002),d.points);
check(width+' nonflat actual byte duration averages',d.points.length===6&&d.points.slice(0,3).every((p,i)=>Math.abs(p.y-[200-.05/.105*190,10,200-.03/.105*190][i])<.001),d.points);
check(width+' all markers and interval detail',d.hidden&&d.points.length===6&&d.points.every(p=>p.width+p.strokeWidth>=4&&p.title?.includes('区间平均')&&p.title.includes('Mbps')&&p.title.includes('至')),d.points);
check(width+' peak/axis precision consistent',(await p.locator('#peak-label').textContent()).includes('0.105 Mbps')&&await p.locator('.yaxis span').first().textContent()==='0.105');
check(width+' average trend scope disclosed',(await p.locator('.chartcard .sectionhead p').textContent()).includes('区间平均')&&d.aria.includes('连线'));
d=await render('true-gap',s=>{s.history[1].start_ns='60000000001';});check(width+' one ns gap never bridged',d.polylines.length===2&&d.polylines.every(l=>l.points.length===2&&l.points[0][0]>300)&&d.points.length===6,d);
d=await render('isolated-gap',s=>{s.history=[s.history[0],s.history[2]];});check(width+' isolated observations visible without bridge',d.polylines.length===0&&d.points.length===4&&d.hidden,d);
d=await render('single-history',s=>{s.history=[s.history[0]];});check(width+' single completed point visible and labelled',d.points.length===2&&d.polylines.length===0&&d.hidden&&(await p.locator('#peak-label').textContent()).includes('0.050'),d);
d=await render('zero',s=>{s.history=s.history.map(i=>({...i,download_bytes:'0',upload_bytes:'0'}));});check(width+' zero baseline actual visible',d.points.length===6&&d.points.every(p=>p.y===200)&&d.polylines.length===2&&d.hidden,d);
d=await render('realtime',s=>{s.history=[];s.elapsed_ns='30000000000';s.rate=interval(25000000000n,30000000000n,12500,12500);});check(width+' provisional actual interval only',d.lines.length===2&&d.polylines.length===0&&d.points.length===0&&d.hidden&&(await p.locator('#peak-label').textContent()).includes('—'),d);
d=await render('empty',s=>{s.history=[];});check(width+' unknown never zero',!d.hidden&&d.points.length===0&&d.lines.length===0&&d.polylines.length===0&&(await p.locator('#peak-label').textContent()).includes('—'),d);
d=await render('history-current-burst',s=>{s.elapsed_ns='210000000000';s.download_bytes=String(1453125n+50000000n);s.rate=interval(205000000000n,210000000000n,50000000,0);});check(width+' current burst excluded from history peak and scale',d.polylines.length===2&&d.lines.length===0&&(await p.locator('#peak-label').textContent()).includes('0.105 Mbps')&&await p.locator('.yaxis span').first().textContent()==='0.105');
d=await render('dense-24h',s=>{s.elapsed_ns='86400000000000';s.history=Array.from({length:1440},(_,i)=>interval(BigInt(i)*60000000000n,BigInt(i+1)*60000000000n,375000,150000));s.download_bytes=String(375000n*1440n);s.upload_bytes=String(150000n*1440n);});check(width+' bounded full retained history renders',d.points.length===2880&&d.polylines.length===2&&d.polylines.every(l=>l.points.length===1440)&&d.hidden);
await context.close();}
check('no browser exceptions',errors.length===0,errors);check('immutable input assets',JSON.stringify(before)===JSON.stringify(pins()));
}finally{await browser.close();await new Promise(r=>server.close(r));fs.writeFileSync(out+'/results.json',JSON.stringify({evidence:'SYNTHETIC_API_FRONTEND',test:{file:import.meta.url,sha256:hash(new URL(import.meta.url))},source:before,checks,shots,errors},null,2));}
const failures=checks.filter(c=>c.status==='FAIL');console.log(JSON.stringify({checks:checks.length,failed:failures.length,failures},null,2));process.exitCode=failures.length?1:0;

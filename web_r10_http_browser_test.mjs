import fs from 'node:fs';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url);
const {chromium}=require('/home/hermeswebui/.hermes/node/lib/node_modules/@askjo/camofox-browser/node_modules/playwright-core');
let input='';for await(const chunk of process.stdin)input+=chunk;
const config=JSON.parse(input),checks=[],errors=[],shots=[];
const browser=await chromium.launch({executablePath:'/home/hermeswebui/.cache/ms-playwright/chromium_headless_shell-1248/chrome-headless-shell-linux64/chrome-headless-shell',headless:true,args:['--no-sandbox'],env:{...process.env,LD_LIBRARY_PATH:'/workspace/browser-libs/extracted/usr/lib/x86_64-linux-gnu',FONTCONFIG_FILE:process.env.ANYTLS_R10_FONTCONFIG||'/workspace/anytls-r10-product-evidence-r2/fonts.conf'}});
const check=(label,value,width)=>{assert.ok(value,label);checks.push({label,width,status:'PASS'});};
try{
 for(const width of [1440,390]){
  const context=await browser.newContext({viewport:{width,height:1000},acceptDownloads:true});
  await context.addCookies([{name:config.cookie_name,value:config.cookie_value,url:config.origin,httpOnly:true,sameSite:'Strict'}]);
  const page=await context.newPage();page.on('pageerror',e=>errors.push(String(e)));
  // There are no route fulfillment callbacks: documents, assets and API calls
  // all go to the actual Go ServeHTTP implementation.
  await page.goto(config.origin,{waitUntil:'networkidle'});
  await page.waitForFunction(()=>!document.getElementById('console-view').hidden&&window.AnyTLSProduct);
  const go=async route=>{await page.evaluate(r=>location.hash=r,route);await page.waitForTimeout(160);};
  const shot=async name=>{await page.evaluate(async()=>{await document.fonts.ready;document.documentElement.style.scrollBehavior='auto';window.scrollTo({top:0,behavior:'instant'});});await page.waitForTimeout(120);const cdp=await context.newCDPSession(page);await cdp.send('DOM.enable');await cdp.send('CSS.enable');const document=await cdp.send('DOM.getDocument');const node=await cdp.send('DOM.querySelector',{nodeId:document.root.nodeId,selector:'#route-heading'});const fonts=await cdp.send('CSS.getPlatformFontsForNode',{nodeId:node.nodeId});await cdp.detach();check('actual Chinese glyphs '+name,fonts.fonts.some(f=>f.familyName==='Noto Sans CJK SC'&&f.glyphCount>0),width);const path=config.evidence+'/'+name+'-'+width+'.png';await page.screenshot({path,fullPage:true});shots.push({width,name,path,fonts:fonts.fonts});};
  const routes=await page.evaluate(()=>AnyTLSProduct.routes);check('exact 16 product routes',routes.length===16,width);
  for(const route of routes){await go(route);check(route+' real page',await page.locator('.view:visible').count()===1,width);check(route+' no horizontal overflow',await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),width);await shot(route.replaceAll('/','-'));}
  await go('settings/profiles');await page.locator('#profile-name').fill('真实HTTP方案'+width);await page.locator('#save-profile').click();await page.waitForTimeout(180);
  check('profile persisted and read back',await page.getByText('真实HTTP方案'+width,{exact:true}).filter({visible:true}).count()===1,width);
  await page.getByRole('button',{name:'重命名',exact:true}).last().click();await page.locator('#product-dialog input').fill('已重命名'+width);await page.getByRole('button',{name:'保存',exact:true}).click();await page.waitForTimeout(180);
  check('profile rename real handler',await page.getByText('已重命名'+width,{exact:true}).filter({visible:true}).count()===1,width);
  await go('settings/import');await page.locator('#import-tab-url').click();await page.locator('#subscription-url').fill('https://example.com/provider?token=LOCAL_ONLY');await page.locator('#subscription-name').fill('HTTP订阅'+width);await page.locator('#preview-subscription').click();await page.waitForTimeout(200);
  check('subscription real preview',await page.locator('#subscription-preview').isVisible(),width);
  await page.locator('#subscription-preview button').click();await page.getByRole('button',{name:'确认',exact:true}).click();await page.waitForTimeout(220);await page.waitForFunction(()=>location.hash==='#settings/subscriptions'&&!document.querySelector('#subscriptions-status')?.textContent.includes('正在读取'),{},{timeout:10000}).catch(async error=>{fs.writeFileSync(config.evidence+'/subscription-debug.txt',JSON.stringify({hash:await page.evaluate(()=>location.hash),notice:await page.locator('#notice').textContent(),status:await page.locator('#subscriptions-status').textContent(),headings:await page.locator('h2').allTextContents()}));throw error;});
  if(await page.getByRole('heading',{name:'HTTP订阅'+width,exact:true}).count()!==1)fs.writeFileSync(config.evidence+'/subscription-debug.txt',JSON.stringify({hash:await page.evaluate(()=>location.hash),notice:await page.locator('#notice').textContent(),status:await page.locator('#subscriptions-status').textContent(),headings:await page.locator('h2').allTextContents()}));
  check('subscription real import readback',await page.getByRole('heading',{name:'HTTP订阅'+width,exact:true}).count()===1,width);
  check('private source token not rendered',!((await page.locator('#subscriptions-list').textContent()).includes('LOCAL_ONLY')),width);
  await shot('subscriptions-persisted');
  await go('overview');await page.waitForTimeout(200);check('service stopped projection',await page.locator('#power-toggle').getAttribute('aria-pressed')==='false',width);
  await page.locator('#power-toggle').click();await page.keyboard.press('Escape');check('power cancel does not mutate',await page.locator('#power-toggle').getAttribute('aria-pressed')==='false',width);
  if(width===390){await page.locator('#drawer-toggle').click();await shot('mobile-drawer');await page.keyboard.press('Escape');}
  await go('debug/report');const summary=await page.locator('#report-summary').textContent();const [download]=await Promise.all([page.waitForEvent('download'),page.locator('#export-summary').click()]);const downloadPath=config.evidence+'/report-'+width+'.txt';await download.saveAs(downloadPath);check('real report downloaded bytes',fs.readFileSync(downloadPath,'utf8')===summary,width);check('report omits provider token',!summary.includes('LOCAL_ONLY'),width);
  check('no page JavaScript error',errors.length===0,width);
  await context.close();
 }
 fs.writeFileSync(config.evidence+'/results.json',JSON.stringify({status:'PASS',evidence:'REAL_AUTHENTICATED_GO_HTTP_BROWSER_PRIVILEGED_LIFECYCLE_AND_PROVIDER_FIXTURE',checks,errors,screenshots:shots},null,2));
 console.log(JSON.stringify({status:'PASS',checks:checks.length,screenshots:shots.length,errors}));
}finally{await browser.close();}

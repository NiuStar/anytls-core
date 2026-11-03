'use strict';
// B1/B2 public-only projection. No DOM scraping, configuration, or raw errors.
(() => {
 const $=id=>document.getElementById(id), stamp=()=>new Date().toISOString();
 const version=v=>typeof v==='string'&&v.length<=128&&/^v[0-9]+(?:[.-][0-9]+)+(?:[-+](?:rc|beta|alpha)[0-9]+)?$/.test(v)?v:null;
 const pick=(v,values,fallback='UNKNOWN')=>values.includes(v)?v:fallback;
 const bool=v=>typeof v==='boolean'?v:null;
 const emptyVersion=()=>({value:null,evidence:'NONE',observedAt:null,freshness:'UNKNOWN'});
 let installed,webui,helper,service,control,pending,dns,history,error='',owner=null,copyOwner=null,dnsTimer=null,historyTimer=null,epoch=0;
 function reset(){
  installed=emptyVersion();webui=emptyVersion();helper={...emptyVersion(),available:null,code:'UNKNOWN',shaKind:'UNKNOWN',executionMapping:'NOT_ATTESTED',configBinding:'NOT_VERIFIED'};
  service={availability:'UNKNOWN',loaded:null,running:null,observedAt:null};control='UNKNOWN';pending={known:null,reload:null};dns={availability:'UNKNOWN',state:'UNKNOWN',ageNS:null,gap:null,observedAt:null};history=null;error='';
 }
 function summary(){
  // Construct every field explicitly; no spreading untrusted HTTP/event data.
  const layer=v=>({value:v.value,evidence:v.evidence,observedAt:v.observedAt,freshness:v.freshness,refreshStatus:v.refreshFailed?'FAILED':'NOT_FAILED'});
  return JSON.stringify({schema:1,versions:{installed:layer(installed),webui:layer(webui),helper:{...layer(helper),available:helper.available,code:helper.code,shaKind:helper.shaKind,executionMapping:'NOT_ATTESTED',configBinding:'NOT_VERIFIED'},coreCurrent:{value:null,evidence:'UNKNOWN',reason:'CURRENT_CORE_PROVENANCE_JOIN_UNAVAILABLE'}},health:{controlPlane:control,service:{...service},pending:{...pending},dns:{...dns},network:'NOT_OBSERVED'},lastStartup:history?{...history}:null},null,2);
 }
 const label=v=>v.value||'UNKNOWN · 未取得证据';
 function render(){
  $('runtime-installed').textContent=label(installed)+(installed.observedAt?' · 上次检查 '+installed.observedAt:' · 仅显式检查更新')+(installed.refreshFailed?' · 本次读取失败':'');
  $('runtime-webui').textContent=label(webui)+' · 内存版本';
  $('runtime-helper').textContent=label(helper)+' · '+(helper.available===true?'已认证助手':'助手可用性未确认');
  $('runtime-core').textContent='UNKNOWN · 缺少当前进程与版本的可靠关联';
  $('runtime-control').textContent=control==='OBSERVED'?'已认证 HTTP 可达；助手 '+(helper.available===true?'可达（配置绑定未核实）':helper.available===false?'不可用':'未知'):'UNKNOWN · 控制面读取未确认';
  $('runtime-service').textContent=service.availability==='AVAILABLE'?(service.running?'运行中':service.loaded?'已加载 · 未运行':'未加载')+' · 服务管理器观察':'UNKNOWN · 服务管理器不可用，不判定停止';
  $('runtime-dns').textContent=dns.availability==='OBSERVED'?'近期 DNS 策略已加载 · '+(dns.gap?'GAP':'仅部分覆盖')+' · 读取时缓存 '+dns.ageNS+' ns':dns.availability+' · DNS 仅手动缓存读取，不代表零查询';
  $('runtime-network').textContent='NOT_OBSERVED · 尚未验证端到端网络';
  $('runtime-history').textContent=history?'上次启动记录：'+(history.version||'UNKNOWN')+' · '+history.observation+' · '+history.startedAt+' · 该次操作 '+history.result:'上次启动记录：尚未取得 · 非当前版本';
  const differences=[];
  if(installed.value&&webui.value&&installed.value!==webui.value)differences.push('磁盘与 WebUI 版本标签不同；可在版本更新页核对并重启控制台。');
  if(helper.value&&webui.value&&helper.value!==webui.value)differences.push('助手与 WebUI 版本标签不同；请在本机核对助手。');
  $('runtime-difference').textContent=differences.join(' ')+' 版本标签相同不证明字节相同；助手 SHA 仅启动时文件字节，非执行映射。';
  $('runtime-error').textContent=error;$('runtime-error').hidden=!error;
  $('runtime-summary').value=summary();
  $('runtime-check').disabled=Boolean(owner)||!csrf||document.hidden;
 }
 function publish(kind,data){
  if(!csrf||document.hidden)return;
  const at=stamp();
  if(kind==='status'){
   control='OBSERVED';webui={value:version(data?.version),evidence:'IN_MEMORY_VERSION',observedAt:at,freshness:'LAST_OBSERVED'};
   const known=data?.availability==='AVAILABLE'&&bool(data.loaded)!==null&&bool(data.running)!==null;
   service={availability:known?'AVAILABLE':'UNKNOWN',loaded:known?data.loaded:null,running:known?data.running:null,observedAt:at};
   pending={known:bool(data?.pendingKnown),reload:data?.pendingKnown===true?bool(data.pendingReload):null};error='';
  }else if(kind==='helper'){
   const s=data?.status,valid=data?.available===true&&s?.ok===true&&s.code===''&&typeof s.loaded==='boolean'&&typeof s.running==='boolean'&&typeof s.config_identity==='string'&&/^[a-f0-9]{64}$/.test(s.config_identity);
   helper={...emptyVersion(),available:data?.available===false?false:valid?true:null,code:valid?'OK':pick(data?.code,['HELPER_CONFIG_MISMATCH','HELPER_UNAVAILABLE','FORBIDDEN','STATE_FAILED','BUSY']),shaKind:valid&&/^[a-f0-9]{64}$/.test(s.helper_sha256)?'FILE_BYTES':'UNKNOWN',executionMapping:'NOT_ATTESTED',configBinding:'NOT_VERIFIED'};
   if(valid){helper.value=version(s.helper_version);helper.evidence='AUTHENTICATED_HELPER';helper.observedAt=at;helper.freshness='LAST_OBSERVED';}
  }else if(kind==='statusError'){
   control='UNKNOWN';service={availability:'UNKNOWN',loaded:null,running:null,observedAt:null};webui=emptyVersion();helper={...emptyVersion(),available:null,code:'UNKNOWN',shaKind:'UNKNOWN'};pending={known:null,reload:null};error='状态读取失败；保存或应用结果未改变。';
  }else if(kind==='helperError'){
   helper={...emptyVersion(),available:null,code:'UNKNOWN',shaKind:'UNKNOWN'};error='助手读取失败；不判定 VPN 停止。';
  }else if(kind==='dns'){
   const age=typeof data?.ageNS==='string'&&/^(0|[1-9][0-9]{0,19})$/.test(data.ageNS)?data.ageNS:null;
   const observed=data?.availability==='OBSERVED'&&data.state==='LOADED'&&age!==null&&BigInt(age)<=2500000000n&&typeof data.gap==='boolean';
   clearTimeout(dnsTimer);dns={availability:observed?'OBSERVED':pick(data?.availability,['STALE','UNAVAILABLE'],'UNKNOWN'),state:pick(data?.state,['STARTING','LOADED','CLOSED']),ageNS:age,gap:bool(data?.gap),observedAt:at};
   if(observed)dnsTimer=setTimeout(()=>{dns.availability='STALE';render();},Math.max(1,2500-Number(BigInt(age)/1000000n)));
  }else if(kind==='history'){
   // Only startup.js's accepted ST1 boundary sends this small projection.
   const time=typeof data?.startedAt==='string'&&/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(data.startedAt)&&Number.isFinite(Date.parse(data.startedAt))?data.startedAt:null;
   clearTimeout(historyTimer);history=time?{version:version(data.version),startedAt:time,observation:pick(data.observation,['STALE','NOT_OBSERVED','UNAVAILABLE','INVALID','TRUNCATED','IDENTITY_MISMATCH','UNSUPPORTED','HISTORY_UNAVAILABLE','NOT_ATTEMPTED']),result:pick(data.result,['SUCCEEDED','FAILED','CANCELLED','UNKNOWN','IN_PROGRESS','NOT_ATTEMPTED'])}:null;
   if(history&&data.observation==='OBSERVED'&&typeof data.ageNS==='string'&&/^(0|[1-9][0-9]{0,19})$/.test(data.ageNS)&&BigInt(data.ageNS)<=1500000000n){history.observation='OBSERVED';historyTimer=setTimeout(()=>{if(history)history.observation='STALE';render();},Math.max(1,1500-Number(BigInt(data.ageNS)/1000000n)));}
  }else if(kind==='historyClear')history=null;
  render();
 }
 function cancel(clear=false){epoch++;const old=owner;owner=null;copyOwner=null;clearTimeout(dnsTimer);clearTimeout(historyTimer);if(old){clearTimeout(old.timer);old.controller.abort();}if(clear){reset();$('runtime-copy-status').textContent='';$('runtime-summary').value='';}else{dns={availability:'UNKNOWN',state:'UNKNOWN',ageNS:null,gap:null,observedAt:null};if(history?.observation==='OBSERVED')history.observation='STALE';error='页面读取已暂停；返回后请重新确认。';}render();}
 const checkToken=()=>({epoch:++epoch,session:sessionGeneration});
 const checkCurrent=token=>Boolean(token&&token.epoch===epoch&&token.session===sessionGeneration&&csrf&&!document.hidden);
 function checkFailure(token){
  if(!checkCurrent(token))return false;
  installed.refreshFailed=true;error='安装版本检查失败；保留上次显式观察，不代表实时磁盘状态。';render();return true;
 }
 function acceptCheck(data,token){
  if(!checkCurrent(token))return false;
  const value=version(data?.installed);
  if(!value||!['UP_TO_DATE','UPDATE_AVAILABLE','RESTART_REQUIRED'].includes(data.status)||!['available','sourceOnly','updated','restartRequired'].every(k=>typeof data[k]==='boolean'))return false;
  installed={value,evidence:'DISK_CHECK',observedAt:stamp(),freshness:'LAST_OBSERVED'};error='';render();return true;
 }
 async function check(){
  if(owner||!csrf||busy||document.hidden)return;
  const token=checkToken(),o={session:sessionGeneration,controller:new AbortController(),timer:null};owner=o;
  const current=()=>owner===o&&token.epoch===epoch&&o.session===sessionGeneration&&Boolean(csrf)&&!document.hidden;
  render();error='';
  // Bounded even when a fetch/body ignores AbortSignal. No polling or retries.
  let rejectAbort;const aborted=new Promise((_,reject)=>rejectAbort=reject);
  o.controller.signal.addEventListener('abort',()=>rejectAbort(Error('CANCELLED')),{once:true});o.timer=setTimeout(()=>o.controller.abort(),10000);
  try{
   const {response,data}=await Promise.race([(async()=>{const response=await fetch('/api/v1/update-check',{method:'GET',credentials:'same-origin',cache:'no-store',redirect:'error',signal:o.controller.signal});const data=await response.json();return {response,data};})(),aborted]);
   if(!current()||o.controller.signal.aborted)return;
   if(response.status===401){showLogin();return;}
   const value=version(data?.installed);
   if(!response.ok||!value||!['UP_TO_DATE','UPDATE_AVAILABLE','RESTART_REQUIRED'].includes(data.status)||!['available','sourceOnly','updated','restartRequired'].every(k=>typeof data[k]==='boolean'))throw Error('INVALID_CHECK');
   installed={value,evidence:'DISK_CHECK',observedAt:stamp(),freshness:'LAST_OBSERVED'};error='';
  }catch{if(current())checkFailure(token);}
  finally{clearTimeout(o.timer);if(owner===o){owner=null;render();}}
 }
 async function copy(){
  if(!csrf||document.hidden)return;const o={session:sessionGeneration};copyOwner=o;const text=summary();
  const current=()=>copyOwner===o&&o.session===sessionGeneration&&Boolean(csrf)&&!document.hidden;
  const manual=()=>{if(!current())return;$('runtime-details').open=true;const field=$('runtime-summary');field.value=text;field.focus();field.select();$('runtime-copy-status').textContent='未复制，请按 Ctrl+C / ⌘C 手动复制已选中的脱敏摘要。';};
  if(!isSecureContext||!navigator.clipboard?.writeText){manual();return;}
  try{await navigator.clipboard.writeText(text);if(current())$('runtime-copy-status').textContent='已复制脱敏摘要；不含配置、节点、地址或原始日志。';}catch{manual();}
 }
 reset();window.AnyTLSRuntime=Object.freeze({publish,summary,cancel,check,checkToken,checkCurrent,acceptCheck,checkFailure});
 $('runtime-check').addEventListener('click',check);$('runtime-copy').addEventListener('click',copy);
 $('logout').addEventListener('click',()=>cancel(true));
 document.addEventListener('visibilitychange',()=>{if(document.hidden)cancel();else render();});
 window.addEventListener('pagehide',()=>cancel(true));render();
})();

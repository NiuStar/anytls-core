'use strict';
// R10 product shell. API data is only rendered through textContent/value.
(() => {
 const routes=[['overview','网络概览','overview'],['connections','连接管理','connections'],['nodes/list','节点列表','nodes'],['nodes/groups','策略组与线路','groups'],['settings/general','常规','general'],['settings/profiles','配置方案','profiles'],['settings/import','导入配置','import'],['settings/subscriptions','订阅管理','subscriptions'],['settings/rules','分流规则','rules'],['settings/advanced','高级配置','advanced'],['settings/update','版本更新','update'],['debug/versions','版本与组件','versions'],['debug/dns','DNS 诊断','dns'],['debug/operations','最近操作','operations'],['debug/logs','日志查看','logs'],['debug/report','诊断报告','report']];
 const groups={nodes:[['list','节点列表'],['groups','策略组与线路']],settings:[['general','常规'],['profiles','配置方案'],['import','导入配置'],['subscriptions','订阅管理'],['rules','分流规则'],['advanced','高级配置'],['update','版本更新']],debug:[['versions','版本与组件'],['dns','DNS 诊断'],['operations','最近操作'],['logs','日志查看'],['report','诊断报告']]};
 let route='',routeEpoch=0,readEpoch=0,authEpoch=0,drawerReturn=null,dialogReturn=null,dialogOwner=null,profiles=[],subscriptions=[],subscriptionPreview=null,subscriptionInputEpoch=0,metricsOwner=null,metricsTimer=null,metrics=null,brand={version:null,state:'unchecked'},copyEpoch=0;
 const el=(tag,text,cls)=>element(tag,text,cls), link=(href,text)=>{const a=el('a',text);a.href=href;return a;}, button=(text,fn,cls)=>{const b=el('button',text,cls);b.type='button';b.onclick=fn;return b;};
 const append=(host,...nodes)=>{host.append(...nodes);return host;};
 $('connection-detail').after(append(el('p',undefined,'small'),Object.assign(el('span','尚未记录网络检查'),{id:'freshness'})));
 displayTime=function(value){const date=new Date(value);return typeof value==='string'&&Number.isFinite(date.getTime())?date.toLocaleString('zh-CN',{hour12:false}):'时间未知';};
 const readableTime=value=>value?displayTime(value):'尚未记录';
 function active(){return Boolean(csrf)&&!$('console-view').hidden;}
 function routeCurrent(epoch,session){return active()&&routeEpoch===epoch&&sessionGeneration===session&&!document.hidden;}
 function clearNotice(){notice('');}
 function closeModal(){const d=$('product-dialog');if(d.open)d.close();dialogOwner=null;if(dialogReturn?.isConnected)dialogReturn.focus();}
 function modal(title,body,actions=[]){
  closeModal();dialogReturn=document.activeElement;const d=$('product-dialog');d.replaceChildren();
  const head=el('div',undefined,'dialoghead'),h=el('h2',title);h.id='product-dialog-title';const close=button('×',closeModal,'close');close.setAttribute('aria-label','关闭对话框');head.append(h,close);d.append(head);
  for(const text of body)d.append(typeof text==='string'?el('p',text):text);
  const foot=el('div',undefined,'dialogfoot');foot.append(button('取消',closeModal));for(const [label,fn,cls]of actions)foot.append(button(label,fn,cls||'primary'));d.append(foot);d.showModal();dialogOwner={session:sessionGeneration,route:routeEpoch};return d;
 }
 function confirmAction(title,body,fn){const owner={session:sessionGeneration,route:routeEpoch};modal(title,body,[['确认',()=>{if(owner.session!==sessionGeneration||owner.route!==routeEpoch||!active()){closeModal();return;}closeModal();fn();}]]);}
 $('product-dialog').addEventListener('cancel',()=>{dialogOwner=null;setTimeout(()=>dialogReturn?.isConnected&&dialogReturn.focus(),0);});
 $('product-dialog').addEventListener('click',e=>{if(e.target!==$('product-dialog'))return;const r=e.target.getBoundingClientRect();if(e.clientX<r.left||e.clientX>r.right||e.clientY<r.top||e.clientY>r.bottom)closeModal();});
 function drawer(open){
  $('sidebar').inert=!open&&matchMedia('(max-width:760px)').matches;document.body.classList.toggle('drawer-open',open);$('drawer-shade').hidden=!open;$('drawer-toggle').setAttribute('aria-expanded',String(open));document.querySelector('main').inert=open;document.body.style.overflow=open?'hidden':'';
  if(open){drawerReturn=document.activeElement;$('brand-version').focus();}else if(drawerReturn?.isConnected)drawerReturn.focus();
 }
 closeDrawer=()=>drawer(false);$('drawer-toggle').onclick=()=>drawer(!document.body.classList.contains('drawer-open'));$('drawer-shade').onclick=()=>drawer(false);
 document.addEventListener('keydown',e=>{if(!document.body.classList.contains('drawer-open'))return;if(e.key==='Escape'){e.preventDefault();drawer(false);}if(e.key==='Tab'){const items=[...$('sidebar').querySelectorAll('a[href],button:not([disabled])')].filter(e=>e.getClientRects().length),first=items[0],last=items.at(-1);if(e.shiftKey&&document.activeElement===first){e.preventDefault();last.focus();}else if(!e.shiftKey&&document.activeElement===last){e.preventDefault();first.focus();}}},true);
 $('sidebar').addEventListener('click',e=>{if(e.target.closest('a')&&document.body.classList.contains('drawer-open'))drawer(false);});
 function routeNotice(){if(operationRoute!==null&&operationRoute!==routeEpoch)return false;const view=routes.find(r=>r[0]===route)?.[2],owner=$('view-'+view);if(owner&&$('notice').parentElement!==owner)owner.prepend($('notice'));return true;}
 let operationRoute=null;
 const inheritedOperation=operation;operation=async function(label,fn){if(busy)return;const epoch=routeEpoch;operationRoute=epoch;try{return await inheritedOperation(label,fn);}finally{if(operationRoute===epoch)operationRoute=null;renderPower();}};
 function normalize(){let hash=location.hash.slice(1)||'overview';hash=({nodes:'nodes/list',settings:'settings/general',debug:'debug/versions'})[hash]||hash;return routes.some(r=>r[0]===hash)?hash:'overview';}
 function renderRoute(force=false){
  const next=normalize();if(!force&&next===route)return;
  route=next;routeEpoch++;readEpoch++;copyEpoch++;nodesRequest++;groupsRequest++;profilesRequest++;cancelStatus();cancelMetrics();cancelRecords(true);cancelProbes();startupCancel();closeModal();drawer(false);
  const [root,sub]=route.split('/'),info=routes.find(r=>r[0]===route);
  // Existing startup parser remains sole owner, but only its debug views admit reads.
  currentView=route==='overview'?'home':root==='debug'&&['operations','logs'].includes(sub)?'overview':info[2];
  for(const s of document.querySelectorAll('.view'))s.hidden=s.id!=='view-'+info[2];
  $('route-heading').textContent=root==='nodes'?'节点与线路':root==='settings'?'设置':root==='debug'?'调试工具':info[1];
  $('route-description').textContent=({overview:'查看本机服务与已记录的网络情况。',connections:'查看已记录的路由选择，了解访问去向。',nodes:'管理常用节点，为不同访问选择合适的线路。',settings:'按你的习惯，安排好每一次连接。',debug:'遇到问题时，查看观察记录与排查资料。'})[root];
  $('page-title').textContent='我的网络 / '+info[1];const tabs=$('route-tabs');tabs.replaceChildren();tabs.hidden=!groups[root];
  for(const [key,label]of groups[root]||[]){const a=link('#'+root+'/'+key,label);if(key===sub)a.setAttribute('aria-current','page');tabs.append(a);}
  for(const a of $('sidebar').querySelectorAll('nav a')){const selected=a.hash.slice(1).split('/')[0]===root;a.classList.toggle('active',selected);if(selected)a.setAttribute('aria-current','page');else a.removeAttribute('aria-current');}
  $('schemebar').hidden=root!=='nodes';routeNotice();$('notice').hidden=true;$('notice').textContent='';
  if(active())loadRoute();
  requestAnimationFrame(()=>{const tab=tabs.querySelector('[aria-current]');if(tab)tabs.scrollLeft=Math.max(0,tab.offsetLeft-tabs.offsetLeft-(tabs.clientWidth-tab.offsetWidth)/2);});
 }
 async function loadRoute(){
  const epoch=routeEpoch,session=sessionGeneration,guard=()=>routeCurrent(epoch,session);
  const read=async fn=>{try{await fn();}catch(e){if(guard())notice(e.message,true);}};
  if(route==='overview'){status();metrics=null;renderMetrics();loadMetrics();loadTraffic();}
  if(route.startsWith('nodes/')){read(loadProfiles);read(route==='nodes/list'?loadNodes:loadGroups);}
  if(route==='connections')openRecords();
  if(route==='settings/profiles')read(loadProfiles);
  if(route==='settings/rules')read(()=>loadRules(false));
  if(route==='settings/subscriptions')read(loadSubscriptions);
  if(route==='debug/versions')status(guard,{explicit:true});
  if(['debug/operations','debug/logs'].includes(route)){startupResume();if(route==='debug/logs')renderLogs();}
  if(route==='debug/report')renderReport();
 }
 window.addEventListener('hashchange',()=>{renderRoute();window.scrollTo(0,0);});
 // Preserve the original auth lifecycle and clear every product-owned late completion.
 const authObserver=new MutationObserver(()=>{
  authEpoch++;readEpoch++;subscriptionInputEpoch++;subscriptionPreview=null;cancelMetrics();closeModal();
  if(active()){brand={version:null,state:'unchecked'};renderBrand();updateCheckPublish();renderRoute(true);}
  else{profiles=[];subscriptions=[];subscriptionPreview=null;subPreview.hidden=true;subPreview.replaceChildren();metrics=null;copyEpoch++;$('subscriptions-list').replaceChildren();$('subscriptions-status').textContent='';$('active-profile').replaceChildren(el('option','尚未读取'));$('active-profile').disabled=true;$('subscription-name').value='';$('subscription-url').value='';$('report-summary').textContent='';$('report-json').textContent='';$('logs-text').textContent='';$('manual-copy').value='';$('manual-copy').hidden=true;brand={version:null,state:'unchecked'};renderBrand();}
 });authObserver.observe($('console-view'),{attributes:true,attributeFilter:['hidden']});
 function renderPower(){if(serviceState?.availability==='AVAILABLE')$('connection-detail').textContent='服务管理器运行状态；不代表 VPN 出口已验证。';const known=serviceState?.availability==='AVAILABLE',running=known&&serviceState.running===true,b=$('power-toggle');b.disabled=busy||!known||!active();b.classList.toggle('off',known&&!running);b.setAttribute('aria-pressed',String(Boolean(running)));b.setAttribute('aria-label',known?(running?'停止连接':'启动连接'):'服务状态未知');$('power-action').textContent=busy?'请稍候':known?(running?'点击停止':'点击启动'):'状态未知';}
 $('power-toggle').onclick=()=>{if(busy||serviceState?.availability!=='AVAILABLE')return;const action=serviceState.running?'stop':'start';confirmAction(action==='stop'?'停止连接？':'启动连接？',[action==='stop'?'现有连接将中断。停止服务不等于已经验证系统网络恢复。':'启动本机服务。运行状态不代表所有网络访问已验证。'],()=>document.querySelector('[data-service="'+action+'"]').onclick());};
 const serviceObserver=new MutationObserver(renderPower);serviceObserver.observe(document.querySelector('.connection-panel'),{attributes:true,attributeFilter:['data-state']});serviceObserver.observe($('notice'),{childList:true,subtree:true});
 const safeVersion=v=>typeof v==='string'&&v.length<=128&&/^v[0-9]+(?:[.-][0-9]+)+(?:[-+](?:rc|beta|alpha)[0-9]+)?$/.test(v)?v:null;
 function publishRuntime(kind,data){if(!active()||document.hidden)return;if(kind==='status'){brand.version=safeVersion(data?.version);}else if(kind==='statusError'){brand.version=null;}else return;renderBrand();}
 function renderBrand(){const b=$('brand-version');b.dataset.state=brand.state;$('brand-version-number').textContent=brand.version||'—';$('brand-version-status').textContent=({unchecked:'更新未检查',checking:'检查中',paused:'检查已暂停',failed:'更新检查失败',unsupported:'更新不可安装',restart:'需重启控制台',available:'有更新',current:'无更新'})[brand.state];b.title='控制台版本 '+(brand.version||'不可用')+' · '+$('brand-version-status').textContent+(brand.disk?'；上次检查磁盘版本 '+brand.disk+' · '+brand.checkedAt:'');b.setAttribute('aria-label',b.title+'；查看版本更新');}
 function updateCheck(snapshot){if(!active())return;brand.state=snapshot.state;const observation=snapshot.observation;if(observation){brand.disk=observation.data.installed;brand.checkedAt=observation.checkedAt;}else{delete brand.disk;delete brand.checkedAt;}renderBrand();}
 const originalRenderUpdate=renderUpdate;renderUpdate=function(data,install){originalRenderUpdate(data,install);if(install){brand.disk=data.installed;brand.checkedAt=new Date().toISOString();brand.state='restart';renderBrand();}};
 $('check-update').onclick=()=>updateOperation(false);
 // All node/group selection paths disclose reconnect before entering the existing save chain.
 for(const id of ['nodes-list','groups-list'])$(id).addEventListener('click',event=>{const b=event.target.closest('button');if(!b||b.disabled||!(b.dataset.nodeSelect||['设为启动节点','保存选择'].includes(b.textContent)))return;event.preventDefault();event.stopImmediatePropagation();const handler=b.onclick;confirmAction('保存线路选择？',['运行中的服务会由服务端自动应用，期间可能短暂重连。未运行时仅保存，不会启动。'],()=>handler?.());},true);
 // Profile stable IDs and opaque versions are server-owned, never reconstructed from labels.
 let profileSwitchVersion='';
 const inheritedClearProfiles=clearProfiles;clearProfiles=function(){profileSwitchVersion='';$('active-profile').disabled=true;inheritedClearProfiles();};
 loadProfiles=async function(){
  const request=++profilesRequest,session=sessionGeneration,epoch=routeEpoch,current=()=>request===profilesRequest&&routeCurrent(epoch,session);
  profilesEtag='';profileSwitchVersion='';$('active-profile').disabled=true;$('profiles-status').textContent='正在读取方案…';
  const data=await api('/profiles?detail=1',{},current);if(!current())return;
  if(!Array.isArray(data.profiles)||typeof data.etag!=='string'||!data.etag||typeof data.switch_version!=='string'||!data.switch_version||typeof data.active_id!=='string'||data.profiles.some(p=>typeof p.id!=='string'||typeof p.name!=='string'||typeof p.version!=='string'||typeof p.current!=='boolean'))throw Error('方案列表响应不完整，请刷新。');
  profiles=data.profiles;profilesEtag=data.etag;profileSwitchVersion=data.switch_version;$('profiles-status').textContent=profiles.length+' 个独立方案';$('profiles-list').replaceChildren();$('active-profile').replaceChildren();
  if(!data.active_id){const o=el('option','当前配置尚未保存为方案');o.value='';$('active-profile').append(o);}
  for(const p of profiles){
   const option=el('option',p.name);option.value=p.id;option.selected=p.id===data.active_id;$('active-profile').append(option);
   const row=el('article',undefined,'entry'),content=el('div',undefined,'entrymain'),copy=el('div');copy.append(el('strong',p.name),el('p',(p.linked?'已关联订阅 · ':'')+'创建于 '+readableTime(p.created_at)));content.append(el('span','▤','entrymark'),copy);row.append(content);const actions=el('div',undefined,'actions');
   if(p.current)actions.append(el('span','当前方案','badge green'));else actions.append(button('切换',()=>switchProfile(p.id)));
   actions.append(button('复制',()=>nameProfile('复制方案',p.name+' 副本',name=>profileMutation('/profiles/copy',{id:p.id,name},'已复制独立方案，未切换网络。'))),button('重命名',()=>nameProfile('重命名方案',p.name,name=>profileMutation('/profiles/rename',{id:p.id,name,version:p.version},'方案已重命名，订阅关联保持不变。'))));
   if(!p.current)actions.append(button('删除',()=>confirmAction('删除方案？',['仅删除此方案与订阅关联，不影响活动网络。'],()=>profileMutation('/profiles/delete',{id:p.id,version:p.version,confirm:true},'方案已删除。')),'danger'));
   row.append(actions);$('profiles-list').append(row);
  }
  $('active-profile').value=data.active_id;$('active-profile').disabled=busy;renderExtraButtons();
 };
 function nameProfile(title,value,submit){const label=el('label','方案名称'),input=el('input');input.value=value;input.maxLength=80;label.append(input);const err=el('p',undefined,'error');modal(title,[label,err],[['保存',()=>{const name=input.value.trim();if(!name){err.textContent='请输入方案名称。';return;}closeModal();submit(name);}]]);input.focus();}
 async function profileMutation(path,body,message){return operation('保存方案',async()=>{const session=sessionGeneration;await api(path,{method:'POST',body});if(session!==sessionGeneration||!active())return;await loadProfiles();notice(message);});}
 $('active-profile').addEventListener('change',e=>{const id=e.target.value;e.target.value=profiles.find(p=>p.current)?.id||'';if(id)switchProfile(id);});
 // Switching still uses the original ETag-aware backup/apply path. Its native
 // confirmation is retained, and the full active route snapshot is then re-read.
 const oldSwitch=switchProfile;switchProfile=async function(id){if(!profileSwitchVersion||!profilesEtag){notice('方案快照不可用，请刷新后再切换。',true);return;}await oldSwitch(id,profileSwitchVersion);if(active()&&route.startsWith('nodes/'))await loadRoute();};
 // Subscription workflow is separate from legacy append/replace import.
 const subscriptionNameLabel=el('label','新方案名称'),subscriptionName=el('input');subscriptionName.id='subscription-name';subscriptionName.autocomplete='off';subscriptionNameLabel.append(subscriptionName);
 $('import-url-panel').prepend(subscriptionNameLabel);$('subscription-help').textContent='链接可能含令牌，来源只显示主机。预览后导入独立新方案，不激活、不覆盖当前配置。浏览器关闭后由常驻服务继续每小时检查。';
 const subPreviewButton=button('预览为新方案',previewSubscription,'primary');subPreviewButton.id='preview-subscription';$('import-url-panel').append(subPreviewButton);
 const subPreview=el('div',undefined,'panel panelpad');subPreview.id='subscription-preview';subPreview.hidden=true;$('import-url-panel').append(subPreview);
 const importScopeLabel=el('label','导入范围'),importScope=el('select');importScope.id='import-scope';for(const [value,text]of [['append_nodes','仅添加节点，保留现有规则与选择'],['replace_config','替换完整配置，保留原配置备份']]){const option=el('option',text);option.value=value;importScope.append(option);}importScopeLabel.append(importScope);$('import-local').append(importScopeLabel);importScope.onchange=invalidateImport;
 $('preview-import').onclick=()=>importMode==='url'?previewSubscription():previewImport(false,importScope.value);
 function invalidateSubPreview(){subscriptionInputEpoch++;subscriptionPreview=null;subPreview.hidden=true;subPreview.replaceChildren();}
 for(const id of ['subscription-url','subscription-name'])$(id).addEventListener('input',invalidateSubPreview);
 async function previewSubscription(){if(busy||!active())return;invalidateSubPreview();const input=subscriptionInputEpoch,epoch=routeEpoch,session=sessionGeneration,current=()=>input===subscriptionInputEpoch&&routeCurrent(epoch,session);return operation('预览订阅',async()=>{
  const data=await api('/subscriptions/preview',{method:'POST',body:{url:$('subscription-url').value.trim(),name:subscriptionName.value.trim()}},current);if(!current())return;
  if(typeof data.token!=='string'||!data.token||typeof data.name!=='string'||typeof data.source_host!=='string'||!['nodes','groups','rules'].every(k=>Number.isInteger(data[k])&&data[k]>=0))throw Error('订阅预览响应不完整。');
  const conversion=conversionReport(data.conversion);if(conversion.issues.length)throw Error('配置转换受阻，未创建方案。');
  subscriptionName.value=data.name;subscriptionPreview={...data,conversion,input};subPreview.replaceChildren(el('h3','预览结果 · 未导入'),el('p',data.nodes+' 个节点 · '+data.groups+' 个策略组 · '+data.rules+' 条规则'),el('p','来源主机：'+data.source_host));
  for(const warning of [...conversion.warnings,...conversion.skipped])subPreview.append(el('p',warning,'warningtext'));
  subPreview.append(button('继续确认',()=>{const snapshot=subscriptionPreview;if(!snapshot)return;confirmAction('确认导入订阅？',['创建「'+snapshot.name+'」独立方案；保留当前网络，不自动激活。','默认每小时由常驻服务检查。'+(snapshot.conversion.warnings.length||snapshot.conversion.skipped.length?'将接受上方转换差异与跳过内容。':'')],()=>commitSubscription(snapshot));},'primary'));subPreview.hidden=false;notice('预览完成，尚未创建方案。');
 });}
 function commitSubscription(snapshot){if(snapshot!==subscriptionPreview||snapshot.input!==subscriptionInputEpoch)return;return operation('导入订阅',async()=>{const session=sessionGeneration;subscriptionPreview=null;await api('/subscriptions/import',{method:'POST',body:{token:snapshot.token,name:snapshot.name,confirm:true,confirm_insecure:true,accept_conversion:true}});if(session!==sessionGeneration||!active())return;$('subscription-url').value='';subscriptionName.value='';invalidateSubPreview();location.hash='settings/subscriptions';renderRoute();operationRoute=null;notice('已创建订阅方案，未自动激活。');});}
 async function loadSubscriptions(){const epoch=routeEpoch,session=sessionGeneration,request=++readEpoch,current=()=>request===readEpoch&&routeCurrent(epoch,session);$('subscriptions-status').textContent='正在读取订阅…';const data=await api('/subscriptions',{},current);if(!current())return;
  if(!Array.isArray(data.subscriptions)||data.interval_seconds!==3600||data.subscriptions.some(s=>!['id','profile_id','profile_name','source_host','version','candidate_version','target_version'].every(k=>typeof s[k]==='string')||!['auto_check','busy','conflict','selection_invalid','has_previous'].every(k=>typeof s[k]==='boolean')||s.selection_invalid&&(!Array.isArray(s.candidate_choices)||s.candidate_choices.some(c=>typeof c!=='string'||!c)||new Set(s.candidate_choices).size!==s.candidate_choices.length)))throw Error('订阅响应不完整，请刷新。');
  subscriptions=data.subscriptions;$('subscriptions-status').textContent='常驻服务每小时检查；停机期间不补造检查。';renderSubscriptions();
 }
 const resultLabels={NOT_CHECKED:'尚未检查',UNCHANGED:'暂无更新',NO_CHANGE:'暂无更新',UPDATED:'已保存新版本',APPLIED:'已应用',PENDING:'更新待应用',PENDING_APPLY:'更新待应用',UPDATE_PENDING:'更新待应用',RESTORE_PENDING:'前一版本待应用',CONFLICT:'人工修改冲突',FAILED:'检查失败，旧方案保留',CHECK_FAILED:'检查失败，旧方案保留',CHECKING:'检查中'};
 function renderSubscriptions(){const host=$('subscriptions-list');host.replaceChildren();if(!subscriptions.length){host.append(el('div','还没有订阅。通过订阅链接导入新的独立方案。','empty'));return;}
  for(const s of subscriptions){const card=el('article',undefined,'panel panelpad subscription-card'),top=el('div',undefined,'toolbar');top.append(el('h2',s.profile_name),el('span',s.busy?'检查中…':resultLabels[s.result]||'已读取订阅状态','badge'));card.append(top,el('p','来源主机：'+s.source_host,'source-mask'));
   const label=el('label',undefined,'settingrow'),copy=el('div');copy.append(el('strong','每小时自动检查'),el('p','由常驻服务执行，关闭浏览器不停止。'));const auto=el('input');auto.type='checkbox';auto.checked=s.auto_check;auto.disabled=s.busy||busy;auto.setAttribute('aria-label',s.profile_name+' 每小时自动检查');auto.onchange=()=>{const desired=auto.checked;auto.disabled=true;subscriptionMutation('/subscriptions/options',{id:s.id,version:s.version,auto_check:desired},'检查选项已保存。').finally(()=>{if(auto.isConnected){auto.checked=s.auto_check;auto.disabled=false;}});};label.append(copy,auto);card.append(label);
   const dl=el('dl',undefined,'detailgrid');for(const [key,value]of [['上次检查',readableTime(s.last_check)],['下次检查',s.auto_check?readableTime(s.next_check):'已暂停'],['最近更新',readableTime(s.last_updated)]])dl.append(el('dt',key),el('dd',value));card.append(dl);
   if(s.candidate_version)card.append(el('p',s.conflict?'人工修改冲突；保留旧方案，确认后才会替换。':'更新待应用；当前网络保持原版本。','note'));
   if(s.selection_invalid)card.append(el('p','原线路身份已失效，不能按同名节点推断。应用后需要重新选择有效线路。','note'));
   const actions=el('div',undefined,'actions'),check=button(s.busy?'检查中…':'检查更新',()=>subscriptionMutation('/subscriptions/check',{id:s.id},'订阅检查已返回，请查看最新状态。'),'primary');check.disabled=s.busy||busy;actions.append(check);
   if(s.candidate_version)actions.append(button('查看并应用',()=>applySubscription(s)));
   if(s.has_previous)actions.append(button('恢复前一版本',()=>confirmAction('恢复前一版本？',['仅准备前一完整版本为候选；仍需核对并确认应用。'],()=>subscriptionMutation('/subscriptions/restore',{id:s.id,version:s.version,confirm:true},'前一版本已准备为候选，请确认应用。'))));
   actions.append(button('解除订阅',()=>confirmAction('解除订阅？',['保留方案与所有节点，停止此来源检查，移除关联与候选。'],()=>subscriptionMutation('/subscriptions/unlink',{id:s.id,version:s.version,confirm:true},'已解除订阅，方案保留。')),'danger'));card.append(actions);host.append(card);
  }
 }
 function applySubscription(s){const snapshot={id:s.id,target_version:s.target_version,candidate_version:s.candidate_version,confirm:true,confirm_insecure:true,accept_conversion:true},body=['替换「'+s.profile_name+'」的完整内容。若是当前方案，可能短暂重连；服务端保留前一完整版本。',s.conflict?'人工修改会被替换。可以取消并先另存方案。':'目标与候选版本会由服务端严格核对；变化后本次确认失效。'];let select=null;if(s.selection_invalid){const label=el('label','原线路身份已失效，请明确选择候选中的线路');select=el('select');select.append(el('option','请选择线路'));select.firstElementChild.value='';for(const name of s.candidate_choices||[]){const o=el('option',name);o.value=name;select.append(o);}label.append(select);body.push(label);}modal('应用订阅新版本？',body,[['确认',()=>{if(select&&!select.value){select.focus();return;}if(select)snapshot.selected=select.value;closeModal();subscriptionMutation('/subscriptions/apply',snapshot,'订阅应用已返回，请核对保存/应用状态。',true);}]]);}
 function subscriptionMutation(path,body,message,apply=false){return operation('处理订阅',async()=>{const session=sessionGeneration,data=await api(path,{method:'POST',body});if(session!==sessionGeneration||!active())return;if(apply){invalidateConfigViews();savedFeedback(data);await refreshAfterSave();}await loadSubscriptions();if(!apply)notice(message);});}
 // Rule ordering/editing uses the original native YAML validator and If-Match save.
 // Only an explicit, unambiguous scalar list is changed; all other bytes survive.
 const originalRulesRender=renderRulesPage;
 renderRulesPage=function(){originalRulesRender();const snapshot=rulesSnapshot;if(!currentRules(snapshot)||snapshot.editable!==true)return;
  for(const row of $('rules-list').children){const index=Number(row.value)-1,rule=snapshot.rules[index];if(rule?.split(',')[0].trim()==='MATCH')continue;const controls=el('div',undefined,'actions rule-order');
   const up=button('上移',()=>editRuleSnapshot(snapshot,index,index-1));up.disabled=busy||index===0;
   const down=button('下移',()=>editRuleSnapshot(snapshot,index,index+1));down.disabled=busy||index>=snapshot.rules.length-2;
   controls.append(up,down,button('编辑',()=>{const label=el('label','规则内容'),input=el('input');input.value=rule;input.maxLength=2048;label.append(input);modal('编辑分流规则',[label,'保存会由服务端校验并自动应用，运行中的连接可能短暂中断。最终 MATCH 不可移动或编辑。'],[['确认保存',()=>{const value=input.value.trim();if(!value||value.startsWith('MATCH,'))return;closeModal();editRuleSnapshot(snapshot,index,null,value);}]]);}));row.querySelector('.rule-row').append(controls);
  }
 };
 function replaceRuleLines(yaml,snapshot,from,to,value){
  const lines=yaml.split(/(?<=\n)/),headers=[];for(let i=0;i<lines.length;i++)if(/^rules\s*:\s*(?:#.*)?\r?\n?$/.test(lines[i]))headers.push(i);if(headers.length!==1)throw Error('此规则格式无法安全移动或编辑，请使用原始配置。');
  const start=headers[0],found=[];let indent=null;
  for(let i=start+1;i<lines.length;i++){const line=lines[i];if(!line.trim()||/^\s*#/.test(line))continue;if(/^\S/.test(line))break;const m=/^(\s+)-\s+([^\r\n]*?)(\r?\n)?$/.exec(line);if(!m)throw Error('规则含复杂 YAML 内容，请使用原始配置。');if(indent===null)indent=m[1];if(indent!==m[1])throw Error('规则缩进不明确，请使用原始配置。');let scalar=m[2].trim();if(scalar.startsWith('"')){try{scalar=JSON.parse(scalar);}catch{throw Error('带注释或复杂引号规则请使用原始配置。');}}else if(/[\[\]{}#&*!|>'"]/.test(scalar))throw Error('此规则格式请使用原始配置。');found.push({index:i,scalar,eol:m[3]||''});}
  if(found.length!==snapshot.rules.length||found.some((r,i)=>r.scalar!==snapshot.rules[i]))throw Error('原始规则与列表不一致，请重新读取。');
  if(to!==null){if(to<0||to>=found.length-1||from>=found.length-1)throw Error('不能移动或跨越最终 MATCH。');const a=found[from].index,b=found[to].index;[lines[a],lines[b]]=[lines[b],lines[a]];}
  else lines[found[from].index]=indent+'- '+JSON.stringify(value)+found[from].eol;
  return lines.join('');
 }
 function editRuleSnapshot(snapshot,from,to,value){if(busy||!currentRules(snapshot)||snapshot.editable!==true||from>=snapshot.rules.length-1||to!==null&&(to<0||to>=snapshot.rules.length-1))return;const perform=()=>operation(to===null?'保存规则编辑':'保存规则顺序',async()=>{
  const current=()=>currentRules(snapshot),owner=finishOperation;if(!current())return;
  const data=await api('/config',{},current);if(!current())return;if(data.etag!==snapshot.etag||typeof data.yaml!=='string')throw Error('规则配置已变化，请重新读取，未覆盖保存。');
  const yaml=replaceRuleLines(data.yaml,snapshot,from,to,value),saved=await api('/config',{method:'PUT',headers:{'If-Match':snapshot.etag},body:saveBody({yaml})},current);if(!current()||owner!==finishOperation)return;await finishRuleSave(saved,snapshot,to===null?'规则已编辑。':'规则顺序已保存。',owner);
 });
 if(to!==null)confirmAction('调整规则顺序？',['规则按从上到下匹配。保存会由服务端自动应用，运行中的连接可能短暂重连。'],perform);else perform();}
 // Both append and replacement imports require a final, cancellable confirmation.
 const originalCommitImport=$('commit-import').onclick;$('commit-import').onclick=()=>{if(busy||!importPreview)return;const preview=importPreview;confirmAction(preview.mode==='append_nodes'?'确认添加节点？':'确认替换完整配置？',[preview.mode==='append_nodes'?'保留现有规则、策略组与选择，只追加节点。':'将备份并替换当前配置；保留旧内容备份。','运行中的服务会自动应用，可能短暂断网重连。取消不发送保存请求。'],()=>{if(preview===importPreview)originalCommitImport();});};
 // Traffic is separate from the fixed HTTPS probe: bytes are SDK payload, not wire/device totals.
 let traffic=null,trafficOwner=null,trafficTimer=null,trafficExpiry=null;
 const exact=(v,keys)=>v!==null&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).length===keys.length&&keys.every(k=>Object.hasOwn(v,k));
 const decimal=v=>typeof v==='string'&&/^(0|[1-9][0-9]{0,19})$/.test(v)&&BigInt(v)<=18446744073709551615n;
 const utc=v=>typeof v==='string'&&/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(v)&&Number.isFinite(Date.parse(v));
 const binding=v=>exact(v,['instance_id','generation','manifest_id'])&&/^[a-f0-9]{32}$/.test(v.instance_id)&&/^[a-f0-9]{32}$/.test(v.generation)&&/^[a-f0-9]{64}$/.test(v.manifest_id);
 function validTraffic(data,now=Date.now()){
  if(!exact(data,['traffic_schema','availability','snapshot'])||data.traffic_schema!==1)return false;
  if(data.availability==='UNAVAILABLE')return data.snapshot===null;
  const s=data.snapshot;if(data.availability!=='OBSERVED'||!exact(s,['traffic_schema','header','source','state','sampled_at','elapsed_ns','upload_bytes','download_bytes','saturated','rate','history'])||s.traffic_schema!==1||s.source!=='SDK_ROUTED_PAYLOAD'||s.state!=='RUNNING'||!utc(s.sampled_at)||now-Date.parse(s.sampled_at)<0||now-Date.parse(s.sampled_at)>15000||typeof s.saturated!=='boolean'||![s.elapsed_ns,s.upload_bytes,s.download_bytes].every(decimal)||BigInt(s.elapsed_ns)>9223372036854775807n||!Array.isArray(s.history)||s.history.length>1440)return false;
  const h=s.header;if(!exact(h,['schema_version','config_identity','instance_id','generation','manifest_id','runtime_sha256','created_at','previous_binding'])||h.schema_version!==1||!binding({instance_id:h.instance_id,generation:h.generation,manifest_id:h.manifest_id})||!['config_identity','runtime_sha256'].every(k=>/^[a-f0-9]{64}$/.test(h[k]))||!utc(h.created_at)||h.previous_binding!==null&&!binding(h.previous_binding))return false;
  const interval=i=>exact(i,['start_ns','end_ns','upload_bytes','download_bytes'])&&[i.start_ns,i.end_ns,i.upload_bytes,i.download_bytes].every(decimal)&&BigInt(i.start_ns)<BigInt(i.end_ns)&&BigInt(i.end_ns)<=BigInt(s.elapsed_ns)&&BigInt(i.upload_bytes)<=BigInt(s.upload_bytes)&&BigInt(i.download_bytes)<=BigInt(s.download_bytes);
  if(s.rate!==null&&(!interval(s.rate)||s.saturated||s.rate.end_ns!==s.elapsed_ns))return false;
  let end=0n,historyUp=0n,historyDown=0n;for(const i of s.history){if(!interval(i)||BigInt(i.start_ns)<end||BigInt(i.end_ns)-BigInt(i.start_ns)<60000000000n||BigInt(s.elapsed_ns)-BigInt(i.start_ns)>86400000000000n)return false;historyUp+=BigInt(i.upload_bytes);historyDown+=BigInt(i.download_bytes);if(historyUp>BigInt(s.upload_bytes)||historyDown>BigInt(s.download_bytes))return false;const r=s.rate;if(r&&BigInt(r.start_ns)>=BigInt(i.start_ns)&&BigInt(r.end_ns)<=BigInt(i.end_ns)&&(BigInt(r.upload_bytes)>BigInt(i.upload_bytes)||BigInt(r.download_bytes)>BigInt(i.download_bytes)))return false;end=BigInt(i.end_ns);}return true;
 }
 // Convert only after exact BigInt division; never round cumulative bytes through Number.
 const fixed=(n,scale,digits=2)=>{const power=10n**BigInt(digits),v=n*power/scale;return String(v/power)+'.'+String(v%power).padStart(digits,'0');};
 const mbps=(i,key)=>Number(BigInt(i[key])*8000000n/(BigInt(i.end_ns)-BigInt(i.start_ns)))/1000;
 function clearTraffic(message='尚无流量记录'){traffic=null;clearTimeout(trafficExpiry);trafficExpiry=null;renderTraffic(message);}
 function cancelTraffic(){if(trafficOwner){trafficOwner.controller.abort();clearTimeout(trafficOwner.timeout);}trafficOwner=null;clearTimeout(trafficTimer);trafficTimer=null;clearTraffic();}
 async function loadTraffic(){if(trafficOwner||!active()||route!=='overview'||document.hidden)return;const epoch=routeEpoch,session=sessionGeneration,o={controller:new AbortController(),timeout:null};trafficOwner=o;const current=()=>trafficOwner===o&&routeCurrent(epoch,session)&&route==='overview'&&!o.controller.signal.aborted;o.timeout=setTimeout(()=>o.controller.abort(),5000);
  try{const aborted=new Promise((_,reject)=>o.controller.signal.addEventListener('abort',()=>reject(Error('流量读取已取消')),{once:true}));const data=await Promise.race([api('/traffic',{headers:{'X-AnyTLS-Origin':location.origin},signal:o.controller.signal},current),aborted]);if(!current())return;if(!validTraffic(data))throw Error('流量响应无效');clearTraffic();if(data.availability==='OBSERVED'){traffic=data.snapshot;renderTraffic();trafficExpiry=setTimeout(()=>{if(traffic===data.snapshot)clearTraffic('流量记录已过期；不沿用旧值');},Math.max(0,15000-(Date.now()-Date.parse(traffic.sampled_at))));}else clearTraffic('流量不可用；尚无当前实例记录');}
  catch{if(trafficOwner===o&&routeCurrent(epoch,session))clearTraffic('流量不可用；未采用旧值');}
  finally{clearTimeout(o.timeout);if(trafficOwner===o){trafficOwner=null;if(routeCurrent(epoch,session)&&route==='overview')trafficTimer=setTimeout(loadTraffic,5000);}}
 }
 function renderTraffic(message='尚无流量记录'){
  const s=traffic,set=(name,value)=>{const node=document.querySelector('[data-metric="'+name+'"]');if(node)node.textContent=value;},down=s?BigInt(s.download_bytes):0n,up=s?BigInt(s.upload_bytes):0n,total=down+up;
  set('download-speed',s?.rate?mbps(s.rate,'download_bytes').toFixed(2):'—');set('upload-speed',s?.rate?mbps(s.rate,'upload_bytes').toFixed(2):'—');set('traffic-total',s?fixed(total,1000000000n):'—');set('traffic-download',s?fixed(down,1000000000n)+' GB':'—');set('traffic-upload',s?fixed(up,1000000000n)+' GB':'—');
  for(const [key,value]of [['traffic-download',down],['traffic-upload',up],['traffic-total',total]]){const node=document.querySelector('[data-metric="'+key+'"]');if(node)node.title=s?String(value)+' bytes':'';}
  $('traffic-scope').textContent=s?(s.saturated?'本实例累计已饱和；速率未知':'本实例已记录 SDK 路由 payload；非全设备流量'):message;$('traffic-ratio').style.width=s&&total?String(Number(down*10000n/total)/100)+'%':'0%';
  document.querySelector('.speedpair').closest('.card').querySelector('.sectionhead .small').textContent=s?'采样于 '+displayTime(s.sampled_at):'尚未记录';
  const chart=document.querySelector('.chartcard'),svg=chart.querySelector('.plot svg'),overlay=chart.querySelector('.emptyoverlay'),axis=chart.querySelector('.yaxis');svg.replaceChildren();
  const history=s&&!s.saturated?s.history:[],provisional=!history.length&&s?.rate&&!s.saturated?s.rate:null,intervals=provisional?[provisional]:history,max=Math.max(.01,...intervals.flatMap(i=>[mbps(i,'download_bytes'),mbps(i,'upload_bytes')])),elapsed=s?BigInt(s.elapsed_ns):0n,windowNS=86400000000000n;
  // Zoom only the actual observed span (bounded to 24h); never invent padding periods.
  const cutoff=elapsed>windowNS?elapsed-windowNS:0n,start=intervals.length?(BigInt(intervals[0].start_ns)>cutoff?BigInt(intervals[0].start_ns):cutoff):0n,span=elapsed-start;
  const speedLabel=value=>value.toFixed(max<1?3:2);
  chart.querySelector('.sectionhead p').textContent=provisional?'实时区间 · 尚无已完成分钟；未计入历史峰值':'自观察起（近 24 小时内）· 区间平均网速；连续区间连线，缺测断开';
  axis.replaceChildren(...[1,.75,.5,.25,0].map(n=>el('span',speedLabel(max*n))));overlay.hidden=intervals.length>0;overlay.querySelector('b').textContent=s?'尚无可显示的网速区间':'还没有网速记录';overlay.querySelector('p').textContent=s?'首次采样或计数饱和时不补造速率。':message;
  const x=v=>40+Number((BigInt(v)-start)*958000n/span)/1000;
  const localTime=ns=>new Date(Date.parse(s.sampled_at)-Number((elapsed-BigInt(ns))/1000000n)).toLocaleString('zh-CN',{hour12:false});
  const shape=(tag,attrs)=>{const node=document.createElementNS('http://www.w3.org/2000/svg',tag);for(const [key,value]of Object.entries(attrs))node.setAttribute(key,String(value));svg.append(node);return node;};
  // A point is an actual interval average at its midpoint, not an instantaneous sample.
  // Split on exact nanosecond adjacency: even the smallest real gap stays unconnected.
  const runs=[];for(const i of history){if(!runs.length||runs.at(-1).at(-1).end_ns!==i.start_ns)runs.push([]);runs.at(-1).push(i);}
  for(const [key,color,width,label,radius]of [['download_bytes','#3478ee',5,'下载',3],['upload_bytes','#24a291',2,'上传',1.5]]){
   const y=i=>200-mbps(i,key)/max*190,mid=i=>(BigInt(i.start_ns)+BigInt(i.end_ns))/2n;
   if(provisional){shape('line',{x1:x(provisional.start_ns),x2:x(provisional.end_ns),y1:y(provisional),y2:y(provisional),stroke:color,'stroke-width':width,'stroke-linecap':'round','data-kind':'rate'});continue;}
   for(const run of runs)if(run.length>1)shape('polyline',{points:run.map(i=>x(mid(i))+','+y(i)).join(' '),fill:'none',stroke:color,'stroke-width':width,'stroke-linecap':'round','stroke-linejoin':'round','data-kind':'history','data-series':key});
   for(const i of history){
    const detail=label+' · '+localTime(i.start_ns)+' 至 '+localTime(i.end_ns)+' · 区间平均 '+speedLabel(mbps(i,key))+' Mbps · '+i[key]+' bytes / '+(BigInt(i.end_ns)-BigInt(i.start_ns))+' ns';
    const point=shape('circle',{cx:x(mid(i)),cy:y(i),r:radius,fill:color,stroke:color,'stroke-width':key==='download_bytes'?5:4,'vector-effect':'non-scaling-stroke','data-kind':'history','data-series':key,'aria-label':detail});
    const title=document.createElementNS('http://www.w3.org/2000/svg','title');title.textContent=detail;point.append(title);
   }
  }
  const xaxis=chart.querySelector('.xaxis');xaxis.replaceChildren(...(intervals.length?[0,.25,.5,.75,1].map(f=>{const ns=start+span*BigInt(Math.round(f*100))/100n,date=new Date(Date.parse(s.sampled_at)-Number((elapsed-ns)/1000000n)),label=date.toLocaleTimeString('zh-CN',{hour12:false});const node=el('span',label);node.title=date.toLocaleString('zh-CN',{hour12:false});return node;}):[el('span','尚无观察区间')]));
  svg.setAttribute('aria-label',provisional?'实时网速区间；尚无已完成分钟历史':history.length?'本实例区间平均网速；点为实际区间中点，连续区间连线仅表示趋势，缺测断开':'尚无下载和上传速度记录');$('peak-label').textContent=history.length?'区间平均下载最高值 '+speedLabel(Math.max(...history.map(i=>mbps(i,'download_bytes'))))+' Mbps':'下载峰值 —';
 }
 // Fixed-schema HTTPS metrics remain independently scoped.
 function cancelMetrics(){cancelTraffic();if(metricsOwner){metricsOwner.controller.abort();clearTimeout(metricsOwner.timeout);}metricsOwner=null;clearTimeout(metricsTimer);metricsTimer=null;}
 function validMetrics(data){const n=data?.network,t=data?.traffic;if(data?.schema_version!==1||t?.quality!=='NOT_OBSERVED'||!['download_bps','upload_bps','recorded_download_bytes','recorded_upload_bytes'].every(k=>t[k]===null)||!['NOT_OBSERVED','OK','FAILED','STALE'].includes(n?.state)||!Array.isArray(data.bins)||data.bins.length!==288)return false;const count=v=>Number.isSafeInteger(v)&&v>=0;if(!count(n.attempts)||!count(n.succeeded)||n.succeeded>n.attempts||n.availability_24h!==null||!(n.sample_success_ratio===null&&n.attempts===0||Number.isFinite(n.sample_success_ratio)&&n.attempts>0&&Math.abs(n.sample_success_ratio-n.succeeded/n.attempts)<1e-9)||n.state==='OK'&&(!Number.isFinite(n.latency_ms)||n.latency_ms<0))return false;let attempts=0,succeeded=0;for(const b of data.bins){if(!count(b.attempts)||!count(b.succeeded)||b.succeeded>b.attempts||b.traffic_quality!=='NOT_OBSERVED'||b.download_bytes!==null||b.upload_bytes!==null)return false;attempts+=b.attempts;succeeded+=b.succeeded;}return attempts===n.attempts&&succeeded===n.succeeded;}
 async function loadMetrics(){if(metricsOwner||!active()||route!=='overview'||document.hidden)return;const epoch=routeEpoch,session=sessionGeneration,o={controller:new AbortController(),timeout:null};metricsOwner=o;const current=()=>metricsOwner===o&&routeCurrent(epoch,session)&&route==='overview'&&!o.controller.signal.aborted;o.timeout=setTimeout(()=>o.controller.abort(),5000);
  try{const aborted=new Promise((_,reject)=>o.controller.signal.addEventListener('abort',()=>reject(Error('指标读取已取消')),{once:true}));const data=await Promise.race([api('/metrics',{headers:{'X-AnyTLS-Origin':location.origin},signal:o.controller.signal},current),aborted]);if(!current())return;if(!validMetrics(data))throw Error('指标响应无效');metrics=data;renderMetrics();}
  catch{if(metricsOwner===o&&routeCurrent(epoch,session)){metrics=null;renderMetrics();$('qualityconclusion').textContent=o.controller.signal.aborted?'检查记录读取超时；未采用旧结果。':'检查记录读取失败；未采用旧结果。';}}
  finally{clearTimeout(o.timeout);if(metricsOwner===o){metricsOwner=null;if(routeCurrent(epoch,session)&&route==='overview')metricsTimer=setTimeout(loadMetrics,15000);}}
 }
 function renderMetrics(){const n=metrics?.network;const texts={'freshness':n?.latest_checked_at?'检查于 '+displayTime(n.latest_checked_at):'尚未记录','coverage':n?.attempts?'实际完成 '+n.attempts+' 次检查':'未记录','check-note':'仅固定 HTTPS 端点的系统路径检查','failed-count':n?String(n.attempts-n.succeeded)+' 次':'—','availability-scope':'已记录检查通过率','qualityconclusion':!n||n.state==='NOT_OBSERVED'?'尚无实际网络检查记录。':n.state==='OK'?'最近固定 HTTPS 检查通过；不代表所有网站或 VPN 出口。':n.state==='STALE'?'最近检查已过期；不沿用旧成功判断当前网络。':'最近固定 HTTPS 检查未通过；不据此判定全部网络。'};for(const [id,value]of Object.entries(texts))if($(id))$(id).textContent=value;
  const a=document.querySelector('[data-metric="success-ratio"]');if(a)a.textContent=n&&Number.isFinite(n.sample_success_ratio)?(n.sample_success_ratio*100).toFixed(n.attempts<100?0:1):'—';
  const latency=document.querySelector('[data-metric="latency"]');if(latency)latency.textContent=n?.state==='OK'&&Number.isFinite(n.latency_ms)?n.latency_ms.toFixed(0):'—';
  const u=$('uptime');if(u){u.replaceChildren();for(const bin of metrics?.bins||Array.from({length:48},()=>null)){const span=el('span');span.className=!bin||!bin.attempts?'missing':bin.succeeded<bin.attempts?'failed':'observed';span.title=!bin||!bin.attempts?'未记录':bin.succeeded+' / '+bin.attempts+' 次检查通过';u.append(span);}}
 }
 function reportObject(){let r;try{r=JSON.parse(AnyTLSRuntime.summary());}catch{r={};}const report={schema:1,binding:'NOT_VERIFIED',network_scope:'NOT_OBSERVED',sensitive_fields:'OMITTED'};
  const selectVersion=v=>({value:typeof v?.value==='string'&&/^v[0-9]+(?:[.-][0-9]+)+(?:[-+](?:rc|beta|alpha)[0-9]+)?$/.test(v.value)?v.value:null,evidence:['NONE','DISK_CHECK','IN_MEMORY_VERSION','AUTHENTICATED_HELPER'].includes(v?.evidence)?v.evidence:'UNKNOWN',refreshStatus:v?.refreshStatus==='FAILED'?'FAILED':'NOT_FAILED'});
  if($('report-versions').checked)report.versions={installed:selectVersion(r.versions?.installed),webui:selectVersion(r.versions?.webui),helper:selectVersion(r.versions?.helper),coreCurrent:'UNKNOWN'};
  if($('report-layers').checked)report.layers={control:r.health?.controlPlane==='OBSERVED'?'OBSERVED':'UNKNOWN',service:r.health?.service?.availability==='AVAILABLE'?(r.health.service.running?'RUNNING':'NOT_RUNNING'):'UNKNOWN',dns:['OBSERVED','STALE','UNAVAILABLE','UNKNOWN'].includes(r.health?.dns?.availability)?r.health.dns.availability:'UNKNOWN',end_to_end:'NOT_OBSERVED'};
  if($('report-history').checked)report.history={coverage:'INCOMPLETE',last_result:['SUCCEEDED','FAILED','CANCELLED','UNKNOWN','IN_PROGRESS','NOT_ATTEMPTED'].includes(r.lastStartup?.result)?r.lastStartup.result:'NOT_OBSERVED'};return report;
 }
 function reportText(r){const lines=['AnyTLS 诊断报告',''];if(r.versions)lines.push('【版本与组件】','已安装程序：'+(r.versions.installed.value||'尚未检查'),'Web 控制台：'+(r.versions.webui.value||'未记录'),'特权助手：'+(r.versions.helper.value||'未记录'),'当前 VPN 内核：未知，缺少可靠当前进程关联。','');if(r.layers)lines.push('【分层观察】','控制面：'+r.layers.control,'服务作业：'+r.layers.service,'DNS 近期证据：'+r.layers.dns,'端到端网络：未观察。','');if(r.history)lines.push('【历史覆盖】','记录可能不完整；最近操作结果：'+r.history.last_result,'');lines.push('【安全与观察边界】','配置绑定未验证。服务启动不代表网络可用。','不含原始配置、日志、密码、节点地址、订阅链接或实例标识。');return lines.join('\n');}
 function renderReport(){if(!active())return;const r=reportObject();$('report-json').textContent=JSON.stringify(r,null,2);$('report-summary').textContent=reportText(r);}
 function download(text,name,type){const url=URL.createObjectURL(new Blob([text],{type})),a=link(url,'');a.download=name;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),0);}
 for(const name of ['versions','layers','history'])$('report-'+name).onchange=()=>{copyEpoch++;$('manual-copy').hidden=true;renderReport();};
 for(const type of ['summary','report']){const target=type==='summary'?'report-summary':'report-json';$('export-'+type).onclick=()=>{renderReport();download($(target).textContent,type==='summary'?'anytls-report.txt':'anytls-report.json',type==='summary'?'text/plain':'application/json');};$('copy-'+type).onclick=async()=>{renderReport();const text=$(target).textContent,epoch=++copyEpoch,session=sessionGeneration,view=routeEpoch,current=()=>epoch===copyEpoch&&session===sessionGeneration&&view===routeEpoch&&active()&&!document.hidden;
  try{if(!navigator.clipboard?.writeText)throw Error('UNAVAILABLE');await navigator.clipboard.writeText(text);if(current())$('copy-feedback').textContent='已复制所选报告内容。';}catch{if(!current())return;$('manual-copy').hidden=false;$('manual-copy').value=text;$('manual-copy').focus();$('manual-copy').select();$('copy-feedback').textContent='浏览器未允许自动复制；请按 Ctrl+C / ⌘C 手动复制已选内容。';}};}
 function renderLogs(){const value=$('startup-text').value,query=$('log-search').value.toLowerCase();$('logs-text').textContent=value?value.split('\n').filter(line=>line.toLowerCase().includes(query)).join('\n'):'尚无通过验证的操作日志。';$('logs-status').textContent=$('startup-status').textContent;}
 $('log-search').oninput=renderLogs;$('logs-refresh').onclick=()=>{startupResume();renderLogs();};const logObserver=new MutationObserver(()=>{if(route==='debug/logs')renderLogs();});logObserver.observe($('startup-status'),{childList:true,subtree:true});logObserver.observe($('startup-summary'),{childList:true,subtree:true});
 document.addEventListener('visibilitychange',()=>{copyEpoch++;if(document.hidden){cancelMetrics();readEpoch++;closeModal();}else if(active()){if(route==='overview'){loadMetrics();loadTraffic();}}});
 window.addEventListener('pagehide',()=>{cancelMetrics();readEpoch++;copyEpoch++;closeModal();});
 window.AnyTLSProduct=Object.freeze({publishRuntime,updateCheck,nodeDetails:(n,edit,tcp)=>modal(n.name,[el('p',n.server+':'+n.port+' · '+(n.hasPassword?'已配置密码':'未配置密码')),el('p','当前启动节点仅表示配置选择，不代表当前已连接。'),tcp,edit,el('p','删除节点请使用原始配置；保存前由现有配置校验与确认流程处理。')]),notice:routeNotice,statusVisible:()=>route==='overview',acceptRuntime:kind=>kind!=='dns'||route==='debug/dns',routes:routes.map(r=>r[0])});
 renderRoute(true);renderMetrics();renderPower();renderBrand();
})();

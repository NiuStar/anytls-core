'use strict';
// No HTML strings are populated from API data. Credentials remain in memory only.
const $ = id => document.getElementById(id);
let csrf = '', busy = false, etag = '', polling = false, currentView = 'overview', updateAvailable = false, serviceState = null;
const messages = {
 CONFIG_CONVERSION_TOO_LARGE:'转换后的配置超过 32 MiB，未生成预览或修改原配置；规则未被删除或去重。', CONFIG_CONVERSION_INVALID:'订阅或配置无法识别为 Clash / AnyTLS YAML。请确认使用 Clash/Mihomo 格式订阅，而不是网页、URI 或 Base64 列表；原配置未改变。', CONVERSION_CONFIRMATION_REQUIRED:'请确认转换差异和跳过清单后再导入。', SUBSCRIPTION_HTML_RESPONSE:'订阅服务返回了网页而非配置：可能是登录页、错误页或访问验证。请使用客户端直连订阅链接。原配置未改变。', SUBSCRIPTION_URI_RESPONSE:'订阅服务返回了 URI 节点列表而非 Clash YAML；已声明 Clash 客户端，请在订阅服务选择 Clash/Mihomo 格式链接后重试。原配置未改变。', SUBSCRIPTION_BASE64_RESPONSE:'订阅服务返回了 Base64 节点列表而非 Clash YAML；请在订阅服务选择 Clash/Mihomo 格式链接后重试。原配置未改变。',
 IMPORT_URL_UNSAFE:'订阅地址不安全：仅允许 HTTPS 443 和公网地址，不能访问本机、内网或元数据服务。', IMPORT_TOO_LARGE:'导入内容为空或超过配置大小限制（32 MiB）。', IMPORT_REMOTE_FILE_REFERENCE:'订阅包含不能使用的本机文件引用，请检查 CA 或规则的实际路径字段；provider 缓存路径不会读取本机文件。', CONFIG_CONVERSION_UNSUPPORTED:'处理后没有可用配置，未生成可导入或导出的预览。请查看下方原因与跳过清单。', IMPORT_NO_SELECTABLE_NODES:'没有完整可选的 AnyTLS 节点，请检查服务器、端口和密码。', IMPORT_CONFIRMATION_REQUIRED:'请重新预览并明确确认替换配置。', IMPORT_WRITE_FAILED_ROLLED_BACK:'导入写入失败，已核对恢复原配置、选择与订阅。请检查目录权限后重新预览。', IMPORT_STATE_UNCERTAIN:'严重警告：导入恢复未能确认，配置与运行状态未知。请检查本机配置及 import-backups 备份，不要继续覆盖。', SUBSCRIPTION_NOT_CONFIGURED:'尚未保存订阅，请输入 HTTPS 订阅地址并预览导入。', SELECTION_UNAVAILABLE:'启动节点选择文件不可读取，请在本机检查权限或文件类型。',
 IMPORT_FORMAT_UNSUPPORTED:'格式不支持：请提供 Clash / Mihomo 或 AnyTLS 原生 YAML；暂不支持 URI 或 Base64。', IMPORT_INVALID:'导入配置无效或超过 32 MiB，请检查 YAML、节点与规则。', IMPORT_FETCH_FAILED:'订阅获取失败，请检查 HTTPS 地址与网络后重试。', IMPORT_SOURCE_REJECTED:'订阅来源被拒绝，请使用允许访问的 HTTPS 地址。', IMPORT_CONFLICT:'当前配置已更改，请重新预览后导入。', IMPORT_PREVIEW_EXPIRED:'预览已过期，请重新预览。', IMPORT_BACKUP_FAILED:'备份失败，未继续导入。请检查应用目录权限。', IMPORT_WRITE_FAILED:'配置写入未完成，请重新读取配置并确认当前状态。', IMPORT_ROLLBACK_FAILED:'严重警告：导入回退失败，配置与运行状态未知。请在本机检查配置、备份和 VPN；不要继续覆盖保存。', SUBSCRIPTION_UNAVAILABLE:'已保存订阅不可用，请重新输入 HTTPS 订阅地址。',
 HELPER_CONFIG_MISMATCH:'助手绑定的配置与当前控制台不一致。请确认 VPN 状态，并在当前安装目录重新执行 anytls helper install。', HELPER_UNAVAILABLE:'特权助手未安装或不可用。请在这台 Mac 的终端运行 anytls helper install，一次系统授权后即可自动控制。', FORBIDDEN:'特权助手拒绝当前用户，请用安装助手时授权的账户操作。', PREFLIGHT_FAILED:'配置预检失败，未停止现有 VPN。请检查节点、证书和规则。', STOP_FAILED:'停止或路由恢复检查失败，未继续启动。', START_FAILED:'新配置启动失败，请检查 VPN 状态和连接配置。', STATE_FAILED:'助手无法确认服务状态。', BUSY:'助手正在执行另一项操作，请等待。', SERVICE_ACTION_FAILED:'服务操作未完成，请检查助手状态。',
 AUTH_REQUIRED:'登录已过期，请重新登录。', INVALID_CREDENTIALS:'账户或应用专用密码不正确。', LOGIN_THROTTLED:'尝试次数过多，请一分钟后重试。', SESSION_LIMIT:'登录会话已达上限，请退出其他会话或轮换密码。',
 INVALID_ORIGIN:'请求来源不匹配，请直接使用本机地址打开控制台。', CSRF_REQUIRED:'登录校验已失效，请重新登录。', CONFIG_CONFLICT:'配置已被其他编辑器修改。请复制你的修改，重新读取后合并。', IF_MATCH_REQUIRED:'请先读取原始配置，再保存。', CONFIG_VALIDATION_FAILED:'配置校验失败：请检查 YAML、节点类型、组选择、规则顺序及引用文件。文件未保存。', CONFIG_UNAVAILABLE:'无法读取应用目录下的配置文件。', CONFIG_INVALID:'配置无法解析，请在本机检查 YAML。', GROUP_SELECTION_REJECTED:'不能保存这个选择，请检查分组成员与循环引用。', NODE_SELECTION_REJECTED:'节点不可选，请补全 AnyTLS 节点参数。', ACTION_BUSY:'另一项操作正在执行，请等待完成。', INVALID_INPUT:'输入格式不正确。', UPDATE_UNAVAILABLE:'更新功能不可用：当前程序未提供有效更新结果，或网络/版本校验失败。', SERVICE_ACTION_FAILED_OR_AUTHORIZATION_UNAVAILABLE:'操作未完成：管理员授权被取消、缺少图形会话或服务操作失败。请在终端检查服务；网页不会接收系统密码。', SERVICE_STATE_NOT_CONFIRMED:'操作后未能确认真实服务状态，请在本机检查。'
};
async function api(path, options = {}) {
 const headers = new Headers(options.headers || {});
 if (options.body !== undefined) { headers.set('Content-Type','application/json'); options.body = JSON.stringify(options.body); }
 if (options.method && options.method !== 'GET') headers.set('X-CSRF-Token',csrf);
 const response = await fetch('/api/v1'+path, { ...options, headers, credentials:'same-origin', cache:'no-store', redirect:'error' });
 let data; try { data = await response.json(); } catch { throw new Error('服务器未返回有效数据。'); }
 if (!response.ok) {
  if (response.status === 401 && path !== '/login') showLogin();
  const error=new Error(messages[data.error] || '操作失败（'+response.status+'）。请检查本机配置或命令行状态。'); error.code=data.error; error.details=data; throw error;
 }
 return data;
}
function syncServiceUI(state, title) {
 const known=state && state.availability==='AVAILABLE';
 const running=known && state.running===true;
 $('header-status').textContent=title; $('connection-state').textContent=title;
 $('header-status').classList.toggle('running',Boolean(running));
 $('header-status').classList.toggle('amber',!known);
 document.querySelector('.connection-panel').dataset.state=running?'running':known?'stopped':'unavailable';
 if($('sidebar-state')) $('sidebar-state').textContent=title;
}
function renderServiceButtons() {
 const known=serviceState && serviceState.availability==='AVAILABLE';
 const running=known && serviceState.running===true;
 const loaded=known && serviceState.loaded===true;
 for(const button of document.querySelectorAll('[data-service]')) {
  const action=button.dataset.service;
  button.hidden=!known || (action==='start'?running:action==='stop'?!loaded&&!running:!running||!serviceState.pendingReload);
  button.disabled=busy || !known;
 }
}
// Follow explicit per-node TLS configuration; warning is informational only.
// This flag permits existing skip-cert-verify nodes, never enables it on others.
function saveBody(body) {return {...body,confirm_insecure:true};}
function savedFeedback(data) {
 const result=data.apply_status;
 const applied=result==='APPLIED';
 const failed=data.changed && !applied && result!=='SAVED_STOPPED';
 const text=!data.changed?'配置未变化，没有重新连接。':applied?'配置已保存并自动生效。':result==='SAVED_STOPPED'?'配置已保存；VPN 未运行，下次启动时生效。':'配置已保存，但自动应用未完成。请检查系统授权或配置；当前连接状态以概览为准。';
 notice(text+(data.apply_error&&messages[data.apply_error]?' '+messages[data.apply_error]:''),Boolean(failed));
}
async function refreshAfterSave(refresh) {
 const savedNotice=$('notice').textContent;
 const savedFailure=$('notice').classList.contains('failure');
 let warning='';
 try { if(refresh) await refresh(); } catch(e) { warning='列表刷新失败，可稍后重新读取。'; }
 await status();
 if (!serviceState) warning+=(warning?' ':'')+'服务状态刷新失败，请稍后确认。';
 notice(savedNotice+(warning?' '+warning:''),savedFailure||Boolean(warning));
}
function notice(text, failure = false) { $('notice').textContent=text; $('notice').classList.toggle('failure',failure); $('notice').hidden=!text; }
async function operation(label, fn) {
 if (busy) return;
 busy=true; const enabled=[...document.querySelectorAll('button')].filter(b=>!b.disabled); enabled.forEach(b=>b.disabled=true); notice(label+'，请稍候…');
 try { await fn(); if ($('notice').textContent === `${label}，请稍候…`) notice(`${label}已完成。`); } catch (e) { notice(e.message, true); }
 finally { busy=false; enabled.forEach(b=>{if(b.isConnected)b.disabled=false;}); if (!etag) $('save-config').disabled=true; $('run-update').disabled=!updateAvailable; renderServiceButtons(); renderImportButtons(); }
}
function showLogin() {clearImportSecrets();serviceState=null;renderServiceButtons();csrf='';etag='';updateAvailable=false;$('yaml-editor').value='';$('yaml-editor').disabled=true;$('nodes-list').replaceChildren();$('groups-list').replaceChildren();nodesLoaded=false;$('nodes-search').value='';$('nodes-count').textContent='尚未读取';$('groups-count').textContent='尚未读取';$('update-result').textContent='尚未检查。';$('console-view').hidden=true;$('login-view').hidden=false;$('password').value='';closeDrawer();}
async function enterConsole(data) {csrf=data.csrf;$('password').value='';$('login-view').hidden=true;$('console-view').hidden=false;$('login-error').textContent='';await status();}
$('login-form').addEventListener('submit',async event=>{event.preventDefault();const button=event.submitter;button.disabled=true;$('login-error').textContent='正在验证…';try{await enterConsole(await api('/login',{method:'POST',body:{username:$('username').value,password:$('password').value}}));}catch(e){$('password').value='';$('login-error').textContent=e.message;}finally{button.disabled=false;}});
$('logout').addEventListener('click',()=>operation('退出登录',async()=>{await api('/logout',{method:'POST',body:{}});showLogin();}));
async function status() {
 if (!csrf || polling) return;
 polling=true;
 try {
  const state=await api('/status');serviceState=state;renderServiceButtons();
  const unavailable=state.availability!=='AVAILABLE';
  const title=unavailable?'状态不可用':state.running?'VPN 已启动':state.loaded?'VPN 已加载 · 未运行':'VPN 未启动';
  syncServiceUI(state,title);
  $('connection-detail').textContent=unavailable?'无法读取服务管理器。请在本机终端检查状态。':'状态来自本机服务管理器；尚未执行网络连通性验证。';
  $('pending').hidden=!state.pendingReload;$('version').textContent=state.version;
  $('helper-detail').textContent='正在检查特权助手…';try{const helper=await api('/helper/status');$('helper-detail').textContent=helper.available?'已连接受限特权助手，系统操作无需反复授权。':helper.code==='HELPER_CONFIG_MISMATCH'?messages.HELPER_CONFIG_MISMATCH:'请在本机终端运行 anytls helper install，完成一次系统授权。';}catch{$('helper-detail').textContent='无法连接助手，请在终端检查 anytls helper status。';}
  $('pending-detail').textContent=state.pendingReload?'配置尚未确认生效。网页保存会自动尝试应用；失败后可重试，外部文件更改请手动重载。':state.pendingKnown?'本次控制台操作后未检测到配置更改。':'尚未确认当前快照与磁盘配置是否一致；必要时明确重载。';
 } catch(e){if(csrf){serviceState=null;renderServiceButtons();syncServiceUI(null,'状态未知');$('connection-detail').textContent='服务状态读取失败，请在本机检查；之前的状态不再作为当前依据。';$('pending').hidden=true;$('version').textContent='—';$('pending-detail').textContent='状态读取失败，无法确认配置是否生效。';$('helper-detail').textContent='状态未确认，请在本机检查特权助手。';notice(e.message,true);}}
 finally{polling=false;}
}
setInterval(()=>{if(!document.hidden)status();},3000);
function closeDrawer(){document.body.classList.remove('drawer-open');$('drawer-shade').hidden=true;$('drawer-toggle').setAttribute('aria-expanded','false');}
$('drawer-toggle').onclick=()=>{const open=!document.body.classList.contains('drawer-open');document.body.classList.toggle('drawer-open',open);$('drawer-shade').hidden=!open;$('drawer-toggle').setAttribute('aria-expanded',String(open));};
$('drawer-shade').onclick=closeDrawer;document.addEventListener('keydown',e=>{if(e.key==='Escape')closeDrawer();});
for(const button of document.querySelectorAll('[data-view]'))button.onclick=()=>{
 currentView=button.dataset.view;for(const section of document.querySelectorAll('.view'))section.hidden=section.id!=='view-'+currentView;
 for(const nav of document.querySelectorAll('[data-view]')){nav.classList.toggle('active',nav===button);if(nav===button)nav.setAttribute('aria-current','page');else nav.removeAttribute('aria-current');}
 $('page-title').textContent=button.textContent.trim();closeDrawer();notice('');
 if(currentView==='nodes')loadNodes().catch(e=>notice(e.message,true));
 if(currentView==='config')loadSubscription();
 if(currentView==='groups')loadGroups().catch(e=>notice(e.message,true));
};
for(const button of document.querySelectorAll('[data-service]'))button.onclick=()=>{
 const action=button.dataset.service;
 if(action==='reload'&&!confirm('重载会停止并重新启动 VPN，期间可能短暂断网。继续？'))return;
 operation(button.textContent,async()=>{await api('/service/'+action,{method:'POST',body:{confirm_insecure:action!=='stop'}});await status();});
};
function element(tag,text,className){const node=document.createElement(tag);if(text!==undefined)node.textContent=text;if(className)node.className=className;return node;}
let nodesLoaded=false;
function nodeMatches(node,query){return [node.name,node.type,node.server].some(value=>String(value||'').toLocaleLowerCase().includes(query.trim().toLocaleLowerCase()));}
function filterNodes(){
 if(!nodesLoaded)return;
 const rows=[...$('nodes-list').querySelectorAll('article')],query=$('nodes-search').value;
 let shown=0;for(const row of rows){row.hidden=!nodeMatches(row.nodeSearch,query);if(!row.hidden)shown++;}
 $('nodes-count').textContent=shown+' / '+rows.length+' 个节点';
 let empty=$('nodes-empty');if(!empty){empty=element('p',undefined,'empty-state');empty.id='nodes-empty';$('nodes-list').append(empty);}
 empty.textContent=rows.length?'没有匹配的节点，请清除或修改搜索。':'没有节点。请在配置页编辑原始 YAML。';empty.hidden=shown>0;
}
$('nodes-search').addEventListener('input',filterNodes);
async function loadNodes(){const result=await api('/nodes');const target=$('nodes-list');target.replaceChildren();nodesLoaded=true;
 for(const n of result.nodes){const row=element('article',undefined,'item'),content=element('div',undefined,'item-content');row.nodeSearch=n;row.classList.toggle('selected',Boolean(n.selected));const heading=element('div',undefined,'node-heading');heading.append(element('strong',n.name),element('span',n.type,'badge'));if(n.selected)heading.append(element('span','当前启动节点','badge current'));if(n.skipVerify)heading.append(element('span','跳过证书校验 · 风险','badge risky'));content.append(heading,element('p',n.server+':'+n.port+' · '+(n.hasPassword?'已配置密码':'未配置密码'),'node-meta'));row.append(content);const choose=element('button',n.selected?'当前启动节点':'设为启动节点');choose.disabled=!n.selectable||n.selected;choose.onclick=()=>operation('保存节点选择',async()=>{const saved=await api('/nodes/selection',{method:'POST',body:saveBody({name:n.name})});savedFeedback(saved);await refreshAfterSave(loadNodes);}); row.append(choose);
 const edit=element('details');const summary=element('summary','编辑节点参数');edit.append(summary);
 const form=element('form');form.className='node-form';
 const inputs={};for(const [key,title,value,type] of [['server','服务器',n.server,'text'],['port','端口',n.port,'number'],['sni','SNI',n.sni||'','text'],['password','新节点密码（留空保留）','','password']]){const label=element('label',title);const input=element('input');input.type=type;input.value=value;input.autocomplete=key==='password'?'new-password':'off';input.setAttribute('aria-label',title);if(key==='port'){input.min='1';input.max='65535';}if(key==='server'||key==='port')input.required=true;label.append(input);form.append(label);inputs[key]=input;}
 const submit=element('button','保存节点参数');submit.type='submit';form.append(submit);form.onsubmit=event=>{event.preventDefault();operation('保存节点参数',async()=>{const saved=await api('/nodes',{method:'PUT',headers:{'If-Match':result.etag},body:saveBody({name:n.name,server:inputs.server.value,port:Number(inputs.port.value),sni:inputs.sni.value,password:inputs.password.value})});inputs.password.value='';savedFeedback(saved);await refreshAfterSave(loadNodes);});};edit.append(form);row.append(edit);target.append(row);}filterNodes();}
$('refresh-nodes').onclick=()=>operation('刷新节点',loadNodes);
async function loadGroups(){const result=await api('/groups');const target=$('groups-list');target.replaceChildren();$('groups-count').textContent=result.groups.length+' 个分组';if(!result.groups.length){target.append(element('p','没有策略分组。直接在节点页选择启动节点，或在 YAML 中添加分组。','empty-state'));return;}
 for(const g of result.groups){const row=element('article',undefined,'item'),content=element('div',undefined,'item-content');content.append(element('strong',g.name),element('p',g.valid?'配置出口：'+g.resolved:'当前选择无效，请修复配置'));const select=element('select');select.setAttribute('aria-label',g.name+'的选择');for(const name of g.choices||[]){const option=element('option',name);option.value=name;option.selected=name===g.selected;select.append(option);}const save=element('button','保存选择');save.onclick=()=>operation('保存分组',async()=>{const saved=await api('/groups/selection',{method:'POST',body:saveBody({group:g.name,choice:select.value})});savedFeedback(saved);await refreshAfterSave(loadGroups);});row.append(content,select,save);target.append(row);}}
$('load-rules').onclick=()=>operation('读取规则',async()=>{const data=await api('/rules');$('rules-list').replaceChildren(...data.rules.map(rule=>element('li',rule)));if(!data.rules.length)$('rules-list').append(element('li','没有分流规则。'));});
$('load-config').onclick=()=>{if(etag&& !confirm('重新读取会丢弃编辑区尚未保存的修改。继续？'))return;operation('读取原始配置',async()=>{const data=await api('/config');$('yaml-editor').value=data.yaml;etag=data.etag;$('yaml-editor').disabled=false;$('save-config').disabled=false;$('editor-info').textContent='已读取配置（含节点密码）。保存后，运行中的 VPN 会自动重新连接以应用配置。';});};
$('save-config').onclick=()=>operation('校验并保存配置',async()=>{const data=await api('/config',{method:'PUT',headers:{'If-Match':etag},body:saveBody({yaml:$('yaml-editor').value})});etag=data.etag;$('editor-info').textContent=data.changed?'已保存并读回校验；未知字段、注释和原始文字保留。':'内容未变化，没有重写文件。';savedFeedback(data);await refreshAfterSave();});
let importGeneration=0, importPreview=null, importMode='local', subscriptionConfigured=false, subscriptionRequest=0, importCommitting=false;
const importLimit=32*1024*1024;
function renderImportButtons(){
 for(const id of ['import-yaml','subscription-url','import-file']) $(id).disabled=importCommitting;
 if(importCommitting) $('yaml-editor').disabled=true;
 const valid=Boolean(importPreview&&importPreview.token&&importPreview.generation===importGeneration);
 $('commit-import').disabled=busy||!valid;
 $('export-converted').disabled=busy||!valid;
 $('preview-import').disabled=busy;
 $('refresh-subscription').disabled=busy||!subscriptionConfigured;
 for(const id of ['import-tab-local','import-tab-url']) $(id).disabled=busy;
}
function invalidateImport(){
 importGeneration++;importPreview=null;$('import-preview').hidden=true;$('import-summary').replaceChildren();$('import-warning').textContent='';
 $('import-format-label').textContent='';$('conversion-warnings').replaceChildren();$('conversion-issues').replaceChildren();$('conversion-skipped').replaceChildren();$('conversion-report').hidden=true;
 $('import-source-status').textContent='';renderImportButtons();
}
function clearImportSecrets(){
 invalidateImport();subscriptionRequest++;subscriptionConfigured=false;
 for(const id of ['import-yaml','subscription-url','import-file']) $(id).value='';
 $('subscription-status').textContent='尚未读取订阅状态';renderImportButtons();
}
function clearConfigDraft(){etag='';$('yaml-editor').value='';$('yaml-editor').disabled=true;$('save-config').disabled=true;}
async function loadSubscription(){
 const request=++subscriptionRequest,session=csrf;
 $('subscription-status').textContent='正在读取订阅状态…';
 try{
  const data=await api('/subscription');if(request!==subscriptionRequest||csrf!==session||!csrf)return;
  subscriptionConfigured=data.configured===true;
  $('subscription-status').textContent=subscriptionConfigured?'已配置订阅 · '+(data.host||'主机未知'):'尚未配置订阅';
 }catch{if(request!==subscriptionRequest||csrf!==session||!csrf)return;subscriptionConfigured=false;$('subscription-status').textContent='订阅状态暂不可用；仍可导入或编辑 YAML。';}
 renderImportButtons();
}
function setImportMode(mode){
 invalidateImport();importMode=mode;
 for(const name of ['local','url']){const tab=$('import-tab-'+name),active=name===mode;tab.setAttribute('aria-selected',String(active));tab.tabIndex=active?0:-1;}
 $('import-local').hidden=mode!=='local';$('import-url-panel').hidden=mode!=='url';
}
for(const name of ['local','url']){
 const tab=$('import-tab-'+name);tab.onclick=()=>setImportMode(name);
 tab.addEventListener('keydown',event=>{if(!['ArrowLeft','ArrowRight','Home','End'].includes(event.key)||busy)return;event.preventDefault();const next=event.key==='Home'?'local':event.key==='End'?'url':name==='local'?'url':'local';setImportMode(next);$('import-tab-'+next).focus();});
}
for(const id of ['import-yaml','subscription-url']) $(id).addEventListener('input',invalidateImport);
$('import-file').addEventListener('change',()=>{invalidateImport();const file=$('import-file').files[0];if(file&&(!/\.ya?ml$/i.test(file.name)||file.size>importLimit))$('import-source-status').textContent='请选择不超过 32 MiB 的 .yaml / .yml 文件。';});
function readImportFile(file){return new Promise((resolve,reject)=>{const reader=new FileReader();reader.onload=()=>resolve(String(reader.result));reader.onerror=reader.onabort=()=>reject(new Error('文件读取失败，请重新选择。'));reader.readAsText(file);});}
function conversionReport(value){
 if(!value||!['clash','native'].includes(value.format)||typeof value.converted!=='boolean'||!['warnings','issues'].every(key=>Array.isArray(value[key])&&value[key].every(item=>typeof item==='string')))throw new Error('转换报告不完整，请重新预览。');
 return {format:value.format,converted:value.converted,warnings:[...value.warnings],issues:[...value.issues],skipped:Array.isArray(value.skipped)&&value.skipped.every(item=>typeof item==='string')?[...value.skipped]:[]};
}
function renderConversion(report){
 $('import-format-label').textContent=report.format==='clash'?'Clash / Mihomo → AnyTLS 配置':'AnyTLS 原生配置 · 不需转换';
 for(const key of ['warnings','issues','skipped']){
  $('conversion-'+key).replaceChildren(...report[key].map(text=>element('li',text)));
  $('conversion-'+key+'-section').hidden=!report[key].length;
 }
 $('conversion-report').hidden=false;
}
function previewImport(useSaved=false){return operation('预览导入',async()=>{
 invalidateImport();const generation=importGeneration,session=csrf;let body;
 if(useSaved)body={use_saved:true};
 else if(importMode==='url'){
  const url=$('subscription-url').value.trim();let parsed;try{parsed=new URL(url);}catch{throw new Error('请输入有效的 HTTPS 订阅 URL。');}
  if(parsed.protocol!=='https:')throw new Error('订阅仅支持 HTTPS。');body={url};
 }else{
  const file=$('import-file').files[0];let yaml;
  if(file){if(!/\.ya?ml$/i.test(file.name))throw new Error(messages.IMPORT_FORMAT_UNSUPPORTED);if(file.size>importLimit)throw new Error('文件超过 32 MiB，未发送。服务器仍会独立校验大小。');yaml=await readImportFile(file);}
  else yaml=$('import-yaml').value;
  if(generation!==importGeneration||!csrf){notice('输入已改变，请重新预览。');return;}
  if(!yaml.trim())throw new Error('请选择 YAML 文件或粘贴配置。');
  if(new TextEncoder().encode(yaml).length>importLimit)throw new Error('配置超过 32 MiB，未发送。服务器仍会独立校验大小。');body={yaml};
 }
 if(generation!==importGeneration||!csrf)return;
 let data;try{data=await api('/import/preview',{method:'POST',body});}
 catch(error){
  if(generation!==importGeneration||csrf!==session||!csrf){notice('输入已改变，已丢弃旧预览。请重新预览。');return;}
  if(error.code==='CONFIG_CONVERSION_UNSUPPORTED'){
   const report=conversionReport(error.details.conversion);renderConversion(report);$('import-preview').hidden=false;
   $('import-source-status').textContent='转换受阻，尚未保存；不能导入或导出。';
  }
  throw error;
 }
 if(generation!==importGeneration||csrf!==session||!csrf){notice('输入已改变，已丢弃旧预览。请重新预览。');return;}
 const conversion=conversionReport(data.conversion);renderConversion(conversion);
 if(conversion.issues.length||(conversion.format==='clash'&&!conversion.converted)){ $('import-preview').hidden=false;throw new Error(messages.CONFIG_CONVERSION_UNSUPPORTED);}
 if(typeof data.token!=='string'||!data.token||typeof data.etag!=='string'||!data.etag||!['nodes','groups','rules'].every(key=>Number.isInteger(data[key])&&data[key]>=0))throw new Error('预览响应不完整，请重试。');
 importPreview={token:data.token,etag:data.etag,generation,conversion};
 const summary=$('import-summary');
 for(const [title,value] of [['节点',data.nodes],['策略组',data.groups],['规则',data.rules],['启动节点',data.selected||'未选择'],...(data.source_host?[['来源主机',data.source_host]]:[])])summary.append(element('dt',title),element('dd',String(value)));
 $('import-warning').textContent=data.warning||'';$('import-warning').hidden=!data.warning;$('import-preview').hidden=false;
 $('import-source-status').textContent='预览就绪，尚未保存。'+(conversion.skipped.length?' 已跳过 '+conversion.skipped.length+' 项，请查看清单。':'');notice('预览完成；确认后才会备份并替换配置。');
 });}
$('preview-import').onclick=()=>previewImport();
$('refresh-subscription').onclick=()=>previewImport(true);
$('commit-import').onclick=()=>operation('备份并导入',async()=>{
 const preview=importPreview;if(!preview||preview.generation!==importGeneration)throw new Error('请先重新预览。');
 const acceptConversion=preview.conversion.warnings.length>0||preview.conversion.skipped.length>0;
 if(acceptConversion&&!confirm('将仅导入可用部分，上方已列出跳过内容及转换差异（可能改变分流或默认出口）。确认接受并备份导入？')){notice('已取消导入；预览仍可导出，尚未应用。');return;}
 // Consume each token once locally, including ambiguous network failures.
 importCommitting=true;const editorWasDisabled=$('yaml-editor').disabled;
 try {
 importPreview=null;renderImportButtons();let data;
 try{data=await api('/import/commit',{method:'POST',headers:{'If-Match':preview.etag},body:{token:preview.token,confirm_replace:true,confirm_insecure:true,...(acceptConversion?{accept_conversion:true}:{})}});}
 catch(error){invalidateImport();if(error.code==='IMPORT_ROLLBACK_FAILED'||error.code==='IMPORT_STATE_UNCERTAIN'){clearConfigDraft();serviceState=null;renderServiceButtons();syncServiceUI(null,'状态未知');$('connection-detail').textContent=messages[error.code];$('editor-info').textContent=messages[error.code];}throw error;}
 clearImportSecrets();clearConfigDraft();$('editor-info').textContent='导入完成；原始编辑草稿已清空。需要编辑时请重新打开配置。';
 if(data.changed){nodesLoaded=false;$('nodes-list').replaceChildren();$('groups-list').replaceChildren();$('rules-list').replaceChildren();$('nodes-count').textContent='尚未读取';$('groups-count').textContent='尚未读取';}
 savedFeedback(data);await refreshAfterSave(loadSubscription);
 } finally {importCommitting=false;if(etag&&!editorWasDisabled) $('yaml-editor').disabled=false;renderImportButtons();}
});
function downloadConfig(data){
 if(typeof data.yaml!=='string'||!data.yaml.trim()||data.format!=='anytls-native')throw new Error('导出响应不完整，未下载文件。');
 const url=URL.createObjectURL(new Blob([data.yaml],{type:'application/yaml'}));
 const anchor=document.createElement('a');anchor.href=url;anchor.download='anytls-config.yaml';
 try{document.body.append(anchor);anchor.click();}finally{anchor.remove();setTimeout(()=>URL.revokeObjectURL(url),0);}
}
$('export-converted').onclick=()=>{
 if(busy||!importPreview||!confirm('导出文件包含节点密码，请妥善保管，不要公开分享。导出不会保存或应用配置。继续？'))return;
 return operation('导出转换后配置',async()=>{
  const preview=importPreview,session=csrf;if(!preview||preview.generation!==importGeneration)throw new Error('请先重新预览。');
  const data=await api('/import/export',{method:'POST',headers:{'If-Match':preview.etag},body:{token:preview.token}});
  if(csrf!==session||!csrf||importPreview!==preview||preview.generation!==importGeneration)throw new Error('输入或会话已改变，未下载旧预览。请重新预览。');
  downloadConfig(data);notice('已导出 AnyTLS 配置（含节点密码）；尚未保存或应用，预览仍可导入。');
 });
};
$('export-current').onclick=()=>{
 if(busy||!confirm('导出文件包含节点密码，请妥善保管，不要公开分享。将导出磁盘上的当前配置，不含未保存的编辑。继续？'))return;
 return operation('导出当前配置',async()=>{const session=csrf,data=await api('/config/export');if(csrf!==session||!csrf)throw new Error('会话已改变，未下载配置。');const report=conversionReport(data.conversion);if(report.issues.length)throw new Error(messages.CONFIG_CONVERSION_UNSUPPORTED);if(report.warnings.length||report.skipped.length){renderConversion(report);$('import-preview').hidden=false;}downloadConfig(data);notice('已导出磁盘上的当前 AnyTLS 配置（含节点密码），未更改或应用配置。'+(report.warnings.length||report.skipped.length?' 转换差异与跳过：'+[...report.warnings,...report.skipped].join('；'):''));});
};
$('check-update').onclick=()=>operation('检查新版本',async()=>{const data=await api('/update-check');$('update-result').textContent=JSON.stringify(data,null,2);updateAvailable=data.available===true;$('run-update').disabled=!updateAvailable;});
$('run-update').onclick=()=>{if(!confirm('将检查并安装官方更新、保留现有配置，不自动重启服务。继续？'))return;operation('安装更新',async()=>{const data=await api('/update',{method:'POST',body:{confirm:true}});$('update-result').textContent=JSON.stringify(data,null,2);});};
(async()=>{try{await enterConsole(await api('/session'));}catch{showLogin();}})();

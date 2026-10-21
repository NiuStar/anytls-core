'use strict';
// No HTML strings are populated from API data. Credentials remain in memory only.
const $ = id => document.getElementById(id);
let csrf = '', busy = false, etag = '', polling = false, currentView = 'overview', updateAvailable = false, serviceState = null;
const messages = {
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
  throw new Error(messages[data.error] || '操作失败（'+response.status+'）。请检查本机配置或命令行状态。');
 }
 return data;
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
 finally { busy=false; enabled.forEach(b=>{if(b.isConnected)b.disabled=false;}); if (!etag) $('save-config').disabled=true; $('run-update').disabled=!updateAvailable; renderServiceButtons(); }
}
function showLogin() {serviceState=null;renderServiceButtons();csrf='';etag='';updateAvailable=false;$('yaml-editor').value='';$('yaml-editor').disabled=true;$('nodes-list').replaceChildren();$('groups-list').replaceChildren();$('update-result').textContent='尚未检查。';$('console-view').hidden=true;$('login-view').hidden=false;$('password').value='';closeDrawer();}
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
  $('header-status').textContent=title;$('connection-state').textContent=title;
  $('header-status').classList.toggle('amber',unavailable);
  $('connection-detail').textContent=unavailable?'无法读取服务管理器。请在本机终端检查状态。':'状态来自本机服务管理器；尚未执行网络连通性验证。';
  $('pending').hidden=!state.pendingReload;$('version').textContent=state.version;
  $('helper-detail').textContent='正在检查特权助手…';try{const helper=await api('/helper/status');$('helper-detail').textContent=helper.available?'已连接受限特权助手，系统操作无需反复授权。':helper.code==='HELPER_CONFIG_MISMATCH'?messages.HELPER_CONFIG_MISMATCH:'请在本机终端运行 anytls helper install，完成一次系统授权。';}catch{$('helper-detail').textContent='无法连接助手，请在终端检查 anytls helper status。';}
  $('pending-detail').textContent=state.pendingReload?'配置尚未确认生效。网页保存会自动尝试应用；失败后可重试，外部文件更改请手动重载。':state.pendingKnown?'本次控制台操作后未检测到配置更改。':'尚未确认当前快照与磁盘配置是否一致；必要时明确重载。';
 } catch(e){if(csrf){serviceState=null;renderServiceButtons();$('header-status').textContent='读取失败';notice(e.message,true);}}
 finally{polling=false;}
}
setInterval(()=>{if(!document.hidden)status();},3000);
function closeDrawer(){document.body.classList.remove('drawer-open');$('drawer-shade').hidden=true;$('drawer-toggle').setAttribute('aria-expanded','false');}
$('drawer-toggle').onclick=()=>{const open=!document.body.classList.contains('drawer-open');document.body.classList.toggle('drawer-open',open);$('drawer-shade').hidden=!open;$('drawer-toggle').setAttribute('aria-expanded',String(open));};
$('drawer-shade').onclick=closeDrawer;document.addEventListener('keydown',e=>{if(e.key==='Escape')closeDrawer();});
for(const button of document.querySelectorAll('[data-view]'))button.onclick=()=>{
 currentView=button.dataset.view;for(const section of document.querySelectorAll('.view'))section.hidden=section.id!=='view-'+currentView;
 for(const nav of document.querySelectorAll('[data-view]'))nav.classList.toggle('active',nav===button);
 $('page-title').textContent=button.textContent;closeDrawer();notice('');
 if(currentView==='nodes')loadNodes().catch(e=>notice(e.message,true));
 if(currentView==='groups')loadGroups().catch(e=>notice(e.message,true));
};
for(const button of document.querySelectorAll('[data-service]'))button.onclick=()=>{
 const action=button.dataset.service;
 if(action==='reload'&&!confirm('重载会停止并重新启动 VPN，期间可能短暂断网。继续？'))return;
 operation(button.textContent,async()=>{await api('/service/'+action,{method:'POST',body:{confirm_insecure:action!=='stop'}});await status();});
};
function element(tag,text,className){const node=document.createElement(tag);if(text!==undefined)node.textContent=text;if(className)node.className=className;return node;}
async function loadNodes(){const result=await api('/nodes');const target=$('nodes-list');target.replaceChildren();if(!result.nodes.length){target.append(element('p','没有节点。请在配置页编辑原始 YAML。','muted'));return;}
 for(const n of result.nodes){const row=element('article',undefined,'item'),content=element('div',undefined,'item-content');content.append(element('strong',n.name),element('p',n.type+' · '+n.server+':'+n.port+' · '+(n.hasPassword?'已配置密码':'未配置密码')+(n.skipVerify?' · 配置要求跳过证书校验':'')));row.append(content);const choose=element('button',n.selected?'当前启动节点':'设为启动节点');choose.disabled=!n.selectable||n.selected;choose.onclick=()=>operation('保存节点选择',async()=>{const saved=await api('/nodes/selection',{method:'POST',body:saveBody({name:n.name})});savedFeedback(saved);await refreshAfterSave(loadNodes);}); row.append(choose);
 const edit=element('details');const summary=element('summary','编辑节点参数');edit.append(summary);
 const form=element('form');form.className='node-form';
 const inputs={};for(const [key,title,value,type] of [['server','服务器',n.server,'text'],['port','端口',n.port,'number'],['sni','SNI',n.sni||'','text'],['password','新节点密码（留空保留）','','password']]){const label=element('label',title);const input=element('input');input.type=type;input.value=value;input.autocomplete=key==='password'?'new-password':'off';input.setAttribute('aria-label',title);if(key==='port'){input.min='1';input.max='65535';}if(key==='server'||key==='port')input.required=true;label.append(input);form.append(label);inputs[key]=input;}
 const submit=element('button','保存节点参数');submit.type='submit';form.append(submit);form.onsubmit=event=>{event.preventDefault();operation('保存节点参数',async()=>{const saved=await api('/nodes',{method:'PUT',headers:{'If-Match':result.etag},body:saveBody({name:n.name,server:inputs.server.value,port:Number(inputs.port.value),sni:inputs.sni.value,password:inputs.password.value})});inputs.password.value='';savedFeedback(saved);await refreshAfterSave(loadNodes);});};edit.append(form);row.append(edit);target.append(row);}}
$('refresh-nodes').onclick=()=>operation('刷新节点',loadNodes);
async function loadGroups(){const result=await api('/groups');const target=$('groups-list');target.replaceChildren();if(!result.groups.length){target.append(element('p','没有策略分组。直接在节点页选择启动节点，或在 YAML 中添加分组。','muted'));return;}
 for(const g of result.groups){const row=element('article',undefined,'item'),content=element('div',undefined,'item-content');content.append(element('strong',g.name),element('p',g.valid?'磁盘配置解析出口：'+g.resolved+'（不代表运行快照）':'当前选择无效，请修复配置'));const select=element('select');select.setAttribute('aria-label',g.name+'的选择');for(const name of g.choices||[]){const option=element('option',name);option.value=name;option.selected=name===g.selected;select.append(option);}const save=element('button','保存选择');save.onclick=()=>operation('保存分组',async()=>{const saved=await api('/groups/selection',{method:'POST',body:saveBody({group:g.name,choice:select.value})});savedFeedback(saved);await refreshAfterSave(loadGroups);});row.append(content,select,save);target.append(row);}}
$('load-rules').onclick=()=>operation('读取规则',async()=>{const data=await api('/rules');$('rules-list').replaceChildren(...data.rules.map(rule=>element('li',rule)));if(!data.rules.length)$('rules-list').append(element('li','没有分流规则。'));});
$('load-config').onclick=()=>{if(etag&& !confirm('重新读取会丢弃编辑区尚未保存的修改。继续？'))return;operation('读取原始配置',async()=>{const data=await api('/config');$('yaml-editor').value=data.yaml;etag=data.etag;$('yaml-editor').disabled=false;$('save-config').disabled=false;$('editor-info').textContent='已读取配置（含节点密码）。保存后，运行中的 VPN 会自动重新连接以应用配置。';});};
$('save-config').onclick=()=>operation('校验并保存配置',async()=>{const data=await api('/config',{method:'PUT',headers:{'If-Match':etag},body:saveBody({yaml:$('yaml-editor').value})});etag=data.etag;$('editor-info').textContent=data.changed?'已保存并读回校验；未知字段、注释和原始文字保留。':'内容未变化，没有重写文件。';savedFeedback(data);await refreshAfterSave();});
$('check-update').onclick=()=>operation('检查新版本',async()=>{const data=await api('/update-check');$('update-result').textContent=JSON.stringify(data,null,2);updateAvailable=data.available===true;$('run-update').disabled=!updateAvailable;});
$('run-update').onclick=()=>{if(!confirm('将检查并安装官方更新、保留现有配置，不自动重启服务。继续？'))return;operation('安装更新',async()=>{const data=await api('/update',{method:'POST',body:{confirm:true}});$('update-result').textContent=JSON.stringify(data,null,2);});};
(async()=>{try{await enterConsole(await api('/session'));}catch{showLogin();}})();

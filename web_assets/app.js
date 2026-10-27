'use strict';
// No HTML strings are populated from API data. Credentials remain in memory only.
const $ = id => document.getElementById(id);
let csrf = '', busy = false, etag = '', polling = false, currentView = 'overview', updateAvailable = false, serviceState = null;
let sessionGeneration=0, profilesRequest=0, profilesEtag='', nodesRequest=0, nodesEtag='', groupsRequest=0, groupsEtag='', probeGeneration=0, probeRunning=false, probeBatch=null, finishOperation=null;
const messages = {
 RULE_INVALID_INPUT:'规则输入无效：类型、匹配值、目标不能为空，不支持逗号或换行；no-resolve 仅适用于 GEOIP / RULE-SET。', RULE_VALUE_INVALID:'匹配值或当前配置未通过原生校验；GEOIP 仅支持 CN，规则集必须已定义并通过摘要审计。', RULE_TARGET_INVALID:'目标已失效，请重新打开新增规则并选择有效目标。', RULE_POSITION_INVALID:'位置无效：请输入现有规则序号，不能放在最终 MATCH 后。', RULE_EDIT_UNSUPPORTED:'当前规则不是可安全插入的普通块列表，或缺少最终 MATCH。请使用原始配置编辑器调整为显式 rules 列表并保留最终 MATCH，再重新打开新增规则。别名、合并和流式规则列表不会自动改写。',
 UPDATE_CHECK_FAILED:'检查更新失败，未取得可信版本信息。请检查网络后重新检查。', UPDATE_PYTHON_REQUIRED:'无法安装更新：本机缺少 Python 3。无需 Go 或系统授权；请先安装 Python 3 后重新检查。', UPDATE_BINARY_UNAVAILABLE:'当前平台没有完整的官方预编译更新包，不能安装；不会改用源码编译。', UPDATE_DOWNLOAD_FAILED:'更新材料下载失败，尚未发布新程序。请检查网络后重新检查。', UPDATE_VALIDATION_FAILED:'更新材料或候选程序校验失败，未发布新程序。请重新检查更新。', UPDATE_PUBLISH_FAILED:'更新材料保留、程序备份或发布失败；程序文件状态需核对。请保留备份及材料，核对后再试。', UPDATE_VERIFY_FAILED:'替换后的程序版本核验失败，安装结果待核对。请保留备份及材料，由维护者核对磁盘版本、摘要及备份；不会自动回滚或重启 VPN。',
 PROFILE_INVALID:'方案名称或标识无效，请检查后重试。', PROFILE_NOT_FOUND:'方案已不存在，请刷新方案列表。', PROFILE_CONFLICT:'配置或方案已改变，请刷新后再切换。', PROFILE_STORE_UNAVAILABLE:'方案存储不可用，请检查本机目录权限。', PROFILE_SAVE_FAILED:'方案保存失败，请检查本机目录权限后刷新确认。', PROFILE_SWITCH_FAILED_ROLLED_BACK:'方案切换失败，已恢复旧配置；请检查配置后重试。', PROFILE_STATE_UNCERTAIN:'严重警告：方案切换恢复未能确认，配置与运行状态未知。请检查本机配置与备份，不要继续覆盖。',
 CONFIG_CONVERSION_TIMEOUT:'订阅已进入配置转换，但获取远程规则集或展开转换超过处理期限。不是订阅格式判定失败；原配置未改变，请检查规则集网络连接。', CONFIG_CONVERSION_CANCELED:'配置转换已取消，未生成预览，原配置未改变。', CONFIG_CONVERSION_TOO_LARGE:'转换后的配置超过 32 MiB，未生成预览或修改原配置；规则未被删除或去重。', CONFIG_CONVERSION_INVALID:'订阅或配置无法识别为 Clash / AnyTLS YAML。请确认使用 Clash/Mihomo 格式订阅，而不是网页、URI 或 Base64 列表；原配置未改变。', CONVERSION_CONFIRMATION_REQUIRED:'请确认转换差异和跳过清单后再导入。', SUBSCRIPTION_HTML_RESPONSE:'订阅服务返回了网页而非配置：可能是登录页、错误页或访问验证。请使用客户端直连订阅链接。原配置未改变。', SUBSCRIPTION_URI_RESPONSE:'订阅服务返回了 URI 节点列表而非 Clash YAML；已声明 Clash 客户端，请在订阅服务选择 Clash/Mihomo 格式链接后重试。原配置未改变。', SUBSCRIPTION_BASE64_RESPONSE:'订阅服务返回了 Base64 节点列表而非 Clash YAML；请在订阅服务选择 Clash/Mihomo 格式链接后重试。原配置未改变。',
 IMPORT_APPEND_UNSAFE:'无法安全添加节点：当前节点列表含重复、别名或合并键，请检查配置。', IMPORT_NODE_CONFLICT:'存在同名但内容不同的节点，未添加任何节点；请明确修改名称或配置后重试。', IMPORT_URL_UNSAFE:'订阅地址不安全：普通链接仅 HTTPS 443；添加节点可用可信分发的公网数字 IP 证书固定链接。禁止本机、内网和元数据地址。', IMPORT_TOO_LARGE:'导入内容为空或超过配置大小限制（32 MiB）。', IMPORT_REMOTE_FILE_REFERENCE:'订阅包含不能使用的本机文件引用，请检查 CA 或规则的实际路径字段；provider 缓存路径不会读取本机文件。', CONFIG_CONVERSION_UNSUPPORTED:'处理后没有可用配置，未生成可导入或导出的预览。请查看下方原因与跳过清单。', IMPORT_NO_SELECTABLE_NODES:'没有完整可选的 AnyTLS 节点，请检查服务器、端口和密码。', IMPORT_CONFIRMATION_REQUIRED:'请重新预览并明确确认替换配置。', IMPORT_WRITE_FAILED_ROLLED_BACK:'导入写入失败，已核对恢复原配置、选择与订阅。请检查目录权限后重新预览。', IMPORT_STATE_UNCERTAIN:'严重警告：导入恢复未能确认，配置与运行状态未知。请检查本机配置及 import-backups 备份，不要继续覆盖。', SUBSCRIPTION_NOT_CONFIGURED:'尚未保存订阅，请输入 HTTPS 订阅地址并预览导入。', SELECTION_UNAVAILABLE:'启动节点选择文件不可读取，请在本机检查权限或文件类型。',
 IMPORT_FORMAT_UNSUPPORTED:'格式不支持：请提供 Clash / Mihomo 或 AnyTLS 原生 YAML；暂不支持 URI 或 Base64。', IMPORT_INVALID:'导入配置无效或超过 32 MiB，请检查 YAML、节点与规则。', IMPORT_FETCH_FAILED:'订阅获取失败，请检查 HTTPS 地址与网络后重试。', IMPORT_SOURCE_REJECTED:'订阅来源被拒绝，请使用允许访问的 HTTPS 地址。', IMPORT_CONFLICT:'当前配置已更改，请重新预览后导入。', IMPORT_PREVIEW_EXPIRED:'预览已过期，请重新预览。', IMPORT_BACKUP_FAILED:'备份失败，未继续导入。请检查应用目录权限。', IMPORT_WRITE_FAILED:'配置写入未完成，请重新读取配置并确认当前状态。', IMPORT_ROLLBACK_FAILED:'严重警告：导入回退失败，配置与运行状态未知。请在本机检查配置、备份和 VPN；不要继续覆盖保存。', SUBSCRIPTION_UNAVAILABLE:'已保存订阅不可用，请重新输入 HTTPS 订阅地址。',
 HELPER_CONFIG_MISMATCH:'助手绑定的配置与当前控制台不一致。请确认 VPN 状态，并在当前安装目录重新执行 anytls helper install。', HELPER_UNAVAILABLE:'特权助手未安装或不可用。请在这台 Mac 的终端运行 anytls helper install，一次系统授权后即可自动控制。', FORBIDDEN:'特权助手拒绝当前用户，请用安装助手时授权的账户操作。', PREFLIGHT_FAILED:'配置预检失败，未停止现有 VPN。请检查节点、证书和规则。', STOP_FAILED:'停止控制或诊断收尾失败，未继续启动；不表示服务一定仍在运行。', START_FAILED:'新配置启动失败，请检查 VPN 状态和连接配置。', STATE_FAILED:'助手无法确认服务状态。', BUSY:'助手正在执行另一项操作，请等待。', SERVICE_ACTION_FAILED:'服务操作未完成，请检查助手状态。',
 AUTH_REQUIRED:'登录已过期，请重新登录。', INVALID_CREDENTIALS:'账户或应用专用密码不正确。', LOGIN_THROTTLED:'尝试次数过多，请一分钟后重试。', SESSION_LIMIT:'登录会话已达上限，请退出其他会话或轮换密码。',
 INVALID_ORIGIN:'请求来源不匹配，请直接使用本机地址打开控制台。', CSRF_REQUIRED:'登录校验已失效，请重新登录。', CONFIG_CONFLICT:'配置已被其他编辑器修改。请复制你的修改，重新读取后合并。', IF_MATCH_REQUIRED:'请先读取原始配置，再保存。', CONFIG_VALIDATION_FAILED:'配置校验失败：请检查 YAML、节点类型、组选择、规则顺序及引用文件。文件未保存。', CONFIG_UNAVAILABLE:'无法读取应用目录下的配置文件。', CONFIG_INVALID:'配置无法解析，请在本机检查 YAML。', GROUP_SELECTION_REJECTED:'不能保存这个选择，请检查分组成员与循环引用。', NODE_SELECTION_REJECTED:'节点不可选，请补全 AnyTLS 节点参数。', ACTION_BUSY:'另一项操作正在执行，请等待完成。', PROBE_BUSY:'测速名额已满，请稍后重试。', INVALID_INPUT:'输入格式不正确。', UPDATE_UNAVAILABLE:'更新结果不可用，安装结果待核对。请保留备份及材料，由维护者核对磁盘版本、摘要及备份；不会自动回滚或重启。', SERVICE_ACTION_FAILED_OR_AUTHORIZATION_UNAVAILABLE:'操作未完成：管理员授权被取消、缺少图形会话或服务操作失败。请在终端检查服务；网页不会接收系统密码。', SERVICE_STATE_NOT_CONFIRMED:'操作后未能确认真实服务状态，请在本机检查。'
};
// Fixed vocabulary only: never display raw helper/tool errors or unknown enum values.
const diagnosticStages = {
 NONE:['无','核实当前服务状态。'], HELPER_PREFLIGHT:['助手预检','核实助手绑定与配置预检结果。'], JOB:['服务作业','核实本机服务管理器的加载与运行状态。'], SNAPSHOT:['启动快照','核实本机快照状态与目录权限；不要删除快照。'], CONFIG:['配置编译','核实配置及其引用资源；编译失败不等于密码错误。'], PROXY:['系统代理','检查系统 HTTP、HTTPS、SOCKS 代理设置。'], SERVER_ROUTE:['服务器路由','核实服务器物理出口及旁路路由。'], PUBLIC_ROUTE:['公共路由','核实公共路由读取结果。'], DNS:['DNS 状态','核实本机 DNS 设置与读取结果。'], BASELINE:['网络基线','核实网络基线的完整性与目录权限。'], PLIST:['服务描述','核实本机服务描述生成与校验结果。'], BOOTSTRAP:['服务注册','核实服务管理器注册结果；尚不能确定系统根因。'], READINESS:['启动就绪','核实进程与 TUN 路由的当前状态。'], HTTPS:['出口 HTTPS 检查','核实出口 HTTPS 的 DNS、连接及证书链；不代表节点认证失败。'], STOP:['停止与恢复','核实停止链及路由、DNS 恢复证据。'], DIAGNOSTIC:['诊断保存','核实诊断保存权限与当前应用状态。'], UNKNOWN:['未知','核实当前服务状态；现有证据不足以确定原因。']
};
const diagnosticReasons = {
 NONE:['NONE','无失败原因'], PREFLIGHT_REJECTED:['HELPER_PREFLIGHT','助手预检拒绝'],
 JOB_STATE_UNAVAILABLE:['JOB','服务作业状态不可读取'], JOB_ALREADY_LOADED:['JOB','服务作业已加载或运行'], JOB_NOT_LOADED:['JOB','服务作业尚未加载'],
 SNAPSHOT_EXISTS:['SNAPSHOT','启动快照已存在'], SNAPSHOT_UNAVAILABLE:['SNAPSHOT','快照状态不可读取'], SNAPSHOT_STAGE_FAILED:['SNAPSHOT','快照创建或资源准备失败'], SNAPSHOT_IDENTITY_FAILED:['SNAPSHOT','快照身份校验失败'],
 CONFIG_COMPILE_FAILED:['CONFIG','配置编译失败'], SYSTEM_PROXY_ACTIVE:['PROXY','系统代理已启用'], PROXY_STATE_UNAVAILABLE:['PROXY','系统代理状态不可读取'],
 SERVER_ROUTE_UNAVAILABLE:['SERVER_ROUTE','服务器路由不可读取'], SERVER_ROUTE_NOT_PHYSICAL:['SERVER_ROUTE','服务器出口不是物理接口'], SERVER_ROUTE_CHANGED:['SERVER_ROUTE','服务器旁路路由已变化'], PUBLIC_ROUTE_UNAVAILABLE:['PUBLIC_ROUTE','公共路由不可读取'],
 DNS_STATE_UNAVAILABLE:['DNS','DNS 状态不可读取'], DNS_EVIDENCE_EMPTY:['DNS','未取得 DNS 列表'], BASELINE_INVALID:['BASELINE','网络基线读取或校验失败'], BASELINE_WRITE_FAILED:['BASELINE','网络基线保存失败'],
 PLIST_CREATE_FAILED:['PLIST','服务描述创建失败'], PLIST_WRITE_FAILED:['PLIST','服务描述写入或关闭失败'], PLIST_INVALID:['PLIST','服务描述校验失败'], LAUNCHD_BOOTSTRAP_FAILED:['BOOTSTRAP','服务注册失败'],
 READINESS_JOB_UNAVAILABLE:['READINESS','就绪检查无法读取作业状态'], READINESS_ROUTE_UNAVAILABLE:['READINESS','就绪检查无法读取路由'], READINESS_CHANGED:['READINESS','就绪检查期间进程或 TUN 路由发生变化'], PROCESS_NOT_RUNNING:['READINESS','观察结束时进程未运行'], TUN_NOT_READY:['READINESS','观察结束时 TUN 未就绪'], PROCESS_AND_TUN_NOT_READY:['READINESS','观察结束时进程与 TUN 均未就绪'], READINESS_UNKNOWN:['READINESS','缺少可信的就绪观察'],
 HTTPS_DNS_FAILED:['HTTPS','出口 HTTPS DNS 解析失败'], HTTPS_CONNECT_FAILED:['HTTPS','出口 HTTPS 连接失败'], HTTPS_TIMEOUT:['HTTPS','出口 HTTPS 检查超时'], HTTPS_TLS_HANDSHAKE_FAILED:['HTTPS','出口 HTTPS TLS 握手失败'], HTTPS_CERTIFICATE_FAILED:['HTTPS','出口 HTTPS 证书验证失败'], HTTPS_HTTP_FAILED:['HTTPS','出口 HTTPS HTTP 响应失败'], HTTPS_EMPTY_RESPONSE:['HTTPS','出口 HTTPS 响应为空'], HTTPS_RECEIVE_FAILED:['HTTPS','出口 HTTPS 接收失败'], HTTPS_RESPONSE_INVALID:['HTTPS','出口 HTTPS 响应不是有效 IP'], HTTPS_FAILED:['HTTPS','出口 HTTPS 检查失败，具体原因未知'],
 STOP_FAILED:['STOP','停止或恢复链未成功'], RECEIPT_WRITE_FAILED:['DIAGNOSTIC','诊断回执保存失败'], UNKNOWN:['UNKNOWN','原因未知']
};
const recoveryLabels={NOT_ATTEMPTED:'未尝试',VERIFIED:'已验证',FAILED:'失败',UNKNOWN:'未知'};
const receiptLabels={NOT_ATTEMPTED:'未尝试',WRITTEN:'已写入',FAILED:'失败',UNKNOWN:'未知'};
const serviceErrorCodes=new Set(['HELPER_CONFIG_MISMATCH','HELPER_UNAVAILABLE','FORBIDDEN','PREFLIGHT_FAILED','STOP_FAILED','START_FAILED','STATE_FAILED','BUSY','SERVICE_ACTION_FAILED','SERVICE_ACTION_FAILED_OR_AUTHORIZATION_UNAVAILABLE','SERVICE_STATE_NOT_CONFIRMED']);
const own=(object,key)=>Object.prototype.hasOwnProperty.call(object,key);
function validDiagnostics(d, operation, success) {
 const fields=['schema','operation','outcome','stage','reason','rollback','restoration','cleanup','receipt','job','tun'];
 if(!d||typeof d!=='object'||Array.isArray(d)||Object.keys(d).length!==fields.length||!fields.every(k=>own(d,k))||d.schema!==1||!fields.slice(1).every(k=>typeof d[k]==='string'))return false;
 if(!['START','RELOAD','STOP'].includes(d.operation)||(operation&&d.operation!==operation)||!own(diagnosticStages,d.stage)||!['SUCCEEDED','FAILED','CANCELLED','UNKNOWN'].includes(d.outcome))return false;
 if(!['rollback','restoration','cleanup'].every(k=>typeof d[k]==='string'&&own(recoveryLabels,d[k]))||typeof d.receipt!=='string'||!own(receiptLabels,d.receipt)||!['NOT_OBSERVED','RUNNING','NOT_RUNNING','UNLOADED','UNKNOWN'].includes(d.job)||!['NOT_OBSERVED','TUN','NOT_TUN','UNKNOWN'].includes(d.tun))return false;
 const matched=typeof d.reason==='string'&&own(diagnosticReasons,d.reason)&&diagnosticReasons[d.reason][0]===d.stage;
 if(success)return d.outcome==='SUCCEEDED'&&d.stage==='NONE'&&d.reason==='NONE';
 if(d.outcome==='SUCCEEDED')return d.stage==='DIAGNOSTIC'&&d.reason==='RECEIPT_WRITE_FAILED'&&d.receipt==='FAILED';
 if(d.outcome==='UNKNOWN')return d.stage==='UNKNOWN'&&d.reason==='UNKNOWN';
 if(d.outcome==='CANCELLED')return d.reason==='CANCELLED'&&d.stage!=='NONE';
 return matched&&d.stage!=='UNKNOWN'&&d.reason!=='NONE'&&d.reason!=='RECEIPT_WRITE_FAILED';
}
function serviceRecoveryWarning(data,operation) {
 if(!own(data,'diagnostics'))return '';
 const d=data.diagnostics;
 if(!validDiagnostics(d,operation,true))return '警告：成功响应的诊断数据无效，未采用网络恢复结论。';
 return d.restoration==='FAILED'||d.restoration==='UNKNOWN'?'警告：服务操作已完成，但先前网络恢复'+(d.restoration==='FAILED'?'检查失败':'未能确认')+'。已有诊断证据保留；恢复差异本身不阻止下次启动。请核实路由与 DNS。':'';
}
function serviceFeedback(code,data,operation) {
 if(typeof code!=='string'||!serviceErrorCodes.has(code))return '';
 const coarse='错误码：'+code;
 if(!own(data,'diagnostics'))return coarse+'\n助手未提供详细原因；可能为旧版助手\n下一步：核实当前服务与配置状态；现有证据不足以确定原因。';
 const d=data.diagnostics;
 if(!validDiagnostics(d,operation,false))return coarse+'\n诊断数据无效，未采用详细原因或恢复结论。\n下一步：核实助手与当前服务状态。';
 const action={START:'启动',RELOAD:'重载',STOP:'停止'}[d.operation];
 const result=d.outcome==='SUCCEEDED'?action+'操作已成功，但诊断保存失败，应用状态仍须核实（SUCCEEDED）。':d.outcome==='CANCELLED'?'操作已取消。':d.outcome==='UNKNOWN'?'操作结果未知。':'操作失败。';
 const reason=d.reason==='CANCELLED'?'操作已取消':diagnosticReasons[d.reason][1];
 const observations={NOT_OBSERVED:'未观察',RUNNING:'运行中',NOT_RUNNING:'未运行',UNLOADED:'未加载',UNKNOWN:'未知',TUN:'已接管',NOT_TUN:'未接管'};
 return [coarse,result,'阶段：'+diagnosticStages[d.stage][0]+'；原因：'+reason,'回滚：'+recoveryLabels[d.rollback]+'；网络恢复：'+recoveryLabels[d.restoration],'快照清理：'+recoveryLabels[d.cleanup]+'；诊断回执：'+receiptLabels[d.receipt],'作业观察：'+observations[d.job]+'；TUN 观察：'+observations[d.tun],'下一步：'+diagnosticStages[d.stage][1]+(d.restoration==='FAILED'||d.restoration==='UNKNOWN'?' 网络恢复尚未确认，请核实路由与 DNS。':'')+(d.operation==='RELOAD'?' 新启动回滚不代表旧 VPN 已恢复。':'')].join('\n');
}
async function api(path, options = {}) {
 const session=sessionGeneration;
 const startupMutation=Boolean(options.method&&options.method!=='GET'&&(/^\/service\/(start|stop|reload)$/.test(path)||['/config','/nodes','/groups/selection','/nodes/selection','/rules','/profiles/switch','/import/commit'].includes(path)));
 const trace=startupMutation&&typeof startupBegin==='function'?startupBegin(!path.startsWith('/service/')):null;if(trace)trace.mutation=true;
 const headers = new Headers(options.headers || {});
 if (options.body !== undefined) { headers.set('Content-Type','application/json'); options.body = JSON.stringify(options.body); }
 if (options.method && options.method !== 'GET') headers.set('X-CSRF-Token',csrf);
 let response,data;try{response=await fetch('/api/v1'+path, { ...options, headers, credentials:'same-origin', cache:'no-store', redirect:'error' });data=await response.json();}catch(error){if(trace&&startupCurrent(trace))startupResult({startup_operation:{timeline_schema:1,operation_id:trace.id,availability:trace.id?'AVAILABLE':'UNAVAILABLE'}},trace);throw new Error(trace?'服务器未返回有效数据；已发送的服务操作不会自动重试。':'服务器未返回有效数据。');}
 if(session!==sessionGeneration&&(startupMutation||path==='/status'||path==='/helper/status'))throw new Error('会话已更换，忽略旧操作响应。');
 if(trace&&!startupCurrent(trace))throw new Error('操作已更换，忽略旧操作响应。');
 if(trace&&session===sessionGeneration)startupResult(data,trace);
 if (!response.ok) {
  if (response.status === 401 && path !== '/login'&&session===sessionGeneration) showLogin();
  const serviceOperation={'/service/start':'START','/service/reload':'RELOAD','/service/stop':'STOP'}[path];
  const feedback=serviceOperation?serviceFeedback(data.error,data,serviceOperation):'';
  const error=new Error(feedback || (typeof data.error==='string'&&own(messages,data.error)?messages[data.error]:'操作失败（'+response.status+'）。请检查本机配置或命令行状态。')); error.code=data.error; error.details=data; throw error;
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
 if(data.changed){invalidateNodes();invalidateGroups();clearProfiles();invalidateRules();}
 const result=data.apply_status;
 const applied=result==='APPLIED';
 const failed=data.changed && !applied && result!=='SAVED_STOPPED';
 const text=!data.changed?'配置未变化，没有重新连接。':applied?'配置已保存并自动生效。':result==='SAVED_STOPPED'?'配置已保存；VPN 未运行，下次启动时生效。':'配置已保存，但自动应用未完成；配置尚未确认生效，当前连接状态以概览为准。';
 const detail=failed?serviceFeedback(data.apply_error,data,'RELOAD'):'';
 const warning=applied?serviceRecoveryWarning(data,'RELOAD'):'';
 notice(text+(detail?'\n'+detail:data.apply_error&&typeof data.apply_error==='string'&&own(messages,data.apply_error)?' '+messages[data.apply_error]:'')+(warning?'\n'+warning:''),Boolean(failed||warning));
}
async function refreshAfterSave(refresh) {
 const session=sessionGeneration;
 const savedNotice=$('notice').textContent;
 const savedFailure=$('notice').classList.contains('failure');
 let warning='';
 try { if(refresh) await refresh(); } catch(e) { warning='列表刷新失败，可稍后重新读取。'; }
 if(session!==sessionGeneration||!csrf)return;
 await status();
 if(session!==sessionGeneration||!csrf)return;
 if (!serviceState) warning+=(warning?' ':'')+'服务状态刷新失败，请稍后确认。';
 notice(savedNotice+(warning?' '+warning:''),savedFailure||Boolean(warning));
}
function notice(text, failure = false) { $('notice').style.whiteSpace='pre-line'; $('notice').textContent=text; $('notice').classList.toggle('failure',failure); $('notice').hidden=!text; }
async function operation(label, fn) {
 if (busy) return;
 const session=sessionGeneration;
 busy=true; const enabled=[...document.querySelectorAll('button')].filter(b=>!b.disabled&&b.id!=='startup-copy'&&b.id!=='startup-refresh'); enabled.forEach(b=>b.disabled=true); renderExtraButtons();notice(label+'，请稍候…');
 // An invalidated probe batch may release its UI immediately. Its late finally
 // must never unlock a newer operation or restore that operation's buttons.
 const finish=()=>{if(finishOperation!==finish)return;finishOperation=null;busy=false;enabled.forEach(b=>{if(b.isConnected)b.disabled=false;});if(!etag)$('save-config').disabled=true;$('run-update').disabled=!updateAvailable;renderServiceButtons();renderImportButtons();renderExtraButtons();};
 finishOperation=finish;
 try { await fn(); if (finishOperation===finish&&session===sessionGeneration&&$('notice').textContent === `${label}，请稍候…`) notice(`${label}已完成。`); } catch (e) { if(finishOperation===finish&&session===sessionGeneration)notice(e.message, true); }
 finally { finish(); }
}
function showLogin() {if(typeof startupCancel==='function')startupCancel(true);if(finishOperation)finishOperation();polling=false;recordsResetFilters();cancelRecords(true);sessionGeneration++;invalidateRules();invalidateGroups();clearProfiles();invalidateNodes();clearImportSecrets();serviceState=null;renderServiceButtons();csrf='';etag='';clearUpdate();$('yaml-editor').value='';$('yaml-editor').disabled=true;$('profile-name').value='';$('nodes-list').replaceChildren();$('groups-list').replaceChildren();nodesLoaded=false;$('nodes-search').value='';$('nodes-count').textContent='尚未读取';$('groups-count').textContent='尚未读取';$('update-result').textContent='尚未检查。';$('console-view').hidden=true;$('login-view').hidden=false;$('password').value='';renderExtraButtons();closeDrawer();}
async function enterConsole(data) {csrf=data.csrf;if(typeof startupResume==='function')startupResume();$('password').value='';$('login-view').hidden=true;$('console-view').hidden=false;$('login-error').textContent='';if(currentView==='connections')openRecords();await status();}
$('login-form').addEventListener('submit',async event=>{event.preventDefault();const button=event.submitter;button.disabled=true;$('login-error').textContent='正在验证…';try{await enterConsole(await api('/login',{method:'POST',body:{username:$('username').value,password:$('password').value}}));}catch(e){$('password').value='';$('login-error').textContent=e.message;}finally{button.disabled=false;}});
$('logout').addEventListener('click',()=>{cancelRecords(true);return operation('退出登录',async()=>{await api('/logout',{method:'POST',body:{}});showLogin();});});
async function status() {
 if (!csrf || polling) return;
 const session=sessionGeneration,owner={};polling=owner;
 try {
  const state=await api('/status');if(session!==sessionGeneration||!csrf)return;serviceState=state;renderServiceButtons();
  const transport=state.transport==='network-http'?'网络 HTTP 无 TLS · 凭据与会话未经传输加密':state.transport==='loopback-http'?'回环 HTTP 无 TLS':'传输方式未知';
  $('transport-footer').textContent=transport;$('transport-badge').textContent=transport;
  const unavailable=state.availability!=='AVAILABLE';
  const title=unavailable?'状态不可用':state.running?'VPN 已启动':state.loaded?'VPN 已加载 · 未运行':'VPN 未启动';
  syncServiceUI(state,title);
  $('connection-detail').textContent=unavailable?'无法读取服务管理器。请在本机终端检查状态。':'状态来自本机服务管理器；尚未执行网络连通性验证。';
  $('pending').hidden=!state.pendingReload;$('version').textContent=state.version;
  $('helper-detail').textContent='正在检查特权助手…';try{const helper=await api('/helper/status');if(session!==sessionGeneration||!csrf)return;$('helper-detail').textContent=helper.available?'已连接受限特权助手，系统操作无需反复授权。':helper.code==='HELPER_CONFIG_MISMATCH'?messages.HELPER_CONFIG_MISMATCH:'请在本机终端运行 anytls helper install，完成一次系统授权。';}catch{if(session!==sessionGeneration||!csrf)return;$('helper-detail').textContent='无法连接助手，请在终端检查 anytls helper status。';}
  $('pending-detail').textContent=state.pendingReload?'配置尚未确认生效。网页保存会自动尝试应用；失败后可重试，外部文件更改请手动重载。':state.pendingKnown?'本次控制台操作后未检测到配置更改。':'尚未确认当前快照与磁盘配置是否一致；必要时明确重载。';
 } catch(e){if(csrf&&session===sessionGeneration){serviceState=null;renderServiceButtons();syncServiceUI(null,'状态未知');$('connection-detail').textContent='服务状态读取失败，请在本机检查；之前的状态不再作为当前依据。';$('pending').hidden=true;$('version').textContent='—';$('pending-detail').textContent='状态读取失败，无法确认配置是否生效。';$('helper-detail').textContent='状态未确认，请在本机检查特权助手。';notice(e.message,true);}}
 finally{if(polling===owner)polling=false;}
}
setInterval(()=>{if(!document.hidden)status();},3000);
function closeDrawer(){document.body.classList.remove('drawer-open');$('drawer-shade').hidden=true;$('drawer-toggle').setAttribute('aria-expanded','false');}
$('drawer-toggle').onclick=()=>{const open=!document.body.classList.contains('drawer-open');document.body.classList.toggle('drawer-open',open);$('drawer-shade').hidden=!open;$('drawer-toggle').setAttribute('aria-expanded',String(open));};
$('drawer-shade').onclick=closeDrawer;document.addEventListener('keydown',e=>{if(e.key==='Escape')closeDrawer();});
for(const button of document.querySelectorAll('[data-view]'))button.onclick=()=>{
 currentView=button.dataset.view;cancelRecords(true);if(typeof startupCancel==='function'){if(currentView==='overview')startupResume();else startupCancel();}if(currentView==='connections')openRecords();for(const section of document.querySelectorAll('.view'))section.hidden=section.id!=='view-'+currentView;
 for(const nav of document.querySelectorAll('[data-view]')){nav.classList.toggle('active',nav===button);if(nav===button)nav.setAttribute('aria-current','page');else nav.removeAttribute('aria-current');}
 $('page-title').textContent=button.textContent.trim();closeDrawer();notice('');
 if(currentView==='nodes'&&!busy)loadNodes().catch(e=>notice(e.message,true));
 if(currentView==='config'){loadSubscription();if(!busy)loadProfiles().catch(e=>notice(e.message,true));}
 if(currentView==='groups')loadGroups().catch(e=>notice(e.message,true));
};
for(const button of document.querySelectorAll('[data-service]'))button.onclick=()=>{
 const action=button.dataset.service;
 if(action==='reload'&&!confirm('重载会停止并重新启动 VPN，期间可能短暂断网。继续？'))return;
 operation(button.textContent,async()=>{const data=await api('/service/'+action,{method:'POST',body:{confirm_insecure:action!=='stop'}});await status();const warning=serviceRecoveryWarning(data,action.toUpperCase());if(warning)notice(button.textContent+'已完成。\n'+warning,true);});
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
async function loadNodes(){const request=++nodesRequest,session=sessionGeneration;cancelProbes();nodesEtag='';renderExtraButtons();let result;try{result=await api('/nodes');}catch(e){if(request===nodesRequest&&session===sessionGeneration)invalidateNodes();throw e;}if(request!==nodesRequest||session!==sessionGeneration||!csrf)return;if(!Array.isArray(result.nodes)||typeof result.etag!=='string'||!result.etag){invalidateNodes();throw new Error('节点列表响应不完整，请重新读取。');}const target=$('nodes-list');target.replaceChildren();nodesLoaded=true;nodesEtag=result.etag;
 for(const n of result.nodes){const row=element('article',undefined,'item'),content=element('div',undefined,'item-content');row.nodeSearch=n;row.classList.toggle('selected',Boolean(n.selected));const heading=element('div',undefined,'node-heading');heading.append(element('strong',n.name),element('span',n.type,'badge'));if(n.selected)heading.append(element('span','当前启动节点','badge current'));if(n.skipVerify)heading.append(element('span','跳过证书校验 · 风险','badge risky'));content.append(heading,element('p',n.server+':'+n.port+' · '+(n.hasPassword?'已配置密码':'未配置密码'),'node-meta'));row.append(content);const choose=element('button',n.selected?'当前启动节点':'设为启动节点');choose.disabled=!n.selectable||n.selected;choose.onclick=()=>operation('保存节点选择',async()=>{const saved=await api('/nodes/selection',{method:'POST',body:saveBody({name:n.name})});savedFeedback(saved);await refreshAfterSave(loadNodes);}); row.append(choose);
 const probes=element('div',undefined,'node-probes'),probeResult=element('p','尚未测速','probe-result');probeResult.setAttribute('role','status');probeResult.dataset.latency='unknown';row.probeResult=probeResult;row.probeName=n.name;
 for(const [mode,label] of [['https','代理延迟'],['tcp','TCP延迟']]){const button=element('button',label);button.type='button';button.dataset.probe=mode;button.onclick=()=>startProbes([row],mode);probes.append(button);}probes.append(probeResult);row.append(probes);
 const edit=element('details');const summary=element('summary','编辑节点参数');edit.append(summary);
 const form=element('form');form.className='node-form';
 const inputs={};for(const [key,title,value,type] of [['server','服务器',n.server,'text'],['port','端口',n.port,'number'],['sni','SNI',n.sni||'','text'],['password','新节点密码（留空保留）','','password']]){const label=element('label',title);const input=element('input');input.type=type;input.value=value;input.autocomplete=key==='password'?'new-password':'off';input.setAttribute('aria-label',title);if(key==='port'){input.min='1';input.max='65535';}if(key==='server'||key==='port')input.required=true;label.append(input);form.append(label);inputs[key]=input;}
 const submit=element('button','保存节点参数');submit.type='submit';form.append(submit);form.onsubmit=event=>{event.preventDefault();operation('保存节点参数',async()=>{const saved=await api('/nodes',{method:'PUT',headers:{'If-Match':result.etag},body:saveBody({name:n.name,server:inputs.server.value,port:Number(inputs.port.value),sni:inputs.sni.value,password:inputs.password.value})});inputs.password.value='';savedFeedback(saved);await refreshAfterSave(loadNodes);});};edit.append(form);row.append(edit);target.append(row);}filterNodes();renderExtraButtons();}
$('refresh-nodes').onclick=()=>operation('刷新节点',loadNodes);
function invalidateGroups(){groupsRequest++;groupsEtag='';$('groups-list').replaceChildren();$('groups-count').textContent='尚未读取';}
async function loadGroups(){
 const request=++groupsRequest,session=sessionGeneration;groupsEtag='';$('groups-list').replaceChildren();$('groups-count').textContent='正在读取…';
 const current=()=>request===groupsRequest&&session===sessionGeneration&&Boolean(csrf);
 let result;try{result=await api('/groups');}catch(e){if(current()){invalidateGroups();throw e;}return;}
 if(!current())return;
 if(!Array.isArray(result.groups)||typeof result.etag!=='string'||!result.etag){invalidateGroups();throw new Error('策略组响应不完整，请重新读取。');}
 groupsEtag=result.etag;const target=$('groups-list');$('groups-count').textContent=result.groups.length+' 个分组';
 if(!result.groups.length){target.append(element('p','没有策略分组。直接在节点页选择启动节点，或在 YAML 中添加分组。','empty-state'));return;}
 for(const g of result.groups){
  const row=element('article',undefined,'item'),content=element('div',undefined,'item-content');content.append(element('strong',g.name),element('p',g.valid?'配置出口：'+g.resolved:'当前选择无效，请修复配置'));
  const select=element('select');select.setAttribute('aria-label',g.name+'的选择');for(const name of g.choices||[]){const option=element('option',name);option.value=name;option.selected=name===g.selected;select.append(option);}
  const save=element('button','保存选择');save.dataset.groupSave='';save.disabled=busy;save.onclick=()=>{if(!current()||groupsEtag!==result.etag)return;operation('保存分组',async()=>{if(!current()||groupsEtag!==result.etag)return;const saved=await api('/groups/selection',{method:'POST',headers:{'If-Match':result.etag},body:saveBody({group:g.name,choice:select.value})});if(session!==sessionGeneration||!csrf)return;savedFeedback(saved);await refreshAfterSave(loadGroups);});};
  row.append(content,select,save);target.append(row);
 }
}
let rulesRequest=0, rulesSnapshot=null, ruleCommitting=false;
function invalidateRules(){rulesRequest++;rulesSnapshot=null;$('rule-form').hidden=true;$('rule-form').reset();$('rule-target').replaceChildren();$('rule-set').replaceChildren();$('rule-preview').textContent='';$('rule-feedback').textContent='';$('rules-list').replaceChildren();renderRuleButtons();}
async function loadRules(open=false){
 invalidateRules();const request=rulesRequest,session=sessionGeneration;
 let data;try{data=await api('/rules');}catch(error){if(request===rulesRequest&&session===sessionGeneration&&csrf)throw error;return;}if(request!==rulesRequest||session!==sessionGeneration||!csrf)return;
 if(!Array.isArray(data.rules)||!Array.isArray(data.targets)||!Array.isArray(data.rule_sets)||typeof data.etag!=='string'||!data.etag)throw new Error('规则响应不完整，请重新读取。');
 rulesSnapshot={...data,request,session};$('rules-list').replaceChildren(...data.rules.map(rule=>element('li',rule)));
 if(!data.rules.length)$('rules-list').append(element('li','没有分流规则。'));
 if(open){if(!data.editable){$('rule-feedback').textContent=messages.RULE_EDIT_UNSUPPORTED;return;}
  for(const name of data.targets){const option=element('option',name);option.value=name;$('rule-target').append(option);}
  for(const name of data.rule_sets){const option=element('option',name);option.value=name;$('rule-set').append(option);}
  $('rule-index').max=String(data.rules.length);$('rule-form').hidden=false;rulePreview();$('rule-type').focus();
 }
}
function renderRuleButtons(){
 $('save-rule').disabled=busy||ruleCommitting||!csrf||!rulesSnapshot||rulesSnapshot.request!==rulesRequest||rulesSnapshot.session!==sessionGeneration||$('rule-type').value==='RULE-SET'&&!$('rule-set').value;
}
function ruleValue(){return $('rule-type').value==='RULE-SET'?$('rule-set').value:$('rule-type').value==='GEOIP'?$('rule-country').value:$('rule-value').value;}
function rulePreview(){
 const kind=$('rule-type').value,set=kind==='RULE-SET',geo=kind==='GEOIP',flag=geo||set;
 $('rule-value').hidden=set||geo;$('rule-value').required=!set&&!geo;$('rule-country').hidden=!geo;$('rule-country').required=geo;$('rule-set').hidden=!set;$('rule-set').required=set;
 $('rule-no-resolve').disabled=!flag;if(!flag)$('rule-no-resolve').checked=false;
 const index=$('rule-position').value==='index';$('rule-index-label').hidden=!index;$('rule-index').required=index;
 const value=ruleValue();
 $('rule-preview').textContent=kind+','+value+','+$('rule-target').value+($('rule-no-resolve').checked?',no-resolve':'')+' · '+(index?'放在现有第 '+$('rule-index').value+' 条前':$('rule-position').value==='first'?'放在最前面':'放在最终 MATCH 前');
 renderRuleButtons();
}
for(const id of ['rule-type','rule-value','rule-country','rule-set','rule-target','rule-position','rule-index','rule-no-resolve'])$(id).addEventListener('input',rulePreview);
$('load-rules').onclick=()=>operation('读取规则',()=>loadRules(false));
$('add-rule').onclick=()=>operation('读取新增规则选项',()=>loadRules(true));
$('cancel-rule').onclick=()=>{if(!ruleCommitting)invalidateRules();};
$('rule-form').onsubmit=event=>{
 event.preventDefault();const snapshot=rulesSnapshot;
 const current=()=>snapshot&&snapshot.request===rulesRequest&&snapshot.session===sessionGeneration&&Boolean(csrf);
 if(busy||!current())return;
 const body=saveBody({type:$('rule-type').value,value:ruleValue(),target:$('rule-target').value,no_resolve:$('rule-no-resolve').checked,position:$('rule-position').value});if(body.position==='index')body.index=Number($('rule-index').value)-1;
 return operation('保存单条规则',async()=>{
  if(!current())return;ruleCommitting=true;$('rule-fields').disabled=true;
  try{
   const data=await api('/rules',{method:'POST',headers:{'If-Match':snapshot.etag},body});if(!current())return;
   if(data.changed&&etag){etag='';$('save-config').disabled=true;$('editor-info').textContent='单条规则已保存。原始配置草稿已保留但版本过期，请先复制草稿，再重新读取并合并；不能直接覆盖保存。';}
   savedFeedback(data);const feedback=(data.inserted?'已新增规则。':'相同规则已存在，未插入、未重新连接。')+' '+$('notice').textContent;
   const savedFailure=$('notice').classList.contains('failure');
   $('rule-feedback').textContent=feedback;$('rule-form').hidden=true;
   // Save result remains visible even if later status/list refresh fails.
   const refreshRequest=rulesRequest+1,refreshed=()=>refreshRequest===rulesRequest&&snapshot.session===sessionGeneration&&Boolean(csrf);let warning='';
   try{await loadRules(false);}catch{warning=' 规则列表刷新失败，请重新读取。';}
   if(!refreshed())return;$('rule-feedback').textContent=feedback+warning;
   await status();if(!refreshed())return;
   if(!serviceState)warning+=' 服务状态刷新失败，请稍后确认。';
   $('rule-feedback').textContent=feedback+warning;notice(feedback+warning,savedFailure||Boolean(warning));
  }catch(error){if(current()){$('rule-feedback').textContent=error.message;if(error.code==='CONFIG_CONFLICT'){rulesRequest++;rulesSnapshot=null;$('save-rule').disabled=true;}}throw error;
  }finally{ruleCommitting=false;$('rule-fields').disabled=false;renderRuleButtons();}
 });
};
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
 $('append-subscription').disabled=busy||importMode!=='url';
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
function clearConfigDraft(){etag='';$('yaml-editor').value='';$('yaml-editor').disabled=true;$('save-config').disabled=true;renderExtraButtons();}
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
function previewImport(useSaved=false,scope='replace_config'){return operation('预览导入',async()=>{
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
 body.mode=scope;
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
 if(data.mode!==undefined&&data.mode!==scope)throw new Error('预览范围不匹配，请重新预览。');
 importPreview={token:data.token,etag:data.etag,generation,conversion,mode:scope};
 $('commit-import').textContent=scope==='append_nodes'?'备份并添加节点':'备份并导入';
 const summary=$('import-summary');
 for(const [title,value] of [['操作',scope==='append_nodes'?'仅添加节点 · 保留选择与分流':'替换完整配置'],...(scope==='append_nodes'?[['新增节点',data.added_nodes]]:[]),[scope==='append_nodes'?'保存后节点总数':'节点',data.nodes],[scope==='append_nodes'?'原有策略组（保留）':'策略组',data.groups],[scope==='append_nodes'?'原有规则（保留）':'规则',data.rules],['启动节点',data.selected||'未选择'],...(data.source_host?[['来源主机',data.source_host]]:[])])summary.append(element('dt',title),element('dd',String(value)));
 $('import-warning').textContent=scope==='append_nodes'?'仅添加通过校验的 AnyTLS 节点，忽略来源中的策略组、规则和提供器；保留当前选择、已保存订阅和分流。新节点需明确选择后使用。保存后运行中的 VPN 可能短暂重连。':data.warning||'';$('import-warning').hidden=!$('import-warning').textContent;$('import-preview').hidden=false;
 $('import-preview').querySelector(':scope > p.hint').textContent=scope==='append_nodes'?'仅导出不会保存或应用。确认添加只追加节点，不替换原有分流或订阅来源；重复节点不会重复添加。':'仅导出不会保存或应用。确认导入将备份并替换完整配置；运行中的 VPN 可能短暂断网并自动重连。';
 $('import-source-status').textContent='预览就绪，尚未保存。'+(conversion.skipped.length?' 已跳过 '+conversion.skipped.length+' 项，请查看清单。':'');notice(scope==='append_nodes'?'预览完成；仅添加节点，不保存此订阅来源，不改变选择或分流。':'预览完成；确认后才会备份并替换配置。');
 });}
$('preview-import').onclick=()=>previewImport();
$('refresh-subscription').onclick=()=>previewImport(true);
$('append-subscription').onclick=()=>previewImport(false,'append_nodes');
$('commit-import').onclick=()=>operation('备份并导入',async()=>{
 const preview=importPreview;if(!preview||preview.generation!==importGeneration)throw new Error('请先重新预览。');
 if(preview.mode==='append_nodes'&&!confirm('仅添加新的 AnyTLS 节点，保留当前选择、策略组、规则和已保存订阅。此链接不会保存。保存后运行中的 VPN 可能因自动应用短暂中断。继续？'))return;
 const acceptConversion=preview.conversion.warnings.length>0||preview.conversion.skipped.length>0;
 if(acceptConversion&&!confirm('将仅导入可用部分，上方已列出跳过内容及转换差异（可能改变分流或默认出口）。确认接受并备份导入？')){notice('已取消导入；预览仍可导出，尚未应用。');return;}
 // Consume each token once locally, including ambiguous network failures.
 importCommitting=true;const editorWasDisabled=$('yaml-editor').disabled;
 try {
 importPreview=null;renderImportButtons();let data;
 try{data=await api('/import/commit',{method:'POST',headers:{'If-Match':preview.etag},body:{token:preview.token,...(preview.mode==='append_nodes'?{confirm_append:true}:{confirm_replace:true}),confirm_insecure:true,...(acceptConversion?{accept_conversion:true}:{})}});}
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
function clearUpdate(text='尚未检查。') {
 updateAvailable=false;$('run-update').disabled=true;$('update-result').textContent=text;
}
function renderUpdate(data,install) {
 const statuses={UPDATED:'已安装完成',RESTART_REQUIRED:'已安装新版，需重启控制台',UPDATE_AVAILABLE:'发现可用更新',UP_TO_DATE:'磁盘程序已是最新版本'};
 if(!data||!['current','installed','latest'].every(k=>typeof data[k]==='string'&&data[k].trim())||!['available','sourceOnly','updated','restartRequired'].every(k=>typeof data[k]==='boolean')||!own(statuses,data.status)||install&&(data.status!=='UPDATED'||!data.updated||!data.restartRequired))throw new Error('更新响应不完整，安装结果待核对。请重新检查；不会自动回滚或重启。');
 updateAvailable=data.available&&!data.sourceOnly&&data.status==='UPDATE_AVAILABLE';
 const restart=data.restartRequired||data.current!==data.installed;
 const lines=[statuses[data.status],'当前控制台（内存）：'+data.current,'已安装程序（磁盘）：'+data.installed,'官方最新版本：'+data.latest];
 if(data.sourceOnly)lines.push('当前平台仅有源码或缺少完整预编译材料，不能安装；不会调用 Go 编译。');
 if(restart)lines.push('需要重启控制台才能运行已安装版本；本次未自动重启控制台，VPN 未重载。');
 if(install)lines.push('配置已保留；更新不调用特权助手或系统授权。');
 $('update-result').textContent=lines.join('\n');
}
function updateOperation(install) {
 if(busy||!csrf||install&&!updateAvailable)return;
 if(install&&!confirm('将下载并校验官方预编译程序，备份程序并保留配置；无需 Go、特权助手或系统授权。不会自动重启控制台或 VPN。继续？'))return;
 return operation(install?'安装更新':'检查新版本',async()=>{
  const session=sessionGeneration,current=()=>session===sessionGeneration&&Boolean(csrf);
  clearUpdate(install?'正在下载、校验并安装预编译更新…':'正在检查官方稳定版本…');
  try {
   const data=await api(install?'/update':'/update-check',install?{method:'POST',body:{confirm:true}}:{});
   if(!current())return;
   renderUpdate(data,install);
   notice(install?'预编译更新已安装；请查看版本与重启提示。':'版本检查完成，请查看下方结果。');
  } catch(error) {
   if(!current())return;
   clearUpdate((install?'安装未能确认完成。':'检查未完成。')+'\n'+(error.code==='UPDATE_UNAVAILABLE'?messages.UPDATE_UNAVAILABLE:error.message));
   throw error;
  }
 });
}
$('check-update').onclick=()=>updateOperation(false);
function renderExtraButtons(){
 renderRuleButtons();
 $('profile-name').disabled=busy||!csrf;
 for(const id of ['save-profile','refresh-profiles'])$(id).disabled=busy||!csrf;
 for(const button of document.querySelectorAll('[data-profile-action]'))button.disabled=busy||!csrf||!profilesEtag;
 $('copy-editor').disabled=busy||!csrf||!etag;
 for(const button of document.querySelectorAll('[data-group-save]'))button.disabled=busy||!csrf||!groupsEtag;
 $('probe-all').disabled=busy||!csrf||!nodesEtag||!$('nodes-list').querySelectorAll('article').length;
 for(const button of document.querySelectorAll('[data-probe]'))button.disabled=busy||!csrf||!nodesEtag;
 $('cancel-probes').hidden=!probeRunning;$('cancel-probes').disabled=!probeRunning;
}
function clearProfiles(){profilesRequest++;profilesEtag='';$('profiles-list').replaceChildren();$('profiles-status').textContent='尚未读取方案';renderExtraButtons();}
function displayTime(value){const date=new Date(value);return typeof value==='string'&&!Number.isNaN(date.getTime())?date.toLocaleString():'时间未知';}
async function loadProfiles(){
 const request=++profilesRequest,session=sessionGeneration;profilesEtag='';$('profiles-list').replaceChildren();$('profiles-status').textContent='正在读取方案…';renderExtraButtons();
 try{
  const data=await api('/profiles');if(request!==profilesRequest||session!==sessionGeneration||!csrf)return;
  if(!Array.isArray(data.profiles)||typeof data.etag!=='string'||!data.etag||data.profiles.some(p=>typeof p.id!=='string'||typeof p.name!=='string'||typeof p.current!=='boolean'))throw new Error('方案列表响应不完整，请刷新。');
  profilesEtag=data.etag;$('profiles-status').textContent=data.profiles.length+' 个方案 · 当前标记按磁盘配置判断';
  for(const profile of data.profiles){
   const row=element('article',undefined,'item'),content=element('div',undefined,'item-content'),heading=element('div',undefined,'node-heading');
   heading.append(element('strong',profile.name));if(profile.current)heading.append(element('span','当前配置','badge current'));
   content.append(heading,element('p','创建于 '+displayTime(profile.created_at)));row.append(content);
   const copy=element('button','复制为新方案');copy.dataset.profileAction='copy';copy.onclick=()=>{if(busy)return;const name=prompt('新方案名称（复制此方案，不切换配置）：',profile.name+' 副本');if(name===null||!name.trim())return;operation('复制方案',async()=>{const session=sessionGeneration;await api('/profiles/copy',{method:'POST',body:{id:profile.id,name:name.trim()}});if(session!==sessionGeneration||!csrf)return;notice('方案已复制，未切换配置。');await loadProfiles();});};
   const change=element('button','切换');change.dataset.profileAction='switch';change.onclick=()=>switchProfile(profile.id);row.append(copy,change);$('profiles-list').append(row);
  }
 }catch(e){if(request===profilesRequest&&session===sessionGeneration){clearProfiles();$('profiles-status').textContent='方案状态未知，请刷新后再操作。';throw e;}}
 finally{renderExtraButtons();}
}
$('refresh-profiles').onclick=()=>operation('刷新方案',loadProfiles);
$('save-profile').onclick=()=>{if(busy)return;const name=$('profile-name').value.trim();if(!name){notice('请输入新方案名称。',true);return;}return operation('保存磁盘配置为方案',async()=>{const session=sessionGeneration;await api('/profiles',{method:'POST',body:{name}});if(session!==sessionGeneration||!csrf)return;$('profile-name').value='';notice('磁盘上的当前配置已保存为方案；未保存编辑未包含，也未切换 VPN。');await loadProfiles();});};
function invalidateConfigViews(){invalidateRules();clearImportSecrets();clearConfigDraft();invalidateNodes();invalidateGroups();clearProfiles();$('rules-list').replaceChildren();}
function switchProfile(id){
 if(busy||!profilesEtag||!confirm('切换会备份旧配置，并清空编辑草稿和导入预览。运行中的 VPN 会自动应用，期间短暂断网重连；未运行时仅保存。继续？'))return;
 const expected=profilesEtag;
 return operation('切换方案',async()=>{
  const session=sessionGeneration,editor=$('yaml-editor'),editorDisabled=editor.disabled;editor.disabled=true;importCommitting=true;renderImportButtons();
  try{
   let data;try{data=await api('/profiles/switch',{method:'POST',headers:{'If-Match':expected},body:{id,confirm_insecure:true,confirm_replace:true}});}catch(error){
    if(session!==sessionGeneration||!csrf)return;
    if(error.code==='PROFILE_STATE_UNCERTAIN'||!error.code){invalidateConfigViews();serviceState=null;renderServiceButtons();syncServiceUI(null,'状态未知');$('editor-info').textContent=messages.PROFILE_STATE_UNCERTAIN;}
    else clearProfiles();throw error;
   }
   if(session!==sessionGeneration||!csrf)return;
   invalidateConfigViews();$('editor-info').textContent='方案已切换；编辑草稿已清空，需要编辑时请重新打开配置。';savedFeedback(data);await refreshAfterSave(async()=>{await loadProfiles();await loadSubscription();});
  }finally{importCommitting=false;if(session===sessionGeneration&&etag)editor.disabled=editorDisabled;renderImportButtons();renderExtraButtons();}
 });
}
$('copy-editor').onclick=async()=>{
 if(busy||!etag||!csrf||!confirm('复制内容包含节点密码及编辑区未保存的草稿，不是磁盘版本。请勿公开分享。继续复制？'))return;
 const session=sessionGeneration,text=$('yaml-editor').value;
 try{if(!navigator.clipboard||!navigator.clipboard.writeText)throw new Error('clipboard unavailable');await navigator.clipboard.writeText(text);if(session===sessionGeneration&&csrf)notice('已复制编辑区配置文本（含节点密码及未保存草稿）；未保存或应用。');}
 catch{if(session!==sessionGeneration||!csrf)return;const editor=$('yaml-editor');editor.focus();editor.select();notice('浏览器未允许自动复制，尚未复制。已选中编辑区，请按 ⌘C / Ctrl+C 手动复制（含节点密码）。',true);}
};
function cancelProbes(){
 probeGeneration++;const batch=probeBatch;if(!batch)return;
 probeBatch=null;probeRunning=false;
 for(const [controller,timer] of batch.controllers){clearTimeout(timer);controller.abort();}batch.controllers.clear();
 for(const row of batch.rows)if(row.probeResult.dataset.pending==='true'){
  row.probeResult.textContent='测速已取消，未获得结果。';row.probeResult.dataset.pending='false';row.probeResult.dataset.latency='unknown';
 }
 batch.finish();renderExtraButtons();
}
function invalidateNodes(){nodesRequest++;cancelProbes();nodesEtag='';nodesLoaded=false;$('nodes-list').replaceChildren();$('nodes-count').textContent='尚未读取';renderExtraButtons();}
$('cancel-probes').onclick=()=>{cancelProbes();notice('已取消测速，不再测试后续节点。');};
$('probe-all').onclick=()=>startProbes([...$('nodes-list').querySelectorAll('article')],'https');
function startProbes(rows,mode){
 if(busy||!csrf||!nodesEtag||!rows.length)return;
 rows=rows.filter(row=>row.isConnected&&row.probeResult);if(!rows.length)return;
 const generation=++probeGeneration,session=sessionGeneration,expected=nodesEtag;
 const valid=()=>generation===probeGeneration&&session===sessionGeneration&&csrf&&expected===nodesEtag;
 return operation(rows.length>1?'并发测试全部代理延迟':'测试节点延迟',async()=>{
  const batch={rows,controllers:new Map(),finish:finishOperation};probeBatch=batch;probeRunning=true;
  const label=mode==='tcp'?'TCP 延迟':'代理延迟';let completed=0,next=0;
  for(const row of rows){row.probeResult.textContent=label+' · 等待测试…';row.probeResult.dataset.pending='true';row.probeResult.dataset.latency='pending';}
  renderExtraButtons();
  async function worker(){while(valid()&&next<rows.length){
   const row=rows[next++];if(!row.isConnected)continue;
   const output=row.probeResult;output.textContent=label+' · 正在测试…';
   const controller=new AbortController();let timedOut=false;
   const timer=setTimeout(()=>{timedOut=true;controller.abort();},8000);batch.controllers.set(controller,timer);
   try{
    const data=await api('/nodes/probe',{method:'POST',headers:{'If-Match':expected},body:{name:row.probeName,mode,confirm_insecure:true},signal:controller.signal});
    if(!valid()||!row.isConnected)return;
    if(data&&typeof data==='object'&&data.config_etag!==expected){invalidateNodes();notice('配置已改变，旧测速结果已丢弃。请刷新节点。',true);return;}
    if(!data||data.name!==row.probeName||data.mode!==mode||!['OK','FAILED','TIMEOUT','UNSUPPORTED'].includes(data.status)||data.status==='OK'&&(!Number.isFinite(data.latency_ms)||data.latency_ms<0))throw new Error('测速响应不完整，未获得可靠结果。');
    const ms=data.status==='OK'?Math.round(data.latency_ms):null,states={FAILED:'失败',TIMEOUT:'超时',UNSUPPORTED:'不支持'};
    output.dataset.latency=ms!==null?(ms<200?'fast':ms<500?'medium':'slow'):'failed';
    output.textContent=label+' · '+(ms!==null?ms+' ms':states[data.status])+' · '+displayTime(data.checked_at)+(data.risk_insecure?' · 跳过证书校验风险':'');completed++;
   }catch(error){
    if(!valid()||!row.isConnected)return;
    if(error.code==='CONFIG_CONFLICT'||error.code==='PROFILE_CONFLICT'){invalidateNodes();notice('配置已改变，请刷新节点后重新测速。',true);return;}
    output.dataset.latency='failed';output.textContent=label+' · '+(timedOut?'超时（8 秒），未获得结果。':'失败 · '+error.message);
   }finally{clearTimeout(timer);batch.controllers.delete(controller);if(valid()&&row.isConnected)output.dataset.pending='false';}
  }}
  try{
   await Promise.all(Array.from({length:Math.min(8,rows.length)},()=>worker()));
   if(valid())notice('延迟测试结束：收到 '+completed+' / '+rows.length+' 个结果；未切换节点或 VPN。');
  }finally{if(probeBatch===batch){probeBatch=null;probeRunning=false;renderExtraButtons();}}
 });
}
// One displayed page, three fixed binding/cursor anchors; no page/run cache.
let recordsEpoch=0,recordsOwner=null,recordsTimer=null,recordsBinding=null,recordsPrevious=null,recordsAfter='0',recordsPageAfter='0',recordsNext='0',recordsHigh='0',recordsManual=false,recordsMore=false,recordsStopped=false;
const recordsLimit=100;
const recordsErrors={INVALID_REQUEST:'分页参数无效。',FORBIDDEN:'记录读取的用户或来源未获授权。',BUSY:'记录读取忙碌；文件操作结束前不会释放名额。',STALE_GENERATION:'历史身份已失效，已清空归属；请明确选择最新历史重新发现。',TELEMETRY_UNAVAILABLE:'连接记录不可用；这不等于没有流量。',STORE_INVALID:'历史存储未通过校验；未采用任何记录。',UNSUPPORTED:'当前助手不支持连接记录；不会安装、更新或重载。'};
function recordsVisible(){return Boolean(csrf)&&currentView==='connections'&&!document.hidden&&!$('console-view').hidden;}
function recordsResetFilters(){
 $('records-search').value='';$('records-protocol').value='all';$('records-exit').value='all';
}
function recordsFilter(){
 const query=$('records-search').value.trim().toLocaleLowerCase(),protocol=$('records-protocol').value,exit=$('records-exit').value;
 const rows=$('records-rows').children;let matched=0;
 for(const row of rows){row.hidden=!(row.textContent.toLocaleLowerCase().includes(query)&&(protocol==='all'||row.dataset.protocol===protocol)&&(exit==='all'||row.dataset.exit===exit));if(!row.hidden)matched++;}
 $('records-count').textContent='本页匹配 '+matched+' / 已加载 '+rows.length+' 条';
 if(rows.length){$('records-empty').hidden=matched>0;$('records-empty').textContent='本页没有匹配记录。请清除筛选，或翻页查看其他历史；这不是无流量的证明。';}
 $('records-clear').disabled=!query&&protocol==='all'&&exit==='all';
}
for(const id of ['records-search','records-protocol','records-exit'])$(id).addEventListener(id==='records-search'?'input':'change',recordsFilter);
$('records-clear').onclick=()=>{recordsResetFilters();recordsFilter();$('records-search').focus();};
function recordsEmpty(text){
 $('records-rows').replaceChildren();$('records-empty').hidden=false;$('records-empty').textContent=text;recordsFilter();
}
function recordsClear(){
 recordsBinding=null;recordsPrevious=null;recordsAfter='0';recordsPageAfter='0';recordsNext='0';recordsHigh='0';recordsMore=false;
 $('records-status').textContent='尚未读取；归属与连续性 UNKNOWN，不代表没有流量。';
 recordsEmpty('尚未读取。点击“最新历史”读取；这不是无流量的证明。');$('records-identity').textContent='';$('records-coverage-detail').textContent='尚未取得覆盖证据。';$('records-gap').textContent='连续性：UNKNOWN · DNS：UNKNOWN';recordsButtons();
}
function cancelRecords(clear=true){
 recordsEpoch++;if(recordsTimer!==null){clearTimeout(recordsTimer);recordsTimer=null;}
 const owner=recordsOwner;recordsOwner=null;if(owner){clearTimeout(owner.timeout);owner.controller.abort();}
 if(clear)recordsClear();recordsButtons();
}
function recordsButtons(){
 const enabled=recordsVisible()&&!recordsStopped&&!recordsOwner;
 $('records-results').setAttribute('aria-busy',String(Boolean(recordsOwner)));
 $('records-latest').disabled=!recordsVisible();
 $('records-prior').disabled=!enabled||!recordsPrevious;
 $('records-start').disabled=!enabled||!recordsBinding;
 $('records-back').disabled=!enabled||!recordsBinding||recordsPageAfter==='0';
 $('records-next').disabled=!enabled||!recordsBinding||!recordsMore;
}
function recordsSame(a,b){return a&&b&&a.instance_id===b.instance_id&&a.generation===b.generation&&a.manifest_id===b.manifest_id;}
function recordsTakeBinding(p){return {instance_id:p.instance_id,generation:p.generation,manifest_id:p.manifest_id};}
function recordsValidBinding(b){return b&&/^[0-9a-f]{32}$/.test(b.instance_id)&&/^[0-9a-f]{32}$/.test(b.generation)&&/^[0-9a-f]{64}$/.test(b.manifest_id);}
function recordsDecimal(s){return typeof s==='string'&&/^(0|[1-9][0-9]*)$/.test(s)&&BigInt(s)<=18446744073709551615n;}
function recordsRender(p,after){
 recordsAfter=after;recordsPageAfter=after;recordsNext=p.next_after;recordsHigh=p.high_water_seq;recordsMore=p.has_more;recordsPrevious=p.previous_binding;
 const status=$('records-status');status.replaceChildren();
 status.append(element('span',recordsManual?'手动历史':'最新已记录历史','records-mode'));
 for(const [label,value] of [['采集',p.collection],['时效',p.freshness],['来源',p.provenance_status]])status.append(element('span',label+' '+(value??'UNKNOWN'),'badge records-status-badge'));
 status.append(element('span','更新于 '+displayTime(p.timestamp)+' · 非当前 VPN 状态','hint'));
 $('records-identity').textContent='Run '+p.instance_id+' · generation '+p.generation+' · manifest '+p.manifest_id+' · runtime '+p.runtime_sha256+' · '+p.history_kind;
 const coverage=p.coverage;
 $('records-gap').textContent=(coverage.gap?'GAP · 记录有缺口 / 不确定性':'覆盖仍不完整')+' · 完整收尾未验证／连续性 UNKNOWN · DNS：UNKNOWN'+(p.closed?' · CLOSED 仅为最后保存的停止采集状态，不代表完整收尾或成功。':'');
 $('records-coverage-detail').textContent='已知丢失 '+(coverage.lost_total??'UNKNOWN')+' · loss epoch '+(coverage.loss_epoch??'UNKNOWN')+' · pending '+(p.pending??'UNKNOWN')+(coverage.counter_saturated?' · 计数已饱和':'')+' · 丢失原因 '+Object.entries(coverage.loss_reasons).map(([k,v])=>k+':'+(v??'UNKNOWN')).join(' / ');
 const rows=[];
 const unknown=value=>value===null||value===undefined||value===''?'UNKNOWN':String(value);
 const destination=d=>d?unknown(d.host)+' / '+unknown(d.ip)+' : '+unknown(d.port)+' · '+unknown(d.host_source):'UNKNOWN';
 for(const record of p.records){
  const r=record.route,d=record.destination,row=element('tr');
  row.dataset.protocol=record.network;row.dataset.exit=r.evidence==='VERIFIED'&&r.terminal_kind==='DIRECT'?'direct':r.evidence==='VERIFIED'&&r.terminal_kind==='NODE'?'proxy':'unknown';
  const source=r.evidence==='VERIFIED'?(r.kind==='DEFAULT_SELECTED'?'默认选中（无 MATCH）':r.kind+' · 源序号 '+(r.source_index===null?'UNKNOWN':String(r.source_index+1)))+' · '+(r.condition?r.condition.value:'')+(r.rule_set?' · 集合 '+r.rule_set.label:''):'来源未知 · '+r.evidence;
  const path=r.group_path?r.group_path.map(edge=>edge.group+' → '+edge.selected).join(' / ')||'无策略组':'UNKNOWN';
  const terminal=row.dataset.exit==='direct'?'直连 · DIRECT':row.dataset.exit==='proxy'?unknown(r.final_node_label):'出口未知 · UNKNOWN';
  const cell=(label)=>{const td=element('td');td.dataset.label=label;row.append(td);return td;};
  const target=cell('目标 / 协议');target.append(element('strong',d.host||d.ip||'目标未知','records-target'),element('span',unknown(d.ip)+' : '+unknown(d.port),'records-secondary'),element('span',String(record.network).toUpperCase(),'badge'));
  const details=element('details',undefined,'records-detail');details.append(element('summary','查看来源与详情'));
  const dl=element('dl');
  for(const [label,value] of [['观察',record.hook+' / '+record.network],['目标来源',d.host_source],['原始目标 origin',destination(record.origin_destination)],['路由原始目标',destination(record.route_original_destination)],['规则来源',source],['来源 ID',unknown(r.source_id)],['规则集 SHA',r.rule_set?r.rule_set.sha256:'UNKNOWN'],['策略组路径',path],['配置目标',unknown(r.configured_target)],['最终节点',unknown(r.final_node_label)],['节点 ID',unknown(r.final_node_id)],['实际出口',unknown(r.outbound_tag)+' / '+unknown(r.outbound_type)],['证据',r.evidence+' / '+unknown(r.terminal_kind)],['选择代次',unknown(r.selection_generation)],['观察 ID',unknown(record.observation_id)],['状态边界','ROUTED · connected / active / duration / ended_at / error UNKNOWN']])dl.append(element('dt',label),element('dd',value));
  details.append(dl);target.append(details);
  cell('命中规则').append(element('span',source,'records-rule'));
  const exit=cell('出口');exit.append(element('strong',terminal),element('span',row.dataset.exit==='proxy'?'代理路由 · NODE':row.dataset.exit==='direct'?'直连路由选择':'未归类为直连或代理','records-secondary'));
  const time=cell('时间 / 状态');time.append(element('span',displayTime(record.observed_at)+' / '+record.seq,'records-time'),element('span','ROUTED','badge records-routed'),element('span','仅路由观察 · 非已连接','records-secondary'));
  rows.push(row);
 }
 $('records-rows').replaceChildren(...rows);$('records-empty').hidden=rows.length>0;
 $('records-empty').textContent='本页没有已提交的观察；不代表没有流量。可稍候刷新或查看上一 Run。';recordsFilter();recordsButtons();
}
function openRecords(){
 cancelRecords(true);recordsManual=false;recordsStopped=false;
 if(recordsVisible())recordsFetch(true);recordsButtons();
}
async function recordsFetch(discovery=false){
 if(!recordsVisible()||recordsStopped||recordsOwner)return;
 if(recordsTimer!==null){clearTimeout(recordsTimer);recordsTimer=null;}
 discovery=discovery||!recordsBinding;
 const epoch=recordsEpoch,auth=sessionGeneration,binding=recordsBinding?{...recordsBinding}:null,after=recordsAfter;
 const owner={controller:new AbortController(),timeout:null};recordsOwner=owner;
 recordsButtons();if(!$('records-rows').children.length)recordsEmpty('正在读取本页… 请稍候；没有记录不代表没有流量。');
 const current=()=>recordsOwner===owner&&epoch===recordsEpoch&&auth===sessionGeneration&&recordsVisible()&&!recordsStopped;
 const query=new URLSearchParams({after:discovery?'0':after,limit:String(recordsLimit)});
 if(!discovery&&binding)for(const [k,v]of Object.entries(binding))query.set(k,v);
 let nextDiscovery=false,rearm=true;
 owner.timeout=setTimeout(()=>owner.controller.abort(),5000);
 try{
  const response=await fetch('/api/v1/connections?'+query,{method:'GET',headers:{'X-AnyTLS-Origin':location.origin},credentials:'same-origin',cache:'no-store',redirect:'error',signal:owner.controller.signal});
  const p=await response.json();if(!current())return;if(owner.controller.signal.aborted)throw new Error('记录读取超时，未采用迟到响应。');
  if(!response.ok){
   if(response.status===401){showLogin();return;}
   const code=p&&p.error_code;
   if(code==='STALE_GENERATION'){recordsClear();recordsStopped=true;rearm=false;$('records-status').textContent=recordsErrors.STALE_GENERATION;return;}
   throw new Error(own(recordsErrors,code)?recordsErrors[code]:'连接记录不可用；未采用响应，不代表没有流量。');
  }
  if(p.schema_version!==1||!recordsValidBinding(p)||!recordsDecimal(p.next_after)||!recordsDecimal(p.high_water_seq)||!Array.isArray(p.records)||p.records.length>recordsLimit||typeof p.has_more!=='boolean'||!p.coverage||p.coverage.complete!==false||!p.dns||p.dns.status!=='UNKNOWN'||!['LAST_RECORDED','HISTORICAL'].includes(p.history_kind))throw new Error('记录响应无效，归属与连续性未知。');
  if(discovery){
   if(p.records.length||p.next_after!=='0')throw new Error('发现响应无效，未采用记录。');
   if(binding&&!recordsManual&&!recordsSame(binding,p)){
    recordsClear();recordsStopped=true;rearm=false;$('records-status').textContent='发现新的历史代次，旧页已清空。请选择“最新历史”确认查看；不会将旧记录重新归属。';return;
   }
   if(!binding){recordsBinding=recordsTakeBinding(p);recordsRender(p,'0');}
   nextDiscovery=false;
  }else{
   if(!recordsSame(binding,p)||!recordsSame(binding,recordsBinding)||after!==recordsAfter||p.records.length&&(p.records[0].seq!==(BigInt(after)+1n).toString()||p.records[p.records.length-1].seq!==p.next_after)||!p.records.length&&p.next_after!==after)throw new Error('历史身份或分页游标不匹配，未采用记录。');
   recordsRender(p,after);
   // Automatic latest-history paging still waits one second after completion.
   // Manual navigation polls its selected page, never silently jumps to latest.
   if(!recordsManual&&p.has_more)recordsAfter=p.next_after;
   nextDiscovery=!recordsManual;
  }
 }catch(error){
  if(current()){
   recordsEmpty('记录不可用，不代表没有流量。请稍候自动重试，或点击“最新历史”；持续失败请在本机检查助手与历史目录权限。');$('records-identity').textContent='';$('records-coverage-detail').textContent='本次读取未取得可信覆盖证据。';$('records-gap').textContent='GAP / UNKNOWN · DNS：UNKNOWN';
   $('records-status').textContent=owner.controller.signal.aborted?'记录读取超过 5 秒，现有状态未知。':error.message;
  }
 }finally{
  clearTimeout(owner.timeout);
  // An old finally cannot own the new controller/timer after cancel→restart.
  if(recordsOwner===owner){recordsOwner=null;if(epoch===recordsEpoch&&auth===sessionGeneration&&recordsVisible()&&!recordsStopped&&rearm)recordsTimer=setTimeout(()=>{recordsTimer=null;recordsFetch(nextDiscovery);},1000);recordsButtons();}
 }
}
function recordsNavigate(kind){
 const binding=kind==='prior'?recordsPrevious:recordsBinding;if(!binding)return;
 let after='0';
 if(kind==='next')after=recordsNext;
 if(kind==='back'){const n=BigInt(recordsPageAfter)-BigInt(recordsLimit);after=(n>0n?n:0n).toString();}
 cancelRecords(false);recordsBinding={...binding};recordsManual=true;recordsStopped=false;recordsAfter=after;
 recordsEmpty('正在读取所选历史页…');$('records-identity').textContent='';recordsFetch(false);
}
$('records-latest').onclick=openRecords;
for(const kind of ['prior','start','back','next'])$('records-'+kind).onclick=()=>recordsNavigate(kind);
document.addEventListener('visibilitychange',()=>{
 if(document.hidden){cancelRecords(false);recordsEmpty('读取已暂停。返回页面后重新读取；不代表没有流量。');$('records-identity').textContent='';$('records-status').textContent='页面已隐藏，读取已取消；状态 UNKNOWN。';$('records-gap').textContent='连续性：UNKNOWN · DNS：UNKNOWN';}
 else if(currentView==='connections'&&csrf){recordsFetch(true);}
});
$('run-update').onclick=()=>updateOperation(true);
(async()=>{try{await enterConsole(await api('/session'));}catch{showLogin();}})();

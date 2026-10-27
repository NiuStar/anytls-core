'use strict';
// ST1 fixed DTO projection. Unknown/missing/duplicate fields never reach display
// or clipboard; elapsed arithmetic uses BigInt and stays within each clock.
const startupEnums={
 result:'NOT_ATTEMPTED IN_PROGRESS SUCCEEDED FAILED CANCELLED UNKNOWN'.split(' '),
 source:'MANUAL_START MANUAL_STOP MANUAL_RELOAD SAVE_YAML SAVE_NODE SAVE_GROUP SAVE_SELECTION SAVE_RULE PROFILE_SWITCH IMPORT_COMMIT IMPORT_APPEND LEGACY_CONTROL'.split(' '),
 read:'OK NO_OPERATION UNSUPPORTED BUSY FORBIDDEN INVALID_REQUEST INVALID_TRACE HELPER_UNAVAILABLE HELPER_CONFIG_MISMATCH OPERATION_MISMATCH HISTORY_UNAVAILABLE UNAVAILABLE'.split(' '),
 segment:'PREFLIGHT STOP START ROLLBACK FINALIZE'.split(' '),
 event:'NONE OK FAILED CANCELLED UNKNOWN UNAVAILABLE SKIPPED GAP STALE IDENTITY_MISMATCH NO_CHANGE SAVED_STOPPED APPLIED APPLY_FAILED STATE_UNAVAILABLE'.split(' '),
 core:'NOT_ATTEMPTED NOT_OBSERVED OBSERVED STALE INVALID TRUNCATED IDENTITY_MISMATCH UNSUPPORTED HISTORY_UNAVAILABLE UNAVAILABLE'.split(' ')
};
const startupStages={
 WEB:'WEB_ACCEPT WEB_BOUND_STATUS WEB_WAIT_HELPER WEB_VERIFY_STATE WEB_FINISH'.split(' '),
 HELPER:'HELPER_ACCEPT HELPER_PREFLIGHT_CAPTURE HELPER_PREFLIGHT_COMPILE HELPER_PREFLIGHT_CA HELPER_PREFLIGHT_ENGINE_CHECK HELPER_RELOAD_JOB JOB_INITIAL SNAPSHOT_EXISTENCE SNAPSHOT_STAGE SNAPSHOT_APP_CONFIG_SELECTED SNAPSHOT_RULES SNAPSHOT_CA SNAPSHOT_IDENTITY RECEIPT_CAPTURE CONFIG_OUTBOUNDS_COMPILE PROXY_CHECK BASELINE_SERVER_ROUTES BASELINE_PUBLIC_ROUTE BASELINE_DNS BASELINE_WRITE BASELINE_REVALIDATE PLIST_CREATE_WRITE_CLOSE PLIST_LINT BOOTSTRAP READINESS_ROUND READINESS_JOB READINESS_PUBLIC_ROUTE READINESS_SERVER_ROUTES READINESS_PAUSE CORE_SNAPSHOT_CAPTURE HTTPS_ATTEMPT HTTPS_RETRY_JOB HTTPS_RETRY_PUBLIC_ROUTE HTTPS_RETRY_SERVER_ROUTES FINAL_JOB FINAL_PUBLIC_ROUTE FINAL_SERVER_ROUTES FINAL_DNS STOP_CAPTURE STOP_BASELINE BOOTOUT STOP_ROUND RESTORE_JOB RESTORE_PUBLIC_ROUTE RESTORE_SERVER_ROUTES RESTORE_DNS SNAPSHOT_REMOVE RECEIPT_FINISH RECEIPT_WRITE HELPER_FINAL_STATE HELPER_FINISH'.split(' '),
 CORE:'CORE_ENTER CORE_COMPILE CORE_COMPILE_MAP CORE_JSON_ENCODE CORE_MANIFEST_CA CORE_MANIFEST_DIGEST CORE_DISPATCH CORE_DECODE CORE_PIN_CA CORE_BOX_NEW CORE_OPEN_SINK CORE_BIND_RECORDS CORE_START CORE_WAIT CORE_CLOSE CORE_RECORDS_SHUTDOWN CORE_FINISH'.split(' ')
};
const stExact=(v,keys)=>v!==null&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).length===keys.split(' ').length&&keys.split(' ').every(k=>own(v,k));
const stID=v=>typeof v==='string'&&/^[a-f0-9]{32}$/.test(v);
const stDigest=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const stDec=v=>typeof v==='string'&&/^(0|[1-9][0-9]*)$/.test(v)&&v.length<=20&&BigInt(v)<=18446744073709551615n;
const stPositive=v=>stDec(v)&&v!=='0';
const stNullable=(v,f)=>v===null||f(v);
const stWall=v=>{if(typeof v!=='string'||!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{0,8}[1-9])?Z$/.test(v))return false;const d=new Date(v);return Number.isFinite(+d)&&d.toISOString().slice(0,19)===v.slice(0,19);};
const stStage=v=>Object.values(startupStages).some(a=>a.includes(v));
const stPhase=p=>stExact(p,'stage segment span_id began_at began_elapsed_ns')&&stStage(p.stage)&&startupEnums.segment.includes(p.segment)&&stPositive(p.span_id)&&stWall(p.began_at)&&stDec(p.began_elapsed_ns);
const stDiagnostics=d=>d===null||validDiagnostics(d,undefined,true)||validDiagnostics(d,undefined,false)||(stExact(d,'schema operation outcome stage reason rollback restoration cleanup receipt job tun')&&d.schema===1&&['START','RELOAD','STOP'].includes(d.operation)&&d.outcome==='SUCCEEDED'&&d.stage==='DIAGNOSTIC'&&d.reason==='RECEIPT_WRITE_FAILED'&&['rollback','restoration','cleanup'].every(k=>own(recoveryLabels,d[k]))&&own(receiptLabels,d.receipt)&&['NOT_OBSERVED','RUNNING','NOT_RUNNING','UNLOADED','UNKNOWN'].includes(d.job)&&['NOT_OBSERVED','TUN','NOT_TUN','UNKNOWN'].includes(d.tun));
function stParse(text) {
 if(typeof text!=='string'||new TextEncoder().encode(text).length>786432||text.includes('\0'))throw Error('INVALID_TRACE');
 // A small JSON grammar pass retains duplicate-key rejection before JSON.parse.
 let i=0;const ws=()=>{while(/[\x20\t\r\n]/.test(text[i]||'!'))i++;};
 function string(){const start=i++;while(i<text.length){if(text[i]==='"'){i++;const v=JSON.parse(text.slice(start,i));if(new TextEncoder().encode(v).length>128||v.includes('\0')||/[\uD800-\uDFFF]/u.test(v.replace(/[\uD800-\uDBFF][\uDC00-\uDFFF]/g,'')))throw Error('INVALID_TRACE');return v;}if(text[i]==='\\')i++;i++;}throw Error('INVALID_TRACE');}
 function value(depth){if(depth>24)throw Error('INVALID_TRACE');ws();const c=text[i];if(c==='"'){string();return;}if(c==='{'||c==='['){i++;ws();const end=c==='{'?'}':']',keys=new Set();let count=0;if(text[i]===end){i++;return;}for(;;){if(++count>1024)throw Error('INVALID_TRACE');if(c==='{'){ws();if(text[i]!=='"')throw Error('INVALID_TRACE');const key=string();if(keys.has(key))throw Error('INVALID_TRACE');keys.add(key);ws();if(text[i++]!==':')throw Error('INVALID_TRACE');}value(depth+1);ws();if(text[i]===end){i++;return;}if(text[i++]!==',')throw Error('INVALID_TRACE');}}const m=/^(true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(text.slice(i));if(!m)throw Error('INVALID_TRACE');i+=m[0].length;}
 value(0);ws();if(i!==text.length)throw Error('INVALID_TRACE');const result=JSON.parse(text);if(!stRead(result))throw Error('INVALID_TRACE');return result;
}
function stStream(s) {
 if(!stExact(s,'role clock_id origin_at elapsed_ns provenance current events generated_events dropped_events first_missing_seq gap retained_ranges terminal')||!own(startupStages,s.role)||!stID(s.clock_id)||!stWall(s.origin_at)||!stDec(s.elapsed_ns)||!stDec(s.generated_events)||!stDec(s.dropped_events)||typeof s.gap!=='boolean'||!Array.isArray(s.events)||!Array.isArray(s.retained_ranges)||s.retained_ranges.length>2)return false;
 const p=s.provenance;if(!stExact(p,'version git_revision dirty sha256 sha_kind execution_mapping')||!stNullable(p.version,v=>typeof v==='string'&&/^[A-Za-z0-9.+_-]{1,128}$/.test(v))||!stNullable(p.git_revision,v=>typeof v==='string'&&/^[a-f0-9]{40}$/.test(v))||!stNullable(p.dirty,v=>typeof v==='boolean')||!stNullable(p.sha256,stDigest)||p.sha_kind!==(p.sha256===null?'UNKNOWN':'FILE_BYTES')||p.execution_mapping!=='NOT_ATTESTED')return false;
 const n=BigInt(s.generated_events),d=BigInt(s.dropped_events),limit=BigInt(s.elapsed_ns),head=s.role==='HELPER'?768n:s.role==='CORE'?64n:32n,tail=s.role==='HELPER'?256n:0n;
 if(n-BigInt(s.events.length)!==d||d<0n||d>0n&&!s.gap||s.events.length>Number(head+tail)||s.first_missing_seq!==(d>0n?String(head+1n):null))return false;
 const ranges=[];if(n>0n){if(n<=head+tail||tail===0n)ranges.push({first:'1',last:String(n<head+tail?n:head+tail)});else ranges.push({first:'1',last:String(head)},{first:String(n-tail+1n),last:String(n)});}
 if(s.retained_ranges.length!==ranges.length||!ranges.every((r,i)=>stExact(s.retained_ranges[i],'first last')&&r.first===s.retained_ranges[i].first&&r.last===s.retained_ranges[i].last))return false;
 if(!stNullable(s.current,c=>stPhase(c)&&startupStages[s.role].includes(c.stage)&&BigInt(c.began_elapsed_ns)<=limit))return false;
 if(!stNullable(s.terminal,t=>stExact(t,'result at elapsed_ns')&&['SUCCEEDED','FAILED','CANCELLED','UNKNOWN'].includes(t.result)&&stWall(t.at)&&stDec(t.elapsed_ns)&&BigInt(t.elapsed_ns)<=limit&&s.current===null))return false;
 let index=0,prev=0n,elapsed=0n,stack=[],unknown=false;
 for(const range of ranges){if(index&&BigInt(range.first)!==prev+1n){stack=[];unknown=true;}for(let seq=BigInt(range.first);seq<=BigInt(range.last);seq++){
  const e=s.events[index++];if(!stExact(e,'seq span_id segment stage state code at elapsed_ns duration_ns round ordinal rule_count completed_count job tun')||e.seq!==String(seq)||!stNullable(e.span_id,stPositive)||!startupEnums.segment.includes(e.segment)||!startupStages[s.role].includes(e.stage)||!startupEnums.event.includes(e.code)||!stWall(e.at)||!stDec(e.elapsed_ns)||!['duration_ns','round','ordinal','rule_count','completed_count'].every(k=>stNullable(e[k],stDec))||!['NOT_OBSERVED','RUNNING','NOT_RUNNING','UNLOADED','UNKNOWN'].includes(e.job)||!['NOT_OBSERVED','TUN','NOT_TUN','UNKNOWN'].includes(e.tun))return false;
  const now=BigInt(e.elapsed_ns);if(now<elapsed||now>limit)return false;elapsed=now;prev=seq;
  if(e.ordinal==='0')return false;if(e.round!==null){const max=e.stage==='HTTPS_ATTEMPT'||e.stage.startsWith('HTTPS_RETRY_')?3n:['STOP','ROLLBACK'].includes(e.segment)?12n:16n;if(BigInt(e.round)<1n||BigInt(e.round)>max)return false;}
  if(e.state==='BEGIN'){if(e.span_id===null||e.code!=='NONE'||e.duration_ns!==null||stack.length>=16||stack.some(x=>x.span_id===e.span_id))return false;stack.push(e);}
  else if(e.state==='END'){if(e.span_id===null||e.code==='NONE'||e.duration_ns===null)return false;if(!stack.length){if(!unknown)return false;}else{const a=stack.pop();if(a.span_id!==e.span_id||a.stage!==e.stage||a.segment!==e.segment||now-BigInt(a.elapsed_ns)!==BigInt(e.duration_ns))return false;}}
  else if(e.state==='OBSERVATION'){if(e.duration_ns!==null||e.code==='NONE'||stack.length&&e.span_id!==stack.at(-1).span_id||!stack.length&&!unknown&&e.span_id!==null)return false;}else return false;
 }}
 if(!s.gap){const a=stack.at(-1);if(!a&&s.current!==null||a&&(!s.current||a.span_id!==s.current.span_id||a.stage!==s.current.stage||a.segment!==s.current.segment||a.elapsed_ns!==s.current.began_elapsed_ns||a.at!==s.current.began_at))return false;}
 return index===s.events.length;
}
function stTrace(t) {
 if(!stExact(t,'authority operation_id helper_epoch config_identity operation source started_at finished_at state lifecycle_result helper_return web_return receipt_result diagnostics streams core_observation gap')||t.authority!=='AUXILIARY_NOT_AUTHORITY'||!stID(t.operation_id)||!stNullable(t.helper_epoch,stID)||!stNullable(t.config_identity,stDigest)||!['START','STOP','RELOAD'].includes(t.operation)||!startupEnums.source.includes(t.source)||!stWall(t.started_at)||!stNullable(t.finished_at,stWall)||!['lifecycle_result','helper_return','web_return'].every(k=>startupEnums.result.includes(t[k]))||!own(receiptLabels,t.receipt_result)||!stDiagnostics(t.diagnostics)||!Array.isArray(t.streams)||t.streams.length>3||typeof t.gap!=='boolean')return false;
 if(t.state==='IN_PROGRESS'){if(t.finished_at!==null)return false;}else if(t.state==='FINISHED'){if(t.finished_at===null||t.web_return==='IN_PROGRESS'||t.helper_return==='IN_PROGRESS')return false;}else if(t.state!=='UNKNOWN')return false;
 if(new Set(t.streams.map(s=>s.role)).size!==t.streams.length||!t.streams.every(s=>stStream(s)&&(!s.gap||t.gap)))return false;
 const o=t.core_observation;if(!stExact(o,'availability captured_at helper_receive_elapsed_ns age_ns clock_id phase gap')||!startupEnums.core.includes(o.availability)||!stNullable(o.captured_at,stWall)||!stNullable(o.helper_receive_elapsed_ns,stDec)||!stNullable(o.age_ns,stDec)||!stNullable(o.clock_id,stID)||typeof o.gap!=='boolean'||o.gap&&!t.gap)return false;
 if(['OBSERVED','STALE'].includes(o.availability)){if(o.captured_at===null||o.helper_receive_elapsed_ns===null||o.age_ns===null||o.clock_id===null||(o.availability==='OBSERVED')!==(BigInt(o.age_ns)<=1500000000n)||!stNullable(o.phase,p=>stPhase(p)&&startupStages.CORE.includes(p.stage)))return false;}else if(o.phase!==null)return false;
 return true;
}
function stRead(v){return stExact(v,'timeline_schema code helper_epoch config_identity operation_id trace')&&v.timeline_schema===1&&startupEnums.read.includes(v.code)&&stNullable(v.helper_epoch,stID)&&stNullable(v.config_identity,stDigest)&&stNullable(v.operation_id,stID)&&(v.code==='OK'?v.trace!==null&&stTrace(v.trace)&&v.operation_id===v.trace.operation_id&&v.helper_epoch===v.trace.helper_epoch&&v.config_identity===v.trace.config_identity:v.trace===null);}
function startupText(v) {
 if(!stRead(v)||v.code!=='OK')throw Error('INVALID_TRACE');
 const t=v.trace;
 // Keep the complete validated DTO, including all event fields and provenance.
 // Group headings make the independent origins explicit; never sort across them.
 const lines=['AnyTLS ST1 · AUXILIARY_NOT_AUTHORITY','辅助观察，不证明当前就绪、恢复或根因。UTC 墙钟不单调；不同进程 elapsed 不可相减。',`schema=${v.timeline_schema} operation_id=${t.operation_id} helper_epoch=${t.helper_epoch}`,`source=${t.source} operation=${t.operation} started UTC=${t.started_at} finish=${t.state}`,t.state==='FINISHED'?'历史快照：截至操作结束收到；core 可能不完整。':'PARTIAL：操作仍在进行；不是最终结果。',`lifecycle=${t.lifecycle_result} helper_return=${t.helper_return} web_return=${t.web_return} receipt=${t.receipt_result} GAP=${t.gap}`];
 for(const s of t.streams)lines.push(`\n[${s.role} clock=${s.clock_id} origin UTC=${s.origin_at} elapsed_ns=${s.elapsed_ns}]`,JSON.stringify(s,null,2));
 lines.push('\n[完整固定 DTO]',JSON.stringify(v,null,2));return lines.join('\n');
}
let startupOwner=null,startupGeneration=0,startupLastSnapshot=null;
function startupCurrent(o){return startupOwner===o&&o.session===sessionGeneration&&Boolean(csrf);}
function startupCancel(clear=false){startupGeneration++;const o=startupOwner;startupOwner=null;if(o){clearTimeout(o.timer);o.controller?.abort();}if(clear){startupLastSnapshot=null;$('startup-text').value='';$('startup-summary').textContent='';$('startup-copy').disabled=true;$('startup-status').textContent='尚未观察服务操作。';$('startup-copy-status').textContent='';}}
function startupBegin(preserve=false){const previous=preserve?startupLastSnapshot:null,baselineID=startupLastSnapshot?.operation_id??null;startupCancel();const o={generation:startupGeneration,session:sessionGeneration,id:null,baselineID,controller:null,timer:null,inflight:false,snapshot:null,previous,pending:true,waiting:true,began:performance.now()};startupOwner=o;$('startup-status').textContent='正在等待本次服务操作；尚未取得时间轴。';$('startup-copy').disabled=true;$('startup-text').value='';$('startup-summary').textContent='';$('startup-copy-status').textContent='';startupLoad(o);return o;}
function startupResume(){if(!csrf||currentView!=='overview'||document.hidden)return;const o=startupOwner||startupBegin();if(!o.mutation)o.pending=false;if(!o.inflight)startupLoad(o);}
async function startupLoad(o) {
 if(!startupCurrent(o)||o.inflight||document.hidden||currentView!=='overview')return;
 clearTimeout(o.timer);o.inflight=true;const controller=new AbortController();o.controller=controller;
 try {
  const response=await fetch('/api/v1/startup-trace'+(o.id?'?operation_id='+encodeURIComponent(o.id):''),{headers:{'X-AnyTLS-Origin':location.origin},signal:controller.signal,credentials:'same-origin',cache:'no-store',redirect:'error'});
  const bytes=await response.arrayBuffer();if(bytes.byteLength>786432)throw Error('INVALID_TRACE');const text=new TextDecoder('utf-8',{fatal:true}).decode(bytes);if(!startupCurrent(o)||controller.signal.aborted)return;
  if(response.status===401){showLogin();return;}
  const data=stParse(text);if(o.id&&data.operation_id!==null&&o.id!==data.operation_id)throw Error('OPERATION_MISMATCH');
  if(data.code!=='OK'){o.snapshot=null;$('startup-copy').disabled=true;$('startup-text').value='';$('startup-status').textContent='时间轴：'+data.code;if(!['NO_OPERATION','BUSY'].includes(data.code))o.waiting=false;return;}
  if(o.pending&&o.mutation&&!o.id&&data.operation_id===o.baselineID)return;
  if(!o.id)o.id=data.operation_id;o.snapshot=data;startupLastSnapshot=data;const t=data.trace;
  $('startup-text').value=startupText(data);$('startup-copy').disabled=false;$('startup-copy').textContent=t.state==='IN_PROGRESS'?'复制日志（操作进行中）':'复制完整日志';
  $('startup-status').textContent=t.state==='IN_PROGRESS'?'正在观察 · 不是进度百分比':'历史快照 · 不是当前就绪证明';
  const helper=t.streams.find(s=>s.role==='HELPER'),core=t.core_observation;
  $('startup-summary').textContent=[`开始 UTC：${t.started_at}`,`来源：${t.source} · ${t.operation}`,`helper elapsed_ns：${helper?.elapsed_ns??'NOT_OBSERVED'}`,`helper 阶段：${helper?.current?.stage??'NOT_OBSERVED'}`,`最后收到 core 阶段：${core.phase?.stage??'NOT_OBSERVED'} · ${core.availability}`,`core 缓存 age_ns：${core.age_ns??'NOT_OBSERVED'}（非实时线程状态）`,`lifecycle=${t.lifecycle_result} helper=${t.helper_return} web=${t.web_return} receipt=${t.receipt_result}`,`GAP=${t.gap} · 浏览器等待 ${Math.floor(performance.now()-o.began)} ms（独立本地时钟）`].join('\n');
  if(t.state!=='IN_PROGRESS'&&!o.pending)o.waiting=false;
 } catch(error) {if(startupCurrent(o)&&!controller.signal.aborted){o.snapshot=null;o.waiting=false;$('startup-text').value='';$('startup-copy').disabled=true;$('startup-status').textContent='时间轴不可用或格式无效；未采用日志。';}}
 finally {if(startupCurrent(o)&&o.controller===controller){o.inflight=false;o.controller=null;if(o.waiting&&!document.hidden&&currentView==='overview')o.timer=setTimeout(()=>startupLoad(o),2000);}}
}
function startupResult(data,o) {
 if(!startupCurrent(o))return;
 const ref=data?.startup_operation;
 o.pending=false;
 if(ref===null){o.controller?.abort();clearTimeout(o.timer);o.controller=null;o.inflight=false;o.waiting=false;o.snapshot=o.previous;if(o.snapshot){o.id=o.snapshot.operation_id;startupLastSnapshot=o.snapshot;$('startup-text').value=startupText(o.snapshot);$('startup-copy').disabled=false;$('startup-status').textContent='最近一次服务操作 · 本次未触发服务操作';$('startup-summary').textContent='开始 UTC：'+o.snapshot.trace.started_at+'\n来源：'+o.snapshot.trace.source+' · '+o.snapshot.trace.state;}else{$('startup-text').value='';$('startup-copy').disabled=true;$('startup-status').textContent='本次未触发服务操作；尚无服务日志。';}$('startup-context').textContent='本次未触发服务操作；下方保留最近一次服务操作。';return;}
 if(!stExact(ref,'timeline_schema operation_id availability')||ref.timeline_schema!==1||!stNullable(ref.operation_id,stID)||!['AVAILABLE','UNAVAILABLE','UNSUPPORTED'].includes(ref.availability)||ref.availability==='AVAILABLE'&&ref.operation_id===null){o.waiting=false;o.controller?.abort();o.controller=null;o.inflight=false;clearTimeout(o.timer);$('startup-status').textContent='操作引用无效，未关联时间轴。';return;}
 if(ref.operation_id!==o.id){o.controller?.abort();o.inflight=false;o.controller=null;o.id=ref.operation_id;o.snapshot=null;$('startup-text').value='';$('startup-copy').disabled=true;}
 $('startup-context').textContent='最近一次服务操作；日志只用于辅助观察。';
 if(ref.availability!=='AVAILABLE'){o.waiting=false;o.controller?.abort();o.controller=null;o.inflight=false;o.snapshot=null;$('startup-text').value='';$('startup-copy').disabled=true;$('startup-status').textContent='时间轴：'+ref.availability;clearTimeout(o.timer);}else{o.waiting=true;startupLoad(o);}
}
$('startup-refresh').onclick=()=>{if(startupOwner)startupLoad(startupOwner);else startupResume();};
$('startup-copy').onclick=async()=>{
 const o=startupOwner;if(!o||!startupCurrent(o)||!o.snapshot)return;
 let text;try{text=startupText(o.snapshot);}catch{return;}
 const manual=()=>{if(!startupCurrent(o))return;$('startup-details').open=true;const field=$('startup-text');field.value=text;field.focus();field.select();field.scrollTop=0;field.scrollLeft=0;$('startup-copy-status').textContent='未复制，请手动复制已选中的完整日志（Ctrl+C / ⌘C）。';};
 if(!isSecureContext||!navigator.clipboard?.writeText){manual();return;}
 try{await navigator.clipboard.writeText(text);if(startupCurrent(o))$('startup-copy-status').textContent='已复制完整当前快照'+(o.snapshot.trace.state==='IN_PROGRESS'?'（未完成）。':'。');}catch{manual();}
};
document.addEventListener('visibilitychange',()=>{if(document.hidden){const o=startupOwner;if(o){clearTimeout(o.timer);o.controller?.abort();o.controller=null;o.inflight=false;}}else startupResume();});
window.addEventListener('pagehide',()=>startupCancel(true));
if(csrf)startupResume();

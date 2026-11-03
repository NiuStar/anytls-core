'use strict';
(() => {
 let owner=null;
 const status=()=>document.getElementById('dns-evidence-status');
 const detail=()=>document.getElementById('dns-evidence-detail');
 const project=p=>runtimePublish('dns',p);
 const clear=()=>{if(owner)owner.abort();owner=null;detail().textContent='';status().textContent='未读取 / 不可用；不是零查询。';project({availability:'UNKNOWN'});};
 async function refresh(){
  clear();if(!csrf)return;
  const session=sessionGeneration,controller=new AbortController();owner=controller;
  const timer=setTimeout(()=>controller.abort(),4500);
  const read=async(query='')=>{const r=await fetch('/api/v1/dns-runtime'+query,{headers:{'X-AnyTLS-Origin':location.origin},credentials:'same-origin',cache:'no-store',redirect:'error',signal:controller.signal});if(!r.ok)throw new Error('UNAVAILABLE');const p=await r.json();if(p.dns_schema!==1||p.code!=='OK')throw new Error(p.code||'UNAVAILABLE');return p;};
  try{
   status().textContent='读取中 · 仅缓存证据';let p=await read();
   if(owner!==controller||session!==sessionGeneration||!csrf||controller.signal.aborted||document.hidden)return;
   if(!p.binding||!['instance_id','generation'].every(k=>/^[a-f0-9]{32}$/.test(p.binding[k]))||!['manifest_id','runtime_sha256'].every(k=>/^[a-f0-9]{64}$/.test(p.binding[k])))throw new Error('UNAVAILABLE');
   const b=p.binding;p=await read('?'+new URLSearchParams({instance_id:b.instance_id,generation:b.generation,manifest_id:b.manifest_id}));
   if(owner!==controller||session!==sessionGeneration||!csrf||controller.signal.aborted||document.hidden)return;
   if(!p.binding||!['instance_id','generation','manifest_id','runtime_sha256'].every(k=>p.binding[k]===b[k]))throw new Error('UNAVAILABLE');
   if(!p.snapshot||p.availability!=='OBSERVED'){project({availability:p.availability});status().textContent='过期 / 不可用 · 不代表当前运行健康';return;}
   const s=p.snapshot;
   if(!s.coverage||s.coverage.scope!=='HTTPS_TRANSPORT_COMPLETION'||typeof s.coverage.gap!=='boolean'||!Array.isArray(s.events)||s.events.length>64||!s.events.every(e=>e.kind==='HTTPS_EXCHANGE_COMPLETED'))throw new Error('UNAVAILABLE');
   project({availability:p.availability,state:s.state,ageNS:p.age_ns,gap:s.coverage.gap});
   status().textContent=(s.state==='LOADED'?'策略已加载':'策略未加载')+' · '+(s.coverage.gap?'GAP：近期证据有丢失':'仅部分覆盖')+' · 已记录 '+s.events.length+' 条 DoH transport 完成；不代表全部查询';
   detail().textContent='运行 '+b.instance_id+'\n缓存年龄 '+p.age_ns+' ns\n策略为严格 TLS（仅在具体 transport 标为 STRICT_CONFIGURED 时）\n'+JSON.stringify({policy:s.policy,coverage:s.coverage,events:s.events},null,2);
  }catch(e){if(owner===controller&&session===sessionGeneration){project({availability:'UNAVAILABLE'});status().textContent='未启用 / 不支持 / 不可用 / 代次不符；未采用响应，不表示零查询。';detail().textContent='';}}
  finally{clearTimeout(timer);if(owner===controller)owner=null;}
 }
 document.getElementById('dns-evidence-refresh').addEventListener('click',refresh);
 document.getElementById('logout').addEventListener('click',clear);
 document.addEventListener('visibilitychange',()=>{if(document.hidden)clear();});
 const observer=new MutationObserver(()=>{if(document.getElementById('console-view').hidden)clear();});observer.observe(document.getElementById('console-view'),{attributes:true,attributeFilter:['hidden']});
})();

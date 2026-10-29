// Node VM behavioral checks; synthetic HTTP/DOM are not browser/backend acceptance.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import {test} from 'node:test';
import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
const root = process.env.WEB_ROOT ? pathToFileURL(resolve(process.env.WEB_ROOT)+'/') : new URL('./web_assets/', import.meta.url);
const source = fs.readFileSync(new URL('app.js', root), 'utf8');
const html = fs.readFileSync(new URL('index.html', root), 'utf8');
const bootstrap = "(async()=>{try{await enterConsole(await api('/session'));}catch{showLogin();}})();";
assert.ok(source.endsWith(bootstrap+'\n') || source.endsWith(bootstrap), 'only remove automatic session bootstrap');

function harness() {
 class Element {
  constructor(tag='div', id='') {Object.assign(this,{tag,id,children:[],dataset:{},style:{},hidden:false,disabled:false,value:'',textContent:'',isConnected:true});this.classes=new Set();this.classList={toggle:(k,on)=>on?this.classes.add(k):this.classes.delete(k),contains:k=>this.classes.has(k),remove:k=>this.classes.delete(k)};}
  append(...children) {for(const child of children) {if(child.tag==='#fragment')this.append(...child.children);else {this.children.push(child);if(this.tag==='select'&&this.children.length===1)this.value=child.value;}}}
  replaceChildren(...children) {this.children=[];this.value='';this.append(...children);}
  querySelectorAll(selector) {return this.children.flatMap(child=>[...(selector==='[data-rule-delete]'&&Object.hasOwn(child.dataset,'ruleDelete')?[child]:selector===child.tag?[child]:[]),...child.querySelectorAll(selector)]);}
  setAttribute() {} addEventListener() {} focus() {} reset() {}
 }
 const nodes=new Map([...html.matchAll(/<([a-z][\w-]*)\b[^>]*\bid="([^"]+)"/g)].map(([,tag,id])=>[id,new Element(tag,id)]));
 const get=id=>{assert.ok(nodes.has(id),'real HTML missing #'+id);return nodes.get(id);};
 get('rule-type').value='DOMAIN';get('rule-position').value='first';
 const document={hidden:false,body:new Element(),getElementById:get,createElement:tag=>new Element(tag),createDocumentFragment:()=>new Element('#fragment'),querySelectorAll:selector=>selector==='button'?[...nodes.values()].filter(n=>n.tag==='button'):[],querySelector:()=>new Element(),addEventListener(){}};
 const requests=[], queue=[];
 const fetch=(path,options)=>{requests.push({path,...options});assert.ok(queue.length,'unexpected fetch '+path);return queue.shift()(path,options);};
 const context=vm.createContext({document,fetch,Headers,console,URL,AbortController,setInterval(){},clearInterval(){},setTimeout(){},clearTimeout(){},confirm:()=>true});
 vm.runInContext(source.slice(0,source.lastIndexOf(bootstrap)),context,{filename:'app.js'});
 const run=code=>vm.runInContext(code,context);
 run("csrf='session';");
 const respond=(data,status=200)=>queue.push(async()=>({ok:status<400,status,json:async()=>structuredClone(data)}));
 const hold=()=>{let release;queue.push(()=>new Promise(resolve=>release=data=>resolve({ok:true,status:200,json:async()=>structuredClone(data)})));return data=>{assert.ok(release,'held request not started');release(data);};};
 return {get,requests,respond,hold,run};
}
const base={rules:['DOMAIN,old.test,DIRECT','MATCH,DIRECT'],etag:'"v1"',editable:true,edit_error:''};
const list=(etag='"v1"')=>({...base,etag,view:'list',options_loaded:false});
const full=(etag='"v2"')=>({...base,etag,targets:['DIRECT','REJECT'],rule_sets:['audited']});

// Separate cases preserve every business failure on the baseline rather than
// letting the first missing mode hide all other assertions.
test('browse requests list-only, renders/deletes, cannot synthetically submit add', async()=>{
 const h=harness();h.respond(list());await h.run('loadRules(false)');
 assert.equal(h.requests[0].path,'/api/v1/rules?view=list');
 assert.equal(h.get('rules-list').children.length,2);
 assert.equal(h.get('rule-form').hidden,true);
 assert.equal(h.get('rule-target').children.length,0);
 assert.equal(h.get('save-rule').disabled,true);
 assert.equal(h.get('rules-list').querySelectorAll('[data-rule-delete]')[0].disabled,false);
 await h.get('rule-form').onsubmit({preventDefault(){}});
 assert.equal(h.requests.length,1,'unloaded options must never submit an add');
});

test('add uses legacy full options with its own ETag and original save API', async()=>{
 const h=harness();h.respond(full());await h.run('loadRules(true)');
 assert.equal(h.requests[0].path,'/api/v1/rules');
 assert.equal(h.get('rule-form').hidden,false);
 assert.deepEqual(h.get('rule-target').children.map(n=>n.value),['DIRECT','REJECT']);
 h.get('rule-value').value='new.test';h.respond({error:'CONFIG_CONFLICT'},412);
 await h.get('rule-form').onsubmit({preventDefault(){}});
 const post=h.requests[1];assert.equal(post.path,'/api/v1/rules');assert.equal(post.method,'POST');assert.equal(post.headers.get('If-Match'),'"v2"');
 assert.deepEqual(JSON.parse(post.body),{type:'DOMAIN',value:'new.test',target:'DIRECT',no_resolve:false,position:'first',confirm_insecure:true});
 assert.equal(h.requests.length,2,'failed save is never retried');
 assert.equal(h.run('rulesSnapshot'),null,'conflict invalidates snapshot');
});

test('late list response cannot replace a newer full editor', async()=>{
 const h=harness(),release=h.hold();const old=h.run('loadRules(false)');
 h.respond(full());await h.run('loadRules(true)');release(list('"old"'));await old;
 assert.equal(h.get('rule-form').hidden,false);assert.equal(h.run('rulesSnapshot.etag'),'"v2"');
 assert.deepEqual(h.get('rule-target').children.map(n=>n.value),['DIRECT','REJECT']);
});

test('late full options cannot reopen editor after a newer list read', async()=>{
 const h=harness(),release=h.hold();const old=h.run('loadRules(true)');
 h.respond(list());await h.run('loadRules(false)');release(full('"old"'));await old;
 assert.equal(h.get('rule-form').hidden,true);assert.equal(h.get('rule-target').children.length,0);assert.equal(h.run('rulesSnapshot.etag'),'"v1"');
});

test('config invalidation and session fences reject late options', async()=>{
 for(const invalidate of ['invalidateRules()',"sessionGeneration++;csrf='new-session';invalidateRules()"]){
  const h=harness(),release=h.hold();const old=h.run('loadRules(true)');h.run(invalidate);release(full());await old;
  assert.equal(h.run('rulesSnapshot'),null);assert.equal(h.get('rule-form').hidden,true);assert.equal(h.get('rule-target').children.length,0);
 }
});

test('full editor rejects a list-only projection instead of opening unloaded choices', async()=>{
 const h=harness();h.respond(list());await assert.rejects(h.run('loadRules(true)'),/规则响应不完整/);
 assert.equal(h.get('rule-form').hidden,true);assert.equal(h.run('rulesSnapshot'),null);
});

test('list redraw retains busy, original-position and stale-row guards', async()=>{
 const h=harness();h.respond({...list(),rules:Array.from({length:205},(_,i)=>i===204?'MATCH,DIRECT':'DOMAIN,duplicate.test,DIRECT')});await h.run('loadRules(false)');
 const first=h.get('rules-list').querySelectorAll('[data-rule-delete]')[0];
 h.run('busy=true;renderRulesPage()');assert.ok(h.get('rules-list').querySelectorAll('[data-rule-delete]').every(b=>b.disabled));
 await first.onclick();assert.equal(h.requests.length,1);
 h.run('busy=false');h.get('rules-last').onclick();assert.equal(h.get('rules-list').children[0].value,201);assert.equal(h.get('rules-list').children.length,5);
 h.run('invalidateRules()');await first.onclick();assert.equal(h.requests.length,1);
});

for(const code of ['CONFIG_WRITE_FAILED','CONFIG_READBACK_FAILED'])test(code+' uses Chinese uncertainty warning once, no implicit retry', async()=>{
 const h=harness();h.respond(full());await h.run('loadRules(true)');h.get('rule-value').value='new.test';h.respond({error:code},500);
 await h.get('rule-form').onsubmit({preventDefault(){}});
 const text=h.get('rule-feedback').textContent;
 assert.match(text,/[\u4e00-\u9fff]/);assert.match(text,/配置/);assert.match(text,/重新读取/);assert.match(text,/确认|核对/);assert.match(text,/自动重试/);
 assert.doesNotMatch(text,/原文件未改变|文件未保存|原配置未改变/);
 assert.equal(h.requests.length,2,'one GET and exactly one attempted POST');assert.equal(h.run('busy'),false);
});

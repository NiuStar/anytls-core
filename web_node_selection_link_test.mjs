// Actual app.js handlers, synthetic DOM/HTTP; no helper or native mutation.
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {harness} from './web_status_lifecycle_test.mjs';
const payload={nodes:[{name:'A',type:'anytls',server:'fixture.invalid',port:443,selectable:true,selected:false}],etag:'"config-v1"'};
async function setup(data=payload){const h=harness();h.run('filterNodes=()=>{}');h.respond(data);await h.run('loadNodes()');return h;}
function choose(h){return h.get('nodes-list').children[0].children[0];}
test('mismatched startup card exposes a single explicit synchronization',async()=>{
 const h=await setup({...payload,nodes:[{...payload.nodes[0],selected:true,defaultSelected:false,selectionNeedsSync:true}]});
 const button=choose(h);assert.equal(button.disabled,false);assert.equal(button.children[0].textContent,'启动节点 · 同步默认组');h.respond({error:'CONFIG_CONFLICT'},412);await button.onclick();assert.equal(h.requests.filter(r=>r.method==='POST').length,1);
});
test('default business egress is not mislabeled as actual startup DNS node',async()=>{
 const h=await setup({...payload,nodes:[{...payload.nodes[0],selected:false,defaultSelected:true,selectionNeedsSync:true}]});
 assert.equal(choose(h).disabled,false);assert.equal(choose(h).children[0].textContent,'默认出口 · 设为启动节点');
});
test('fully linked startup node stays selected and disabled',async()=>{
 const h=await setup({...payload,nodes:[{...payload.nodes[0],selected:true,defaultSelected:true,selectionNeedsSync:false}]});assert.equal(choose(h).disabled,true);assert.equal(choose(h).children[0].textContent,'当前启动节点');
});
test('startup card sends its rendered config ETag exactly once',async()=>{
 const h=await setup();h.respond({error:'CONFIG_CONFLICT'},412);await choose(h).onclick();
 const posts=h.requests.filter(r=>r.method==='POST');assert.equal(posts.length,1);assert.equal(posts[0].path,'/api/v1/nodes/selection');assert.equal(posts[0].headers.get('If-Match'),'"config-v1"');assert.equal(JSON.parse(posts[0].body).name,'A');assert.ok(!h.requests.some(r=>r.path.includes('/service/')));
});
for(const invalidate of ['invalidateNodes()','showLogin();csrf="new-session"'])test('detached startup card cannot save after '+invalidate,async()=>{
 const h=await setup(),old=choose(h);h.run(invalidate);h.respond({error:'CONFIG_CONFLICT'},412);await old.onclick();assert.equal(h.requests.length,1,'stale owner sends no mutation');
});
test('late save result cannot invalidate or fetch for a new session',async()=>{
 const h=await setup(),release=h.hold(),pending=choose(h).onclick();
 h.run('showLogin();csrf="new-session";nodesEtag="new-owner"');release({changed:true,apply_status:'SAVED_STOPPED'});await pending;
 assert.equal(h.run('nodesEtag'),'new-owner');assert.equal(h.requests.length,2,'late response never refreshes new session');
});

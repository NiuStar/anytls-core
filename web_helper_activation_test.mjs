// Real app.js execution; synthetic DOM/HTTP, no Mac/helper installation.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {harness} from './web_status_lifecycle_test.mjs';
const root=process.env.WEB_ROOT||new URL('./web_assets/',import.meta.url).pathname;
const html=fs.readFileSync(root+'index.html','utf8');
const guidance=/仅更新普通用户程序/;
test('update page distinguishes update-only, full get install and explicit reconnect',()=>{
 const section=html.split('id="view-update"')[1].split('</section>')[0];
 assert.match(section,guidance);assert.match(section,/get\.sh.*包含.*助手/);assert.match(section,/anytls helper install/);assert.match(section,/完整安装.*无需重复/);assert.match(section,/自行.*重连/);assert.match(section,/不.*自动.*重连/);
 assert.equal((section.match(/<button\b/g)||[]).length,2,'no automatic helper install control');
});
for(const version of ['v2026-10-22-06','v2026-11-04-01'])test(`available helper ${version} and unavailable traffic do not prove upgrade cause or activation`,async()=>{
 const h=harness();h.respond({availability:'AVAILABLE',running:true,loaded:true,version:'v2026-11-04-01'});h.respond({available:true,version});await h.run('status()');
 h.respond({error:'TELEMETRY_UNAVAILABLE'},503);await assert.rejects(h.run("api('/traffic')"));
 assert.match(h.get('helper-detail').textContent,/仅表示控制通道可用/);assert.doesNotMatch(h.get('helper-detail').textContent,/已激活|流量统计已生效|旧版助手/);
 h.run(`renderUpdate({status:'UPDATED',current:'v2026-11-04-01',installed:'v2026-11-04-01',latest:'v2026-11-04-01',available:false,sourceOnly:false,updated:true,restartRequired:true},true)`);
 assert.match(h.get('update-result').textContent,guidance);assert.match(h.get('update-result').textContent,/anytls helper install/);assert.match(h.get('update-result').textContent,/自行.*重连/);
 assert.ok(h.requests.every(r=>!r.method||r.method==='GET'),'no install or reload request');assert.equal(h.requests.length,3);
});
test('restart completion keeps helper and reconnect guidance',()=>{
 const h=harness();h.run("updateRestartFeedback('Web 控制台已恢复。')");assert.match(h.get('update-result').textContent,guidance);assert.match(h.get('update-result').textContent,/自行.*重连/);
});

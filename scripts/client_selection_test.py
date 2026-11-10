#!/usr/bin/env python3
"""Real checked-out client JS/API execution in QuickJS; not browser/native QA."""
import json
from pathlib import Path
import unittest
try:
    import quickjs
except ImportError:
    quickjs = None

ROOT = Path(__file__).resolve().parents[1]

@unittest.skipIf(quickjs is None, 'QuickJS is required for client VM tests')
class ClientSelectionTests(unittest.TestCase):
    def vm(self):
        source = (ROOT / 'web_assets/app.js').read_text()
        c = quickjs.Context()
        c.eval('new Function(' + json.dumps(source) + ')')
        c.eval('''
var calls=[],replies=[],held=[],recorded;
class TextEncoder {encode(s){return unescape(encodeURIComponent(s));}}
class Headers {constructor(){this.values={};}set(k,v){this.values[k]=v;}}
class URLSearchParams {constructor(o){this.o=o;}toString(){return Object.entries(this.o).map(([k,v])=>encodeURIComponent(k)+'='+encodeURIComponent(v)).join('&');}}
class AbortController {constructor(){this.signal={aborted:false};}abort(){this.signal.aborted=true;}}
function setTimeout(){return 1;}function clearTimeout(){}
function fetch(url,options){calls.push({url,...options});const r=replies.shift();if(r==='hold')return new Promise(resolve=>held.push(resolve));if(r==='lost')return Promise.reject(Error('lost ACK'));return Promise.resolve(response(r));}
function response(r){return {ok:r.status===200,status:r.status,headers:{get:()=>r.etag===undefined?JSON.parse(r.body).etag:r.etag},json:()=>Promise.resolve(JSON.parse(r.body))};}
function notice(text,failed){recorded={text,failed};}
function invalidateNodes(){}function invalidateGroups(){}function clearProfiles(){}function invalidateRules(){}
function startupBegin(){return null;}function renderExtraButtons(){}function renderServiceButtons(){}
function showLogin(){sessionGeneration++;csrf='';}
''')
        c.eval(source[:source.index('function syncServiceUI(')])
        a = source.index('function savedFeedback(')
        c.eval(source[a:source.index('async function refreshAfterSave(', a)])
        c.eval('''
csrf='synthetic';
const tag='"'+'a'.repeat(64)+'"';
const tuple={operation:'a'.repeat(32),generation:'b'.repeat(32),revision:7,node:'节点 +&?#/名'};
const hot={ok:true,saved:true,changed:true,applied:true,apply_status:'HOT_APPLIED',pendingReload:false,pendingKnown:true,etag:tag,startup_operation:null,connection_policy:'EXISTING_CONNECTIONS_RETAIN_OLD_EXIT',selection_operation:tuple,readback_requires_owned_lease:false};
const unknown={...hot,applied:false,apply_status:'SWITCH_UNKNOWN',pendingReload:true,pendingKnown:false};
function enqueue(body,status=200){replies.push({status,body:JSON.stringify(body)});}
var done=false,error=null;
function run(p){done=false;error=null;p.then(()=>done=true,e=>{error=e.message;done=true;});}
''')
        return c

    def settle(self, c):
        for _ in range(300):
            if not c.execute_pending_job():
                break
        self.assertTrue(c.eval('done'), c.eval('error'))

    def test_real_hot_dto_and_same_selection_feedback(self):
        c = self.vm()
        c.eval("enqueue({...hot,changed:false});run(api('/nodes/selection',{method:'POST',body:{name:tuple.node}}).then(savedFeedback));")
        self.settle(c)
        self.assertIsNone(c.eval('error'))
        self.assertIn('已有连接保留原出口', c.eval('recorded.text'))
        self.assertFalse(c.eval('recorded.failed'))

    def test_unknown_held_get_and_exact_encoded_tuple_unlocks(self):
        c = self.vm()
        c.eval("enqueue(unknown);run(api('/nodes/selection',{method:'POST',body:{name:tuple.node}}));")
        self.settle(c)
        c.eval("replies.push('hold');run(recoverSelectionReadback());")
        while c.execute_pending_job():
            pass
        self.assertTrue(c.eval('selectionUnknown'))
        c.eval("run(api('/nodes/selection',{method:'POST',body:{name:tuple.node}}));")
        self.settle(c)
        self.assertEqual(c.eval('calls.length'), 2)
        request = json.loads(c.eval('JSON.stringify(calls[1])'))
        from urllib.parse import parse_qs, urlsplit
        self.assertEqual(request['method'], 'GET')
        self.assertEqual(parse_qs(urlsplit(request['url']).query), {
            'operation': ['a' * 32], 'generation': ['b' * 32], 'revision': ['7'], 'node': ['节点 +&?#/名']})
        c.eval("held.shift()(response({status:200,body:JSON.stringify(hot)}));")
        while c.execute_pending_job():
            pass
        self.assertFalse(c.eval('selectionUnknown'))
        self.assertEqual(c.eval('calls.filter(c=>c.method!=="GET").length'), 1)

    def test_readback_poison_transport_nochange_and_stale_session_keep_lock(self):
        poisons = ["{...hot,etag:'\"'+'c'.repeat(64)+'\"'}", "{...hot,pendingReload:true}",
                   "{...hot,pendingKnown:false}", "{...hot,selection_operation:null}",
                   "{...hot,foreign:true}", "{...hot,readback_requires_owned_lease:true}",
                   "{...hot,apply_status:'NO_CHANGE',changed:false}", "{availability:'AVAILABLE',running:true}"]
        poisons += ["{...hot,selection_operation:{...tuple," + key + ":" + val + "}}" for key, val in
                    [('operation', "'c'.repeat(32)"), ('generation', "'d'.repeat(32)"), ('revision', '8'), ('node', "'foreign'")]]
        for poison in poisons + ['lost', 'stale']:
            with self.subTest(poison=poison):
                c = self.vm()
                c.eval("enqueue(unknown);run(api('/nodes/selection',{method:'POST',body:{name:tuple.node}}));")
                self.settle(c)
                if poison == 'lost':
                    c.eval("replies.push('lost');run(recoverSelectionReadback());")
                elif poison == 'stale':
                    c.eval("replies.push('hold');run(recoverSelectionReadback());sessionGeneration++;held.shift()(response({status:200,body:JSON.stringify(hot)}));")
                else:
                    c.eval('enqueue(' + poison + ');run(recoverSelectionReadback());')
                self.settle(c)
                self.assertTrue(c.eval('selectionUnknown'))
                self.assertEqual(c.eval('calls.length'), 2)
                self.assertEqual(c.eval('calls[1].method'), 'GET')

    def test_same_selection_readback_and_unsafe_revision(self):
        for revision in ['7', '9007199254740993']:
            with self.subTest(revision=revision):
                c = self.vm()
                c.eval('enqueue({...unknown,changed:false,selection_operation:{...tuple,revision:' + revision + "}});run(api('/nodes/selection',{method:'POST',body:{name:tuple.node}}));")
                self.settle(c)
                c.eval('enqueue({...hot,changed:false});run(recoverSelectionReadback());')
                self.settle(c)
                self.assertEqual(c.eval('selectionUnknown'), revision != '7')
                self.assertEqual(c.eval('calls.length'), 2 if revision == '7' else 1)
                if revision != '7':
                    self.assertIn('初始化', c.eval('recorded.text'))

    def test_status_nochange_legacy_and_explicit_reinitialization(self):
        c = self.vm()
        c.eval("enqueue(unknown);run(api('/nodes/selection',{method:'POST',body:{name:tuple.node}}));")
        self.settle(c)
        c.eval("enqueue({availability:'AVAILABLE',loaded:true,running:true,pendingReload:false});run(api('/status'));")
        self.settle(c)
        self.assertTrue(c.eval('selectionUnknown'))
        c.eval("enqueue({...hot,apply_status:'NO_CHANGE',changed:false});run(recoverSelectionReadback());")
        self.settle(c)
        self.assertTrue(c.eval('selectionUnknown'))
        c.eval("enqueue({ok:true,loaded:true,running:true});run(api('/service/reload',{method:'POST',body:{}}));")
        self.settle(c)
        self.assertTrue(c.eval('selectionUnknown'))
        c.eval("const diagnostic={schema:1,operation:'RELOAD',outcome:'SUCCEEDED',stage:'LOCAL_READY',reason:'INTERNET_UNVERIFIED',rollback:'NOT_ATTEMPTED',restoration:'NOT_ATTEMPTED',cleanup:'NOT_ATTEMPTED',receipt:'WRITTEN',job:'RUNNING',tun:'TUN'};enqueue({ok:true,loaded:true,running:true,diagnostics:diagnostic});run(api('/service/reload',{method:'POST',body:{}}));")
        self.settle(c)
        self.assertFalse(c.eval('selectionUnknown'))
        c.eval("enqueue({ok:true,saved:true,changed:true,applied:true,apply_status:'APPLIED',pendingReload:false,pendingKnown:true,startup_operation:null});run(api('/nodes/selection',{method:'POST',body:{name:tuple.node}}));")
        self.settle(c)
        self.assertFalse(c.eval('selectionUnknown'))

    def test_header_mismatch_and_http_failures_never_unlock(self):
        for kind in ['header', '409', '401']:
            with self.subTest(kind=kind):
                c = self.vm()
                c.eval("enqueue(unknown);run(api('/nodes/selection',{method:'POST',body:{name:tuple.node}}));")
                self.settle(c)
                if kind == 'header':
                    c.eval("replies.push({status:200,etag:'bad',body:JSON.stringify(hot)});")
                else:
                    c.eval('enqueue({error:"SWITCH_UNKNOWN",readback_requires_owned_lease:true},' + kind + ');')
                c.eval('run(recoverSelectionReadback());')
                self.settle(c)
                self.assertTrue(c.eval('selectionUnknown'))

    def test_lost_post_ack_without_tuple_never_replays(self):
        c = self.vm()
        c.eval("replies.push('lost');run(api('/nodes/selection',{method:'POST',body:{name:tuple.node}}));")
        self.settle(c)
        c.eval('run(recoverSelectionReadback());')
        self.settle(c)
        self.assertTrue(c.eval('selectionUnknown'))
        self.assertEqual(c.eval('calls.length'), 1)

if __name__ == '__main__':
    unittest.main()

#!/usr/bin/env python3
"""LOCALONLY: native IPC/ps boundaries are synthetic; no lifecycle requests."""
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import types
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('reconcile_fixture', Path(__file__).with_name('install_core_reload_test.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
b = m.b


def stop_diagnostics():
    return dict(schema=1,operation='STOP',outcome='SUCCEEDED',stage='NONE',reason='NONE',
                rollback='NOT_ATTEMPTED',restoration='NOT_ATTEMPTED',cleanup='NOT_ATTEMPTED',
                receipt='NOT_ATTEMPTED',job='UNLOADED',tun='NOT_TUN')


class Reconcile(unittest.TestCase):
    def setUp(self):
        self.w = m.Worker()
        self.w.setUp()
        self.addCleanup(self.w.doCleanups)
        w = self.w
        # Keep the full install's real home/.anytls path, not a second guard-only
        # namespace. Rebind only local fixture paths before creating receipts.
        old_app=w.app
        w.app.rename(w.app.parent/'.anytls')
        w.app=w.app.parent/'.anytls'
        w.tx=w.app/('.core-reload-'+w.op)
        w.old['command']=w.old['command'].replace(str(old_app),str(w.app))
        w.before['config']=w.n['config_pin'](w.app)
        w.identity=w.before['config']['identity']
        w.job['app']=str(w.app)
        w.status['config_identity']=w.identity
        w.response['config_identity']=w.identity
        w.trace['config_identity']=w.identity
        w.trace['trace']['config_identity']=w.identity
        self.app, self.root = w.app, w.tx
        self.diag = dict(schema=1, operation='RELOAD', outcome='FAILED', stage='HELPER_PREFLIGHT',
                         reason='PREFLIGHT_REJECTED', rollback='NOT_ATTEMPTED', restoration='NOT_ATTEMPTED',
                         cleanup='NOT_ATTEMPTED', receipt='NOT_ATTEMPTED', job='NOT_OBSERVED', tun='NOT_OBSERVED')
        self.response = dict(w.response, ok=False, code='PREFLIGHT_FAILED', loaded=False, running=False,
                             diagnostics=self.diag)
        # Sanitized native Mac schema: complete six-event HELPER stream, global
        # gap TRUE solely because no CORE observation exists before compile failed.
        self.trace = copy.deepcopy(w.trace)
        t = self.trace['trace']
        t.update(lifecycle_result='FAILED', helper_return='FAILED', receipt_result='NOT_ATTEMPTED',
                 diagnostics=self.diag, gap=True)
        t['core_observation'].update(availability='NOT_OBSERVED', gap=True)
        s = t['streams'][0]
        s.update(role='HELPER', current=None, generated_events='6', dropped_events='0',
                 first_missing_seq=None, retained_ranges=[dict(first='1', last='6')], gap=False)
        s['terminal']['result'] = 'FAILED'
        original = s['events'][0]
        s['events'] = []
        for seq, stage, state, code, segment, span in (
            (1,'HELPER_ACCEPT','OBSERVATION','OK','PREFLIGHT',None),
            (2,'HELPER_PREFLIGHT_CAPTURE','BEGIN','NONE','PREFLIGHT','1'),
            (3,'HELPER_PREFLIGHT_CAPTURE','END','OK','PREFLIGHT','1'),
            (4,'HELPER_PREFLIGHT_COMPILE','BEGIN','NONE','PREFLIGHT','2'),
            (5,'HELPER_PREFLIGHT_COMPILE','END','FAILED','PREFLIGHT','2'),
            (6,'HELPER_FINISH','OBSERVATION','FAILED','FINALIZE',None)):
            s['events'].append(dict(original, seq=str(seq), stage=stage, state=state, code=code,
                                    segment=segment, span_id=span, elapsed_ns=str(seq),
                                    duration_ns='1' if state=='END' else None))
        s['elapsed_ns'] = '7'
        s['terminal']['elapsed_ns'] = '7'
        self.current = dict(w.status, loaded=False, running=False)
        self.rows = []
        self.requests = []
        self.records = dict(
            job=w.job, intent=dict(operation_id=w.op, helper_epoch=w.epoch, action='reload',
                                  allow_insecure=False, single_dispatch=True),
            response=self.response, result=dict(state='UNKNOWN', operation_id=w.op,
                error_class='ValueError', code='CORE_RELOAD_INVALID'),
            claim=dict(pid=123456789), pending=dict(operation_id=w.op))
        self.save()
        self.original = {p.name:p.read_bytes() for p in self.root.iterdir()}
        def request(q, timeout=5):
            self.requests.append(q)
            self.assertIn(q['action'], ('status','startup.read','stop'))
            if q['action']=='stop':
                self.assertIs(q['allow_insecure'],False)
                self.assertTrue((self.root/'stop-intent.json').exists())
                self.current.update(loaded=False,running=False);self.rows=[]
                return dict(self.response,code='',ok=True,operation_id=q['operation_id'],
                            diagnostics=stop_diagnostics())
            if q['action']=='startup.read':
                if q['operation_id']!=w.op:
                    t=copy.deepcopy(self.trace)
                    t['operation_id']=q['operation_id']
                    t['trace'].update(operation_id=q['operation_id'],operation='STOP',source='MANUAL_STOP',
                                      lifecycle_result='SUCCEEDED',helper_return='SUCCEEDED')
                    t['trace'].update(receipt_result='NOT_ATTEMPTED',diagnostics=stop_diagnostics())
                    # control_helper.executeContext/startupFinish: STOP does not
                    # traverse RELOAD's preflight. Match the real wire control.
                    s=t['trace']['streams'][0];base=s['events'][0];s['events']=[]
                    for seq,stage,state,code,segment,span in (
                        (1,'HELPER_ACCEPT','OBSERVATION','OK','PREFLIGHT',None),
                        (2,'HELPER_FINAL_STATE','BEGIN','NONE','FINALIZE','1'),
                        (3,'HELPER_FINAL_STATE','END','OK','FINALIZE','1'),
                        (4,'HELPER_FINISH','OBSERVATION','OK','FINALIZE',None)):
                        s['events'].append(dict(base,seq=str(seq),stage=stage,state=state,code=code,
                            segment=segment,span_id=span,elapsed_ns=str(seq),duration_ns='1' if state=='END' else None))
                    s.update(generated_events='4',retained_ranges=[dict(first='1',last='4')],elapsed_ns='5')
                    s['terminal'].update(result='SUCCEEDED',elapsed_ns='5')
                    return t
                return copy.deepcopy(self.trace)
            return copy.deepcopy(self.current)
        self.patch = mock.patch.dict(b.CORE_RELOAD_SUPPORT, request=request,
            helper_hash=lambda:w.digest, processes=lambda app, timeout=5:copy.deepcopy(self.rows))
        self.patch.start(); self.addCleanup(self.patch.stop)
        self.ps = mock.patch.object(b.subprocess, 'run', return_value=types.SimpleNamespace(
            returncode=0, stdout=b'1 0 Thu Nov 5 01:02:03 2026 /sbin/launchd\n', stderr=b''))
        self.ps.start(); self.addCleanup(self.ps.stop)

    def save(self):
        for name, value in self.records.items():
            path = self.root/(name+'.json')
            path.write_text(json.dumps(value)); path.chmod(0o600)

    def guard(self):
        with b.installation_lock(self.app):
            b.core_reload_guard(self.app)

    def unchanged(self):
        for name, raw in self.original.items():
            if name!='pending.json':
                self.assertEqual((self.root/name).read_bytes(), raw)
        self.assertFalse(any(q['action'] not in ('status','startup.read','stop') for q in self.requests))
        self.assertEqual(list(self.app.glob('.core-reload-*')), [self.root])

    def test_actual_guard_reconciles_native_preflight_without_archive(self):
        self.guard()
        marker = json.loads((self.root/'reconciled.json').read_bytes())
        self.assertEqual(marker['status'], 'RECONCILED_PREFLIGHT_REJECTED')
        self.assertFalse((self.root/'pending.json').exists())
        self.unchanged()
        with mock.patch.dict(b.CORE_RELOAD_SUPPORT, request=mock.Mock(side_effect=AssertionError('no reread'))):
            self.guard()
        with mock.patch.dict(b.CORE_RELOAD_SUPPORT, capture=mock.Mock(return_value=dict(state='STOPPED'))):
            with b.installation_lock(self.app):
                self.assertEqual(b.CoreReload(self.app).before['state'], 'STOPPED')

    def blocked(self):
        with self.assertRaisesRegex(ValueError, 'UNKNOWN/pending'):
            self.guard()
        self.assertTrue((self.root/'pending.json').exists())
        self.assertFalse((self.root/'reconciled.json').exists())

    def test_rotated_timeline_typed_mismatch_uses_original_bound_response(self):
        self.trace = dict(timeline_schema=1,code='OPERATION_MISMATCH',helper_epoch=self.w.epoch,
                          config_identity=self.w.identity,operation_id='f'*32,trace=None)
        self.guard()
        marker=json.loads((self.root/'reconciled.json').read_bytes())
        self.assertEqual(marker['helper_read']['code'],'OPERATION_MISMATCH')
        self.unchanged()
        self.guard()

    def test_rotated_mismatch_does_not_excuse_missing_response_or_identity(self):
        self.trace=dict(timeline_schema=1,code='OPERATION_MISMATCH',helper_epoch=self.w.epoch,
                        config_identity=self.w.identity,operation_id='f'*32,trace=None)
        baseline=self.trace.copy()
        for key,value in [('helper_epoch','b'*32),('config_identity','b'*64),
                          ('operation_id',self.w.op),('operation_id',None),('timeline_schema',True),
                          ('trace',{}),('code','NO_OPERATION')]:
            with self.subTest(key=key):
                self.trace=dict(baseline,**{key:value});self.blocked()
        self.trace=baseline
        (self.root/'response.json').unlink();self.blocked()

    def test_job_unknown_fields_claim_bool_and_legacy_intent_type_block(self):
        for name,key,value in [('job','operation_id','A'*32),('job','extra',True),
                               ('claim','pid',True),('intent','allow_insecure',1),
                               ('intent','single_dispatch',1),('intent','helper_epoch','b'*32)]:
            saved=copy.deepcopy(self.records[name])
            with self.subTest(name=name,key=key):
                self.records[name][key]=value;self.save();self.blocked()
            self.records[name]=saved
        self.save()
        self.records['job']['before']['status']=dict(self.w.status, helper_sha256='b'*64,helper_version='v0.1')
        self.save();self.guard()  # before helper replacement may legitimately be older

    def test_legacy_and_current_intent_and_original_running_are_supported(self):
        self.records['intent']['allow_insecure'] = True
        self.save()
        self.current.update(loaded=True,running=True)
        self.rows = [self.w.old]
        self.guard()
        self.assertIsNone(json.loads((self.root/'reconciled.json').read_bytes())['current']['core'])
        self.assertEqual(sum(q['action']=='stop' for q in self.requests),1)

    def test_response_identity_and_diagnostics_matrix(self):
        cases = [('operation_id','b'*32),('helper_epoch','b'*32),('helper_sha256','b'*64),
                 ('helper_version','v0'),('config_identity','b'*64),('timeline_schema',True),
                 ('code','TIMEOUT'),('ok',True),('loaded',True),('running',True),
                 ('timeline_availability','UNAVAILABLE')]
        baseline = copy.deepcopy(self.response)
        for key, value in cases:
            with self.subTest(key=key):
                self.records['response'] = dict(baseline, **{key:value}); self.save(); self.blocked()
        for key,value in [('stage','HELPER_STOP'),('receipt','WRITTEN'),('cleanup','VERIFIED'),
                          ('job','RUNNING'),('tun','TUN'),('schema',True),('outcome','SUCCEEDED')]:
            with self.subTest(diag=key):
                self.records['response']=copy.deepcopy(baseline)
                self.records['response']['diagnostics'][key]=value
                self.save(); self.blocked()

    def test_trace_incomplete_foreign_and_lifecycle_mutations_block(self):
        baseline = copy.deepcopy(self.trace)
        def assign(path,value):
            d=self.trace
            for part in path[:-1]: d=d[part]
            d[path[-1]]=value
        cases = [(['helper_epoch'],'b'*32),(['operation_id'],'b'*32),(['code'],'NO_OPERATION'),
                 (['trace','operation_id'],'b'*32),(['trace','authority'],'AUTHORITY'),
                 (['trace','helper_epoch'],'b'*32),(['trace','diagnostics','stage'],'HELPER_STOP'),
                 (['trace','streams',0,'gap'],True),(['trace','streams',0,'dropped_events'],'1'),
                 (['trace','streams',0,'first_missing_seq'],'1'),
                 (['trace','streams',0,'retained_ranges'],[]),
                 (['trace','streams',0,'events',4,'stage'],'HELPER_STOP'),
                 (['trace','streams',0,'events',4,'stage'],'CORE_START'),
                 (['trace','streams',0,'events',4,'elapsed_ns'],'0'),
                 (['trace','streams',0,'events',4,'seq'],'7'),
                 (['trace','streams',0,'terminal','result'],'SUCCEEDED'),
                 (['trace','streams',0,'provenance','sha256'],'b'*64),
                 (['trace','streams',0,'events'],[]),(['trace','unknown'],True)]
        for path,value in cases:
            with self.subTest(path=path):
                self.trace=copy.deepcopy(baseline);assign(path,value);self.blocked()

    def test_current_helper_config_selection_and_core_drift_block(self):
        baseline = self.current.copy()
        for key,value in [('helper_sha256','b'*64),('helper_version','v0'),('config_identity','b'*64),
                          ('loaded',True),('running',True),('ok',False)]:
            with self.subTest(key=key):
                self.current=dict(baseline,**{key:value}); self.blocked()
        self.current = baseline
        self.rows = [dict(self.w.old,pid=999)]
        self.blocked()
        self.rows=[]
        (self.app/'config.yaml.selected').write_text('new selection')
        (self.app/'config.yaml').write_text('changed config')
        self.guard()
        self.unchanged()

    def test_live_or_reused_claim_pid_and_bad_census_block(self):
        for raw,rc,err in [(b'',0,b''),(b'broken\n',0,b''),
                           (b'123456789 0 Thu Nov 5 01:02:03 2026 unrelated\n',0,b''),
                           (b'1 0 Thu Nov 5 01:02:03 2026 init\n',1,b''),
                           (b'1 0 Thu Nov 5 01:02:03 2026 init\n',0,b'warning')]:
            with self.subTest(raw=raw), mock.patch.object(b.subprocess,'run',return_value=types.SimpleNamespace(
                stdout=raw,returncode=rc,stderr=err)):
                self.blocked()

    def test_unsafe_receipts_and_unknown_shape_or_duplicates_block(self):
        path=self.root/'response.json';raw=path.read_bytes()
        for changed in [raw[:-1]+b',"ok":true}',raw[:-1]+b',"extra":true}',b'null',b'x'*(768*1024+1)]:
            with self.subTest(kind=changed[:15]):
                path.write_bytes(changed);self.blocked()
        path.write_bytes(raw)
        path.chmod(0o644);self.blocked();path.chmod(0o600)
        link=self.root/'foreign';os.link(path,link);self.blocked();link.unlink()
        path.unlink();path.symlink_to(self.root/'job.json');self.blocked();path.unlink();path.write_bytes(raw);path.chmod(0o600)
        self.root.chmod(0o755);self.blocked();self.root.chmod(0o700)
        for key,value in [('state','SUCCEEDED'),('state','REJECTED'),('code','CORE_RELOAD_TIMEOUT')]:
            saved=self.records['result'].copy();self.records['result'][key]=value;self.save();self.blocked();self.records['result']=saved
        self.save();path.unlink();self.blocked()

    def test_marker_hash_change_deletion_foreign_and_pending_resurrection_block(self):
        self.guard()
        raw=(self.root/'result.json').read_bytes()
        (self.root/'result.json').write_bytes(raw+b' ')
        with self.assertRaisesRegex(ValueError,'UNKNOWN/pending'):self.guard()
        (self.root/'result.json').write_bytes(raw)
        marker=json.loads((self.root/'reconciled.json').read_bytes())
        marker['operation_id']='b'*32
        (self.root/'reconciled.json').write_text(json.dumps(marker))
        with self.assertRaisesRegex(ValueError,'UNKNOWN/pending'):self.guard()
        marker['operation_id']=self.w.op
        (self.root/'reconciled.json').write_text(json.dumps(marker))
        (self.root/'pending.json').write_text(json.dumps(dict(operation_id=self.w.op)))
        with self.assertRaisesRegex(ValueError,'UNKNOWN/pending'):self.guard()
        self.assertTrue((self.root/'pending.json').exists())
        (self.root/'job.json').unlink()
        with self.assertRaisesRegex(ValueError,'UNKNOWN/pending'):self.guard()

    def test_write_fsync_directory_sync_readback_and_unlink_fail_closed(self):
        real_fsync=os.fsync
        for target in ('write','file','directory','readback','unlink'):
            with self.subTest(target=target):
                def fsync(fd):
                    import stat
                    isdir=stat.S_ISDIR(os.fstat(fd).st_mode)
                    if (target=='file' and not isdir) or (target=='directory' and isdir):
                        raise OSError('synthetic durability failure')
                    return real_fsync(fd)
                real_read=b.reconciliation_receipt
                def read(root,name):
                    if target=='readback' and name=='reconciled.json':raise ValueError('synthetic readback')
                    return real_read(root,name)
                with contextlib.ExitStack() as stack:
                    if target=='write':stack.enter_context(mock.patch.dict(b.CORE_RELOAD_SUPPORT,put=mock.Mock(side_effect=OSError('write'))))
                    if target in ('file','directory'):stack.enter_context(mock.patch.object(os,'fsync',side_effect=fsync))
                    if target=='readback':stack.enter_context(mock.patch.object(b,'reconciliation_receipt',side_effect=read))
                    if target=='unlink':stack.enter_context(mock.patch.object(Path,'unlink',side_effect=OSError('unlink')))
                    with self.assertRaisesRegex(ValueError,'UNKNOWN/pending'):self.guard()
                self.assertTrue((self.root/'pending.json').exists());self.unchanged()
                if (self.root/'reconciled.json').exists():
                    with self.assertRaisesRegex(ValueError,'UNKNOWN/pending'):self.guard()
                    (self.root/'reconciled.json').unlink()  # owned fixture reset, NOT production recovery

    def test_no_lock_or_other_thread_cannot_reconcile(self):
        with self.assertRaisesRegex(ValueError,'UNKNOWN/pending'): b.core_reload_guard(self.app)
        import threading
        errors=[]
        with b.installation_lock(self.app):
            def other():
                try:b.core_reload_guard(self.app)
                except ValueError as e:errors.append(str(e))
            t=threading.Thread(target=other);t.start();t.join(timeout=2)
        self.assertEqual(len(errors),1);self.assertTrue((self.root/'pending.json').exists())
        self.assertEqual(self.requests,[])

    def test_guard_all_real_callers_hold_lock_before_permit(self):
        def permit(app):
            b.reconciliation_lock_required(app)
            return real_guard(app)
        real_guard=b.core_reload_guard
        # Use real guard, constructor and entry orchestration; stop at the existing
        # mutation seam after permission, never execute native helper/install.
        spec=importlib.util.spec_from_file_location('reconcile_install_fixture',Path(__file__).with_name('install_binary_test.py'))
        im=importlib.util.module_from_spec(spec);spec.loader.exec_module(im)
        im.b=b
        c=im.InstallerTests();c.setUp();self.addCleanup(c.doCleanups)
        c.app=self.app
        c.processes=[]
        _,bundle,_,_=c.verified()
        class Reached(Exception):pass
        with mock.patch.object(b,'core_reload_guard',side_effect=permit), \
             mock.patch.dict(b.CORE_RELOAD_SUPPORT,capture=lambda app:dict(state='STOPPED')), \
             contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
            for reload in (True,False):
                b.install_verified(bundle,im.TAG,self.app,c.home,c.runner,
                                   env={'HOME':str(c.home)},tty=lambda:io.BytesIO(),reload_core=reload)
            with b.installation_lock(self.app):b.CoreReload(self.app)
            # Real full-run default and explicit opt-out traverse the SAME
            # reconciled journal before the existing install mutation seam.
            with mock.patch.object(b,'_install_verified',side_effect=Reached):
                for reload in (None,False):
                    args=types.SimpleNamespace(check_download=False,version=im.TAG,arch=None,reload_core=reload)
                    with self.assertRaises(Reached):
                        b.run(args,transport=c.transport,runner=c.runner,system='Darwin',machine='arm64',
                              euid=501,home=self.app.parent,env={'HOME':str(self.app.parent)})
        # update_only reaches download only AFTER a real locked guard.
        args=types.SimpleNamespace(update_arch='arm64',check_download=False,arch=None,version='v1.2.3',
                                   app_dir=str(self.app),target=str(self.app/'anytls-macos'))
        reached=[]
        def download(*a,**kw):
            b.reconciliation_lock_required(self.app);reached.append(True);raise Reached()
        with mock.patch.object(b,'core_reload_guard',side_effect=permit),mock.patch.object(b,'verified_download',side_effect=download):
            with self.assertRaises(b.UpdateFailed):b.update_only(args,system='Darwin',machine='arm64',euid=501)
        self.assertEqual(reached,[True])

    def test_pending_invalid_response_blocks_real_install_before_any_mutation(self):
        self.records['response']['helper_epoch']='b'*32;self.save()
        spec=importlib.util.spec_from_file_location('reconcile_block_fixture',Path(__file__).with_name('install_binary_test.py'))
        im=importlib.util.module_from_spec(spec);spec.loader.exec_module(im)
        im.b=b
        c=im.InstallerTests();c.setUp();self.addCleanup(c.doCleanups)
        c.processes=[]
        _,bundle,_,_=c.verified()
        with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
            for reload in (True,False):
                with self.assertRaisesRegex(ValueError,'UNKNOWN/pending'):
                    b.install_verified(bundle,im.TAG,self.app,c.home,c.runner,
                                       env={'HOME':str(c.home)},tty=lambda:io.BytesIO(),reload_core=reload)
            for reload in (None,False):
                args=types.SimpleNamespace(check_download=False,version=im.TAG,arch=None,reload_core=reload)
                with self.assertRaisesRegex(ValueError,'UNKNOWN/pending'):
                    b.run(args,transport=c.transport,runner=c.runner,system='Darwin',machine='arm64',
                          euid=501,home=self.app.parent,env={'HOME':str(self.app.parent)})
        self.assertEqual(c.processes,[])
        c.webui_factory.assert_not_called()
        self.assertEqual(self.requests,[])
        self.assertFalse((self.app/'releases').exists())

    def test_no_journal_does_not_read_helper(self):
        for p in self.root.iterdir():p.unlink()
        self.root.rmdir()
        with mock.patch.dict(b.CORE_RELOAD_SUPPORT,request=mock.Mock(side_effect=AssertionError('helper'))):
            b.core_reload_guard(self.app)



class ReconcileR2(unittest.TestCase):
    setUp = Reconcile.setUp
    save = Reconcile.save
    guard = Reconcile.guard
    blocked = Reconcile.blocked
    unchanged = Reconcile.unchanged

    def test_installed_binary_drift_at_each_observation(self):
        real=b.CORE_RELOAD_SUPPORT['file_hash']
        for at in range(1, 7):
            calls=[]
            def hashed(path):
                digest=real(path)
                if path==self.app/'anytls-macos':
                    calls.append(path)
                    if len(calls)>=at:return 'f'*64
                return digest
            with self.subTest(observation=at), mock.patch.dict(b.CORE_RELOAD_SUPPORT,file_hash=hashed):
                with self.assertRaisesRegex(ValueError,'UNKNOWN/pending'):self.guard()
            self.assertTrue((self.root/'pending.json').exists())
            if (self.root/'reconciled.json').exists():(self.root/'reconciled.json').unlink()

    def test_retained_semantic_scalars_and_spans(self):
        baseline=copy.deepcopy(self.trace)
        changes=[('duration_ns',None,4),('duration_ns','1',3),('duration_ns','00',4),
                 ('duration_ns','2',4),('duration_ns',True,4),('duration_ns','18446744073709551616',4),
                 ('elapsed_ns','18446744073709551616',4),('elapsed_ns','01',4),
                 ('at','not-a-time',4),('at','2026-02-30T01:02:05Z',4),
                 ('at','2026-11-04T01:02:05.0Z',4),('at','2026-11-04T01:02:05+00:00',4),
                 ('at','2026-11-04T01:02:05.1234567890Z',4)]
        for key,value,index in changes:
            with self.subTest(key=key,value=value):
                self.trace=copy.deepcopy(baseline)
                self.trace['trace']['streams'][0]['events'][index][key]=value
                self.blocked()
        for path in [('started_at',),('finished_at',),('streams',0,'origin_at'),
                     ('streams',0,'terminal','at'),('streams',0,'terminal','elapsed_ns')]:
            self.trace=copy.deepcopy(baseline);d=self.trace['trace']
            for k in path[:-1]:d=d[k]
            d[path[-1]]='bad'
            with self.subTest(path=path):self.blocked()

    def test_timestamp_year_zero_and_nano_precision_valid(self):
        t=self.trace['trace'];t['started_at']='0000-01-01T00:00:00Z'
        t['finished_at']='9999-12-31T23:59:59.123456789Z'
        self.guard()

    def test_stored_proof_nested_primitives_strict(self):
        self.current.update(loaded=True,running=True);self.rows=[copy.deepcopy(self.w.old)]
        self.guard();p=self.root/'reconciled.json';original=json.loads(p.read_bytes())
        original['current'].update(state='RUNNING',core=copy.deepcopy(self.w.old))
        original['current']['status'].update(loaded=True,running=True)
        changes=[(('schema',),True),(('current','core','uid'),False),
                 (('current','core','pid'),True),(('current','core','birth'),False),
                 (('current','config','config'),False),(('current','config','selection'),False),
                 (('current','config','identity'),True),(('current','status','loaded'),1),
                 (('current','status','running'),1),(('receipt_sha256','claim.json'),True),
                 (('helper_read','trace','diagnostics','schema'),True),
                 (('helper_read','trace','streams',0,'provenance','dirty'),0)]
        for path,value in changes:
            marker=copy.deepcopy(original);d=marker
            for k in path[:-1]:d=d[k]
            d[path[-1]]=value;p.write_text(json.dumps(marker))
            with self.subTest(path=path), self.assertRaisesRegex(ValueError,'UNKNOWN/pending'):self.guard()
        for path in [('current','config'),('receipt_sha256',),('current','core')]:
            marker=copy.deepcopy(original);d=marker
            for k in path:d=d[k]
            d['unknown']=None;p.write_text(json.dumps(marker))
            with self.subTest(extra=path), self.assertRaisesRegex(ValueError,'UNKNOWN/pending'):self.guard()

    def test_fresh_core_bool_is_not_root_int(self):
        self.current.update(loaded=True,running=True);self.rows=[dict(self.w.old,uid=False)]
        self.blocked()

    def test_stopped_changed_content_is_pinned_without_restoring(self):
        old=copy.deepcopy(self.records['job']['before']['config'])
        (self.app/'config.yaml').write_text('new config selected by user')
        (self.app/'config.yaml.selected').write_text('new user selection')
        fresh=b.CORE_RELOAD_SUPPORT['config_pin'](self.app)
        self.assertNotEqual(old,fresh);self.guard();self.unchanged()
        marker=json.loads((self.root/'reconciled.json').read_bytes())
        self.assertEqual(marker['current']['config'],fresh)
        self.assertEqual(marker['current']['state'],'STOPPED')
        self.assertEqual(json.loads((self.root/'job.json').read_bytes())['before']['config'],old)
        self.guard()

    def test_running_new_core_and_content_drift_stops_once(self):
        self.current.update(loaded=True,running=True);self.rows=[copy.deepcopy(self.w.old)]
        self.rows=[dict(self.w.old,pid=91,birth='new core birth')]
        (self.app/'config.yaml').write_text('changed config');self.guard();self.guard()
        self.assertEqual(sum(q['action']=='stop' for q in self.requests),1)
        self.assertIsNone(json.loads((self.root/'reconciled.json').read_bytes())['current']['core'])

    def test_config_changes_during_every_fence_block(self):
        real=b.CORE_RELOAD_SUPPORT['config_pin']
        for at in range(2,9):
            calls=[]
            def pinned(app):
                pin=real(app);calls.append(1)
                if len(calls)>=at:pin['config']='f'*64
                return pin
            with self.subTest(at=at), mock.patch.dict(b.CORE_RELOAD_SUPPORT,config_pin=pinned):
                with self.assertRaisesRegex(ValueError,'UNKNOWN/pending'):self.guard()
            self.assertTrue((self.root/'pending.json').exists())
            if (self.root/'reconciled.json').exists():(self.root/'reconciled.json').unlink()

    def test_path_identity_drift_blocks_even_stopped(self):
        fresh=b.CORE_RELOAD_SUPPORT['config_pin'](self.app);fresh['identity']='f'*64
        with mock.patch.dict(b.CORE_RELOAD_SUPPORT,config_pin=lambda app:fresh):self.blocked()

    def test_deadline_before_marker_and_before_unlink(self):
        realread=b.reconciliation_receipt;clock=[0.0]
        for boundary in ('response.json','reconciled.json'):
            clock[0]=0.0
            def read(root,name):
                value=realread(root,name)
                if name==boundary:clock[0]=25.1
                return value
            with self.subTest(boundary=boundary), mock.patch.object(b.time,'monotonic',side_effect=lambda:clock[0]), \
                 mock.patch.object(b,'reconciliation_receipt',side_effect=read):
                with self.assertRaisesRegex(ValueError,'UNKNOWN/pending'):self.guard()
            self.assertTrue((self.root/'pending.json').exists());self.unchanged()
            if (self.root/'reconciled.json').exists():(self.root/'reconciled.json').unlink()

    def test_aggregate_budget_through_real_process_parsers(self):
        n={'__name__':'r2_real_parser'};exec(b.CORE_RELOAD_WORKER,n)
        clock=[0.0];bounds=[];counts={'ps':0,'request':0}
        realreq=b.CORE_RELOAD_SUPPORT['request']
        def boundary(timeout):
            bounds.append(timeout);self.assertGreater(timeout,0);self.assertLessEqual(timeout,5)
            clock[0]+=3.05
        def run(argv,**kw):
            counts['ps']+=1;boundary(kw['timeout'])
            return types.SimpleNamespace(returncode=0,stdout=b'1 0 Thu Nov 5 01:02:03 2026 init\n',stderr=b'')
        def processes(app,timeout=5):return n['processes'](app,timeout=timeout)
        def request(q,timeout=5):counts['request']+=1;boundary(timeout);return realreq(q,timeout)
        with mock.patch.object(b.time,'monotonic',side_effect=lambda:clock[0]), \
             mock.patch.object(b.subprocess,'run',side_effect=run), \
             mock.patch.dict(b.CORE_RELOAD_SUPPORT,request=request,processes=processes):
            with self.assertRaisesRegex(ValueError,'UNKNOWN/pending'):self.guard()
        self.assertGreaterEqual(sum(counts.values()),8)
        self.assertTrue(any(v<5 for v in bounds))
        self.assertTrue((self.root/'pending.json').exists());self.unchanged()

    def test_stop_transport_authenticates_before_send_and_rejects_wrong_bool(self):
        n={'__name__':'r2_stop_transport'};exec(b.CORE_RELOAD_WORKER,n)
        events=[];sock=mock.MagicMock();sock.__enter__.return_value=sock
        sock.recv.side_effect=[b'{}',b'']
        def authenticate(s):s.sendall.assert_not_called();events.append('auth')
        sock.sendall.side_effect=lambda raw:events.append(json.loads(raw)['action'])
        q=dict(timeline_schema=1,action='stop',operation_id='f'*32,allow_insecure=False)
        with mock.patch.object(n['socket'],'socket',return_value=sock), mock.patch.dict(n,root_peer=authenticate):
            n['request'](q)
        self.assertEqual(events,['auth','stop'])
        for value in (True,0,1,None):
            with self.subTest(value=value),self.assertRaises(ValueError):n['request'](dict(q,allow_insecure=value))

    def test_stop_receipt_failures_hold_before_clearance(self):
        realput=b.CORE_RELOAD_SUPPORT['put']
        self.current.update(loaded=True,running=True);self.rows=[dict(self.w.old,pid=91)]
        def put(root,name,value):
            if name=='stop-intent.json':raise OSError('durability')
            return realput(root,name,value)
        with mock.patch.dict(b.CORE_RELOAD_SUPPORT,put=put):self.blocked()
        self.assertEqual(sum(q['action']=='stop' for q in self.requests),0)
        def put(root,name,value):
            if name=='stop-response.json':raise OSError('durability')
            return realput(root,name,value)
        with mock.patch.dict(b.CORE_RELOAD_SUPPORT,put=put):self.blocked()
        self.assertEqual(sum(q['action']=='stop' for q in self.requests),1)
        self.guard();self.guard()
        self.assertEqual(sum(q['action']=='stop' for q in self.requests),1)

    def test_reconciliation_stop_is_not_reinterpreted_as_reload_before_state(self):
        self.current.update(loaded=True,running=True);self.rows=[dict(self.w.old,pid=91)]
        with mock.patch.dict(b.CORE_RELOAD_SUPPORT,capture=lambda app:dict(state='RUNNING' if self.current['running'] else 'STOPPED')):
            with b.installation_lock(self.app):operation=b.CoreReload(self.app)
        self.assertEqual(operation.before['state'],'STOPPED')
        with contextlib.redirect_stdout(io.StringIO()):operation.finish(self.w.digest,self.w.tag,self.w.rev)
        self.assertEqual(sum(q['action']=='stop' for q in self.requests),1)
        self.assertFalse(any(q['action']=='reload' for q in self.requests))

    def test_already_stopped_never_dispatches_stop(self):
        self.guard();self.guard()
        self.assertEqual(sum(q['action']=='stop' for q in self.requests),0)

    def test_stop_failure_or_timeout_preserves_pending_never_resends(self):
        real=b.CORE_RELOAD_SUPPORT['request'];sent=[]
        self.current.update(loaded=True,running=True);self.rows=[dict(self.w.old,pid=91)]
        def request(q,timeout=5):
            if q['action']=='stop':sent.append(q);raise TimeoutError('owned timeout')
            if q['action']=='startup.read' and q['operation_id']!=self.w.op:
                raise TimeoutError('stop outcome unavailable')
            return real(q,timeout)
        with mock.patch.dict(b.CORE_RELOAD_SUPPORT,request=request):
            self.blocked();self.blocked()
        self.assertEqual(len(sent),1);self.unchanged()
        self.assertTrue((self.root/'stop-intent.json').exists())
        self.current.update(loaded=False,running=False);self.rows=[]
        self.guard()  # exact operation read + fresh stopped proof, no second dispatch
        self.assertEqual(len(sent),1)
        self.assertEqual(sum(q['action']=='stop' for q in self.requests),0)

    def test_stop_failed_timeline_does_not_clear_pending(self):
        real=b.CORE_RELOAD_SUPPORT['request'];sent=[]
        self.current.update(loaded=True,running=True);self.rows=[dict(self.w.old,pid=91)]
        def request(q,timeout=5):
            if q['action']=='stop':sent.append(q)
            value=real(q,timeout)
            if q['action']=='startup.read' and q['operation_id']!=self.w.op:
                value['trace']['lifecycle_result']='FAILED'
            return value
        with mock.patch.dict(b.CORE_RELOAD_SUPPORT,request=request):
            self.blocked();self.blocked()
        self.assertEqual(len(sent),1)

    def test_lost_stop_reply_can_resolve_exact_success_without_retry(self):
        real=b.CORE_RELOAD_SUPPORT['request'];sent=[]
        self.current.update(loaded=True,running=True);self.rows=[dict(self.w.old,pid=91)]
        def request(q,timeout=5):
            value=real(q,timeout)
            if q['action']=='stop':sent.append(q);raise TimeoutError('reply lost after stop')
            return value
        with mock.patch.dict(b.CORE_RELOAD_SUPPORT,request=request):self.guard();self.guard()
        self.assertEqual(len(sent),1);self.assertFalse((self.root/'pending.json').exists())

    def test_retained_r3_content_hashes_stopped_not_rebound(self):
        old=dict(config='4449ece2ccc801cea37ccf0c94c1d05758943dbbb0eb3bd669168435ae99e6a7',
                 selection='72dce7c5500728df65722fe50312c25f969548ae21f30ac6bc31f0f9ec317a6f')
        fresh=dict(identity=self.w.identity,config='d89a3d0d492ad1a45465b1a277aa034d5bd2759219781d8cb440863034698b9f',
                   selection='85a7cfe53a21b35944ca4f68894478e4ac2a18af207566ce9e2112cdf435600f')
        self.records['job']['before']['config'].update(old);self.save()
        self.trace=dict(timeline_schema=1,code='OPERATION_MISMATCH',helper_epoch=self.w.epoch,
                        config_identity=self.w.identity,operation_id='f'*32,trace=None)
        with mock.patch.dict(b.CORE_RELOAD_SUPPORT,config_pin=lambda app:copy.deepcopy(fresh)):self.guard();self.guard()
        marker=json.loads((self.root/'reconciled.json').read_bytes())
        self.assertEqual(marker['current']['config'],fresh)
        self.assertEqual(json.loads((self.root/'job.json').read_bytes())['before']['config']['config'],old['config'])

class ReconcileR3(unittest.TestCase):
    @contextlib.contextmanager
    def fixture(self, running=True):
        c=Reconcile();c.setUp()
        if running:
            c.current.update(loaded=True,running=True);c.rows=[dict(c.w.old,pid=91)]
        try:yield c
        finally:c.doCleanups()

    @contextlib.contextmanager
    def wire(self,c,alter=lambda q,v:v,raw=None,peer_error=False):
        n={'__name__':'r3_real_transport'};exec(b.CORE_RELOAD_WORKER,n)
        original=b.CORE_RELOAD_SUPPORT['request'];events=[]
        class Socket:
            def __enter__(self):return self
            def __exit__(self,*a):pass
            def settimeout(self,t):pass
            def connect(self,p):pass
            def shutdown(self,v):pass
            def sendall(self,data):
                q=json.loads(data);events.append(q['action'])
                if q['action']=='stop':
                    intent,_=b.reconciliation_receipt(c.root,'stop-intent.json')
                    c.assertEqual(intent['operation_id'],q['operation_id'])
                value=alter(q,original(q))
                self.data=raw if raw is not None and q['action']=='stop' else json.dumps(value).encode()
                self.used=False
            def recv(self,n):
                if self.used:return b''
                self.used=True;return self.data
        def peer(s):
            if peer_error:raise ValueError('CORE_RELOAD_PEER_NOT_ROOT')
        with mock.patch.object(n['socket'],'socket',side_effect=lambda *a:Socket()), \
             mock.patch.dict(n,root_peer=peer),mock.patch.dict(b.CORE_RELOAD_SUPPORT,request=n['request']):
            yield events

    def nested_stop(self,c,q,v):
        # Retained review-r4/nested_stop_probe.py source-shaped restoration path:
        # stopRound -> traceRemove -> traceCapture -> Recorder.Observe.
        if q['action']=='startup.read' and q['operation_id']!=c.w.op:
            s=v['trace']['streams'][0];base=s['events'][0];events=[]
            spec=[('HELPER_ACCEPT','OBSERVATION','OK','PREFLIGHT',None,None),
                  ('STOP_ROUND','BEGIN','NONE','STOP','2',None),
                  ('JOB_INITIAL','BEGIN','NONE','STOP','3',None),
                  ('JOB_INITIAL','END','OK','STOP','3','1'),
                  ('CORE_SNAPSHOT_CAPTURE','OBSERVATION','UNAVAILABLE','STOP','2',None),
                  ('SNAPSHOT_REMOVE','BEGIN','NONE','STOP','4',None),
                  ('SNAPSHOT_REMOVE','END','OK','STOP','4','1'),
                  ('STOP_ROUND','END','OK','STOP','2','6'),
                  ('HELPER_FINAL_STATE','BEGIN','NONE','FINALIZE','5',None),
                  ('HELPER_FINAL_STATE','END','OK','FINALIZE','5','1'),
                  ('HELPER_FINISH','OBSERVATION','OK','FINALIZE',None,None)]
            for seq,(stage,state,code,segment,span,duration) in enumerate(spec,1):
                events.append(dict(base,seq=str(seq),stage=stage,state=state,code=code,
                    segment=segment,span_id=span,duration_ns=duration,elapsed_ns=str(seq)))
            s.update(events=events,generated_events='11',retained_ranges=[dict(first='1',last='11')],elapsed_ns='12')
            s['terminal']['elapsed_ns']='12'
        return v

    def test_stop_nested_observation_active_top_allows_one_stop(self):
        with self.fixture() as c,self.wire(c,lambda q,v:self.nested_stop(c,q,v)) as events:
            c.guard();c.guard()
            self.assertEqual(events.count('stop'),1)
            self.assertFalse((c.root/'pending.json').exists())
            self.assertTrue((c.root/'reconciled.json').exists());c.unchanged()

    def test_stop_nested_observation_and_end_stack_negatives(self):
        for case in ('unknown','parent','null','missing','duration','outside','end_order'):
            with self.subTest(case=case),self.fixture() as c:
                def alter(q,v):
                    self.nested_stop(c,q,v)
                    if q['action']=='startup.read' and q['operation_id']!=c.w.op:
                        e=v['trace']['streams'][0]['events'];obs=e[4]
                        if case=='unknown':obs['span_id']='99'
                        elif case=='null':obs['span_id']=None
                        elif case=='missing':del obs['span_id']
                        elif case=='duration':obs['duration_ns']='0'
                        elif case=='outside':e[0]['span_id']='2'
                        elif case=='parent':
                            # Observe STOP_ROUND while JOB_INITIAL is still top.
                            e[3],e[4]=e[4],e[3]
                            e[4]['duration_ns']='2'
                            for seq,event in enumerate(e,1):event.update(seq=str(seq),elapsed_ns=str(seq))
                        elif case=='end_order':
                            e[3].update(stage='STOP_ROUND',span_id='2',duration_ns='2')
                            obs['span_id']='3'
                            e[7].update(stage='JOB_INITIAL',span_id='3',duration_ns='5')
                    return v
                with self.wire(c,alter) as events:c.blocked()
                self.assertEqual(events.count('stop'),1);c.unchanged()

    def test_stop_real_wire_control_and_response_hash(self):
        with self.fixture() as c,self.wire(c) as events:
            c.guard();c.guard()
            marker=json.loads((c.root/'reconciled.json').read_bytes())
            self.assertEqual(set(marker['stop_sha256']),{'stop-intent.json','stop-read.json','stop-response.json'})
            self.assertEqual(events.count('stop'),1)

    def test_stop_real_wire_reply_identity_and_success_matrix(self):
        cases=[('operation_id','f'*32),('helper_epoch','f'*32),('config_identity','f'*64),
               ('helper_sha256','f'*64),('helper_version','vWrong'),('ok',False),('ok',1),
               ('code','STOP_FAILED'),('loaded',True),('running',True),('loaded',0),
               ('timeline_schema',True),('timeline_availability','UNAVAILABLE'),('extra',None)]
        cases += [('diagnostics.'+k,v) for k,v in [('schema',True),('operation','RELOAD'),
                  ('outcome','FAILED'),('stage','STOP'),('reason','STOP_FAILED'),('job','RUNNING'),('tun','TUN')]]
        for key,value in cases:
            with self.subTest(key=key,value=value),self.fixture() as c:
                def alter(q,v):
                    if q['action']=='stop':
                        d=v
                        if key.startswith('diagnostics.'):d=v['diagnostics']
                        d[key.split('.')[-1]]=value
                    return v
                with self.wire(c,alter):c.blocked()
                # Invalid received replies remain invalid on exact-success reentry.
                with self.assertRaisesRegex(ValueError,'UNKNOWN/pending'):c.guard()
                self.assertEqual(sum(q['action']=='stop' for q in c.requests),1)

    def test_stop_real_wire_invalid_json_null_frame_or_security_never_read_recovers(self):
        for raw in (b'{',b'null',b'{"ok":true,"ok":true}',b'x'*4097,b'',b'\xff'):
            with self.subTest(raw=raw[:20]),self.fixture() as c,self.wire(c,raw=raw):c.blocked()
        with self.fixture() as c:
            original=b.CORE_RELOAD_SUPPORT['request'];exact=[]
            def request(q,timeout=5):
                if q['action']=='stop':raise ValueError('CORE_RELOAD_PEER_NOT_ROOT')
                if q['action']=='startup.read' and q['operation_id']!=c.w.op:exact.append(q)
                return original(q,timeout)
            with mock.patch.dict(b.CORE_RELOAD_SUPPORT,request=request):c.blocked()
            self.assertEqual(exact,[])

    def test_stop_exact_read_provenance_terminal_and_scalar_matrix(self):
        changes=[(('streams',0,'provenance',k),v) for k,v in [('sha256','f'*64),('version','vWrong'),
            ('git_revision','f'*40),('dirty',0),('sha_kind','UNAVAILABLE'),('execution_mapping','ATTESTED')]]
        changes += [(('finished_at',),None),(('finished_at',),'2026-02-30T00:00:00Z'),
                    (('streams',0,'terminal','result'),'FAILED'),(('streams',0,'terminal'),None),
                    (('streams',0,'events',2,'duration_ns'),None),
                    (('streams',0,'events',2,'duration_ns'),'2'),
                    (('streams',0,'events',1,'duration_ns'),'1'),
                    (('streams',0,'events',2,'elapsed_ns'),'18446744073709551616'),
                    (('streams',0,'events',2,'at'),'bad'),(('streams',0,'gap'),True),
                    (('streams',0,'events',2,'span_id'),'9'),(('streams',0,'events',2,'code'),'FAILED')]
        for path,value in changes:
            with self.subTest(path=path,value=value),self.fixture() as c:
                def alter(q,v):
                    if q['action']=='startup.read' and q['operation_id']!=c.w.op:
                        d=v['trace']
                        for k in path[:-1]:d=d[k]
                        d[path[-1]]=value
                    return v
                with self.wire(c,alter):c.blocked()

    def test_stop_marker_retained_response_validation_even_if_rehashed(self):
        for rehash in (False,True):
            with self.subTest(rehash=rehash),self.fixture() as c:
                c.guard();p=c.root/'stop-response.json';v=json.loads(p.read_bytes());v['helper_sha256']='f'*64
                p.write_text(json.dumps(v))
                if rehash:
                    marker=json.loads((c.root/'reconciled.json').read_bytes())
                    marker['stop_sha256']['stop-response.json']=b.reconciliation_receipt(c.root,'stop-response.json')[1]
                    (c.root/'reconciled.json').write_text(json.dumps(marker))
                with self.assertRaisesRegex(ValueError,'UNKNOWN/pending'):c.guard()

    def test_stop_marker_empty_hash_downgrade_and_orphan_files_block(self):
        for name in ('stop-intent.json','stop-read.json','stop-response.json'):
            with self.subTest(name=name),self.fixture(running=False) as c:
                c.guard();p=c.root/name;p.write_text('{}');p.chmod(0o600)
                with self.assertRaisesRegex(ValueError,'UNKNOWN/pending'):c.guard()
        with self.fixture() as c:
            c.guard();p=c.root/'reconciled.json';v=json.loads(p.read_bytes());v['stop_sha256']={};p.write_text(json.dumps(v))
            (c.root/'stop-read.json').write_text('{}')
            with self.assertRaisesRegex(ValueError,'UNKNOWN/pending'):c.guard()

    def test_stop_pending_orphan_files_block_without_dispatch(self):
        for running in (False,True):
            for name in ('stop-read.json','stop-response.json'):
                with self.subTest(running=running,name=name),self.fixture(running=running) as c:
                    p=c.root/name;p.write_text('{}');p.chmod(0o600);c.blocked()
                    self.assertFalse(any(q['action']=='stop' for q in c.requests))

    def test_stop_response_file_and_directory_fsync_reentry_no_resend(self):
        import stat
        for kind in ('file','directory'):
            with self.subTest(kind=kind),self.fixture() as c:
                original=os.fsync
                def fsync(fd):
                    p=c.root/'stop-response.json';st=os.fstat(fd)
                    if p.exists() and (stat.S_ISDIR(st.st_mode) if kind=='directory' else
                        (st.st_dev,st.st_ino)==(p.stat().st_dev,p.stat().st_ino)):
                        raise OSError('owned response sync failure')
                    return original(fd)
                with mock.patch.object(os,'fsync',side_effect=fsync):c.blocked()
                c.guard();c.guard()
                self.assertEqual(sum(q['action']=='stop' for q in c.requests),1)

    def test_stop_success_allows_source_recovery_warning_and_real_lifecycle_spans(self):
        with self.fixture() as c:
            def alter(q,v):
                if q['action']=='stop':v['diagnostics'].update(restoration='FAILED',cleanup='VERIFIED',receipt='WRITTEN')
                if q['action']=='startup.read' and q['operation_id']!=c.w.op:
                    t=v['trace'];t['diagnostics'].update(restoration='FAILED',cleanup='VERIFIED',receipt='WRITTEN')
                    s=t['streams'][0];base=s['events'][0]
                    # A failed baseline capture is a valid successful STOP with
                    # restoration warning (serviceLifecycle.stopRecoveryWarning).
                    s['events'][1:1]=[
                        dict(base,stage='STOP_BASELINE',segment='STOP',state='BEGIN',code='NONE',span_id='2'),
                        dict(base,stage='STOP_BASELINE',segment='STOP',state='END',code='FAILED',span_id='2',duration_ns='1')]
                    for seq,event in enumerate(s['events'],1):event.update(seq=str(seq),elapsed_ns=str(seq))
                    s.update(generated_events='6',retained_ranges=[dict(first='1',last='6')],elapsed_ns='7')
                    s['terminal']['elapsed_ns']='7'
                return v
            with self.wire(c,alter):c.guard();c.guard()
            self.assertEqual(sum(q['action']=='stop' for q in c.requests),1)

    def test_stop_partial_response_file_reentry_holds(self):
        with self.fixture() as c:
            put=b.CORE_RELOAD_SUPPORT['put']
            def partial(root,name,v):
                if name=='stop-response.json':
                    p=root/name;p.write_text('{');p.chmod(0o600);raise OSError('partial write')
                return put(root,name,v)
            with mock.patch.dict(b.CORE_RELOAD_SUPPORT,put=partial):c.blocked()
            c.blocked()
            self.assertEqual(sum(q['action']=='stop' for q in c.requests),1)


class ReconcileAPFS(unittest.TestCase):
    def test_owned_entry_directory_nlink_drift_preserves_security_fences(self):
        # APFS counts regular directory entries in st_nlink. Only the owned
        # root stat is synthetic; receipt files retain real hardlink checks.
        for drift in (None,'st_dev','st_ino','st_mode','st_uid','st_gid'):
            with self.subTest(drift=drift),ReconcileR3().fixture() as c:
                original=Path.lstat
                baseline=original(c.root)
                observed=[]
                fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink')
                def lstat(path,*args,**kwargs):
                    actual=original(path,*args,**kwargs)
                    if path!=c.root:return actual
                    added=sum((c.root/name).exists() for name in
                              ('stop-intent.json','stop-response.json','stop-read.json'))
                    values={k:getattr(baseline,k) for k in fields}
                    values['st_nlink']=8+added
                    if drift is not None and added==3:
                        values[drift]+=1
                    observed.append((added,values.copy()))
                    return types.SimpleNamespace(**values)
                with mock.patch.object(Path,'lstat',lstat):
                    if drift is None:c.guard()
                    else:c.blocked()
                self.assertTrue(any(n==0 and v['st_nlink']==8 for n,v in observed))
                self.assertTrue(any(n==3 and v['st_nlink']==11 for n,v in observed))
                self.assertEqual(sum(q['action']=='stop' for q in c.requests),1)
                c.unchanged()
                if drift is None:
                    self.assertFalse((c.root/'pending.json').exists())
                    marker=json.loads((c.root/'reconciled.json').read_bytes())
                    self.assertEqual(set(marker['stop_sha256']),
                                     {'stop-intent.json','stop-response.json','stop-read.json'})
                else:
                    self.assertTrue((c.root/'pending.json').exists())
                    self.assertFalse((c.root/'reconciled.json').exists())


if __name__=='__main__':
    unittest.main(verbosity=2)

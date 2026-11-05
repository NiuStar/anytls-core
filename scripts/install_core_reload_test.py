#!/usr/bin/env python3
"""LOCALONLY/SYNTHETIC macOS peers; never contact native control or the network."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('reload_installer', Path(__file__).with_name('install-binary.py'))
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)


class CLI(unittest.TestCase):
    def test_default_opt_out_and_mutual_exclusion(self):
        for argv, expected in (([], None), (['--reload-core'], True), (['--no-reload-core'], False),
                               (['--check-download'], None), (['--check-download','--no-reload-core'], False),
                               (['--update-only','--version','v1.2.3','--app-dir','/unused',
                                 '--target','/unused/anytls','--update-arch','arm64','--no-reload-core'], False)):
            with self.subTest(argv=argv), mock.patch.object(b, 'run', return_value={}) as run, \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(b.main(argv), 0)
                self.assertIs(run.call_args.args[0].reload_core, expected)
        with mock.patch.object(b, 'run') as run, contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                b.main(['--reload-core','--no-reload-core'])
            run.assert_not_called()

    def test_direct_run_missing_or_none_reload_defaults_full_only(self):
        spec=importlib.util.spec_from_file_location('mode_fixture',Path(__file__).with_name('install_binary_test.py'))
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        c=module.InstallerTests();c.setUp()
        try:
            for explicit in ('MISSING', None, False, True):
                args=types.SimpleNamespace(check_download=False, version=module.TAG, arch=None)
                if explicit != 'MISSING': args.reload_core=explicit
                with self.subTest(explicit=explicit), mock.patch.object(b, '_install_verified', return_value=None) as install, \
                     contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    b.run(args,transport=c.transport,runner=c.runner,system='Darwin',machine='arm64',euid=501,
                          home=c.home,env={'HOME':str(c.home)})
                    self.assertIs(install.call_args.args[-2], explicit is not False)
        finally:
            c.doCleanups()

    def test_option_is_parsed_for_full_install(self):
        with mock.patch.object(b, 'run', return_value={}) as run:
            self.assertEqual(b.main(['--reload-core']), 0)
        self.assertTrue(run.call_args.args[0].reload_core)

    def test_incompatible_modes_rejected_before_run(self):
        for argv in (['--reload-core', '--check-download'],
                     ['--update-only', '--reload-core', '--version', 'v1.2.3',
                      '--app-dir', '/unused', '--target', '/unused/anytls', '--update-arch', 'arm64']):
            with self.subTest(argv=argv), mock.patch.object(b, 'run') as run, \
                    contextlib.redirect_stderr(io.StringIO()):
                try:
                    result = b.main(argv)
                except SystemExit as exc:
                    result = exc.code
                self.assertNotEqual(result, 0)
                run.assert_not_called()

    def test_direct_run_also_rejects_before_any_io(self):
        for update, check in ((True, False), (False, True)):
            with mock.patch.object(b, 'update_only') as updater, mock.patch.object(b, 'verified_download') as download:
                with self.assertRaisesRegex(ValueError, 'reload-core'):
                    b.run(types.SimpleNamespace(reload_core=True, update_only=update, check_download=check))
                updater.assert_not_called()
                download.assert_not_called()


class Worker(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='reload-offline-', dir=os.environ['TMPDIR'])
        self.addCleanup(self.temp.cleanup)
        self.app = Path(self.temp.name) / 'app'
        self.app.mkdir(mode=0o700)
        (self.app / 'config.yaml').write_text('private fixture only')
        (self.app / 'anytls-macos').write_bytes(b'candidate fixture')
        self.n = dict(b.CORE_RELOAD_SUPPORT)
        self.n['__name__'] = 'synthetic_worker'
        exec(b.CORE_RELOAD_WORKER, self.n)
        self.digest = self.n['file_hash'](self.app / 'anytls-macos')
        self.identity = self.n['config_pin'](self.app)['identity']
        self.op = 'a' * 32
        self.epoch = 'e' * 32
        self.tag = 'v1.2.3'
        self.rev = 'b' * 40
        self.status = dict(ok=True, code='', message='status', loaded=True, running=True,
                           helper_sha256=self.digest, helper_version=self.tag, config_identity=self.identity)
        self.old = dict(pid=40, uid=0, birth='Wed Nov  4 01:02:03 2026', command=str(self.app / 'service/anytls-macos') + ' -config old -network tun run')
        self.new = dict(pid=41, uid=0, birth='Wed Nov  4 01:02:05 2026', command=self.n['core_command'](self.app, self.op, self.epoch))
        self.diag = dict(schema=1, operation='RELOAD', outcome='SUCCEEDED', stage='NONE', reason='NONE',
                         rollback='NOT_ATTEMPTED', restoration='NOT_ATTEMPTED', cleanup='NOT_ATTEMPTED',
                         receipt='WRITTEN', job='RUNNING', tun='TUN')
        self.cap = dict(timeline_schema=1, code='NO_OPERATION', helper_epoch=self.epoch,
                        config_identity=self.identity, operation_id=None, trace=None)
        self.response = dict(timeline_schema=1, code='', ok=True, helper_epoch=self.epoch, operation_id=self.op,
                             timeline_availability='AVAILABLE', helper_version=self.tag, helper_sha256=self.digest,
                             config_identity=self.identity, loaded=True, running=True, diagnostics=self.diag)
        self.trace = dict(timeline_schema=1, code='OK', helper_epoch=self.epoch, config_identity=self.identity,
                          operation_id=self.op, trace=dict(authority='AUXILIARY_NOT_AUTHORITY', operation_id=self.op,
                          helper_epoch=self.epoch, config_identity=self.identity, operation='RELOAD', source='MANUAL_RELOAD',
                          started_at='2026-11-04T01:02:03Z', finished_at='2026-11-04T01:02:05Z', state='FINISHED',
                          lifecycle_result='SUCCEEDED', helper_return='SUCCEEDED', web_return='NOT_ATTEMPTED',
                          receipt_result='WRITTEN', diagnostics=self.diag, gap=False,
                          core_observation=dict(availability='OBSERVED', captured_at=None, helper_receive_elapsed_ns=None,
                                                age_ns=None, clock_id=None, phase=None, gap=False), streams=[dict(
                          role='CORE', clock_id='c'*32, origin_at='2026-11-04T01:02:05Z', elapsed_ns='1',
                          provenance=dict(version=self.tag, git_revision=self.rev, dirty=False, sha256=self.digest,
                                          sha_kind='FILE_BYTES', execution_mapping='NOT_ATTESTED'), current=None,
                          events=[dict(stage='CORE_START', state='END', code='OK',seq='1',span_id='1',segment='START',
                                       at='2026-11-04T01:02:05Z',elapsed_ns='1',duration_ns='1',round=None,ordinal=None,
                                       rule_count=None,completed_count=None,job='NOT_OBSERVED',tun='NOT_OBSERVED')],
                          generated_events='0', dropped_events='0', first_missing_seq=None, retained_ranges=[],
                          terminal=dict(result='SUCCEEDED', at='2026-11-04T01:02:05Z', elapsed_ns='1'), gap=False)]))
        self.requests = []
        def request(q, timeout=5):
            self.requests.append(q)
            if q['action'] == 'status':
                return self.status.copy()
            if q['action'] == 'startup.read':
                return json.loads(json.dumps(self.cap if q['operation_id'] is None else self.trace))
            self.assertTrue((self.tx / 'intent.json').is_file(), 'intent must be durable BEFORE send')
            self.assertEqual(q, dict(timeline_schema=1, action='reload', operation_id=self.op, allow_insecure=False))
            return json.loads(json.dumps(self.response))
        self.n['request'] = request
        self.n['helper_hash'] = lambda: self.digest
        self.n['tun_readback'] = lambda: 'utun123'
        self.n['processes'] = lambda app: [self.new.copy()] if any(q['action']=='reload' for q in self.requests) else [self.old.copy()]
        self.before = dict(state='RUNNING', config=self.n['config_pin'](self.app), core=self.old)
        self.tx = self.app / ('.core-reload-' + self.op)
        self.tx.mkdir(mode=0o700)
        self.job = dict(app=str(self.app), operation_id=self.op, digest=self.digest, tag=self.tag, revision=self.rev, before=self.before)

    def run_worker(self):
        self.n['put'](self.tx, 'job.json', self.job)
        return self.n['worker'](self.tx)

    def test_real_worker_orchestration_single_dispatch_and_full_readback(self):
        self.assertEqual(self.run_worker(), 0)
        result = json.loads((self.tx/'result.json').read_bytes())
        self.assertEqual(result['state'], 'SUCCEEDED')
        self.assertEqual(result['operation_id'], self.op)
        self.assertEqual(result['new_core'], self.new)
        self.assertEqual([q['action'] for q in self.requests], ['status', 'startup.read', 'status', 'reload', 'startup.read', 'status'])
        self.assertEqual((self.tx/'intent.json').stat().st_mode & 0o777, 0o600)
        self.assertNotIn('private fixture', ''.join(p.read_text() for p in self.tx.iterdir()))

    def test_preflight_identity_drift_never_mutates(self):
        for key, value in (('helper_sha256','0'*64), ('helper_version','v0.0.0'), ('config_identity','0'*64), ('running',False)):
            with self.subTest(key=key):
                self.status[key] = value
                self.assertEqual(self.run_worker(), 1)
                self.assertFalse((self.tx/'intent.json').exists())
                self.assertFalse(any(q['action']=='reload' for q in self.requests))
                for p in self.tx.iterdir(): p.unlink()
                self.status[key] = dict(helper_sha256=self.digest, helper_version=self.tag, config_identity=self.identity, running=True)[key]

    def test_post_send_uncertainty_never_resends(self):
        mutations = [lambda: self.response.update(operation_id='f'*32),
                     lambda: self.response.update(helper_epoch='f'*32),
                     lambda: self.response.update(ok=1),
                     lambda: self.response.update(diagnostics={**self.diag,'tun':'UNKNOWN'}),
                     lambda: self.trace.update(operation_id='f'*32),
                     lambda: self.trace['trace']['streams'][0]['provenance'].update(sha256='0'*64),
                     lambda: self.n.update(processes=lambda app:[self.old.copy()]),
                     lambda: self.trace['trace']['streams'][0]['events'][0].update(secret='not allowed'),
                     lambda: self.response.update(loaded=1),
                     lambda: self.response.update(config_identity='0'*64),
                     lambda: self.n.update(tun_readback=lambda: self.n['need'](False,'CORE_RELOAD_TUN_UNAVAILABLE'))]
        original_r, original_t = json.dumps(self.response), json.dumps(self.trace)
        for change in mutations:
            with self.subTest(index=mutations.index(change)):
                change()
                self.assertEqual(self.run_worker(),1)
                result = json.loads((self.tx/'result.json').read_bytes())
                self.assertEqual(result['state'],'UNKNOWN')
                self.assertEqual(sum(q['action']=='reload' for q in self.requests),1)
                # An existing journal must refuse another dispatch, not resume mutation.
                self.assertEqual(self.n['worker'](self.tx),1)
                self.assertEqual(sum(q['action']=='reload' for q in self.requests),1)
                for p in self.tx.iterdir(): p.unlink()
                self.requests.clear()
                self.response, self.trace = json.loads(original_r), json.loads(original_t)
                self.n['processes'] = lambda app:[self.new.copy()] if any(q['action']=='reload' for q in self.requests) else [self.old.copy()]

    def test_capability_failure_and_config_selection_drift_prevent_dispatch(self):
        self.cap['helper_epoch']=None
        self.assertEqual(self.run_worker(),1)
        self.assertFalse((self.tx/'intent.json').exists())
        self.assertFalse(any(q['action']=='reload' for q in self.requests))

    def test_unknown_on_transport_timeout_or_disconnect(self):
        original=self.n['request']
        for error in (TimeoutError,ConnectionResetError,OSError):
            with self.subTest(error=error.__name__):
                def request(q, timeout=5):
                    if q['action']=='reload':
                        self.requests.append(q)
                        raise error('synthetic private sentinel')
                    return original(q,timeout)
                self.n['request']=request
                self.assertEqual(self.run_worker(),1)
                r=json.loads((self.tx/'result.json').read_bytes())
                self.assertEqual(r['state'],'UNKNOWN')
                self.assertNotIn('sentinel',json.dumps(r))
                self.assertEqual(sum(q['action']=='reload' for q in self.requests),1)
                for p in self.tx.iterdir():p.unlink()
                self.requests.clear()


    def test_actual_detached_isolated_child_survives_deleted_bootstrap(self):
        fixture = dict(status=self.status,cap=self.cap,response=self.response,trace=self.trace,
                       old=self.old,new=self.new,digest=self.digest)
        bootstrap = self.app/'deleted-bootstrap.py'
        bootstrap.write_text('# disposable bootstrap fixture')
        seam = r'''
_root = Path(sys.argv[1])
_fixture = strict((_root/'fixture.json').read_bytes())
put(_root,'child-runtime.json',dict(pid=os.getpid(),sid=os.getsid(0),isolated=sys.flags.isolated,
                                  bytecode=sys.dont_write_bytecode,bootstrap_exists=Path(BOOTSTRAP).exists()))
print('synthetic durable stdout',flush=True)
print('synthetic durable stderr',file=sys.stderr,flush=True)
def request(q, timeout=5):
    with (_root/'requests.jsonl').open('a') as f:
        f.write(json.dumps(q)+'\n');f.flush();os.fsync(f.fileno())
    if q['action']=='status': return _fixture['status']
    if q['action']=='startup.read': return _fixture['cap'] if q['operation_id'] is None else _fixture['trace']
    need((_root/'intent.json').is_file())
    put(_root,'synthetic-mutation.json',q)
    return _fixture['response']
def helper_hash(): return _fixture['digest']
def processes(app): return [_fixture['new'] if (_root/'synthetic-mutation.json').exists() else _fixture['old']]
def tun_readback(): return 'utun123'
'''.replace('BOOTSTRAP',repr(str(bootstrap)))
        real_popen = subprocess.Popen
        runtime = {}
        def launch(argv, **kwargs):
            self.assertEqual(argv[1:4],['-I','-B','-c'])
            self.assertEqual(argv[4],b.CORE_RELOAD_WORKER)
            self.assertTrue(kwargs['start_new_session'])
            self.assertIs(kwargs['stdout'],kwargs['stderr'])
            root=Path(argv[5]);runtime['root']=root
            self.n['put'](root,'fixture.json',fixture)
            bootstrap.unlink()
            source=argv[4].replace("if __name__ == '__main__':",seam+"\nif __name__ == '__main__':",1)
            return real_popen(argv[:4]+[source]+argv[5:],**kwargs)
        core=b.CoreReload.__new__(b.CoreReload)
        core.app,core.before=self.app,self.before
        self.tx.rmdir()
        with mock.patch.object(b.i.uuid,'uuid4',return_value=types.SimpleNamespace(hex=self.op)), \
             mock.patch.object(b.subprocess,'Popen',side_effect=launch), contextlib.redirect_stdout(io.StringIO()) as out, \
             b.installation_lock(self.app) as lock_fd:
            core.lock_fd = lock_fd
            core.finish(self.digest,self.tag,self.rev)
        root=runtime['root']
        self.assertIn('Core reload SUCCEEDED',out.getvalue())
        info=json.loads((root/'child-runtime.json').read_bytes())
        self.assertEqual(info['pid'],info['sid'])
        self.assertEqual(info['isolated'],1)
        self.assertTrue(info['bytecode'])
        self.assertFalse(info['bootstrap_exists'])
        self.assertIn('synthetic durable stdout',(root/'worker.log').read_text())
        self.assertIn('synthetic durable stderr',(root/'worker.log').read_text())
        requests=[json.loads(line) for line in (root/'requests.jsonl').read_text().splitlines()]
        self.assertEqual(sum(q['action']=='reload' for q in requests),1)
        self.assertEqual(json.loads((root/'result.json').read_bytes())['state'],'SUCCEEDED')
        self.assertEqual((root/'worker.log').stat().st_mode & 0o777,0o600)


    def test_config_and_selection_content_drift_pre_dispatch(self):
        for name in ('config.yaml','config.yaml.selected'):
            with self.subTest(name=name):
                (self.app/name).write_text('changed private bytes')
                self.assertEqual(self.run_worker(),1)
                self.assertFalse((self.tx/'intent.json').exists())
                self.assertFalse(any(q['action']=='reload' for q in self.requests))
                for p in self.tx.iterdir(): p.unlink()
                (self.app/'config.yaml').write_text('private fixture only')
                (self.app/'config.yaml.selected').unlink(missing_ok=True)

    def test_capture_running_stopped_and_inconsistent_state(self):
        self.n['SOCKET']=self.app/'fixture.sock'
        self.n['SOCKET'].touch()
        self.assertEqual(self.n['capture'](self.app)['state'],'RUNNING')
        self.status.update(running=False,loaded=False)
        self.n['processes']=lambda app:[]
        self.assertEqual(self.n['capture'](self.app)['state'],'STOPPED')
        self.status.update(running=True,loaded=False)
        with self.assertRaisesRegex(ValueError,'STATUS_STATE'):
            self.n['capture'](self.app)
        self.status.update(running=False,loaded=True)
        self.n['processes']=lambda app:[self.old]
        with self.assertRaisesRegex(ValueError,'PROCESS_STATE'):
            self.n['capture'](self.app)

    def test_first_install_absence_requires_exact_launchd_and_no_core(self):
        self.n['SOCKET']=self.app/'missing.sock'
        self.n['HELPER']=self.app/'missing-helper'
        self.n['processes']=lambda app:[]
        def absent(argv,**kwargs):
            label=argv[-1].split('/')[-1]
            return types.SimpleNamespace(returncode=113,stdout=b'',stderr=('Bad request.\nCould not find service "'+label+'" in domain for system\n').encode())
        with mock.patch.object(self.n['subprocess'],'run',side_effect=absent) as runner:
            self.assertEqual(self.n['capture'](self.app)['state'],'ABSENT')
            self.assertEqual(runner.call_count,2)
        with mock.patch.object(self.n['subprocess'],'run',return_value=types.SimpleNamespace(returncode=1,stdout=b'',stderr=b'denied')):
            with self.assertRaisesRegex(ValueError,'ABSENCE_UNPROVEN'):
                self.n['capture'](self.app)
        self.n['processes']=lambda app:[self.old]
        with self.assertRaisesRegex(ValueError,'HELPER_UNAVAILABLE'):
            self.n['capture'](self.app)

    def test_request_rejects_bad_payload_before_socket_and_auth_before_send(self):
        real={ '__name__':'synthetic_transport' }
        exec(b.CORE_RELOAD_WORKER,real)
        for q in (dict(action='reload',allow_insecure=False),
                  dict(timeline_schema=True,action='reload',operation_id=self.op,allow_insecure=False),
                  dict(timeline_schema=1,action='reload',operation_id='INVALID',allow_insecure=False),
                  dict(timeline_schema=1,action='reload',operation_id=self.op,allow_insecure=True)):
            with mock.patch.object(real['socket'],'socket',side_effect=AssertionError('must reject before connect')):
                with self.assertRaises(ValueError): real['request'](q)
        # Exercise actual transport sequencing with a synthetic socket, never native socket.
        s=mock.MagicMock();s.__enter__.return_value=s
        real['root_peer']=lambda peer: real['need'](False,'PEER_NOT_ROOT')
        with mock.patch.object(real['socket'],'socket',return_value=s):
            with self.assertRaisesRegex(ValueError,'PEER_NOT_ROOT'):
                real['request'](dict(action='status',allow_insecure=False))
        s.connect.assert_called_once();s.sendall.assert_not_called()
        for raw in (b'{"a":1,"a":2}',b'{} {}',b'{"n":NaN}'):
            with self.assertRaises(ValueError): real['strict'](raw)

    def test_native_peer_function_requires_root_and_success(self):
        real={'__name__':'synthetic_getpeereid'}
        exec(b.CORE_RELOAD_WORKER,real)
        import ctypes
        for rc,uid,accepted in ((0,0,True),(0,501,False),(-1,0,False)):
            class GetPeer:
                def __call__(self,fd,up,gp):
                    self_outer.assertEqual(fd,77)
                    ctypes.cast(up,ctypes.POINTER(ctypes.c_uint))[0]=uid
                    return rc
            self_outer=self
            with mock.patch.object(real['ctypes'],'CDLL',return_value=types.SimpleNamespace(getpeereid=GetPeer())):
                peer=types.SimpleNamespace(fileno=lambda:77)
                if accepted: real['root_peer'](peer)
                else:
                    with self.assertRaisesRegex(ValueError,'PEER_NOT_ROOT'):real['root_peer'](peer)

    def test_unknown_journal_blocks_new_installer_operation(self):
        self.n['put'](self.tx,'result.json',dict(state='UNKNOWN',operation_id=self.op))
        with mock.patch.dict(b.CORE_RELOAD_SUPPORT, capture=mock.Mock(side_effect=AssertionError('no native observation'))):
            with self.assertRaisesRegex(ValueError,'UNKNOWN/pending'):
                b.CoreReload(self.app)

    def test_stopped_and_absent_skip_without_popen(self):
        for state in ('ABSENT','STOPPED'):
            core=b.CoreReload.__new__(b.CoreReload)
            core.app,core.before=self.app,dict(state=state)
            with mock.patch.object(b.subprocess,'Popen',side_effect=AssertionError('no child for skip')),contextlib.redirect_stdout(io.StringIO()) as out:
                core.finish(self.digest,self.tag,self.rev)
            self.assertIn('SKIPPED',out.getvalue())
            self.assertIn(state,out.getvalue())

    def test_parent_timeout_retains_worker_and_never_relaunches(self):
        core=b.CoreReload.__new__(b.CoreReload)
        core.app,core.before=self.app,self.before
        child=mock.Mock()
        child.wait.side_effect=subprocess.TimeoutExpired('synthetic detached worker',360)
        self.tx.rmdir()
        with mock.patch.object(b.i.uuid,'uuid4',return_value=types.SimpleNamespace(hex=self.op)), \
             mock.patch.object(b.subprocess,'Popen',return_value=child) as launch, \
             b.installation_lock(self.app) as lock_fd:
            core.lock_fd = lock_fd
            with self.assertRaisesRegex(ValueError,'Core reload UNKNOWN.*receipt:'):
                core.finish(self.digest,self.tag,self.rev)
        launch.assert_called_once()
        child.terminate.assert_not_called();child.kill.assert_not_called()
        self.assertTrue((self.tx/'job.json').is_file())
        with mock.patch.dict(b.CORE_RELOAD_SUPPORT,capture=mock.Mock(side_effect=AssertionError('must block'))):
            with self.assertRaisesRegex(ValueError,'UNKNOWN/pending'): b.CoreReload(self.app)


class InstallIntegration(unittest.TestCase):
    def setUp(self):
        spec=importlib.util.spec_from_file_location('inherited_installer_fixture',Path(__file__).with_name('install_binary_test.py'))
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        self.c=module.InstallerTests();self.c.setUp()
        self.addCleanup(self.c.doCleanups)
        self.module=module

    def test_default_capture_precedes_helper_and_finish_follows_webui(self):
        c,m=self.c,self.module
        _,bundle,_,_=c.verified();c.app.mkdir();c.processes=[]
        events=[]
        class Activation:
            def __init__(self,app): events.append('capture')
            def finish(self,digest,tag,revision):
                events.append('reload')
                self_outer.assertEqual((c.app/'anytls-macos').read_bytes(),m.BINARY)
                self_outer.assertEqual((tag,revision),(m.TAG,m.COMMIT))
        self_outer=self
        original=c.runner
        def runner(argv,**kw):
            if argv[1:]==['helper','install']:events.append('helper')
            return original(argv,**kw)
        c.webui_factory.return_value.restart.side_effect=lambda:events.append('webui')
        with mock.patch.object(m.b,'CoreReload',Activation):
            m.b.install_verified(bundle,m.TAG,c.app,c.home,runner,env={'HOME':str(c.home)},tty=lambda:io.BytesIO())
        self.assertEqual(events,['capture','helper','webui','reload'])

    def test_explicit_opt_out_no_preflight_and_webui_failure_no_reload(self):
        c,m=self.c,self.module
        _,bundle,_,_=c.verified()
        c.app.mkdir()
        c.processes=[]
        with mock.patch.object(m.b,'CoreReload',side_effect=AssertionError('opt-out must not observe helper')):
            m.b.install_verified(bundle,m.TAG,c.app,c.home,c.runner,env={'HOME':str(c.home)},tty=lambda:io.BytesIO(),reload_core=False)
        c.webui_factory.return_value.restart.side_effect=ValueError('synthetic readiness failure')
        with mock.patch.object(m.b,'CoreReload') as activation:
            with self.assertRaisesRegex(ValueError,'WebUI start failed'):
                m.b.install_verified(bundle,m.TAG,c.app,c.home,c.runner,env={'HOME':str(c.home)},tty=lambda:io.BytesIO(),reload_core=True)
            activation.return_value.finish.assert_not_called()

    def test_default_stopped_absent_full_install_never_starts_vpn(self):
        for state in ('STOPPED','ABSENT'):
            with self.subTest(state=state):
                c,m=self.c,self.module
                _,bundle,_,_=c.verified()
                c.app.mkdir(exist_ok=True);c.processes=[]
                capture=mock.Mock(return_value=dict(state=state))
                with mock.patch.dict(m.b.CORE_RELOAD_SUPPORT,capture=capture), \
                     contextlib.redirect_stdout(io.StringIO()) as out:
                    m.b.install_verified(bundle,m.TAG,c.app,c.home,c.runner,
                                         env={'HOME':str(c.home)},tty=lambda:io.BytesIO())
                capture.assert_called_once_with(c.app.resolve())
                self.assertIn('Core reload SKIPPED: original VPN '+state,out.getvalue())
                self.assertIn(['helper','install'],[argv[1:] for argv,_ in c.processes])
                self.assertFalse(list(c.app.glob('.core-reload-*')))

    def test_capture_failure_prevents_privileged_mutation(self):
        c,m=self.c,self.module
        _,bundle,_,_=c.verified();c.app.mkdir();c.processes=[]
        with mock.patch.object(m.b,'CoreReload',side_effect=ValueError('synthetic preflight rejected')):
            with self.assertRaisesRegex(ValueError,'preflight rejected'):
                m.b.install_verified(bundle,m.TAG,c.app,c.home,c.runner,env={'HOME':str(c.home)},tty=lambda:io.BytesIO(),reload_core=True)
        self.assertEqual(c.processes,[])
        self.assertFalse((c.app/'anytls-macos').exists())


if __name__ == '__main__':
    unittest.main()

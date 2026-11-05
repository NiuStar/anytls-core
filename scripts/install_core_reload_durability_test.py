#!/usr/bin/env python3
"""LOCALONLY: actual detached processes/flock/journals; all macOS peers synthetic.

Pair unchanged bytes against a copied predecessor scripts directory. No native
helper, device, network, SSH, Go or installation command is executed.
"""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import types
import unittest
from unittest import mock

HERE = Path(__file__).parent
REAL_POPEN = subprocess.Popen


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


f = load('reload_durability_fixture', HERE/'install_core_reload_test.py')
b = f.b

# Insert only native peer/process/TUN observations, leaving worker orchestration,
# exclusive journals and every actual fsync untouched except selected faults.
SEAM = r'''
_root = Path(sys.argv[1])
_fixture = strict((_root/'fixture.json').read_bytes())
def helper_hash(): return _fixture['digest']
def processes(app): return [_fixture['new'] if (_root/'entered.json').exists() else _fixture['old']]
def tun_readback(): return 'utun123'
def request(q, timeout=5):
    if q['action']=='status': return _fixture['status']
    if q['action']=='startup.read': return _fixture['cap'] if q['operation_id'] is None else _fixture['trace']
    put(_root,'entered.json',q)
    if _fixture.get('held'):
        while not (_root/'release').exists(): time.sleep(.01)
    if _fixture.get('unknown'): raise TimeoutError('synthetic lost reply')
    return _fixture['response']
_real_fsync = os.fsync
def injected_fsync(fd):
    target = os.readlink('/proc/self/fd/'+str(fd))
    fault = _fixture.get('fault')
    if ((fault=='result-file' and target==str(_root/'result.json')) or
        (fault=='result-directory' and target==str(_root) and (_root/'result.json').exists())):
        (_root/'fault-fired').touch()
        raise OSError('synthetic terminal sync failure')
    return _real_fsync(fd)
os.fsync = injected_fsync
'''


class Durability(unittest.TestCase):
    def setUp(self):
        self.w = f.Worker()
        self.w.setUp()
        self.addCleanup(self.w.doCleanups)
        self.children = []
        self.addCleanup(self.cleanup_children)

    def cleanup_children(self):
        for child, root in self.children:
            (root/'release').touch()
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
                self.fail('owned synthetic child required forced cleanup')

    def fixture(self, **extra):
        w = self.w
        return dict(status=w.status, cap=w.cap, response=w.response, trace=w.trace,
                    old=w.old, new=w.new, digest=w.digest, **extra)

    def launch(self, fixture, wait_timeout=False):
        def launch(argv, **kwargs):
            root = Path(argv[5])
            self.w.n['put'](root, 'fixture.json', fixture)
            source = argv[4].replace("if __name__ == '__main__':", SEAM+"\nif __name__ == '__main__':", 1)
            child = REAL_POPEN(argv[:4]+[source]+argv[5:], **kwargs)
            self.children.append((child, root))
            if not wait_timeout:
                return child
            outer = self
            class TimeoutWaiter:
                def wait(self, timeout):
                    outer.await_entered(child, root)
                    raise subprocess.TimeoutExpired('controlled parent timeout', timeout)
            return TimeoutWaiter()
        return launch

    def await_entered(self, child, root):
        until = time.monotonic()+10
        while not (root/'entered.json').exists():
            self.assertIsNone(child.poll(), 'worker exited before inert mutation seam')
            self.assertLess(time.monotonic(), until, 'worker did not enter seam')
            time.sleep(.01)

    def finish(self, fixture, timeout=False, parent_fault=None):
        w = self.w
        core = b.CoreReload.__new__(b.CoreReload)
        core.app, core.before = w.app, w.before
        w.tx.rmdir()
        real_fsync = os.fsync
        def sync(fd):
            target = os.readlink('/proc/self/fd/'+str(fd))
            is_result = target == str(w.tx/'result.json')
            is_ack = target == str(w.tx/'accepted.json')
            is_ack_dir = target == str(w.tx) and (w.tx/'accepted.json').exists()
            if ((parent_fault=='parent-result' and is_result) or
                (parent_fault=='accepted-file' and is_ack) or
                (parent_fault=='accepted-directory' and is_ack_dir)):
                self.parent_fault_fired = True
                raise OSError('synthetic parent confirmation sync failure')
            return real_fsync(fd)
        self.parent_fault_fired = False
        with b.installation_lock(w.app) as fd, \
             mock.patch.object(b.i.uuid, 'uuid4', return_value=types.SimpleNamespace(hex=w.op)), \
             mock.patch.object(b.subprocess, 'Popen', side_effect=self.launch(fixture, timeout)), \
             mock.patch.object(b.os, 'fsync', side_effect=sync), \
             contextlib.redirect_stdout(io.StringIO()):
            core.lock_fd = fd
            core.finish(w.digest, w.tag, w.rev)

    def assert_all_mutators_blocked(self):
        w = self.w
        capture = mock.Mock(side_effect=AssertionError('must not contact helper'))
        with mock.patch.dict(b.CORE_RELOAD_SUPPORT, capture=capture):
            with self.assertRaisesRegex(ValueError, 'UNKNOWN/pending'):
                b.CoreReload(w.app)
        capture.assert_not_called()
        im = load('durability_install_fixture', HERE/'install_binary_test.py')
        im.b = b
        c = im.InstallerTests()
        c.setUp()
        try:
            _, bundle, _, _ = c.verified()
            c.processes = []
            previous = (w.app/'anytls-macos').read_bytes()
            with mock.patch.object(b.i, 'publish_binary', side_effect=AssertionError('publish forbidden')) as publish:
                for mode in (None, False, True):
                    options = {} if mode is None else dict(reload_core=mode)
                    with self.subTest(mode=mode), self.assertRaisesRegex(ValueError, 'UNKNOWN/pending'):
                        b.install_verified(bundle, im.TAG, w.app, c.home, c.runner,
                                           env={'HOME':str(c.home)}, tty=lambda:io.BytesIO(), **options)
                args = types.SimpleNamespace(update_arch='arm64', check_download=False, arch=None,
                                             version=im.TAG, app_dir=str(w.app), target=str(w.app/'anytls-macos'))
                download = mock.Mock(side_effect=AssertionError('pending update must stop before download'))
                with self.assertRaises(b.UpdateFailed) as caught:
                    b.update_only(args, transport=download, system='Darwin', machine='arm64', euid=501)
                self.assertEqual(caught.exception.code, 45)
                download.assert_not_called()
                publish.assert_not_called()
            self.assertEqual(c.processes, [], 'no helper install/status/version')
            self.assertEqual((w.app/'anytls-macos').read_bytes(), previous)
        finally:
            c.doCleanups()

    def test_result_file_fsync_failure_blocks_all_next_install_modes(self):
        with self.assertRaisesRegex(ValueError, 'UNKNOWN'):
            self.finish(self.fixture(fault='result-file'))
        self.assertTrue((self.w.tx/'fault-fired').exists())
        self.assertEqual(self.children[0][0].returncode, 1)
        self.assertEqual(json.loads((self.w.tx/'result.json').read_bytes())['state'], 'SUCCEEDED')
        self.assert_all_mutators_blocked()

    def test_result_directory_fsync_failure_blocks_all_next_install_modes(self):
        with self.assertRaisesRegex(ValueError, 'UNKNOWN'):
            self.finish(self.fixture(fault='result-directory'))
        self.assertTrue((self.w.tx/'fault-fired').exists())
        self.assertEqual(self.children[0][0].returncode, 1)
        self.assertEqual(json.loads((self.w.tx/'result.json').read_bytes())['state'], 'SUCCEEDED')
        self.assert_all_mutators_blocked()

    def test_parent_result_resync_failure_keeps_pending(self):
        with self.assertRaisesRegex(ValueError, 'UNKNOWN'):
            self.finish(self.fixture(), parent_fault='parent-result')
        self.assertTrue(self.parent_fault_fired)
        self.assertEqual(self.children[0][0].returncode, 0)
        self.assertTrue((self.w.tx/'pending.json').exists())
        self.assert_all_mutators_blocked()

    def test_acceptance_file_fsync_failure_is_not_clearance(self):
        with self.assertRaisesRegex(ValueError, 'UNKNOWN'):
            self.finish(self.fixture(), parent_fault='accepted-file')
        self.assertTrue(self.parent_fault_fired)
        self.assertTrue((self.w.tx/'accepted.json').exists())
        self.assertTrue((self.w.tx/'pending.json').exists())
        self.assert_all_mutators_blocked()

    def test_acceptance_directory_fsync_failure_is_not_clearance(self):
        with self.assertRaisesRegex(ValueError, 'UNKNOWN'):
            self.finish(self.fixture(), parent_fault='accepted-directory')
        self.assertTrue(self.parent_fault_fired)
        self.assertTrue((self.w.tx/'accepted.json').exists())
        self.assertTrue((self.w.tx/'pending.json').exists())
        self.assert_all_mutators_blocked()

    def test_actual_detached_worker_keeps_flock_after_parent_timeout(self):
        with self.assertRaisesRegex(ValueError, 'UNKNOWN'):
            self.finish(self.fixture(held=True, unknown=True), timeout=True)
        child, root = self.children[0]
        self.assertIsNone(child.poll())
        self.assertTrue((root/'intent.json').exists())
        self.assertFalse((root/'result.json').exists())
        with self.assertRaisesRegex(ValueError, 'another binary installer'):
            with b.installation_lock(self.w.app):
                self.fail('live detached worker lost install flock')
        with self.assertRaisesRegex(ValueError, 'another binary installer'):
            b.install_verified(None, self.w.tag, self.w.app, self.w.app.parent)
        (root/'release').touch()
        self.assertEqual(child.wait(timeout=10), 1)
        with b.installation_lock(self.w.app):
            pass  # ownership ends with worker; durable UNKNOWN still blocks.
        self.assert_all_mutators_blocked()

    def test_actual_parent_exit_keeps_worker_flock_and_never_auto_accepts(self):
        w = self.w
        w.tx.rmdir()
        fixture_file = w.app/'parent-fixture.json'
        fixture_file.write_text(json.dumps(self.fixture(held=True)))
        # Actual parent exits inside installation_lock, without Python finally.
        parent_source = r'''
import importlib.util,json,os,subprocess,sys,time,types
from pathlib import Path
spec=importlib.util.spec_from_file_location('parent_installer',sys.argv[1])
b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
app=Path(sys.argv[2]); fixture=json.loads((app/'parent-fixture.json').read_bytes())
real_popen=subprocess.Popen
seam=sys.argv[3]
def launch(argv,**kwargs):
    root=Path(argv[5]);b.CORE_RELOAD_SUPPORT['put'](root,'fixture.json',fixture)
    source=argv[4].replace("if __name__ == '__main__':",seam+"\nif __name__ == '__main__':",1)
    child=real_popen(argv[:4]+[source]+argv[5:],**kwargs)
    (app/'worker-pid').write_text(str(child.pid))
    class ExitWaiter:
        def wait(self,timeout):
            end=time.monotonic()+10
            while not (root/'entered.json').exists():
                if child.poll() is not None or time.monotonic()>end:os._exit(98)
                time.sleep(.01)
            os._exit(73)
    return ExitWaiter()
subprocess.Popen=launch
b.i.uuid.uuid4=lambda:types.SimpleNamespace(hex='a'*32)
core=b.CoreReload.__new__(b.CoreReload)
core.app=app
core.before=dict(state='RUNNING',config=b.CORE_RELOAD_SUPPORT['config_pin'](app),core=fixture['old'])
with b.installation_lock(app) as fd:
    core.lock_fd=fd
    core.finish(fixture['digest'],'v1.2.3','b'*40)
'''
        # Linux subreaper makes the actual orphan ours to wait/reap in this test.
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)
        previous = ctypes.c_int()
        self.assertEqual(libc.prctl(37, ctypes.byref(previous), 0, 0, 0), 0)
        self.assertEqual(libc.prctl(36, 1, 0, 0, 0), 0)
        pid = None
        try:
            parent = REAL_POPEN([sys.executable, '-I', '-B', '-c', parent_source,
                                 str(HERE/'install-binary.py'), str(w.app), SEAM],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env={'PATH':'/usr/bin:/bin','LANG':'C'})
            stdout, stderr = parent.communicate(timeout=15)
            self.assertEqual(parent.returncode, 73, stderr.decode())
            pid = int((w.app/'worker-pid').read_text())
            with self.assertRaisesRegex(ValueError, 'another binary installer'):
                with b.installation_lock(w.app):
                    self.fail('parent exit released live worker flock')
            (w.tx/'release').touch()
            until = time.monotonic()+10
            while True:
                reaped, status = os.waitpid(pid, os.WNOHANG)
                if reaped:
                    pid = None
                    self.assertEqual(os.waitstatus_to_exitcode(status), 0)
                    break
                self.assertLess(time.monotonic(), until)
                time.sleep(.01)
            # Even a later SUCCEEDED worker cannot accept a lost parent's result.
            self.assertEqual(json.loads((w.tx/'result.json').read_bytes())['state'], 'SUCCEEDED')
            self.assert_all_mutators_blocked()
        finally:
            (w.tx/'release').touch()
            if pid is not None:
                os.kill(pid, 9)
                os.waitpid(pid, 0)
            libc.prctl(36, previous.value, 0, 0, 0)

    def test_successful_parent_commit_allows_next_install(self):
        self.finish(self.fixture())
        w = self.w
        self.assertFalse((w.tx/'pending.json').exists())
        self.assertTrue((w.tx/'accepted.json').is_file())
        capture = mock.Mock(return_value=dict(state='STOPPED'))
        with mock.patch.dict(b.CORE_RELOAD_SUPPORT, capture=capture):
            b.CoreReload(w.app)
        capture.assert_called_once()
        im = load('durability_success_install_fixture', HERE/'install_binary_test.py')
        im.b = b
        c = im.InstallerTests(); c.setUp()
        try:
            _, bundle, _, _ = c.verified()
            c.app = w.app
            c.processes = []
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()), \
                 mock.patch.dict(b.CORE_RELOAD_SUPPORT, capture=mock.Mock(return_value=dict(state='STOPPED'))):
                b.install_verified(bundle, im.TAG, w.app, c.home, c.runner,
                                   env={'HOME':str(c.home)}, tty=lambda:io.BytesIO())
            self.assertIn(['helper','install'], [argv[1:] for argv, _ in c.processes])
        finally:
            c.doCleanups()

    def test_default_full_install_really_captures_then_detached_reload_once(self):
        w = self.w
        w.tx.rmdir()
        im = load('durability_default_install_fixture', HERE/'install_binary_test.py')
        im.b = b
        c = im.InstallerTests(); c.setUp()
        try:
            _, bundle, _, _ = c.verified()
            c.app = w.app
            c.processes = []
            # A prior core is running; candidate is the inert package fixture.
            (w.app/'anytls-macos').write_bytes(im.BINARY)
            w.digest = w.n['file_hash'](w.app/'anytls-macos')
            w.status['helper_sha256'] = w.digest
            w.response['helper_sha256'] = w.digest
            w.trace['trace']['streams'][0]['provenance'].update(sha256=w.digest, git_revision=im.COMMIT)
            events = []
            def capture(app):
                self.assertEqual(app, w.app)
                self.assertFalse(any(argv[1:]==['helper','install'] for argv, _ in c.processes))
                events.append('capture')
                return w.before
            original = c.runner
            def runner(argv, **kwargs):
                if argv[1:]==['helper','install']: events.append('helper')
                return original(argv, **kwargs)
            launch = self.launch(self.fixture())
            def recorded_launch(argv, **kwargs):
                events.append('reload')
                self.assertIn('webui', events)
                return launch(argv, **kwargs)
            c.webui_factory.return_value.restart.side_effect = lambda:events.append('webui')
            with mock.patch.dict(b.CORE_RELOAD_SUPPORT, capture=capture), \
                 mock.patch.object(b.i.uuid, 'uuid4', return_value=types.SimpleNamespace(hex=w.op)), \
                 mock.patch.object(b.subprocess, 'Popen', side_effect=recorded_launch), \
                 contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                b.install_verified(bundle, im.TAG, w.app, c.home, runner,
                                   env={'HOME':str(c.home)}, tty=lambda:io.BytesIO())
            self.assertEqual(events, ['capture','helper','webui','reload'])
            self.assertEqual(len(self.children), 1)
            self.assertEqual(self.children[0][0].returncode, 0)
            self.assertEqual(json.loads((w.tx/'entered.json').read_bytes())['operation_id'], w.op)
            self.assertTrue((w.tx/'accepted.json').is_file())
            self.assertFalse((w.tx/'pending.json').exists())
        finally:
            c.doCleanups()

    def test_unknown_receipt_blocks_explicit_opt_out_before_helper_install(self):
        w = self.w
        (w.tx/'result.json').write_text(json.dumps(dict(state='UNKNOWN',operation_id=w.op)))
        im = load('durability_unknown_full_fixture', HERE/'install_binary_test.py')
        im.b = b
        c = im.InstallerTests(); c.setUp()
        try:
            _, bundle, _, _ = c.verified()
            c.app = w.app
            c.processes = []
            with self.assertRaisesRegex(ValueError,'UNKNOWN/pending'), \
                 contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                b.install_verified(bundle,im.TAG,w.app,c.home,c.runner,
                                   env={'HOME':str(c.home)},tty=lambda:io.BytesIO(),reload_core=False)
            self.assertEqual(c.processes,[])
            self.assertEqual((w.app/'anytls-macos').read_bytes(),b'candidate fixture')
        finally:
            c.doCleanups()

    def test_full_run_pending_guard_before_retention_helper_and_publish(self):
        im = load('durability_run_fixture', HERE/'install_binary_test.py')
        im.b = b
        c = im.InstallerTests(); c.setUp()
        try:
            c.app.mkdir()
            tx=c.app/('.core-reload-'+'f'*32);tx.mkdir(mode=0o700)
            (tx/'result.json').write_text(json.dumps(dict(state='UNKNOWN',operation_id='f'*32)))
            c.processes=[]
            for explicit in (None,False,True):
                args=types.SimpleNamespace(check_download=False,version=im.TAG,arch=None,reload_core=explicit)
                with self.subTest(explicit=explicit), self.assertRaisesRegex(ValueError,'UNKNOWN/pending'), \
                     contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    b.run(args,transport=c.transport,runner=c.runner,system='Darwin',machine='arm64',
                          euid=501,home=c.home,env={'HOME':str(c.home)},tty=lambda:io.BytesIO())
            self.assertEqual(c.processes,[])
            self.assertFalse((c.app/'releases').exists())
            self.assertFalse((c.app/'anytls-macos').exists())
            c.webui_factory.assert_not_called()
        finally:
            c.doCleanups()

    def test_bare_success_rejected_and_unknown_all_block(self):
        for state in ('SUCCEEDED', 'REJECTED', 'UNKNOWN'):
            with self.subTest(state=state):
                p = self.w.tx/'result.json'
                p.write_text(json.dumps(dict(state=state, operation_id=self.w.op)))
                self.assert_all_mutators_blocked()

    def test_pre_send_intent_and_post_send_response_failures_keep_distinct_results(self):
        w = self.w
        original = w.n['put']
        for name, state, sends in (('intent.json','REJECTED',0), ('response.json','UNKNOWN',1)):
            with self.subTest(name=name):
                def put(root, filename, value):
                    if filename == name:
                        raise OSError('synthetic journal write failure')
                    return original(root, filename, value)
                w.n['put'] = put
                self.assertEqual(w.run_worker(), 1)
                result = json.loads((w.tx/'result.json').read_bytes())
                self.assertEqual(result['state'], state)
                self.assertEqual(sum(q['action']=='reload' for q in w.requests), sends)
                self.assert_all_mutators_blocked()
                for p in w.tx.iterdir(): p.unlink()
                w.requests.clear()


if __name__ == '__main__':
    unittest.main()

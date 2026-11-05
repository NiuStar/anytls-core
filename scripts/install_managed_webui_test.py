#!/usr/bin/env python3
"""LOCALONLY simulated macOS managed WebUI boundaries; no device/native acceptance."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import selectors
import socket
import subprocess
import tempfile
import types
import unittest
from unittest import mock

REAL_POPEN = subprocess.Popen
REAL_KILL = os.kill

spec = importlib.util.spec_from_file_location('managed_binary_tests', Path(__file__).with_name('install_binary_test.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
b = m.b
WebUI = b.WebUI


class ManagedWebUITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='managed-webui-')
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name).resolve()
        self.app = self.home / '.anytls'
        self.app.mkdir()
        self.target = self.app / 'anytls-macos'
        self.target.write_bytes(b'old fixture executable; never executed')
        (self.app / 'config.yaml').write_bytes(b'nodes: []\n')
        self.label = 'com.anytls.webui.' + hashlib.sha256((str(os.getuid()) + '\0' + str(self.target) + '\0' + str(self.app / 'config.yaml')).encode()).hexdigest()[:24]
        self.plist = self.home / 'Library/LaunchAgents' / (self.label + '.plist')
        self.plist.parent.mkdir(parents=True)
        self.plist.write_bytes(b'fixture plist verified by simulated existing CLI')
        self.command = str(self.target) + ' webui --listen 0.0.0.0 --port 18089 --managed-agent ' + self.label
        self.old = (str(os.getuid()), 'Wed Oct 21 10:00:00 2026', self.command)
        self.new = (self.old[0], 'Wed Oct 21 10:01:00 2026', self.command)
        self.ui = WebUI(self.target, {'HOME': str(self.home)})
        self.pids = {42}
        self.identities = {42: self.old, 77: self.new}
        self.addCleanup(mock.patch.stopall)
        self.kill = mock.patch.object(os, 'kill').start()
        self.popen = mock.patch.object(subprocess, 'Popen', side_effect=AssertionError('second WebUI forbidden')).start()
        self.run = mock.patch.object(subprocess, 'run', side_effect=self.status).start()
        mock.patch.object(socket, 'socket', side_effect=AssertionError('network forbidden')).start()
        mock.patch.object(b.time, 'sleep').start()
        mock.patch.object(self.ui, 'listeners', side_effect=lambda: self.pids.copy()).start()
        mock.patch.object(self.ui, 'identity', side_effect=lambda pid: self.identities.get(pid)).start()
        self.reply = None
        self.rc = 0
        self.err = b''
        self.opener = mock.Mock()
        response = mock.MagicMock()
        response.__enter__.return_value.status = 200
        response.__enter__.return_value.read.return_value = b'<title>AnyTLS actual console</title>'
        self.response = response.__enter__.return_value
        self.opener.open.return_value = response
        mock.patch.object(b.urllib.request, 'build_opener', return_value=self.opener).start()

    def dto(self, pid=None):
        if pid is None:
            pid = next(iter(self.pids)) if self.pids else 0
        return dict(label=self.label, target='gui/%d/%s' % (os.getuid(), self.label),
                    plist=str(self.plist), pid=pid, restartManaged=True)

    def status(self, argv, **kwargs):
        self.assertEqual(argv, [str(self.target), 'webui', 'agent-status', '--listen', '0.0.0.0', '--port', '18089'])
        self.assertNotIn('sudo', argv)
        self.assertFalse(kwargs.get('check', False))
        return types.SimpleNamespace(returncode=self.rc, stderr=self.err,
                                     stdout=json.dumps(self.dto()).encode() if self.reply is None else self.reply)

    def preflight(self):
        self.ui.preflight()
        self.assertEqual(self.ui.old, (42, self.old))

    def publish(self):
        self.target.write_bytes(b'new fixture executable; never executed')
        self.ui.published_digest = hashlib.sha256(self.target.read_bytes()).hexdigest()

    def respawn(self, pid, sig):
        self.assertEqual((pid, sig), (42, b.signal.SIGTERM))
        self.identities.pop(42)
        self.pids = {77}

    def test_existing_managed_preflight_recognized(self):
        self.preflight()
        self.run.assert_called_once()
        self.kill.assert_not_called()
        self.popen.assert_not_called()

    def test_keepalive_restart_uses_only_old_term_and_readonly_status(self):
        self.preflight()
        before = self.plist.read_bytes()
        self.publish()
        self.kill.side_effect = self.respawn
        self.ui.restart()
        self.kill.assert_called_once_with(42, b.signal.SIGTERM)
        self.popen.assert_not_called()
        self.assertEqual(self.plist.read_bytes(), before)
        self.assertGreaterEqual(self.run.call_count, 4)
        self.opener.open.assert_called_once_with('http://127.0.0.1:18089/', timeout=1)

    def test_strict_status_schema_and_identity_reject(self):
        good = self.dto()
        bad = [b'null', b'[]', b'not json', b'{"pid":42,"pid":42}',
               json.dumps(good).replace('"pid": 42', '"pid": 42, "pid": 42').encode()]
        for key in good:
            for value in (None, False, [], {}):
                bad.append(json.dumps(dict(good, **{key: value})).encode())
            missing = good.copy()
            missing.pop(key)
            bad.append(json.dumps(missing).encode())
        for changes in ({'extra': True}, {'restartManaged': 1}, {'restartManaged': False},
                        {'pid': 43}, {'pid': '42'}, {'pid': 42.0}, {'label': self.label + '0'},
                        {'target': 'gui/999/' + self.label}, {'plist': str(self.plist) + '.other'}):
            bad.append(json.dumps(dict(good, **changes)).encode())
        for raw in bad:
            with self.subTest(raw=raw):
                self.reply = raw
                with self.assertRaisesRegex(ValueError, 'MANAGED_WEBUI_STATUS'):
                    self.ui.preflight()
        self.assertIsNone(self.ui.old)
        self.kill.assert_not_called()
        self.popen.assert_not_called()

    def test_exit_zero_is_not_authority_and_unavailable_cli_holds(self):
        for rc, err in ((1, b''), (0, b'warning')):
            self.rc, self.err = rc, err
            with self.subTest(rc=rc, err=err), self.assertRaisesRegex(ValueError, 'MANAGED_WEBUI_STATUS'):
                self.ui.preflight()
        for exc in (FileNotFoundError(), subprocess.TimeoutExpired('agent-status', 10)):
            self.run.side_effect = exc
            with self.subTest(exc=exc), self.assertRaisesRegex(ValueError, 'MANAGED_WEBUI_STATUS'):
                self.ui.preflight()
        self.kill.assert_not_called()

    def test_forged_managed_flag_wrong_uid_path_label_and_duplicate_reject(self):
        invalid = [(str(os.getuid() + 1), *self.old[1:]),
                   (*self.old[:2], self.command.replace(str(self.target), '/other/anytls-macos'))]
        invalid += [(*self.old[:2], self.command + tail) for tail in (
            ' --managed-agent ' + self.label, ' --unknown x', ' extra')]
        invalid += [(*self.old[:2], self.command.replace(self.label, label)) for label in (
            'com.anytls.webui.forged', self.label.upper(), self.label + '0', "'" + self.label + "'")]
        for identity in invalid:
            self.identities[42] = identity
            with self.subTest(identity=identity), self.assertRaises(ValueError):
                self.ui.preflight()
        self.run.assert_not_called()
        self.kill.assert_not_called()

    def test_managed_listen_migration_rejected_preinstall(self):
        self.identities[42] = (*self.old[:2], self.command.replace('0.0.0.0', '127.0.0.1'))
        with self.assertRaisesRegex(ValueError, 'MANAGED_WEBUI_LISTEN_MIGRATION_UNSUPPORTED'):
            self.ui.preflight()
        self.run.assert_not_called()
        self.kill.assert_not_called()

    def test_status_cannot_authorize_changed_preflight_identity_or_binary(self):
        def changed(argv, **kwargs):
            result = self.status(argv, **kwargs)
            self.identities[42] = self.new
            return result
        self.run.side_effect = changed
        with self.assertRaisesRegex(ValueError, 'changed'):
            self.ui.preflight()
        def binary_changed(*args, **kwargs):
            result = self.status(*args, **kwargs)
            self.target.write_bytes(b'changed')
            return result
        self.identities[42] = self.old
        self.run.side_effect = binary_changed
        with self.assertRaisesRegex(ValueError, 'changed'):
            self.ui.preflight()
        self.kill.assert_not_called()

    def test_missing_symlink_or_changed_plist_rejected(self):
        original = self.plist.read_bytes()
        self.plist.unlink()
        with self.assertRaises(ValueError):
            self.ui.preflight()
        other = self.home / 'other.plist'
        other.write_bytes(original)
        self.plist.symlink_to(other)
        with self.assertRaises(ValueError):
            self.ui.preflight()
        self.plist.unlink()
        self.plist.write_bytes(original)
        self.preflight()
        self.publish()
        self.plist.write_bytes(b'changed plist')
        with self.assertRaisesRegex(ValueError, 'changed'):
            self.ui.restart()
        self.kill.assert_not_called()

    def test_restart_old_birth_uid_command_or_listener_drift_no_signal(self):
        self.preflight()
        self.publish()
        for identity, pids in ((self.new, {42}), ((str(os.getuid()+1), *self.old[1:]), {42}),
                               ((*self.old[:2], self.command + ' --unknown'), {42}),
                               (None, set()), (self.old, {77}), (self.old, {42, 77})):
            self.identities[42] = identity
            self.pids = pids
            with self.subTest(identity=identity, pids=pids), self.assertRaises(ValueError):
                self.ui.restart()
        self.kill.assert_not_called()
        self.popen.assert_not_called()

    def test_status_race_before_term_does_not_signal(self):
        self.preflight()
        self.publish()
        def race(*args, **kwargs):
            result = self.status(*args, **kwargs)
            self.identities[42] = self.new
            return result
        self.run.side_effect = race
        with self.assertRaisesRegex(ValueError, 'changed'):
            self.ui.restart()
        self.kill.assert_not_called()

    def test_status_race_keepalive_pid_swap_never_signals_replacement(self):
        self.preflight()
        self.publish()
        def race(*args, **kwargs):
            self.identities.pop(42)
            self.pids = {77}
            return self.status(*args, **kwargs)
        self.run.side_effect = race
        with self.assertRaisesRegex(ValueError, 'MANAGED_WEBUI_STATUS'):
            self.ui.restart()
        self.kill.assert_not_called()

    def test_published_binary_or_status_drift_before_term_holds(self):
        self.preflight()
        self.publish()
        self.target.write_bytes(b'foreign replacement')
        with self.assertRaisesRegex(ValueError, 'binary changed'):
            self.ui.restart()
        self.target.write_bytes(b'new fixture executable; never executed')
        self.reply = json.dumps(dict(self.dto(), restartManaged=False)).encode()
        with self.assertRaisesRegex(ValueError, 'MANAGED_WEBUI_STATUS'):
            self.ui.restart()
        self.kill.assert_not_called()

    def test_owned_local_child_gracefully_drains_term_without_force_kill(self):
        # Real local TERM/drain; process/launchd/HTTP observations remain SIM.
        code = ('import signal,time,sys\n'
                'def drain(sig,frame):\n'
                ' print("DRAIN",flush=True);time.sleep(.15);sys.exit(0)\n'
                'signal.signal(signal.SIGTERM,drain);signal.alarm(5)\n'
                'print("READY",flush=True)\n'
                'signal.pause()\n')
        child = REAL_POPEN([b.sys.executable, '-I', '-B', '-c', code],
                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           env={'PATH': '/usr/bin:/bin'}, start_new_session=True)
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout, selectors.EVENT_READ)
                self.assertTrue(selector.select(timeout=3), 'owned child READY timeout')
            self.assertEqual(child.stdout.readline(), b'READY\n')
            self.identities = {child.pid: self.old, 77: self.new}
            self.ui.listeners.side_effect = lambda: {child.pid} if child.poll() is None else {77}
            self.ui.identity.side_effect = lambda pid: (self.old if child.poll() is None else None) if pid == child.pid else self.identities.get(pid)
            self.pids = {child.pid}
            self.ui.preflight()
            self.publish()
            def send(pid, sig):
                self.assertEqual((pid, sig), (child.pid, b.signal.SIGTERM))
                REAL_KILL(pid, sig)
            self.kill.side_effect = send
            def status(argv, **kwargs):
                self.pids = self.ui.listeners()
                return self.status(argv, **kwargs)
            self.run.side_effect = status
            self.ui.restart()
            self.assertEqual(child.wait(timeout=3), 0)
            self.assertEqual(child.stdout.read(), b'DRAIN\n')
            self.kill.assert_called_once_with(child.pid, b.signal.SIGTERM)
            self.popen.assert_not_called()
        finally:
            if child.poll() is None:
                REAL_KILL(child.pid, b.signal.SIGTERM)
            child.wait(timeout=3)
            child.stdout.close()
            child.stderr.close()

    def test_old_term_drain_timeout_unknown_no_force_or_second_start(self):
        self.preflight()
        self.publish()
        self.ui.timeout = 0
        with self.assertRaisesRegex(ValueError, 'UNKNOWN.*no SIGKILL'):
            self.ui.restart()
        self.kill.assert_called_once_with(42, b.signal.SIGTERM)
        self.popen.assert_not_called()
        self.opener.open.assert_not_called()

    def test_respawn_timeout_unknown_never_starts(self):
        self.preflight()
        self.publish()
        def drain(pid, sig):
            self.identities.pop(42)
            self.pids = set()
        self.kill.side_effect = drain
        with mock.patch.object(b.time, 'monotonic', side_effect=[0, 0, 11]), self.assertRaisesRegex(ValueError, 'UNKNOWN'):
            self.ui.restart()
        self.kill.assert_called_once_with(42, b.signal.SIGTERM)
        self.popen.assert_not_called()

    def test_foreign_respawn_never_probes_or_signals(self):
        self.preflight()
        self.publish()
        self.identities[77] = (*self.new[:2], '/foreign webui')
        self.kill.side_effect = self.respawn
        with self.assertRaisesRegex(ValueError, 'UNKNOWN'):
            self.ui.restart()
        self.opener.open.assert_not_called()
        self.kill.assert_called_once_with(42, b.signal.SIGTERM)
        self.popen.assert_not_called()

    def test_new_status_must_bind_new_listener_pid(self):
        self.preflight()
        self.publish()
        def spawn(pid, sig):
            self.respawn(pid, sig)
            self.reply = json.dumps(self.dto(42)).encode()
        self.kill.side_effect = spawn
        with self.assertRaisesRegex(ValueError, 'UNKNOWN'):
            self.ui.restart()
        self.opener.open.assert_not_called()
        self.popen.assert_not_called()

    def test_real_console_marker_and_post_http_identity_required(self):
        for kind in ('foreign-page', 'identity-race', 'listener-race'):
            with self.subTest(kind=kind):
                self.pids = {42}
                self.identities[42] = self.old
                self.identities[77] = self.new
                self.ui = WebUI(self.target, {'HOME': str(self.home)})
                with mock.patch.object(self.ui, 'listeners', side_effect=lambda: self.pids.copy()), \
                        mock.patch.object(self.ui, 'identity', side_effect=lambda pid: self.identities.get(pid)):
                    self.preflight()
                    self.publish()
                    self.kill.side_effect = self.respawn
                    self.response.read.return_value = b'foreign page' if kind == 'foreign-page' else b'<title>AnyTLS console</title>'
                    def opened(*args, **kwargs):
                        if kind == 'identity-race':
                            self.identities[77] = self.old
                        if kind == 'listener-race':
                            self.pids = {88}
                        response = mock.MagicMock()
                        response.__enter__.return_value = self.response
                        return response
                    self.opener.open.side_effect = opened
                    with mock.patch.object(b.time, 'monotonic', side_effect=[0, 0, 11]), self.assertRaisesRegex(ValueError, 'UNKNOWN'):
                        self.ui.restart()
        self.popen.assert_not_called()

    def test_manual_path_unchanged_no_status_cli(self):
        self.identities[42] = (*self.old[:2], str(self.target) + ' webui --listen 127.0.0.1')
        self.ui.preflight()
        self.run.assert_not_called()
        with mock.patch.object(self.ui, 'start') as start:
            self.kill.side_effect = self.respawn
            self.ui.listeners.side_effect = [{42}, set()]
            self.ui.restart()
        start.assert_called_once()
        self.kill.assert_called_once_with(42, b.signal.SIGTERM)


class ManagedInstallOrderTests(unittest.TestCase):
    def setUp(self):
        self.case = m.InstallerTests('test_webui_preflight_failure_precedes_helper_publish')
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.c = self.case

    def test_real_preflight_rejection_before_helper_and_publish(self):
        c = self.c
        c.app.mkdir()
        target = c.app / 'anytls-macos'
        target.write_bytes(b'old untouched')
        ui = WebUI(target, {'HOME': str(c.home)})
        command = str(target) + ' webui --listen 0.0.0.0 --port 18089 --managed-agent com.anytls.webui.forged'
        c.webui_factory.side_effect = lambda *args, **kwargs: ui
        with mock.patch.object(ui, 'listeners', return_value={42}), \
                mock.patch.object(ui, 'identity', return_value=(str(os.getuid()), 'birth', command)), \
                mock.patch.object(b, 'CoreReload') as activation:
            c.processes = []
            _, bundle, _, _ = c.verified()
            with self.assertRaises(ValueError):
                b.install_verified(bundle, m.TAG, c.app, c.home, runner=c.runner, tty=lambda: io.BytesIO())
        self.assertEqual(c.processes, [])
        activation.assert_not_called()
        self.assertEqual(target.read_bytes(), b'old untouched')

    def managed_fixture(self):
        fixture = ManagedWebUITests('test_existing_managed_preflight_recognized')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.c.home, self.c.app = fixture.home, fixture.app
        self.c.webui_factory.side_effect = lambda *args, **kwargs: fixture.ui
        self.c.processes = []
        return fixture

    def test_full_install_real_managed_restart_after_helper_publish_stopped_vpn(self):
        c = self.c
        f = self.managed_fixture()
        _, bundle, _, _ = c.verified()
        events = []
        def runner(argv, **kwargs):
            events.append(tuple(argv[1:]))
            return c.runner(argv, **kwargs)
        def signal(pid, sig):
            self.assertIn(('helper', 'install'), events)
            self.assertIn(('helper', 'status'), events)
            self.assertEqual(f.target.read_bytes(), m.BINARY)
            events.append(('term',))
            f.respawn(pid, sig)
        f.kill.side_effect = signal
        # Real CoreReload constructor/finish, only authenticated OS observation
        # seam is simulated: a stopped VPN must not dispatch or auto-start.
        finish = b.CoreReload.finish
        def finished(obj, *args):
            self.assertEqual(obj.before['state'], 'STOPPED')
            events.append(('activation-after-ready',))
            return finish(obj, *args)
        with mock.patch.dict(b.CORE_RELOAD_SUPPORT, {'capture': lambda app: {'state': 'STOPPED'}}), \
                mock.patch.object(b.CoreReload, 'finish', autospec=True, side_effect=finished):
            b.install_verified(bundle, m.TAG, c.app, c.home, runner=runner,
                               tty=lambda: io.BytesIO(), env={'HOME': str(c.home)})
        self.assertEqual(events[-1], ('activation-after-ready',))
        self.assertEqual(sum(e == ('helper', 'install') for e in events), 1)
        f.kill.assert_called_once_with(42, b.signal.SIGTERM)
        f.popen.assert_not_called()
        f.opener.open.assert_called_once()
        self.assertFalse(any('start' in argv or 'reload' in argv for argv, _ in c.processes))

    def test_real_managed_status_and_migration_fail_before_helper(self):
        c = self.c
        f = self.managed_fixture()
        _, bundle, _, _ = c.verified()
        for kind in ('status', 'migration'):
            f.reply = b'{}' if kind == 'status' else None
            f.identities[42] = f.old if kind == 'status' else (*f.old[:2], f.command.replace('0.0.0.0', '127.0.0.1'))
            with self.subTest(kind=kind), mock.patch.object(b, 'CoreReload') as activation:
                with self.assertRaisesRegex(ValueError, 'WEBUI_PREFLIGHT_REJECTED'):
                    b.install_verified(bundle, m.TAG, c.app, c.home, runner=c.runner,
                                       tty=lambda: io.BytesIO(), env={'HOME': str(c.home)})
                activation.assert_not_called()
        self.assertEqual(c.processes, [])
        f.kill.assert_not_called()
        f.popen.assert_not_called()

    def test_managed_restart_unknown_blocks_activation_after_publish(self):
        c = self.c
        f = self.managed_fixture()
        _, bundle, _, _ = c.verified()
        f.ui.timeout = 0
        with mock.patch.object(b, 'CoreReload') as activation:
            with self.assertRaisesRegex(ValueError, 'MANAGED_WEBUI_UNKNOWN'):
                b.install_verified(bundle, m.TAG, c.app, c.home, runner=c.runner,
                                   tty=lambda: io.BytesIO(), env={'HOME': str(c.home)})
            activation.return_value.finish.assert_not_called()
        self.assertEqual(f.target.read_bytes(), m.BINARY)
        self.assertEqual(sum(argv[1:] == ['helper', 'install'] for argv, _ in c.processes), 1)
        f.kill.assert_called_once_with(42, b.signal.SIGTERM)
        f.popen.assert_not_called()

    def test_preflight_cli_error_message_does_not_claim_reload_may_dispatched(self):
        # Exercise the real main rendering, not merely an exception substring.
        c = self.c
        f = self.managed_fixture()
        f.identities[42] = (*f.old[:2], f.command.replace(f.label, 'com.anytls.webui.forged'))
        _, bundle, _, _ = c.verified()
        def rejected(args):
            return b.install_verified(bundle, m.TAG, c.app, c.home, runner=c.runner,
                                      tty=lambda: io.BytesIO(), env={'HOME': str(c.home)})
        output = io.StringIO()
        with mock.patch.object(b, 'run', side_effect=rejected), mock.patch.object(b.sys, 'stderr', output):
            self.assertEqual(b.main([]), 1)
        self.assertIn('WEBUI_PREFLIGHT_REJECTED', output.getvalue())
        self.assertNotIn('may have been dispatched', output.getvalue())


if __name__ == '__main__':
    unittest.main()

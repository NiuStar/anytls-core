#!/usr/bin/env python3
"""Offline native-ps shape regression; no actual processes or helper calls."""
import importlib.util
import json
from pathlib import Path
import types
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('ps_installer', Path(__file__).with_name('install-binary.py'))
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)

class ProcessRows(unittest.TestCase):
    def setUp(self):
        self.n = {'__name__': 'offline_ps_fixture'}
        exec(b.CORE_RELOAD_WORKER, self.n)
        self.app = Path('/Users/fixture/.anytls')
        self.core = str(self.app / 'service/anytls-macos')

    def read(self, text):
        with mock.patch.object(self.n['subprocess'], 'run', return_value=types.SimpleNamespace(stdout=text.encode())) as run:
            rows = self.n['processes'](self.app)
        self.assertEqual(run.call_args.args[0], ['/bin/ps','-ww','-axo','pid=,uid=,lstart=,command='])
        return rows

    def test_real_darwin_negative_system_uid_does_not_block_core_census(self):
        # Sanitized observed Darwin system row, plus an inert synthetic core.
        raw = '  180    -2 Wed Nov  4 15:16:23 2026     /usr/libexec/dhcp6d\n'
        raw += '20596 0 Thu Nov  5 09:13:26 2026 '+self.core+' -config x -network tun run\n'
        rows = self.read(raw)
        self.assertEqual(rows, [dict(pid=20596,uid=0,birth='Thu Nov 5 09:13:26 2026',command=self.core+' -config x -network tun run')])

    def test_negative_scoped_uid_is_retained_and_rejected_by_capture(self):
        for uid in ('-2', '-1', '501'):
            with self.subTest(uid=uid):
                exec(b.CORE_RELOAD_WORKER, self.n)
                rows = self.read('20596 '+uid+' Thu Nov  5 09:13:26 2026 '+self.core+' run\n')
                self.assertEqual(rows[0]['uid'], int(uid))
                # Do not skip/repair a suspicious actual core UID.
                self.n['SOCKET'] = Path(__file__)
                self.n['config_pin'] = lambda app: dict(identity='a'*64)
                self.n['helper_hash'] = lambda: 'b'*64
                self.n['processes'] = lambda app: rows
                self.n['request'] = lambda q: dict(ok=True,code='',message='',loaded=True,running=True,helper_version='v1.2.3',helper_sha256='b'*64,config_identity='a'*64)
                with self.assertRaisesRegex(ValueError,'CORE_RELOAD_PROCESS_UID'):
                    self.n['capture'](self.app)

    def test_malformed_rows_are_not_silently_discarded(self):
        for pid,uid in [('abc','0'),('1','--2'),('1','+2'),('1','2.0'),('1','root'),('1',''),('1','−2')]:
            with self.subTest(pid=pid,uid=uid), self.assertRaisesRegex(ValueError,'CORE_RELOAD_PROCESS_READ'):
                self.read(pid+' '+uid+' Wed Nov 4 15:16:23 2026 /usr/libexec/example\n')
        with self.assertRaisesRegex(ValueError,'CORE_RELOAD_PROCESS_READ'):
            self.read('180 -2 incomplete\n')

    def test_system_only_negative_uids_are_not_false_core(self):
        self.assertEqual(self.read('180 -2 Wed Nov 4 15:16:23 2026 /usr/libexec/dhcp6d\n'), [])

class PreflightPhase(unittest.TestCase):
    def test_capture_failure_is_pre_mutation_and_does_not_echo_private_error(self):
        import contextlib
        import io
        spec = importlib.util.spec_from_file_location('base_fixture', Path(__file__).with_name('install_binary_test.py'))
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        c = m.InstallerTests()
        c.setUp()
        try:
            _, bundle, _, _ = c.verified()
            c.app.mkdir()
            c.processes = []
            with mock.patch.object(m.b, 'CoreReload', side_effect=ValueError('CORE_RELOAD_PROCESS_READ')):
                with self.assertRaises(m.b.CoreReloadPreflightRejected) as caught:
                    m.b.install_verified(bundle, m.TAG, c.app, c.home, c.runner,
                                         env={'HOME':str(c.home)}, tty=lambda:io.BytesIO())
            self.assertIn('no helper install, binary publish, WebUI signal or core reload dispatched', str(caught.exception))
            self.assertEqual(c.processes, [])
            c.webui_factory.return_value.restart.assert_not_called()
            with mock.patch.object(m.b, 'run', side_effect=caught.exception), contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertEqual(m.b.main([]), 1)
            self.assertNotIn('may have been dispatched', err.getvalue())
            self.assertIn('CORE_RELOAD_PROCESS_READ', err.getvalue())
        finally:
            c.doCleanups()

if __name__ == '__main__':
    unittest.main(verbosity=2)

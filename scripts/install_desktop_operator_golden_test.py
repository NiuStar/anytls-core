#!/usr/bin/env python3
"""Independent unchanged Python receiver for the Go operator golden bytes."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('operator_golden_installer', Path(__file__).with_name('install-binary.py'))
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)


class DesktopOperatorGolden(unittest.TestCase):
    def test_same_golden_unchanged_receiver_readonly(self):
        with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as temp:
            app = Path(temp).resolve()/'.anytls'
            app.mkdir(mode=0o700)
            root = app/'.core-reload-887e3586e7684e7b8ead5b5a12a7af67'
            root.mkdir(mode=0o700)
            raw = (Path(__file__).resolve().parent.parent/'testdata/desktop-reload/operator.json').read_text()
            files = json.loads(raw.replace('/fixture/.anytls', str(app)).replace(
                hashlib.sha256(b'/fixture/.anytls/config.yaml').hexdigest(),
                hashlib.sha256(str(app/'config.yaml').encode()).hexdigest()))
            marker = json.loads(files['operator-reconciled.json'])
            marker['receipt_sha256'] = {n: hashlib.sha256(files[n].encode()).hexdigest() for n in marker['receipt_sha256']}
            files['operator-reconciled.json'] = json.dumps(marker, sort_keys=True)
            for n, raw in files.items():
                (root/n).write_text(raw)
                (root/n).chmod(0o600)
            before = {p.name:p.read_bytes() for p in root.iterdir()}
            with mock.patch.object(b.subprocess, 'run', side_effect=AssertionError('no process or IPC')):
                with b.installation_lock(app):
                    self.assertTrue(b.operator_reconciliation_safe(app, root))
                    b.core_reload_guard(app)
            self.assertEqual(before, {p.name:p.read_bytes() for p in root.iterdir()})
            self.assertEqual(json.loads(before['result.json'])['state'], 'UNKNOWN')


if __name__ == '__main__':
    unittest.main()

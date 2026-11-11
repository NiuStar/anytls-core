#!/usr/bin/env python3
"""Offline exact successor-patch and packaging consumption checks."""
import copy
import difflib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

w = load('hook_wrapper', ROOT/'scripts/go-patched.py')
p = load('hook_packager', ROOT/'scripts/package-binary.py')

class HookTests(unittest.TestCase):
    def test_exact_successor_and_drift(self):
        ack, ack_patch = w.ack_identity()
        m, patch = w.hook_identity()
        entries = json.loads(patch)['files']
        diff = ''.join(''.join(difflib.unified_diff(e['old'].splitlines(True), e['new'].splitlines(True),
                        fromfile='a/'+e['file'], tofile='b/'+e['file'])) for e in entries)
        self.assertEqual(diff.encode(), (ROOT/'patches/sing-anytls/die-hook-publication.patch').read_bytes())
        with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as td:
            dest = Path(td)/'module'; dest.mkdir()
            w.stage_archive(ROOT/'scripts/tests/fixtures/sing-anytls-v0.0.11.zip', dest,
                            ack['module_sum'], ack['module'], ack['version'])
            w.apply_ack(dest, ack, ack_patch)
            self.assertEqual(w.apply_hook(dest, m, patch), m['files'])
            for pin in m['files']:
                self.assertEqual(w.sha((dest/pin['file']).read_bytes()), pin['result_sha256'])
            with self.assertRaisesRegex(ValueError, 'hook source'): w.apply_hook(dest, m, patch)

            tampered = copy.deepcopy(json.loads(patch)); tampered['files'][1]['new'] += '\n'
            (dest/m['files'][1]['file']).write_bytes(entries[1]['old'].encode())
            (dest/m['files'][0]['file']).write_bytes(entries[0]['old'].encode())
            with self.assertRaisesRegex(ValueError, 'hook result'): w.apply_hook(dest, m, json.dumps(tampered).encode())
        with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as td:
            target = Path(td)/'patches/sing-anytls'
            shutil.copytree(ROOT/'patches/sing-anytls', target)
            identity = target/'die-hook-publication.identity.json'
            identity.write_bytes(identity.read_bytes()+b'\n')
            with self.assertRaisesRegex(ValueError, 'hook identity SHA'): w.hook_identity(Path(td))

    def test_ccs_material_and_receipt_rejection(self):
        import tarfile
        fixture = load('hook_package_fixture', ROOT/'scripts/package_binary_test.py').PackagingTests()
        with fixture.package_fixture('arm64') as (root, settings, receipt, invoke):
            self.assertEqual(invoke()['modules'], 38)
            prefix = 'anytls-core-v1.0.0'
            with tarfile.open(root/'out'/(prefix+'-corresponding-source.tar.gz')) as archive:
                import io
                application = tarfile.open(fileobj=io.BytesIO(archive.extractfile(prefix+'/application-source.tar.gz').read()), mode='r:gz')
                for name in ('die-hook-publication.identity.json', 'die-hook-publication.patch.json',
                             'die-hook-publication.patch'):
                    rel = 'patches/sing-anytls/'+name
                    self.assertEqual(application.extractfile(prefix+'/'+rel).read(), (ROOT/rel).read_bytes())
                identity = json.load(archive.extractfile(prefix+'/BUILD-IDENTITY.json'))
                self.assertEqual(identity['certified_build']['stream_die_hook_publication'],
                                 w.hook_receipt(*w.hook_identity()))
            for field in receipt['stream_die_hook_publication']:
                bad = copy.deepcopy(receipt); bad['stream_die_hook_publication'][field] = 'tampered'
                with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'source identity'):
                    p.certified_sources(root, bad)
            bad = copy.deepcopy(receipt); bad.pop('stream_die_hook_publication')
            with self.assertRaisesRegex(ValueError, 'source identity'): p.certified_sources(root, bad)
            target = root/'patches/sing-anytls/die-hook-publication.patch.json'
            target.write_bytes(target.read_bytes()+b'\n')
            with self.assertRaisesRegex(ValueError, 'hook patch SHA'): p.certified_sources(root, receipt)
        with fixture.package_fixture('arm64', missing_material='patches/sing-anytls/die-hook-publication.patch') as (root, settings, receipt, invoke):
            with self.assertRaisesRegex(KeyError, 'die-hook-publication.patch'): invoke()
            self.assertFalse(list((root/'out').glob('*corresponding-source.tar.gz')))

if __name__ == '__main__': unittest.main(verbosity=2)

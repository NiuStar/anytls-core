#!/usr/bin/env python3
"""Leaf-pin patch/CCS regression; no Go or private cache required."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
w = load('leaf_wrapper', ROOT / 'scripts/go-patched.py')
p = load('leaf_packager', ROOT / 'scripts/package-binary.py')

class LeafPatchTests(unittest.TestCase):
    def receipt(self):
        start, patch = w.identity()
        core, cp = w.core_identity()
        chrome, chp = w.chrome_identity()
        return dict(go_version='go version go1.27.3 linux/amd64', identity_sha256=w.IDENTITY_SHA,
                    wrapper_sha256=w.sha((ROOT/'scripts/go-patched.py').read_bytes()),
                    module=w.MODULE, version=w.VERSION, commit=start['commit'],
                    source_sha256=start['source_sha256'], patch_sha256=w.sha(patch),
                    result_sha256=start['result_sha256'],
                    core_slim=dict(identity_sha256=w.CORE_IDENTITY_SHA, patch_sha256=w.sha(cp), files=core['files']),
                    chrome_backend=w.chrome_receipt(chrome, chp))

    def stage(self, root):
        m, patch = w.leaf_identity()
        for pin in m['files']:
            target = root/pin['file']
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((ROOT/'scripts/tests/fixtures/sing-box-v1.14.3'/pin['fixture']).read_bytes())
        return m, patch

    def test_real_source_patch_is_exact_and_leaf_only(self):
        with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as d:
            root = Path(d)
            m, patch = self.stage(root)
            self.assertEqual(w.apply_leaf(root,m,patch), m['files'])
            for pin in m['files']:
                self.assertEqual(w.sha((root/pin['file']).read_bytes()), pin['result_sha256'])
            std = (root/'common/tls/std_client.go').read_text()
            self.assertIn('sha256.Sum256(rawCerts[0])', std)
            self.assertIn('subtle.ConstantTimeCompare(value, hashValue[:])', std)
            self.assertIn('matched |=', std)
            self.assertIn('ValidateCertificateSHA256Options(options.Options)', (root/'common/tls/client.go').read_text())
            with self.assertRaisesRegex(ValueError,'source SHA'):
                w.apply_leaf(root,m,patch)

    def test_rejects_tampered_source_and_operation(self):
        import json
        for kind in ('source','operation'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as d:
                root = Path(d)
                m, patch = self.stage(root)
                if kind == 'source':
                    target = root/m['files'][0]['file']
                    target.write_bytes(target.read_bytes()+b'\n')
                else:
                    ops = json.loads(patch)
                    ops['files'][0]['replacements'][0]['new'] += '\n'
                    patch = json.dumps(ops).encode()
                with self.assertRaisesRegex(ValueError, 'SHA'):
                    w.apply_leaf(root,m,patch)

    def test_manifest_and_patch_authentication(self):
        m, patch = w.leaf_identity()
        with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as d:
            root=Path(d);dest=root/'patches/sing-box';dest.mkdir(parents=True)
            raw=(ROOT/'patches/sing-box/leaf.identity.json').read_bytes()
            (dest/'leaf.identity.json').write_bytes(raw)
            (dest/m['patch']).write_bytes(patch+b'\n')
            with self.assertRaisesRegex(ValueError,'patch SHA'): w.leaf_identity(root)
            (dest/'leaf.identity.json').write_bytes(raw+b'\n')
            with self.assertRaisesRegex(ValueError,'identity SHA'): w.leaf_identity(root)

    def test_complete_ccs_receipt_accepted_and_tamper_rejected(self):
        import copy
        m,patch=w.leaf_identity();receipt=self.receipt()
        receipt['leaf_certificate']=w.leaf_receipt(m,patch)
        materials=p.certified_sources(ROOT,receipt)
        self.assertIn('patches/sing-box/leaf.patch.json',materials)
        self.assertIn('patches/sing-box/leaf.identity.json',materials)
        altered=copy.deepcopy(receipt)
        altered['leaf_certificate']['files'][0]['result_sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'source identity'): p.certified_sources(ROOT,altered)

    def test_actual_staging_and_cache_final_guards(self):
        import ast
        main=next(n for n in ast.parse((ROOT/'scripts/go-patched.py').read_text()).body if isinstance(n,ast.FunctionDef) and n.name=='main')
        transaction=next(n for n in main.body if isinstance(n,ast.Try))
        first=next(i for i,n in enumerate(transaction.body) if isinstance(n,ast.Expr) and isinstance(n.value,ast.Call) and isinstance(n.value.func,ast.Name) and n.value.func.id=='apply_leaf')
        with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as d:
            root=Path(d);replacement=root/'private';directory=root/'cache'
            m,patch=self.stage(replacement);self.stage(directory)
            originals={pin['file']:(directory/pin['file']).read_bytes() for pin in m['files']}
            ctx=dict(w.__dict__,replacement=replacement,directory=directory,leaf_m=m,leaf_patch=patch,original_leaf=originals,receipt={})
            exec(compile(ast.Module(body=transaction.body[first:first+2],type_ignores=[]),'actual-leaf-stage','exec'),ctx)
            self.assertEqual(ctx['receipt']['leaf_certificate'],w.leaf_receipt(m,patch))
            for message in ('final staged leaf sources changed','module-cache leaf sources changed during command'):
                guards=[n for n in ast.walk(transaction) if isinstance(n,ast.Expr) and isinstance(n.value,ast.Call) and any(isinstance(a,ast.Constant) and a.value==message for a in n.value.args)]
                self.assertEqual(len(guards),1 if message.startswith('final') else 2)
                for guard in guards:
                    code=compile(ast.Module(body=[guard],type_ignores=[]),'actual-leaf-guard','exec')
                    exec(code,ctx)
                    target=(replacement if message.startswith('final') else directory)/m['files'][0]['file']
                    before=target.read_bytes();target.write_bytes(before+b'\n')
                    with self.assertRaisesRegex(ValueError,'leaf sources changed'):exec(code,ctx)
                    target.write_bytes(before)

    def test_ccs_rejects_missing_leaf_pin_receipt(self):
        with self.assertRaisesRegex(ValueError, 'source identity'):
            p.certified_sources(ROOT, self.receipt())

if __name__ == '__main__':
    unittest.main(verbosity=2)

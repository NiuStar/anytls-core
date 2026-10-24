"""Real authenticated upstream transformations; no Go or network execution."""
import ast
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
import zipfile

SCRIPT = Path(__file__).with_name('go-patched.py')
spec = importlib.util.spec_from_file_location('core_wrapper', SCRIPT)
w = importlib.util.module_from_spec(spec)
spec.loader.exec_module(w)


class CoreSlimTests(unittest.TestCase):
    def setUp(self):
        self.start, self.start_patch = w.identity()
        self.core, self.patch = w.core_identity()
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ['TMPDIR'])
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        # These two authenticated upstream files travel with clean source/CCS.
        # Python validation runs before Go/cache setup in the release workflow.
        fixture = w.ROOT / 'scripts/tests/fixtures/sing-box-v1.14.3'
        self.originals = {pin['file']: (fixture / (pin['file'] + '.txt')).read_bytes()
                          for pin in self.core['files']}
        for name, raw in self.originals.items():
            self.assertEqual(w.sha(raw), next(p['original_sha256'] for p in self.core['files'] if p['file'] == name))
            (self.root / name).write_bytes(raw)
        (self.root / 'box.go').write_bytes(w.transform(self.originals['box.go'], self.start, self.start_patch))

    def test_exact_approved_final_sources_and_double_apply(self):
        self.assertEqual(w.apply_core(self.root, self.core, self.patch), self.core['files'])
        for pin in self.core['files']:
            self.assertEqual(w.sha((self.root / pin['file']).read_bytes()), pin['result_sha256'])
        with self.assertRaisesRegex(ValueError, 'core input SHA'):
            w.apply_core(self.root, self.core, self.patch)

    def test_rejects_tampered_source_and_payload(self):
        with self.assertRaisesRegex(ValueError, 'core result SHA'):
            w.apply_core(self.root, self.core, self.patch.replace(b'cache file is unsupported', b'cache file is unavailable'))
        (self.root / 'box.go').write_bytes((self.root / 'box.go').read_bytes() + b'\n')
        with self.assertRaisesRegex(ValueError, 'core input SHA'):
            w.apply_core(self.root, self.core, self.patch)

    def test_rejects_tampered_identity_and_patch_materials(self):
        dest = self.root / 'patches/sing-box'
        dest.mkdir(parents=True)
        raw = (w.ROOT / 'patches/sing-box/core-slim.identity.json').read_bytes()
        (dest / 'core-slim.identity.json').write_bytes(raw)
        (dest / 'core-slim.patch.json').write_bytes(self.patch + b'\n')
        with self.assertRaisesRegex(ValueError, 'core patch SHA'):
            w.core_identity(self.root)
        (dest / 'core-slim.identity.json').write_bytes(raw + b'\n')
        with self.assertRaisesRegex(ValueError, 'core identity SHA'):
            w.core_identity(self.root)

    def test_actual_receipt_and_final_source_assertion_blocks(self):
        # Execute production AST blocks with real source files, not mocked Go output.
        main = next(n for n in ast.parse(SCRIPT.read_text()).body if isinstance(n, ast.FunctionDef) and n.name == 'main')
        transaction = next(n for n in main.body if isinstance(n, ast.Try))
        first = next(i for i, n in enumerate(transaction.body) if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'core_results' for t in n.targets))
        ctx = dict(w.__dict__, replacement=self.root, core_m=self.core, core_patch=self.patch, receipt={})
        exec(compile(ast.Module(body=transaction.body[first:first + 3], type_ignores=[]), str(SCRIPT), 'exec'), ctx)
        receipt = ctx['receipt']
        self.assertEqual(receipt['core_slim'], dict(identity_sha256=w.CORE_IDENTITY_SHA, patch_sha256=w.sha(self.patch), files=self.core['files']))
        self.assertIn('intermediate', receipt['result_sha256_scope'])
        assertion = next(n for n in transaction.body if isinstance(n, ast.Expr) and isinstance(n.value, ast.Call) and any(isinstance(a, ast.Constant) and a.value == 'final staged core sources changed' for a in n.value.args))
        code = compile(ast.Module(body=[assertion], type_ignores=[]), str(SCRIPT), 'exec')
        exec(code, ctx)
        for pin in self.core['files']:
            p = self.root / pin['file']; original = p.read_bytes(); p.write_bytes(original + b'\n')
            with self.assertRaisesRegex(ValueError, 'final staged core'):
                exec(code, ctx)
            p.write_bytes(original)

    def test_both_cache_sources_checked_after_command_and_in_finally(self):
        main = next(n for n in ast.parse(SCRIPT.read_text()).body if isinstance(n, ast.FunctionDef) and n.name == 'main')
        transaction = next(n for n in main.body if isinstance(n, ast.Try))
        checks = [n for n in ast.walk(transaction) if isinstance(n, ast.Expr) and isinstance(n.value, ast.Call) and any(isinstance(a, ast.Constant) and a.value == 'module-cache sources changed during command' for a in n.value.args)]
        self.assertEqual(len(checks), 2)
        box = self.root / 'cached-box'; debug = self.root / 'cached-debug'
        box.write_bytes(self.originals['box.go']); debug.write_bytes(self.originals['debug_http.go'])
        ctx = dict(w.__dict__, source=box, original=box.read_bytes(), cache_debug=debug, original_debug=debug.read_bytes())
        for check in checks:
            code = compile(ast.Module(body=[check], type_ignores=[]), str(SCRIPT), 'exec')
            exec(code, ctx)
            for path in (box, debug):
                raw = path.read_bytes(); path.write_bytes(raw + b'\n')
                with self.assertRaisesRegex(ValueError, 'module-cache sources changed'):
                    exec(code, ctx)
                path.write_bytes(raw)


if __name__ == '__main__':
    unittest.main(verbosity=2)

#!/usr/bin/env python3
"""Real authenticated SDK bytes; no Go invocations or invented Go output."""
import importlib.util
import json
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
w = load('chrome_wrapper', ROOT / 'scripts/go-patched.py')
p = load('chrome_packager', ROOT / 'scripts/package-binary.py')

class ChromePatchTests(unittest.TestCase):
    def test_packaging_requires_chrome_receipt_not_only_historical_patches(self):
        start, patch = w.identity()
        core, core_patch = w.core_identity()
        receipt = dict(go_version='go version go1.27.3 linux/amd64', identity_sha256=w.IDENTITY_SHA, wrapper_sha256=w.sha((ROOT/'scripts/go-patched.py').read_bytes()),
                       module=w.MODULE, version=w.VERSION, commit=start['commit'], source_sha256=start['source_sha256'],
                       patch_sha256=w.sha(patch), result_sha256=start['result_sha256'],
                       core_slim=dict(identity_sha256=w.CORE_IDENTITY_SHA, patch_sha256=w.sha(core_patch), files=core['files']))
        with self.assertRaisesRegex(ValueError, 'source identity'):
            p.certified_sources(ROOT, receipt)

    def test_real_source_patch_and_narrow_factory_contract(self):
        m, patch = w.chrome_identity()
        source = (ROOT/'scripts/tests/fixtures/sing-box-v1.14.3/anytls-outbound.go.txt').read_bytes()
        result = w.transform_chrome(source, m, patch)
        self.assertEqual(w.sha(source), m['source_sha256'])
        self.assertEqual(w.sha(result), m['result_sha256'])
        self.assertIn(b'NewChromeClient(context.Context, string, option.OutboundTLSOptions) (tls.Config, error)', result)
        self.assertIn(b'(tlsOptions.Reality == nil || !tlsOptions.Reality.Enabled)', result)
        self.assertIn(b'(tlsOptions.Engine == "" || tlsOptions.Engine == "go")', result)
        self.assertIn(b'tlsOptions.UTLS != nil && tlsOptions.UTLS.Enabled', result)
        self.assertIn(b'(tlsOptions.UTLS.Fingerprint == "" || tlsOptions.UTLS.Fingerprint == "chrome")', result)
        self.assertIn(b'Chrome TLS factory is not registered', result)
        self.assertEqual(result.count(b' = tls.NewClient('), 1)
        self.assertLess(result.index(b'if options.DialerOptions.TCPFastOpen'), result.index(b'factory := service.FromContext['))
        self.assertLess(result.index(b'factory := service.FromContext['), result.index(b'dialer.NewWithOptions('))
        for invalid in (source+b'\n', result):
            with self.assertRaisesRegex(ValueError, 'source SHA'):
                w.transform_chrome(invalid, m, patch)
        altered = patch.replace(b'Chrome TLS factory', b'Altered TLS factory')
        with self.assertRaisesRegex(ValueError, 'result SHA'):
            w.transform_chrome(source, m, altered)
        ops = json.loads(patch)
        ops['replacements'][0]['unexpected'] = True
        with self.assertRaises(ValueError):
            w.transform_chrome(source, m, json.dumps(ops).encode())

    def test_chrome_manifest_and_patch_authentication(self):
        m, patch = w.chrome_identity()
        with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as d:
            root = Path(d); dest = root/'patches/sing-box'; dest.mkdir(parents=True)
            raw = (ROOT/'patches/sing-box/chrome.identity.json').read_bytes()
            (dest/'chrome.identity.json').write_bytes(raw)
            (dest/m['patch']).write_bytes(patch+b'\n')
            with self.assertRaisesRegex(ValueError, 'patch SHA'):
                w.chrome_identity(root)
            (dest/'chrome.identity.json').write_bytes(raw+b'\n')
            with self.assertRaisesRegex(ValueError, 'identity SHA'):
                w.chrome_identity(root)

    def test_production_staging_receipt_and_cache_guards(self):
        import ast
        m, patch = w.chrome_identity()
        original = (ROOT/'scripts/tests/fixtures/sing-box-v1.14.3/anytls-outbound.go.txt').read_bytes()
        transformed = w.transform_chrome(original, m, patch)
        main = next(n for n in ast.parse((ROOT/'scripts/go-patched.py').read_text()).body
                    if isinstance(n, ast.FunctionDef) and n.name == 'main')
        transaction = next(n for n in main.body if isinstance(n, ast.Try))
        first = next(i for i, n in enumerate(transaction.body) if isinstance(n, ast.Assign)
                     and any(isinstance(t, ast.Name) and t.id == 'staged_chrome' for t in n.targets))
        with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as d:
            replacement = Path(d)/'private'; target = replacement/m['file']
            target.parent.mkdir(parents=True); target.write_bytes(original)
            cached = Path(d)/'cached-outbound'; cached.write_bytes(original)
            ctx = dict(w.__dict__, replacement=replacement, chrome_m=m, chrome_patch=patch,
                       original_chrome=original, patched_chrome=transformed, receipt={},
                       cache_chrome=cached)
            block = compile(ast.Module(body=transaction.body[first:first+4], type_ignores=[]), 'actual-staging', 'exec')
            exec(block, ctx)
            self.assertEqual(target.read_bytes(), transformed)
            self.assertEqual(ctx['receipt']['chrome_backend'], w.chrome_receipt(m, patch))
            checks = [n for n in ast.walk(transaction) if isinstance(n, ast.Expr)
                      and isinstance(n.value, ast.Call) and any(isinstance(a, ast.Constant)
                      and a.value == 'module-cache AnyTLS source changed during command' for a in n.value.args)]
            self.assertEqual(len(checks), 2)
            for check in checks:
                code = compile(ast.Module(body=[check], type_ignores=[]), 'actual-cache-guard', 'exec')
                exec(code, ctx); cached.write_bytes(original+b'\n')
                with self.assertRaisesRegex(ValueError, 'module-cache AnyTLS'):
                    exec(code, ctx)
                cached.write_bytes(original)
            final = next(n for n in transaction.body if isinstance(n, ast.Expr)
                         and isinstance(n.value, ast.Call) and any(isinstance(a, ast.Constant)
                         and a.value == 'final staged retry source changed' for a in n.value.args))
            # Chrome is now an immutable intermediate, retry binds final output.
            ctx['patched_retry'] = w.transform_retry(transformed, *w.retry_identity())
            target.write_bytes(ctx['patched_retry'])
            code = compile(ast.Module(body=[final], type_ignores=[]), 'actual-final-guard', 'exec')
            exec(code, ctx); target.write_bytes(original)
            with self.assertRaisesRegex(ValueError, 'final staged retry'):
                exec(code, ctx)

    def test_historical_identity_pins_unchanged(self):
        start, _ = w.identity(); core, _ = w.core_identity()
        self.assertEqual(start['toolchain'], 'go1.26.8')
        self.assertEqual(w.IDENTITY_SHA, '9679eb6c27343cbdc0bcb3559869638a4c78c2809dca9760439f46f506636c5f')
        self.assertEqual(w.CORE_IDENTITY_SHA, '7faf6af8e873bb568f15029070f3c8051365af7ba3dd43f343488d78dcaee9e3')
        self.assertEqual(w.CURRENT_GO, 'go1.27.3')

if __name__ == '__main__':
    unittest.main(verbosity=2)

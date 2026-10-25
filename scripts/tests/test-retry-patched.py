#!/usr/bin/env python3
"""Authenticated retry chain and CCS contracts, without Go/cache."""
import ast
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[2]
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
w=load('retry_wrapper',ROOT/'scripts/go-patched.py')
p=load('retry_packager',ROOT/'scripts/package-binary.py')
leaf=load('retry_leaf_tests',ROOT/'scripts/tests/test-leaf-patched.py')
class RetryPatchTests(unittest.TestCase):
 def before(self):
  return w.transform_chrome((ROOT/'scripts/tests/fixtures/sing-box-v1.14.3/anytls-outbound.go.txt').read_bytes(),*w.chrome_identity())
 def receipt(self):
  r=leaf.LeafPatchTests().receipt();r['leaf_certificate']=w.leaf_receipt(*w.leaf_identity());return r
 def test_exact_chain_and_no_business_retry(self):
  m,patch=w.retry_identity();before=self.before();after=w.transform_retry(before,m,patch)
  self.assertEqual(w.sha(after),m['result_sha256'])
  self.assertEqual(before.split(b'func (h *Outbound) createProxy')[1].split(b'func (h *Outbound) dialOut')[0],after.split(b'func (h *Outbound) createProxy')[1].split(b'func (h *Outbound) dialOut')[0])
  self.assertIn(b'retry.DialAnyTLS(ctx, h.dialer, h.server, h.tlsConfig.HandshakeTimeout())',after)
  for bad in (before+b'\n',after):
   with self.assertRaisesRegex(ValueError,'source SHA'):w.transform_retry(bad,m,patch)
  ops=json.loads(patch);ops['replacements'][1]['new']+='\n'
  with self.assertRaisesRegex(ValueError,'result SHA'):w.transform_retry(before,m,json.dumps(ops).encode())
 def test_identity_and_patch_tampering(self):
  m,patch=w.retry_identity()
  with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as d:
   root=Path(d);dest=root/'patches/sing-box';dest.mkdir(parents=True)
   raw=(ROOT/'patches/sing-box/retry.identity.json').read_bytes();(dest/'retry.identity.json').write_bytes(raw);(dest/m['patch']).write_bytes(patch+b'\n')
   with self.assertRaisesRegex(ValueError,'patch SHA'):w.retry_identity(root)
   (dest/'retry.identity.json').write_bytes(raw+b'\n')
   with self.assertRaisesRegex(ValueError,'identity SHA'):w.retry_identity(root)
 def test_ccs_requires_retry_and_ships_materials(self):
  receipt=self.receipt();materials=p.certified_sources(ROOT,receipt)
  self.assertIn('patches/sing-box/retry.identity.json',materials);self.assertIn('patches/sing-box/retry.patch.json',materials)
  for field in ('identity_sha256','patch_sha256','source_sha256','result_sha256','toolchain'):
   r=copy.deepcopy(receipt);r['transient_retry'][field]='bad'
   with self.assertRaisesRegex(ValueError,'source identity'):p.certified_sources(ROOT,r)
  del receipt['transient_retry']
  with self.assertRaisesRegex(ValueError,'source identity'):p.certified_sources(ROOT,receipt)
 def test_actual_wrapper_stages_and_final_guard(self):
  main=next(n for n in ast.parse((ROOT/'scripts/go-patched.py').read_text()).body if isinstance(n,ast.FunctionDef) and n.name=='main')
  transaction=next(n for n in main.body if isinstance(n,ast.Try))
  first=next(i for i,n in enumerate(transaction.body) if isinstance(n,ast.Expr) and isinstance(n.value,ast.Call) and any(isinstance(a,ast.Constant) and a.value=='retry intermediate source mismatch' for a in n.value.args))
  m,patch=w.retry_identity();before=self.before();after=w.transform_retry(before,m,patch)
  with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as d:
   staged=Path(d)/'outbound.go';staged.write_bytes(before)
   ctx=dict(w.__dict__,staged_chrome=staged,patched_chrome=before,patched_retry=after,retry_m=m,retry_patch=patch,receipt={})
   exec(compile(ast.Module(body=transaction.body[first:first+4],type_ignores=[]),'actual-retry-stage','exec'),ctx)
   self.assertEqual(staged.read_bytes(),after);self.assertEqual(ctx['receipt']['transient_retry'],w.retry_receipt(m,patch))
   guard=next(n for n in ast.walk(transaction) if isinstance(n,ast.Expr) and isinstance(n.value,ast.Call) and any(isinstance(a,ast.Constant) and a.value=='final staged retry source changed' for a in n.value.args))
   code=compile(ast.Module(body=[guard],type_ignores=[]),'actual-retry-final','exec');exec(code,ctx);staged.write_bytes(after+b'\n')
   with self.assertRaisesRegex(ValueError,'retry source changed'):exec(code,ctx)
if __name__=='__main__':unittest.main(verbosity=2)

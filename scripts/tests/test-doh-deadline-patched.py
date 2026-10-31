#!/usr/bin/env python3
"""Exact authenticated DoH transform and real CCS negative gates (no network)."""
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
w=load('doh_wrapper',ROOT/'scripts/go-patched.py')
p=load('doh_packager',ROOT/'scripts/package-binary.py')
class DoHDeadlineTests(unittest.TestCase):
 def test_exact_transform_preserves_explicit_reset_and_no_retired_pool(self):
  m,patch=w.doh_identity();before=(ROOT/'scripts/tests/fixtures/sing-box-v1.14.3/https.go.txt').read_bytes();after=w.transform_doh(before,m,patch)
  self.assertEqual(w.sha(after),m['result_sha256'])
  self.assertNotIn(b'transportResetAt',after);self.assertNotIn(b'context.DeadlineExceeded',after)
  for name,end in [('Reset','SetKeepIdleConnections'),('exchange','')]:
   token=('func (t *HTTPSTransport) '+name+'(').encode()
   old=before.split(token)[1];new=after.split(token)[1]
   if end:
    delim=('func (t *HTTPSTransport) '+end+'(').encode();old=old.split(delim)[0];new=new.split(delim)[0]
   self.assertEqual(old,new)
  self.assertIn(b'oldTransport.Close()',after)
  for bad in (before+b'\n',after):
   with self.assertRaisesRegex(ValueError,'source SHA'):w.transform_doh(bad,m,patch)
  ops=json.loads(patch);ops['replacements'][0]['new']+='\n'
  with self.assertRaisesRegex(ValueError,'result SHA'):w.transform_doh(before,m,json.dumps(ops).encode())
 def test_authentication_tampering(self):
  m,patch=w.doh_identity()
  with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as d:
   root=Path(d);dest=root/'patches/sing-box';dest.mkdir(parents=True)
   raw=(ROOT/'patches/sing-box/doh-deadline-isolation.identity.json').read_bytes()
   for name in ('identity.json','box-start.patch.json'):(dest/name).write_bytes((ROOT/'patches/sing-box'/name).read_bytes())
   (dest/'doh-deadline-isolation.identity.json').write_bytes(raw);(dest/m['patch']).write_bytes(patch+b'\n')
   with self.assertRaisesRegex(ValueError,'patch SHA'):w.doh_identity(root)
   (dest/'doh-deadline-isolation.identity.json').write_bytes(raw+b'\n')
   with self.assertRaisesRegex(ValueError,'identity SHA'):w.doh_identity(root)
 def test_ccs_requires_complete_doh_receipt_and_materials(self):
  fixture=load('doh_package_fixture',ROOT/'scripts/package_binary_test.py').PackagingTests()
  with fixture.package_fixture('arm64') as (root,settings,receipt,invoke):
   self.assertEqual(invoke()['modules'],37)
   materials=p.certified_sources(root,receipt)
   for name in ('doh-deadline-isolation.identity.json','doh-deadline-isolation.patch.json'):
    self.assertIn('patches/sing-box/'+name,materials)
   for field in ('identity_sha256','patch_sha256','source_sha256','result_sha256','toolchain','file'):
    r=copy.deepcopy(receipt);r['doh_deadline_isolation'][field]='bad'
    with self.assertRaisesRegex(ValueError,'source identity'):p.certified_sources(root,r)
   receipt.pop('doh_deadline_isolation')
   with self.assertRaisesRegex(ValueError,'source identity'):invoke(out=root/'rejected')
   self.assertFalse(list((root/'rejected').glob('*.tar.gz')))
if __name__=='__main__':unittest.main(verbosity=2)

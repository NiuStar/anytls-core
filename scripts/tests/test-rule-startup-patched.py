#!/usr/bin/env python3
"""Authenticated startup ordering, rejection and CCS material contracts."""
import copy, importlib.util, json, os, tempfile, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
w=load('startup_wrapper',ROOT/'scripts/go-patched.py')
p=load('startup_packager',ROOT/'scripts/package-binary.py')
class RuleStartupPatchTests(unittest.TestCase):
 def test_authenticated_startup_order(self):
  self.assertTrue(hasattr(w,'rule_startup_identity'),'missing authenticated rule startup patch')
  m,patch=w.rule_startup_identity()
  old=(ROOT/'scripts/tests/fixtures/sing-box-v1.14.3/box.go.txt').read_bytes()
  start,sp=w.identity();old=w.transform(old,start,sp)
  core,cp=w.core_identity()
  with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as d:
   root=Path(d);(root/'box.go').write_bytes(old)
   (root/'debug_http.go').write_bytes((ROOT/'scripts/tests/fixtures/sing-box-v1.14.3/debug_http.go.txt').read_bytes())
   w.apply_core(root,core,cp);old=(root/'box.go').read_bytes()
  after=w.transform_rule_startup(old,m,patch)
  self.assertEqual(w.sha(after),m['result_sha256'])
  startbody=after.decode().split('func (s *Box) start() error {',1)[1]
  self.assertLess(startbody.index('boxComponent{"router", s.router}'),startbody.index('boxComponent{"inbound", s.inbound}'))
  self.assertEqual(startbody.count('boxComponent{"router", s.router}'),2) # PostStart once, Started once
  for bad in (old+b'\n',after):
   with self.assertRaisesRegex(ValueError,'source SHA'):w.transform_rule_startup(bad,m,patch)
  ops=json.loads(patch);ops['replacements'][0]['new']+='\n'
  with self.assertRaisesRegex(ValueError,'result SHA'):w.transform_rule_startup(old,m,json.dumps(ops).encode())
 def test_manifest_and_patch_tampering_rejected(self):
  m,patch=w.rule_startup_identity()
  with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as d:
   root=Path(d);dest=root/'patches/sing-box';dest.mkdir(parents=True)
   raw=(ROOT/'patches/sing-box/rule-startup.identity.json').read_bytes()
   (dest/'rule-startup.identity.json').write_bytes(raw)
   (dest/m['patch']).write_bytes(patch+b'\n')
   with self.assertRaisesRegex(ValueError,'patch SHA'):w.rule_startup_identity(root)
   (dest/m['patch']).write_bytes(patch)
   (dest/'rule-startup.identity.json').write_bytes(raw+b'\n')
   with self.assertRaisesRegex(ValueError,'identity SHA'):w.rule_startup_identity(root)
 def test_ccs_rejects_missing_and_forged_startup_receipt(self):
  self.assertTrue(hasattr(w,'rule_startup_identity'),'missing authenticated rule startup patch')
  fixture=load('startup_fixture',ROOT/'scripts/package_binary_test.py').PackagingTests()
  with fixture.package_fixture('arm64') as (root,settings,receipt,invoke):
   self.assertEqual(invoke()['modules'],38)
   materials=p.certified_sources(root,receipt)
   for name in ('rule-startup.identity.json','rule-startup.patch.json'):
    self.assertIn('patches/sing-box/'+name,materials)
   for field in ('identity_sha256','patch_sha256','source_sha256','result_sha256','file'):
    r=copy.deepcopy(receipt);r['rule_startup'][field]='bad'
    with self.assertRaisesRegex(ValueError,'source identity'):p.certified_sources(root,r)
   del receipt['rule_startup']
   with self.assertRaisesRegex(ValueError,'source identity'):invoke(out=root/'rejected')
if __name__=='__main__':unittest.main(verbosity=2)

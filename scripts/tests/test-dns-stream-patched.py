#!/usr/bin/env python3
"""Authenticated DNS stream transform and mandatory CCS/installer consumers."""
import copy,importlib.util,json,os,shutil,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
w=load('stream_wrapper',ROOT/'scripts/go-patched.py')
p=load('stream_packager',ROOT/'scripts/package-binary.py')
class DNSStreamPatchTests(unittest.TestCase):
 def stage(self,root):
  m,patch=w.dns_stream_identity()
  for pin in m['files']:
   f=root/pin['file'];f.parent.mkdir(parents=True,exist_ok=True)
   f.write_bytes((ROOT/'scripts/tests/fixtures/sing-box-v1.14.3'/('dns-stream-'+pin['file'].replace('/','-')+'.txt')).read_bytes())
  return m,patch
 def test_exact_source_result_chain_and_double_apply(self):
  with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as d:
   root=Path(d);m,patch=self.stage(root);w.apply_dns_stream(root,m,patch)
   for pin in m['files']:self.assertEqual(w.sha((root/pin['file']).read_bytes()),pin['result_sha256'])
   with self.assertRaisesRegex(ValueError,'source SHA'):w.apply_dns_stream(root,m,patch)
 def test_identity_patch_diff_and_source_tampering(self):
  for name in ['dns-stream-close.identity.json','dns-stream-close.patch.json','dns-stream-close.patch']:
   with self.subTest(name=name),tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as d:
    root=Path(d);shutil.copytree(ROOT/'patches',root/'patches');f=root/'patches/sing-box'/name;f.write_bytes(f.read_bytes()+b'\n')
    with self.assertRaisesRegex(ValueError,'SHA'):w.dns_stream_identity(root)
  with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as d:
   root=Path(d);m,patch=self.stage(root);f=root/m['files'][0]['file'];f.write_bytes(f.read_bytes()+b'\n')
   with self.assertRaisesRegex(ValueError,'source SHA'):w.apply_dns_stream(root,m,patch)
 def test_ccs_exact_mandatory_receipt_and_materials(self):
  fixture=load('stream_package_fixture',ROOT/'scripts/package_binary_test.py').PackagingTests()
  with fixture.package_fixture('arm64') as (root,settings,receipt,invoke):
   self.assertEqual(invoke()['modules'],38)
   for name in ('dns-stream-close.identity.json','dns-stream-close.patch.json','dns-stream-close.patch'):self.assertIn('patches/sing-box/'+name,p.certified_sources(root,receipt))
   for field in receipt['dns_stream_close']:
    r=copy.deepcopy(receipt);r['dns_stream_close'][field]='bad'
    with self.assertRaisesRegex(ValueError,'source identity'):p.certified_sources(root,r)
   receipt.pop('dns_stream_close')
   with self.assertRaisesRegex(ValueError,'source identity'):invoke(out=root/'rejected')
   self.assertFalse(list((root/'rejected').glob('*.tar.gz')))
if __name__=='__main__':unittest.main(verbosity=2)

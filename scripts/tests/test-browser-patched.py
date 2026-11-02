#!/usr/bin/env python3
"""Offline browser patch/material receipts; simulated compiler is not native proof."""
import copy,importlib.util,json,os,shutil,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def load(name,p):
 s=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
w=load('browser_wrapper',ROOT/'scripts/go-patched.py')
p=load('browser_packager',ROOT/'scripts/package-binary.py')
class BrowserBuildTests(unittest.TestCase):
 def test_certified_transform_and_tampered_source(self):
  m=w.browser_identity()
  with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as d:
   root=Path(d)
   for pin,name in zip(m['files'],('browser-dns-router.go.txt','browser-route.go.txt')):
    target=root/pin['file'];target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes((ROOT/'scripts/tests/fixtures/sing-box-v1.14.3'/name).read_bytes())
   w.apply_browser(root,m)
   for pin in m['files']:self.assertEqual(w.sha((root/pin['file']).read_bytes()),pin['result_sha256'])
   with self.assertRaisesRegex(ValueError,'source SHA'):w.apply_browser(root,m)
 def test_ccs_missing_or_drifted_browser_receipt(self):
  fixture=load('browser_package_fixture',ROOT/'scripts/package_binary_test.py').PackagingTests()
  with fixture.package_fixture('arm64') as (root,settings,receipt,invoke):
   self.assertEqual(invoke()['modules'],38)
   for field in ('identity_sha256','files','toolchain'):
    bad=copy.deepcopy(receipt);bad['browser_provenance'][field]='tampered'
    with self.assertRaisesRegex(ValueError,'source identity'):p.certified_sources(root,bad)
   bad=copy.deepcopy(receipt);bad.pop('browser_provenance')
   with self.assertRaisesRegex(ValueError,'source identity'):p.certified_sources(root,bad)
if __name__=='__main__':unittest.main()

import base64, hashlib, importlib.util, io, os
from unittest import mock
from pathlib import Path
import tarfile, tempfile, unittest, zipfile
spec=importlib.util.spec_from_file_location('packager',Path(__file__).with_name('package-binary.py'))
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)

class PackagingTests(unittest.TestCase):
 def test_module_escape(self):
  self.assertEqual(p.module_escape('github.com/Upper/Name'),'github.com/!upper/!name')
 def test_zip_hash_matches_go_hash1_algorithm(self):
  with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as d:
   z=Path(d)/'m.zip'
   with zipfile.ZipFile(z,'w') as f:f.writestr('m@v1/b',b'B');f.writestr('m@v1/a',b'A')
   plain=''.join(hashlib.sha256(data).hexdigest()+'  '+name+'\n' for name,data in [('m@v1/a',b'A'),('m@v1/b',b'B')])
   self.assertEqual(p.zip_h1(z),'h1:'+base64.b64encode(hashlib.sha256(plain.encode()).digest()).decode())
 def test_settings_parser(self):
  self.assertEqual(p.build_settings('x: go1.26.8\n\tbuild\tGOOS=darwin\n\tbuild\t-trimpath=true\n')['GOOS'],'darwin')
 def test_source_notice_keeps_origin_comment(self):
  self.assertIn(b'Copyright',p.source_notice(b'// Copyright Acme\n// BSD license text\n\npackage sample\nfunc X(){}'))
  self.assertEqual(p.source_notice(b'package sample\n'),b'')
 def test_rejects_dirty_source_and_wrong_binary_identity(self):
  with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as d:
   root=Path(d);(root/'VERSION').write_text('v1.0.0');binary=root/'binary';binary.write_bytes(b'unit')
   good='unit: go1.26.8\n'+''.join('\tbuild\t'+k+'='+v+'\n' for k,v in {'GOOS':'darwin','GOARCH':'arm64','CGO_ENABLED':'0','-trimpath':'true','vcs.revision':'a'*40,'vcs.modified':'false','-tags':'with_gvisor,with_utls,with_upstream_cleanup_patch,embedded_core'}.items())
   for dirty,info,error in [(' M VERSION\n',good,'dirty'),('',good.replace('CGO_ENABLED=0','CGO_ENABLED=1'),'settings'),('',good.replace('vcs.revision='+'a'*40,'vcs.revision='+'b'*40),'settings')]:
    def output(args,**kwargs):
     if args[0]=='go':return info
     if args[1]=='rev-parse':return 'a'*40+'\n'
     if args[1]=='status':return dirty
     raise AssertionError(args)
    with mock.patch.object(p.subprocess,'check_output',side_effect=output),self.assertRaisesRegex(ValueError,error):p.package(root,binary,root/'out','v1.0.0','go',root/'cache',root/'receipt')
 def test_add_bytes_regular_safe_metadata(self):
  buffer=io.BytesIO()
  with tarfile.open(fileobj=buffer,mode='w') as t:p.add_bytes(t,'prefix/NOTICE',b'notice')
  with tarfile.open(fileobj=io.BytesIO(buffer.getvalue()),mode='r:') as t:
   m=t.getmembers()[0];self.assertTrue(m.isfile());self.assertEqual(m.mode,0o644);self.assertEqual(t.extractfile(m).read(),b'notice')

if __name__=='__main__':unittest.main()

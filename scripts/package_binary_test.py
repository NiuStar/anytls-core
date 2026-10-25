import base64, gzip, hashlib, importlib.util, io, json, os
from contextlib import contextmanager
from unittest import mock
from pathlib import Path
import tarfile, tempfile, unittest, zipfile
spec=importlib.util.spec_from_file_location('packager',Path(__file__).with_name('package-binary.py'))
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
spec=importlib.util.spec_from_file_location('wrapper',Path(__file__).with_name('go-patched.py'))
w=importlib.util.module_from_spec(spec);spec.loader.exec_module(w)

class PackagingTests(unittest.TestCase):
 @contextmanager
 def package_fixture(self,arch,missing_material=None):
  # Only external Go/Git inspection is simulated; exercise real packaging,
  # module authentication, source/notice collection and archive writing.
  with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as d:
   root=Path(d);cache=root/'cache';goroot=root/'go';(goroot/'src').mkdir(parents=True)
   (goroot/'LICENSE').write_text('Go license fixture')
   (goroot/'VERSION').write_text('go1.27.3\ntime 2026-10-01T00:00:00Z\n')
   (goroot/'bin').mkdir();compiler=goroot/'bin/go'
   compiler.write_bytes(b'UNIT-SIMULATED compiler');compiler.chmod(0o755)
   (root/'packaging-go-version').write_text('go version go1.27.3 darwin/arm64\n')
   (goroot/'src/runtime.go').write_text('// Copyright Go authors\n// BSD license\n\npackage runtime\n')
   for name,data in {'VERSION':'v1.0.0','LICENSE':'GPL fixture','THIRD_PARTY_NOTICES.md':'Notices','config.example.yaml':'example'}.items():(root/name).write_text(data)
   binary=root/'binary';binary.write_bytes(b'UNIT-SIMULATED binary '+arch.encode())
   sums=[];deps=[]
   for i in range(37):
    mod='example.com/module'+str(i);version='v1.0.0';prefix=mod+'@'+version
    z=cache/'cache/download'/mod/'@v'/(version+'.zip');z.parent.mkdir(parents=True)
    with zipfile.ZipFile(z,'w') as f:
     f.writestr(prefix+'/LICENSE',b'Module license fixture')
     f.writestr(prefix+'/main.go',b'// Copyright module authors\n// BSD license\n\npackage sample\n')
    modfile=z.with_suffix('.mod');modfile.write_text('module '+mod+'\n')
    modsum='h1:'+base64.b64encode(hashlib.sha256((hashlib.sha256(modfile.read_bytes()).hexdigest()+'  go.mod\n').encode()).digest()).decode()
    sums.extend([mod+' '+version+' '+p.zip_h1(z),mod+' '+version+'/go.mod '+modsum]);deps.append('\tdep\t'+mod+' '+version+' '+p.zip_h1(z)+'\n')
   (root/'go.sum').write_text('\n'.join(sums)+'\n')
   (root/'go.mod').write_text('module example.com/test\n\ngo 1.27.3\n')
   settings={'GOOS':'darwin','GOARCH':arch,'CGO_ENABLED':'0','-trimpath':'true','vcs.revision':'a'*40,'vcs.modified':'false','-tags':'with_gvisor,with_utls,with_upstream_cleanup_patch,embedded_core'}
   settings['GOAMD64' if arch=='amd64' else 'GOARM64']='v1' if arch=='amd64' else 'v8.0'
   receipt={'rc':0,'ephemeral_cleanup':'ok','output_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'target':{'GOOS':'darwin','GOARCH':arch,'CGO_ENABLED':'0'},'go_version':'go version go1.27.3 darwin/arm64'}
   receipt_path=root/'receipt'
   start,patch=w.identity();core,core_patch=w.core_identity();chrome,chrome_patch=w.chrome_identity()
   leaf,leaf_patch=w.leaf_identity()
   materials=['scripts/go-patched.py','patches/sing-box/identity.json','patches/sing-box/box-start.patch.json','patches/sing-box/core-slim.identity.json','patches/sing-box/core-slim.patch.json','patches/sing-box/chrome.identity.json','patches/sing-box/chrome.patch.json']
   materials+=['patches/sing-box/leaf.identity.json','patches/sing-box/leaf.patch.json']
   materials+=['patches/sing-box/retry.identity.json','patches/sing-box/retry.patch.json']
   for name in materials:
    target=root/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes((w.ROOT/name).read_bytes())
   receipt.update(identity_sha256=w.IDENTITY_SHA,wrapper_sha256=w.sha((root/'scripts/go-patched.py').read_bytes()),module=w.MODULE,version=w.VERSION,commit=start['commit'],source_sha256=start['source_sha256'],patch_sha256=w.sha(patch),result_sha256=start['result_sha256'],core_slim={'identity_sha256':w.CORE_IDENTITY_SHA,'patch_sha256':w.sha(core_patch),'files':core['files']},chrome_backend=w.chrome_receipt(chrome,chrome_patch))
   receipt['go_bin']=str(compiler)
   receipt['leaf_certificate']=w.leaf_receipt(leaf,leaf_patch)
   receipt['transient_retry']=w.retry_receipt(*w.retry_identity())
   def output(args,**kwargs):
    if args[1:]==['version']:return (root/'packaging-go-version').read_text()
    if args[1:3]==['version','-m']:return 'unit: go1.27.3\n'+''.join(deps)+''.join('\tbuild\t'+k+'='+v+'\n' for k,v in settings.items())
    if args[1:]==['env','GOROOT']:return str(goroot)+'\n'
    if args[:2]==['git','rev-parse']:return 'a'*40+'\n'
    if args[:2]==['git','status']:return ''
    raise AssertionError(args)
   source_buffer=io.BytesIO()
   with tarfile.open(fileobj=source_buffer,mode='w') as t:
    p.add_bytes(t,'anytls-core-v1.0.0/VERSION',b'v1.0.0\n')
    for name in materials:
     if name!=missing_material:p.add_bytes(t,'anytls-core-v1.0.0/'+name,(root/name).read_bytes())
   def archive(args,**kwargs):
    self.assertEqual(args[:2],['git','archive']);kwargs['stdout'].write(gzip.compress(source_buffer.getvalue(),mtime=0))
   def invoke(out=None,go=None,**kwargs):
    receipt_path.write_text('PATCHED_GO_END '+json.dumps(receipt)+'\n')
    with mock.patch.object(p.subprocess,'check_output',side_effect=output),mock.patch.object(p.subprocess,'run',side_effect=archive):
     return p.package(root,binary,out or root/'out','v1.0.0',go or str(compiler),cache,receipt_path,**kwargs)
   yield root,settings,receipt,invoke

 def test_packages_each_architecture_with_bound_identity(self):
  for arch in ('arm64','amd64'):
   for host in ('arm64','amd64'):
    with self.subTest(arch=arch,host=host),self.package_fixture(arch) as (root,settings,receipt,invoke):
     receipt['go_version']='go version go1.27.3 darwin/'+host
     # Keep the legacy positional/default entry point working for arm64.
     result=invoke(**({'arch':arch} if arch=='amd64' else {}))
     prefix='anytls-core-v1.0.0';platform='darwin-'+arch;bp=prefix+'-'+platform
     ccs=prefix+('-corresponding-source.tar.gz' if arch=='arm64' else '-darwin-amd64-corresponding-source.tar.gz')
     expected=[prefix+'-source.tar.gz',ccs,bp+'.tar.gz','SHA256SUMS']
     self.assertEqual(result['assets'],expected);self.assertEqual(result['modules'],37)
     out=root/'out'
     self.assertEqual((out/'SHA256SUMS').read_text(),''.join(hashlib.sha256((out/name).read_bytes()).hexdigest()+'  '+name+'\n' for name in expected[:-1]))
     with tarfile.open(out/(bp+'.tar.gz')) as t:
      info=json.load(t.extractfile(bp+'/BUILD-INFO.json'));self.assertEqual(info['platform'],platform);self.assertEqual(info['corresponding_source'],ccs)
      self.assertEqual(info['binary_sha256'],receipt['output_sha256'])
      self.assertIn(b'Copyright Go',t.extractfile(bp+'/licenses/Go/SOURCE-NOTICES.txt').read())
     with tarfile.open(out/ccs) as t:
      identity=json.load(t.extractfile(prefix+'/BUILD-IDENTITY.json'))
      self.assertEqual(identity['settings']['GOARCH'],arch);self.assertEqual(identity['certified_build'],receipt)
      with tarfile.open(fileobj=io.BytesIO(t.extractfile(prefix+'/application-source.tar.gz').read()),mode='r:gz') as app:
       for name in p.certified_sources(root,receipt):self.assertEqual(app.extractfile(prefix+'/'+name).read(),(root/name).read_bytes())
      self.assertEqual(len(json.load(t.extractfile(prefix+'/MODULES.json'))),37)
      self.assertIn(('darwin/'+arch).encode(),t.extractfile(prefix+'/BUILD.txt').read())
      self.assertEqual(t.extractfile(prefix+'/go-toolchain/LICENSE').read(),b'Go license fixture')
      self.assertIn(b'package runtime',t.extractfile(prefix+'/go-toolchain/src/runtime.go').read())

 def test_rejects_wrong_missing_or_malformed_goroot_version(self):
  for version in (None,'','go1.26.8\n','go1.27.30\n','version go1.27.3\n','\ngo1.27.3\n'):
   with self.subTest(version=version),self.package_fixture('arm64') as (root,settings,receipt,invoke):
    path=root/'go/VERSION'
    if version is None:path.unlink()
    else:path.write_text(version)
    with self.assertRaisesRegex(ValueError,'toolchain source version'):invoke()
    self.assertFalse(list((root/'out').iterdir()))

 def test_rejects_wrong_or_malformed_packaging_compiler_version(self):
  for version in ('go version go1.26.8 darwin/arm64\n','','go1.27.3','go version go1.27.30 darwin/arm64\n'):
   with self.subTest(version=version),self.package_fixture('arm64') as (root,settings,receipt,invoke):
    (root/'packaging-go-version').write_text(version)
    with self.assertRaisesRegex(ValueError,'packaging toolchain version'):invoke()
    self.assertFalse(list((root/'out').iterdir()))

 def test_rejects_unbound_compiler_and_goroot(self):
  for kind in ('missing-receipt','absent-receipt-file','different-receipt-compiler','different-goroot-compiler'):
   with self.subTest(kind=kind),self.package_fixture('arm64') as (root,settings,receipt,invoke):
    other=root/'other-go';other.write_bytes(b'different compiler');other.chmod(0o755)
    go=None
    if kind=='missing-receipt':receipt.pop('go_bin')
    elif kind=='absent-receipt-file':receipt['go_bin']=str(root/'absent')
    elif kind=='different-receipt-compiler':receipt['go_bin']=str(other)
    else:
     go=root/'packaging-go';go.write_bytes((root/'go/bin/go').read_bytes());go.chmod(0o755)
     receipt['go_bin']=str(go);(root/'go/bin/go').write_bytes(b'different GOROOT compiler')
    with self.assertRaisesRegex(ValueError,'toolchain compiler identity'):invoke(go=go)
    self.assertFalse(list((root/'out').iterdir()))

 def test_accepts_same_compiler_bytes_at_another_path(self):
  with self.package_fixture('arm64') as (root,settings,receipt,invoke):
   other=root/'packaging-go';other.write_bytes((root/'go/bin/go').read_bytes());other.chmod(0o755)
   self.assertEqual(invoke(go=other)['modules'],37)

 def test_independent_outputs_share_only_byte_identical_application_source(self):
  archives={}
  for arch in ('arm64','amd64'):
   with self.package_fixture(arch) as (root,settings,receipt,invoke):
    out=root/arch;result=invoke(out=out,arch=arch)
    for name in result['assets'][:-1]:
     data=(out/name).read_bytes()
     if name in archives:
      self.assertTrue(name.endswith('-source.tar.gz'))
      self.assertFalse(name.endswith('-corresponding-source.tar.gz'))
      self.assertEqual(archives[name],data)
     else:archives[name]=data
  self.assertEqual(len(archives),5)

 def test_rejects_receipt_target_mismatch(self):
  for arch in ('arm64','amd64'):
   targets=[None,{},dict(GOOS='darwin',GOARCH='amd64' if arch=='arm64' else 'arm64',CGO_ENABLED='0'),dict(GOOS='linux',GOARCH=arch,CGO_ENABLED='0'),dict(GOOS='darwin',GOARCH=arch,CGO_ENABLED='1')]
   for target in targets:
    with self.subTest(arch=arch,target=target),self.package_fixture(arch) as (root,settings,receipt,invoke):
     receipt['target']=target
     with self.assertRaisesRegex(ValueError,'target'):invoke(arch=arch)
     self.assertFalse(list((root/'out').glob('*.tar.gz')))

 def test_rejects_wrong_architecture_and_nonbaseline_amd64(self):
  for arch in ('arm64','amd64'):
   with self.subTest(arch=arch),self.package_fixture(arch) as (root,settings,receipt,invoke):
    settings['GOARCH']='amd64' if arch=='arm64' else 'arm64'
    with self.assertRaisesRegex(ValueError,'settings'):invoke(arch=arch)
    self.assertFalse(list((root/'out').glob('*.tar.gz')))
  for baseline in ('v2','v3','v4',None):
   with self.subTest(baseline=baseline),self.package_fixture('amd64') as (root,settings,receipt,invoke):
    if baseline is None:settings.pop('GOAMD64')
    else:settings['GOAMD64']=baseline
    with self.assertRaisesRegex(ValueError,'settings'):invoke(arch='amd64')

 def test_rejects_unsupported_architecture_before_external_effects(self):
  for arch in ('386','aarch64','ARM64','',None):
   with self.subTest(arch=arch),mock.patch.object(p.subprocess,'check_output',side_effect=AssertionError('no external inspection')):
    with self.assertRaisesRegex(ValueError,'unsupported architecture'):p.package(None,None,None,None,None,None,None,arch)

 def test_rejects_unbound_binary_digest(self):
  for arch in ('arm64','amd64'):
   with self.subTest(arch=arch),self.package_fixture(arch) as (root,settings,receipt,invoke):
    receipt['output_sha256']='0'*64
    with self.assertRaisesRegex(ValueError,'digest'):invoke(arch=arch)
    self.assertFalse(list((root/'out').glob('*.tar.gz')))

 def test_module_escape(self):
  self.assertEqual(p.module_escape('github.com/Upper/Name'),'github.com/!upper/!name')

 def test_rejects_tampered_or_missing_final_source_identity(self):
  for field in ('identity_sha256','wrapper_sha256','patch_sha256','result_sha256','core_slim','chrome_backend','leaf_certificate'):
   with self.subTest(field=field),self.package_fixture('arm64') as (root,settings,receipt,invoke):
    receipt.pop(field)
    with self.assertRaisesRegex(ValueError,'source identity'):invoke()
    self.assertFalse(list((root/'out').glob('*.tar.gz')))
  with self.package_fixture('arm64') as (root,settings,receipt,invoke):
   receipt['core_slim']['files'][0]['result_sha256']='0'*64
   with self.assertRaisesRegex(ValueError,'source identity'):invoke()

 def test_rejects_chrome_receipt_result_and_old_toolchain(self):
  with self.package_fixture('arm64') as (root,settings,receipt,invoke):
   receipt['chrome_backend']['result_sha256']='0'*64
   with self.assertRaisesRegex(ValueError,'source identity'):invoke()
  with self.package_fixture('arm64') as (root,settings,receipt,invoke):
   receipt['go_version']='go version go1.26.8 darwin/arm64'
   with self.assertRaisesRegex(ValueError,'toolchain'):invoke()
  with self.package_fixture('arm64') as (root,settings,receipt,invoke):
   (root/'go.mod').write_text('module example.com/test\n\ngo 1.26.8\n')
   with self.assertRaisesRegex(ValueError,'root module'):invoke()

 def test_rejects_source_archive_without_core_patch_materials(self):
  for name in ('patches/sing-box/core-slim.identity.json','patches/sing-box/core-slim.patch.json','patches/sing-box/chrome.identity.json','patches/sing-box/chrome.patch.json','patches/sing-box/leaf.identity.json','patches/sing-box/leaf.patch.json'):
   with self.subTest(name=name),self.package_fixture('arm64',missing_material=name) as (root,settings,receipt,invoke):
    with self.assertRaises(KeyError):invoke()
    self.assertFalse(list((root/'out').glob('*corresponding-source.tar.gz')))

 def test_zip_hash_matches_go_hash1_algorithm(self):
  with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as d:
   z=Path(d)/'m.zip'
   with zipfile.ZipFile(z,'w') as f:f.writestr('m@v1/b',b'B');f.writestr('m@v1/a',b'A')
   plain=''.join(hashlib.sha256(data).hexdigest()+'  '+name+'\n' for name,data in [('m@v1/a',b'A'),('m@v1/b',b'B')])
   self.assertEqual(p.zip_h1(z),'h1:'+base64.b64encode(hashlib.sha256(plain.encode()).digest()).decode())
 def test_settings_parser(self):
  self.assertEqual(p.build_settings('x: go1.27.3\n\tbuild\tGOOS=darwin\n\tbuild\t-trimpath=true\n')['GOOS'],'darwin')
 def test_source_notice_keeps_origin_comment(self):
  self.assertIn(b'Copyright',p.source_notice(b'// Copyright Acme\n// BSD license text\n\npackage sample\nfunc X(){}'))
  self.assertEqual(p.source_notice(b'package sample\n'),b'')
 def test_rejects_dirty_source_and_wrong_binary_identity(self):
  with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as d:
   root=Path(d);(root/'VERSION').write_text('v1.0.0');binary=root/'binary';binary.write_bytes(b'unit')
   good='unit: go1.27.3\n'+''.join('\tbuild\t'+k+'='+v+'\n' for k,v in {'GOOS':'darwin','GOARCH':'arm64','CGO_ENABLED':'0','-trimpath':'true','vcs.revision':'a'*40,'vcs.modified':'false','-tags':'with_gvisor,with_utls,with_upstream_cleanup_patch,embedded_core'}.items())
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

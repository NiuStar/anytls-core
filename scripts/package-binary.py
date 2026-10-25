#!/usr/bin/env python3
"""Package an already-built binary and matching module sources; no build/download."""
from pathlib import Path
import argparse,base64,hashlib,importlib.util,io,json,os,re,subprocess,tarfile,zipfile


def certified_sources(root,receipt):
 # Load the local official tool, never Python supplied by a source archive.
 spec=importlib.util.spec_from_file_location('certified_wrapper',Path(__file__).with_name('go-patched.py'))
 wrapper=importlib.util.module_from_spec(spec);spec.loader.exec_module(wrapper)
 start,patch=wrapper.identity(root);core,core_patch=wrapper.core_identity(root)
 chrome,chrome_patch=wrapper.chrome_identity(root)
 leaf,leaf_patch=wrapper.leaf_identity(root)
 retry,retry_patch=wrapper.retry_identity(root)
 if not re.search(r'^go 1\.27\.3$',(root/'go.mod').read_text(),re.M):raise ValueError('root module requires Go 1.27.3')
 if receipt.get('go_version','').split()[2:3]!=[wrapper.CURRENT_GO]:raise ValueError('certified toolchain mismatch')
 expected={'identity_sha256':wrapper.IDENTITY_SHA,'wrapper_sha256':wrapper.sha((root/'scripts/go-patched.py').read_bytes()),
           'module':wrapper.MODULE,'version':wrapper.VERSION,'commit':start['commit'],
           'source_sha256':start['source_sha256'],'patch_sha256':wrapper.sha(patch),'result_sha256':start['result_sha256'],
           'core_slim':{'identity_sha256':wrapper.CORE_IDENTITY_SHA,'patch_sha256':wrapper.sha(core_patch),'files':core['files']},
           'chrome_backend':wrapper.chrome_receipt(chrome,chrome_patch),
           'leaf_certificate':wrapper.leaf_receipt(leaf,leaf_patch),
           'transient_retry':wrapper.retry_receipt(retry,retry_patch)}
 if any(receipt.get(k)!=v for k,v in expected.items()):raise ValueError('certified source identity mismatch')
 return ['scripts/go-patched.py','patches/sing-box/identity.json','patches/sing-box/box-start.patch.json',
         'patches/sing-box/core-slim.identity.json','patches/sing-box/core-slim.patch.json',
         'patches/sing-box/chrome.identity.json','patches/sing-box/chrome.patch.json',
         'patches/sing-box/leaf.identity.json','patches/sing-box/leaf.patch.json',
         'patches/sing-box/retry.identity.json','patches/sing-box/retry.patch.json']


def source_notice(data):
 text=data.decode('utf-8','replace')
 # Preserve leading comment corpus verbatim, with exact file origins in index.
 prefix=text.split('\npackage ',1)[0] if '\npackage ' in text else '\n'.join(text.splitlines()[:120])
 return prefix.encode() if re.search(r'copyright|license|redistribution|permission to|SPDX',prefix,re.I) else b''


def build_settings(info):
 settings={}
 for line in info.splitlines():
  f=line.split(None,1)
  if f[:1]==['build'] and len(f)==2:
   k,_,v=f[1].partition('=');settings[k]=v
 return settings


def module_escape(s):
 return ''.join('!'+c.lower() if 'A'<=c<='Z' else c for c in s)


def zip_h1(path):
 with zipfile.ZipFile(path) as z:
  names=z.namelist()
  if len(names)!=len(set(names)):raise ValueError('duplicate ZIP names')
  summary=hashlib.sha256()
  for n in sorted(names):
   digest=hashlib.sha256()
   with z.open(n) as f:
    while True:
     b=f.read(1024*1024)
     if not b:break
     digest.update(b)
   summary.update((digest.hexdigest()+'  '+n+'\n').encode())
  return 'h1:'+base64.b64encode(summary.digest()).decode()


def add_bytes(t,name,data,mode=0o644):
 info=tarfile.TarInfo(name);info.size=len(data);info.mode=mode;info.mtime=0;t.addfile(info,io.BytesIO(data))


def toolchain_source(go,receipt):
 # Packaging and certified build run in the same job. Require its compiler
 # to remain available; equal bytes permit relocation without freezing paths.
 env=dict(os.environ,GOTOOLCHAIN='local')
 version=subprocess.check_output([str(go),'version'],text=True,env=env).strip()
 if not re.fullmatch(r'go version go1\.27\.3 [^\s/]+/[^\s/]+',version):raise ValueError('packaging toolchain version mismatch')
 goroot=Path(subprocess.check_output([str(go),'env','GOROOT'],text=True,env=env).strip())
 try:
  with (goroot/'VERSION').open(encoding='utf-8') as f:source_version=f.readline().rstrip('\r\n')
 except (OSError,UnicodeError) as e:raise ValueError('toolchain source version unavailable') from e
 if source_version!='go1.27.3':raise ValueError('toolchain source version mismatch')
 try:
  certified=Path(receipt['go_bin']);compiler=Path(go)
  if not compiler.is_absolute() or not certified.is_absolute() or not goroot.is_absolute():raise ValueError('toolchain compiler identity requires absolute paths')
  digest=hashlib.sha256(compiler.read_bytes()).digest()
  if any(hashlib.sha256(p.read_bytes()).digest()!=digest for p in (certified,goroot/'bin/go')):raise ValueError('toolchain compiler identity mismatch')
 except (KeyError,TypeError,OSError) as e:raise ValueError('toolchain compiler identity unavailable') from e
 return goroot


def package(root,binary,out,tag,go,cache,receipt,arch='arm64'):
 if arch not in ('arm64','amd64'):raise ValueError('unsupported architecture: '+str(arch))
 root=Path(root).resolve();binary=Path(binary).resolve();out=Path(out).resolve();cache=Path(cache).resolve();out.mkdir(exist_ok=True,parents=True)
 if (root/'VERSION').read_text().strip()!=tag:raise ValueError('VERSION/tag mismatch')
 commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
 info=subprocess.check_output([str(go),'version','-m',str(binary)],cwd=root,text=True)
 if subprocess.check_output(['git','status','--porcelain','--untracked-files=no'],cwd=root,text=True).strip():raise ValueError('tracked release source is dirty')
 settings=build_settings(info)
 expected={'GOOS':'darwin','GOARCH':arch,'CGO_ENABLED':'0','-trimpath':'true','vcs.revision':commit,'vcs.modified':'false'}
 if arch=='amd64':expected['GOAMD64']='v1'
 if any(settings.get(k)!=v for k,v in expected.items()) or not info.splitlines()[0].endswith('go1.27.3'):raise ValueError('unexpected binary build settings or VCS binding')
 if set(settings.get('-tags','').split(','))!=set('with_gvisor,with_utls,with_upstream_cleanup_patch,embedded_core'.split(',')):raise ValueError('unexpected binary tags')
 ends=[json.loads(line.split(' ',1)[1]) for line in Path(receipt).read_text().splitlines() if line.startswith('PATCHED_GO_END ')]
 if len(ends)!=1 or ends[0].get('rc')!=0 or ends[0].get('ephemeral_cleanup')!='ok':raise ValueError('missing successful certified wrapper END')
 build_receipt=ends[0];binary_digest=hashlib.sha256(binary.read_bytes()).hexdigest()
 if binary_digest!=build_receipt.get('output_sha256'):raise ValueError('wrapper END does not bind binary digest')
 if build_receipt.get('target')!={'GOOS':'darwin','GOARCH':arch,'CGO_ENABLED':'0'}:raise ValueError('wrapper END target does not match binary architecture')
 materials=certified_sources(root,build_receipt)
 goroot=toolchain_source(go,build_receipt)
 modules=[]
 sums={}
 for l in (root/'go.sum').read_text().splitlines():
  fields=l.split()
  if len(fields)==3:sums[(fields[0],fields[1])]=fields[2]
 for line in info.splitlines():
  f=line.split()
  if f[:1]!=['dep']:continue
  mod,version=f[1:3];expected=sums[(mod,version)];p=cache/'cache/download'/module_escape(mod)/'@v'/(module_escape(version)+'.zip')
  if zip_h1(p)!=expected:raise ValueError('module hash mismatch: '+mod)
  modfile=p.with_suffix('.mod')
  if not modfile.is_file():raise ValueError('missing module metadata: '+mod)
  modsum='h1:'+base64.b64encode(hashlib.sha256((hashlib.sha256(modfile.read_bytes()).hexdigest()+'  go.mod\n').encode()).digest()).decode()
  if modsum!=sums[(mod,version+'/go.mod')]:raise ValueError('module metadata hash mismatch: '+mod)
  with zipfile.ZipFile(p) as z:
   licenses=[n for n in z.namelist() if re.search(r'(^|/)(LICENSE[^/]*|COPYING[^/]*|NOTICE[^/]*|COPYRIGHT[^/]*|AUTHORS[^/]*|PATENTS[^/]*)$',n,re.I)]
  if not licenses:raise ValueError('no license material in exact module: '+mod)
  modules.append({'module':mod,'version':version,'go_sum':expected,'zip_sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'zip':str(p),'licenses':licenses})
 if not modules:raise ValueError('no linked modules')
 prefix='anytls-core-'+tag
 source=out/(prefix+'-source.tar.gz')
 with source.open('wb') as f:subprocess.run(['git','archive','--format=tar.gz','--prefix='+prefix+'/','HEAD'],cwd=root,stdout=f,check=True)
 with tarfile.open(source,'r:gz') as t:
  for name in materials:
   member=t.getmember(prefix+'/'+name)
   if not member.isfile() or t.extractfile(member).read()!=(root/name).read_bytes():raise ValueError('source archive patch materials mismatch: '+name)
 ccs=out/(prefix+('-corresponding-source.tar.gz' if arch=='arm64' else '-darwin-amd64-corresponding-source.tar.gz'))
 with tarfile.open(ccs,'w:gz') as t:
  t.add(source,arcname=prefix+'/application-source.tar.gz',recursive=False)
  for row in modules:t.add(row['zip'],arcname=prefix+'/modules/'+module_escape(row['module'])+'@'+row['version']+'.zip',recursive=False)
  manifest=[{k:v for k,v in row.items() if k!='zip'} for row in modules]
  # Go's module graph may need .mod/.info for pruned, non-linked requirements.
  # Preserve cached public metadata too; never copy credential/config files.
  for metadata in sorted((cache/'cache/download').rglob('*')):
   if metadata.is_file() and metadata.suffix in ('.mod','.info'):
    t.add(metadata,arcname=prefix+'/module-cache/cache/download/'+str(metadata.relative_to(cache/'cache/download')),recursive=False)
  for path in sorted(goroot.rglob('*')):
   rel=path.relative_to(goroot)
   if not path.is_file() or rel.parts[0] in ('bin','pkg'):continue
   t.add(path,arcname=prefix+'/go-toolchain/'+str(rel),recursive=False)
  add_bytes(t,prefix+'/BUILD-IDENTITY.json',json.dumps({'source_commit':commit,'binary_sha256':binary_digest,'settings':settings,'certified_build':build_receipt},indent=2).encode())
  add_bytes(t,prefix+'/MODULES.json',json.dumps(manifest,indent=2).encode())
  add_bytes(t,prefix+'/BUILD.txt',('Source commit: '+commit+'\nGo 1.27.3 darwin/'+arch+' CGO=0\nUse scripts/go-patched.py, exact patch/identity and tags in README.\nDependencies are Go module ZIPs; verify against MODULES.json and go.sum.\nGo toolchain: https://go.dev/dl/ ; source: https://go.dev/dl/?mode=json&include=all\nExtract module ZIPs or populate GOPROXY cache, then use the certified wrapper.\n').encode())
 platform='darwin-'+arch;bp=prefix+'-'+platform;bundle=out/(bp+'.tar.gz');sha=hashlib.sha256(binary.read_bytes()).hexdigest()
 with tarfile.open(bundle,'w:gz') as t:
  t.add(binary,arcname=bp+'/bin/anytls-macos',recursive=False)
  for n in ['VERSION','LICENSE','THIRD_PARTY_NOTICES.md','config.example.yaml']:t.add(root/n,arcname=bp+'/'+n,recursive=False)
  add_bytes(t,bp+'/BUILD-INFO.json',json.dumps({'source_commit':commit,'binary_sha256':sha,'go_version':'1.27.3','platform':platform,'corresponding_source':ccs.name},indent=2).encode())
  add_bytes(t,bp+'/SOURCE-LOCATION.txt',('Corresponding source, dependencies and Go sources:\nhttps://github.com/NiuStar/anytls-core/releases/download/'+tag+'/'+ccs.name+'\n').encode())
  for path in sorted(goroot.rglob('*')):
   rel=path.relative_to(goroot)
   if path.is_file() and rel.parts[0] not in ('bin','pkg') and re.fullmatch(r'(LICENSE.*|COPYING.*|NOTICE.*|COPYRIGHT.*|AUTHORS.*|PATENTS.*)',path.name,re.I):
    t.add(path,arcname=bp+'/licenses/Go/'+str(rel),recursive=False)
  for row in modules:
   with zipfile.ZipFile(row['zip']) as z:
    for name in row['licenses']:add_bytes(t,bp+'/licenses/'+module_escape(row['module'])+'@'+row['version']+'/'+name.split('/',1)[-1],z.read(name))
    corpus=[]
    for name in z.namelist():
     if name.endswith(('.go','.c','.h','.s','.S','.rs')):
      notice=source_notice(z.read(name))
      if notice:corpus.append(b'\nFILE: '+name.encode()+b'\n'+notice)
    if corpus:add_bytes(t,bp+'/licenses/'+module_escape(row['module'])+'@'+row['version']+'/SOURCE-NOTICES.txt',b'\n'.join(corpus))
  go_notices=[]
  for p in sorted((goroot/'src').rglob('*')):
   if p.is_file() and p.suffix in ('.go','.c','.h','.s','.S'):
    notice=source_notice(p.read_bytes())
    if notice:go_notices.append(b'\nFILE: '+str(p.relative_to(goroot)).encode()+b'\n'+notice)
  add_bytes(t,bp+'/licenses/Go/SOURCE-NOTICES.txt',b'\n'.join(go_notices))
 sumsout=out/'SHA256SUMS';sumsout.write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n' for p in [source,ccs,bundle]))
 return {'source_commit':commit,'binary_sha256':sha,'modules':len(modules),'assets':[p.name for p in [source,ccs,bundle,sumsout]]}


if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--binary',required=True);p.add_argument('--out',required=True);p.add_argument('--tag',required=True);p.add_argument('--receipt',required=True);p.add_argument('--arch',choices=('arm64','amd64'),default='arm64');a=p.parse_args()
 print(json.dumps(package(Path.cwd(),a.binary,a.out,a.tag,os.environ['GO_BIN'],os.environ['GOMODCACHE'],a.receipt,a.arch)))

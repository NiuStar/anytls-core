#!/usr/bin/env python3
"""Offline authenticated ACK build chain; no Go compilation/native acceptance."""
import ast
import copy
import importlib.util
import json
import os
import shutil
import io
import contextlib
import base64
import hashlib
import zipfile
from unittest import mock
from pathlib import Path
import tempfile
import unittest
ROOT = Path(__file__).resolve().parents[2]
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
w = load('ack_wrapper', ROOT/'scripts/go-patched.py')
p = load('ack_packager', ROOT/'scripts/package-binary.py')
class ACKTests(unittest.TestCase):
    def test_identity_patch_source_result_tampering(self):
        m,patch=w.ack_identity()
        with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as d:
            root=Path(d);shutil.copytree(ROOT/'patches/sing-anytls',root/'patches/sing-anytls')
            identity=root/'patches/sing-anytls/identity.json'
            identity.write_bytes(identity.read_bytes()+b'\n')
            with self.assertRaisesRegex(ValueError,'identity SHA'):w.ack_identity(root)
            identity.write_bytes((ROOT/'patches/sing-anytls/identity.json').read_bytes())
            payload=root/'patches/sing-anytls'/m['patch'];payload.write_bytes(patch+b'\n')
            with self.assertRaisesRegex(ValueError,'patch SHA'):w.ack_identity(root)
            source=root/'stage';source.mkdir()
            w.stage_archive(ROOT/'scripts/tests/fixtures/sing-anytls-v0.0.11.zip',source,m['module_sum'],m['module'],m['version'])
            ops=json.loads(patch);ops['files'][0]['new']+='\n'
            with self.assertRaisesRegex(ValueError,'result SHA'):w.apply_ack(source,m,json.dumps(ops).encode())
    def test_ccs_ack_tampering_and_archive_materials(self):
        import tarfile
        fixture=load('ack_package_fixture',ROOT/'scripts/package_binary_test.py').PackagingTests()
        with fixture.package_fixture('arm64') as (root,settings,receipt,invoke):
            self.assertEqual(invoke()['modules'],38)
            prefix='anytls-core-v1.0.0'
            with tarfile.open(root/'out'/ (prefix+'-corresponding-source.tar.gz')) as archive:
                self.assertEqual(archive.extractfile(prefix+'/modules/'+w.ACK_MODULE+'@'+w.ACK_VERSION+'.zip').read(),(ROOT/'scripts/tests/fixtures/sing-anytls-v0.0.11.zip').read_bytes())
                identity=json.load(archive.extractfile(prefix+'/BUILD-IDENTITY.json'))
                self.assertEqual(identity['certified_build']['stream_connect_ack'],w.ack_receipt(*w.ack_identity()))
                self.assertEqual(identity['certified_build']['stream_die_hook_publication'],w.hook_receipt(*w.hook_identity()))
            for field in receipt['stream_connect_ack']:
                bad=copy.deepcopy(receipt);bad['stream_connect_ack'][field]='tampered'
                with self.subTest(field=field),self.assertRaisesRegex(ValueError,'source identity'):p.certified_sources(root,bad)
            cache=root/'cache/cache/download'/w.ACK_MODULE/'@v'/(w.ACK_VERSION+'.zip')
            cache.unlink()
            with self.assertRaises(OSError):invoke(out=root/'rejected')
            self.assertFalse(list((root/'rejected').glob('*.tar.gz')))
    def test_main_two_private_replacements_and_cleanup(self):
        # Actual entry, authentic ACK ZIP and exact sing-box source fixtures.
        # External Go inspection/compile is UNIT-SIMULATED, never a native receipt.
        for rc in (0,7,'exception'):
            with self.subTest(rc=rc),tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as d:
                root=Path(d);shutil.copytree(ROOT/'patches',root/'patches')
                for name in ('go.mod','go.sum'):(root/name).write_bytes((ROOT/name).read_bytes())
                box=root/'cache-box';box.mkdir()
                fixture=ROOT/'scripts/tests/fixtures/sing-box-v1.14.3'
                mapping={'box.go':'box.go.txt','debug_http.go':'debug_http.go.txt','protocol/anytls/outbound.go':'anytls-outbound.go.txt','dns/transport/https.go':'https.go.txt'}
                mapping.update({pin['file']:pin['fixture'] for pin in w.leaf_identity()[0]['files']})
                mapping.update({'dns/router.go':'browser-dns-router.go.txt','route/route.go':'browser-route.go.txt'})
                mapping.update({n:'dns-stream-'+n.replace('/','-')+'.txt' for n in w.DNS_STREAM_FILES if n!='route/route.go'})
                for name,fn in mapping.items():
                    target=box/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes((fixture/fn).read_bytes())
                # Synthetic archive, authenticated with its own independent h1 below.
                boxzip=root/'box.zip'
                with zipfile.ZipFile(boxzip,'w') as z:
                    for name in mapping:z.writestr(w.MODULE+'@'+w.VERSION+'/'+name,(box/name).read_bytes())
                summary=b''.join((w.sha((box/name).read_bytes())+'  '+w.MODULE+'@'+w.VERSION+'/'+name+'\n').encode() for name in sorted(mapping))
                synthetic_h1='h1:'+base64.b64encode(hashlib.sha256(summary).digest()).decode()
                ack=root/'cache-ack';ack.mkdir();ackzip=ROOT/'scripts/tests/fixtures/sing-anytls-v0.0.11.zip'
                am,ap=w.ack_identity();w.stage_archive(ackzip,ack,am['module_sum'],w.ACK_MODULE,w.ACK_VERSION)
                self.assertEqual(w.sha((ack/'session/client.go').read_bytes()),w.hook_identity()[0]['files'][0]['source_sha256'])
                originals={str(f):f.read_bytes() for base in (box,ack) for f in base.rglob('*') if f.is_file()}
                replacements={};workpaths=[];stage=w.stage_archive
                def inspect(cmd,**kw):
                    args=cmd[1:]
                    if args==['version']:return b'go version go1.27.3 linux/amd64\n'
                    module=w.ACK_MODULE if any(w.ACK_MODULE in v for v in args) else w.MODULE
                    m=am if module==w.ACK_MODULE else w.identity()[0]
                    directory=ack if module==w.ACK_MODULE else box
                    info=dict(Path=module,Version=m['version'],Dir=str(directory))
                    if args[:2]==['mod','download']:
                        info.update(Zip=str(ackzip if module==w.ACK_MODULE else boxzip),Sum=m['module_sum'],GoModSum=m['go_mod_sum'])
                    elif args[:2]==['mod','edit']:
                        modfile=Path(args[2].split('=',1)[1]);modfile.write_text(modfile.read_text()+args[3]+'\n')
                        key,value=args[3].split('=',1)[1].split('=',1);replacements[key.split('@')[0]]=value
                        workpaths.append(modfile.parent);return b''
                    elif any(a.startswith('-modfile=') for a in args):
                        info['Replace']=dict(Path=replacements[module],Dir=replacements[module])
                    return json.dumps(info).encode()
                def staging(archive,dest,expected,module=w.MODULE,version=w.VERSION):
                    return stage(archive,dest,synthetic_h1 if module==w.MODULE else expected,module,version)
                def compile_fixture(cmd,**kw):
                    self.assertEqual(set(replacements),{w.MODULE,w.ACK_MODULE})
                    self.assertTrue(all(Path(path).is_dir() for path in replacements.values()))
                    sm,sp=w.dns_stream_identity()
                    self.assertTrue(all(w.sha((Path(replacements[w.MODULE])/pin['file']).read_bytes())==pin['result_sha256'] for pin in sm['files']))
                    if rc=='exception':raise OSError('UNIT compiler launch failure')
                    return rc
                out=io.StringIO()
                with mock.patch.object(w,'ROOT',root),mock.patch.object(w,'arguments',return_value=('/UNIT/go',['test','./...'],None)),mock.patch.object(w,'stage_archive',side_effect=staging),mock.patch.object(w.subprocess,'check_output',side_effect=inspect),mock.patch.object(w.subprocess,'call',side_effect=compile_fixture),contextlib.redirect_stdout(out):
                    if rc=='exception':
                        with self.assertRaisesRegex(OSError,'UNIT compiler launch failure'):w.main(['test','./...'])
                    else:self.assertEqual(w.main(['test','./...']),rc)
                lines=out.getvalue().splitlines()
                if rc=='exception':
                    self.assertEqual([s.split(' ',1)[0] for s in lines],['PATCHED_GO_BEGIN'])
                    self.assertTrue(all(not path.exists() for path in workpaths))
                    self.assertEqual(originals,{name:Path(name).read_bytes() for name in originals})
                    continue
                self.assertEqual([s.split(' ',1)[0] for s in lines],['PATCHED_GO_BEGIN','PATCHED_GO_END'])
                end=json.loads(lines[-1].split(' ',1)[1]);self.assertEqual(end['rc'],rc)
                self.assertTrue(end['original_ack_sources_unchanged']);self.assertTrue(end['original_ack_zip_unchanged'])
                self.assertTrue(end['original_dns_stream_sources_unchanged'])
                self.assertEqual(end['dns_stream_close'],w.dns_stream_receipt(*w.dns_stream_identity()))
                self.assertEqual(end['stream_connect_ack'],w.ack_receipt(am,ap))
                self.assertEqual(end['stream_die_hook_publication'],w.hook_receipt(*w.hook_identity()))
                self.assertTrue(all(not path.exists() for path in workpaths))
                self.assertEqual(originals,{name:Path(name).read_bytes() for name in originals})
    def test_authenticated_archive_and_exact_files(self):
        import difflib
        m, patch = w.ack_identity()
        diff=''.join(''.join(difflib.unified_diff((entry['old'] or '').splitlines(True),entry['new'].splitlines(True),fromfile='a/'+entry['file'] if entry['old'] is not None else '/dev/null',tofile='b/'+entry['file'])) for entry in json.loads(patch)['files'])
        self.assertEqual(diff.encode(),(ROOT/'patches/sing-anytls/connect-ack.patch').read_bytes())
        with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as d:
            dest = Path(d)/'private'; dest.mkdir()
            archive = ROOT/'scripts/tests/fixtures/sing-anytls-v0.0.11.zip'
            receipt = w.stage_archive(archive, dest, m['module_sum'], m['module'], m['version'])
            self.assertEqual(receipt['zip_sha256'], m['zip_sha256'])
            before = {str(f.relative_to(dest)): f.read_bytes() for f in dest.rglob('*') if f.is_file()}
            self.assertEqual(w.apply_ack(dest,m,patch), m['files'])
            after = {str(f.relative_to(dest)): f.read_bytes() for f in dest.rglob('*') if f.is_file()}
            changed = {name for name in after if before.get(name) != after[name]}
            self.assertEqual(changed, {pin['file'] for pin in m['files']})
            self.assertFalse(any('ack_lab' in name for name in after))
            with self.assertRaisesRegex(ValueError,'source'): w.apply_ack(dest,m,patch)
    def test_ccs_missing_ack_is_rejected(self):
        fixture = load('ack_leaf_fixture', ROOT/'scripts/tests/test-leaf-patched.py').LeafPatchTests()
        receipt = fixture.receipt()
        receipt['leaf_certificate'] = w.leaf_receipt(*w.leaf_identity())
        receipt.pop('stream_connect_ack', None)
        with self.assertRaisesRegex(ValueError,'source identity'): p.certified_sources(ROOT,receipt)
if __name__ == '__main__': unittest.main(verbosity=2)

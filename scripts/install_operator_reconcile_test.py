#!/usr/bin/env python3
"""LOCALONLY retained 184 event streams, sanitized/rebound; no native IPC.

Fixture source SHA256 5aa14ed397c0594000bc4eaacc8c6a296ec3be8ce793ab64a4312aae58e56c88.
Keep the actual 273 HELPER/26 CORE reload and 135 HELPER stop events. Paths,
config hashes, executable provenance and old process row are fixture identities.
"""
import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('operator_installer', Path(__file__).with_name('install-binary.py'))
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)


class OperatorReconciliation(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='operator-reconcile-', dir=os.environ['TMPDIR'])
        self.addCleanup(temp.cleanup)
        self.app = Path(temp.name).resolve()/'.anytls'
        self.app.mkdir(mode=0o700)
        self.op = '887e3586e7684e7b8ead5b5a12a7af67'
        self.root = self.app/('.core-reload-'+self.op)
        self.root.mkdir(mode=0o700)
        raw = Path(__file__).with_name('fixtures').joinpath('operator_reconciliation_184.json').read_text()
        oldid = hashlib.sha256(b'/fixture/.anytls/config.yaml').hexdigest()
        identity = hashlib.sha256(str(self.app/'config.yaml').encode()).hexdigest()
        f = json.loads(raw.replace('/fixture/.anytls',str(self.app)).replace(oldid,identity))
        self.records = f['receipts']
        self.pending = json.dumps(self.records.pop('pending.json'),sort_keys=True).encode()
        self.marker = dict(schema=1,status='RECONCILED_RELOAD_STOPPED',operation_id=self.op,
            helper_epoch=self.records['intent.json']['helper_epoch'], receipt_sha256={},
            pending_raw_base64=base64.b64encode(self.pending).decode(),pending_sha256=hashlib.sha256(self.pending).hexdigest(),
            stop_read=f['stop_read'],current=f['current'],authorization='EXPLICIT_OPERATOR',
            historical_process_identity='UNAVAILABLE',action='UNLINK_PENDING_ONLY')
        self.save()
        self.baseline = copy.deepcopy(self.marker)
        self.original_records = copy.deepcopy(self.records)
        self.before = self.snapshot()
        # Receiver must not make any native call, write proof, or probe a worker.
        for key in ('request','helper_hash','processes','config_pin','capture','put'):
            patch = mock.patch.dict(b.CORE_RELOAD_SUPPORT,{key:mock.Mock(side_effect=AssertionError('no '+key))})
            patch.start();self.addCleanup(patch.stop)
        patch = mock.patch.object(b,'reconciliation_worker_absent',side_effect=AssertionError('no ps'))
        patch.start();self.addCleanup(patch.stop)
        patch = mock.patch.object(b.subprocess,'run',side_effect=AssertionError('no subprocess'))
        patch.start();self.addCleanup(patch.stop)

    def snapshot(self):
        return {p.name:p.read_bytes() for p in self.root.iterdir()}

    def save(self):
        for name,value in self.records.items():
            path=self.root/name;path.write_text(json.dumps(value,sort_keys=True));path.chmod(0o600)
        log=self.root/'worker.log';log.write_bytes(b'');log.chmod(0o600)
        self.marker['receipt_sha256']={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in self.root.iterdir()
            if p.name in {*self.records,'worker.log'}}
        self.save_marker()

    def save_marker(self):
        path=self.root/'operator-reconciled.json';path.write_text(json.dumps(self.marker,sort_keys=True));path.chmod(0o600)

    def guard(self):
        with b.installation_lock(self.app):b.core_reload_guard(self.app)

    def blocked(self):
        before=self.snapshot()
        with self.assertRaisesRegex(ValueError,'UNKNOWN/pending'):self.guard()
        self.assertEqual(self.snapshot(),before)

    def test_retained_actual_streams_pass_without_mutation_or_live_reads(self):
        self.guard();self.guard()
        self.assertEqual(self.snapshot(),self.before)
        self.assertEqual(self.records['result.json']['state'],'UNKNOWN')
        self.assertFalse((self.root/'accepted.json').exists())
        self.assertFalse((self.root/'reconciled.json').exists())

    def test_future_config_and_worker_pid_do_not_change_frozen_proof(self):
        # Historical content need not remain equal, and live worker checks are
        # writer-only. PID reuse or later manual start is not a receiver query.
        (self.app/'config.yaml').write_bytes(b'later selection/config, not historical')
        self.records['claim.json']['pid']=os.getpid();self.save();self.guard()

    def test_marker_missing_or_pending_present_never_auto_authors(self):
        (self.root/'pending.json').write_bytes(self.pending);(self.root/'pending.json').chmod(0o600)
        self.blocked();(self.root/'pending.json').unlink()
        (self.root/'operator-reconciled.json').unlink();self.blocked()

    def test_marker_contract_hash_pending_and_primitive_controls(self):
        cases=[('schema',True),('status','SUCCEEDED'),('operation_id','f'*32),('helper_epoch','f'*32),
               ('authorization','AUTOMATIC'),('historical_process_identity','VERIFIED'),('action','RELOAD'),
               ('receipt_sha256',{}),('pending_sha256','f'*64),('pending_raw_base64','%%%'),
               ('pending_raw_base64',None),('foreign',True)]
        for key,value in cases:
            with self.subTest(key=key):
                self.marker=copy.deepcopy(self.baseline);self.marker[key]=value;self.save_marker();self.blocked()
        for payload in (b'{"operation_id":"ffffffffffffffffffffffffffffffff"}', b'{"operation_id":true}',
                        ('{"operation_id":"'+self.op+'","operation_id":"'+self.op+'"}').encode()):
            self.marker=copy.deepcopy(self.baseline)
            self.marker.update(pending_raw_base64=base64.b64encode(payload).decode(),pending_sha256=hashlib.sha256(payload).hexdigest())
            self.save_marker();self.blocked()

    def test_original_receipt_shapes_and_bound_success_controls(self):
        cases=[('job.json','operation_id','f'*32),('job.json','revision','F'*40),('claim.json','pid',True),
               ('intent.json','single_dispatch',1),('intent.json','allow_insecure',1),
               ('intent.json','helper_epoch','f'*32),('result.json','code','CORE_RELOAD_INVALID'),
               ('result.json','state','SUCCEEDED'),('response.json','timeline_schema',True),
               ('response.json','ok',1),('response.json','loaded',False),('response.json','helper_sha256','f'*64),
               ('response.json','helper_version','v0'),('response.json','operation_id','f'*32),
               ('response.json','config_identity','f'*64),('response.json','helper_epoch','f'*32)]
        for name,key,value in cases:
            with self.subTest(name=name,key=key):
                self.records=copy.deepcopy(self.original_records);self.marker=copy.deepcopy(self.baseline)
                self.records[name][key]=value;self.save();self.blocked()
        self.records=copy.deepcopy(self.original_records);self.marker=copy.deepcopy(self.baseline);self.save()
        (self.root/'response.json').unlink();self.blocked()

    def test_timeline_provenance_and_success_not_bypassed_by_rehash(self):
        for key,value in [('sha256','f'*64),('version','v0'),('git_revision','f'*40),('dirty',0),
                          ('sha_kind','UNKNOWN'),('execution_mapping','ATTESTED')]:
            with self.subTest(key=key):
                self.records=copy.deepcopy(self.original_records);self.marker=copy.deepcopy(self.baseline)
                core=next(s for s in self.records['timeline.json']['trace']['streams'] if s['role']=='CORE')
                core['provenance'][key]=value;self.save();self.blocked()
        self.records=copy.deepcopy(self.original_records)
        self.records['timeline.json']['trace']['lifecycle_result']='FAILED';self.save();self.blocked()

    def test_stop_trace_provenance_spans_foreign_operation_and_order(self):
        paths=[(('helper_epoch',),'f'*32), (('operation_id',),self.op),
               (('trace','source'),'MANUAL_RELOAD'),(('trace','lifecycle_result'),'FAILED'),
               (('trace','started_at'),'2026-11-06T01:00:00Z'),
               (('trace','streams',0,'provenance','sha256'),'f'*64),
               (('trace','streams',0,'provenance','version'),'v0'),
               (('trace','streams',0,'provenance','git_revision'),'f'*40),
               (('trace','streams',0,'provenance','dirty'),0),
               (('trace','streams',0,'events',0,'span_id'),'99'),
               (('trace','streams',0,'terminal','result'),'FAILED'),
               (('trace','diagnostics','schema'),True), (('timeline_schema',),True)]
        for path,value in paths:
            with self.subTest(path=path):
                self.marker=copy.deepcopy(self.baseline);target=self.marker['stop_read']
                for key in path[:-1]:target=target[key]
                target[path[-1]]=value;self.save_marker();self.blocked()

    def test_stopped_capture_status_identity_and_bools(self):
        cases=[(('state',),'RUNNING'),(('core',),self.records['job.json']['before']['core']),
               (('config','identity'),'f'*64),(('config','config'),False),
               (('status','running'),True),(('status','loaded'),True),(('status','ok'),1),
               (('status','helper_sha256'),'f'*64),(('status','helper_version'),'v0')]
        for path,value in cases:
            with self.subTest(path=path):
                self.marker=copy.deepcopy(self.baseline);target=self.marker['current']
                for key in path[:-1]:target=target[key]
                target[path[-1]]=value;self.save_marker();self.blocked()

    def test_filesystem_modes_links_and_original_byte_hashes(self):
        for name in ('operator-reconciled.json',*self.records,'worker.log'):
            path=self.root/name;raw=path.read_bytes()
            with self.subTest(name=name,case='mode'):
                path.chmod(0o644);self.blocked();path.chmod(0o600)
            with self.subTest(name=name,case='hardlink'):
                link=self.app/'link';os.link(path,link);self.blocked();link.unlink()
            with self.subTest(name=name,case='symlink'):
                target=self.app/'target';path.rename(target);path.symlink_to(target);self.blocked();path.unlink();target.rename(path)
            if name!='operator-reconciled.json':
                with self.subTest(name=name,case='hash'):
                    path.write_bytes(raw+b' ');self.blocked();path.write_bytes(raw)
        self.root.chmod(0o755);self.blocked();self.root.chmod(0o700)
        (self.root/'accepted.json').write_text('{}');self.blocked();(self.root/'accepted.json').unlink()
        (self.root/'reconciled.json').write_text('{}');self.blocked()

    def test_malformed_json_and_owner_controls(self):
        path=self.root/'operator-reconciled.json'
        for raw in (b'{',b'null',b'[]',b'{"schema":1,"schema":1}'):
            with self.subTest(raw=raw):
                path.write_bytes(raw);self.blocked()
        self.save_marker()
        real=b.os.getuid
        with b.installation_lock(self.app),mock.patch.object(b.os,'getuid',return_value=real()+1):
            with self.assertRaisesRegex(ValueError,'UNKNOWN/pending'):b.core_reload_guard(self.app)

    def test_python39_wall_parser_preserves_all_fraction_digits(self):
        import ast
        import datetime
        import inspect
        import re
        tree=ast.parse(inspect.getsource(b.operator_reconciliation_safe))
        wall=next(node for node in ast.walk(tree) if isinstance(node,ast.FunctionDef) and node.name=='wall')
        namespace={'need':b.CORE_RELOAD_SUPPORT['need'],'datetime':datetime,'re':re}
        exec(compile(ast.fix_missing_locations(ast.Module(body=[wall],type_ignores=[])),'wall-regression','exec'),namespace)
        parse=namespace['wall']
        for digits in ('','1','12','123','1234','15886','123456','1234567','12345678','123456789'):
            stamp='2026-11-06T01:19:15'+('.'+digits if digits else '')+'Z'
            with self.subTest(stamp=stamp):
                self.assertEqual(parse(stamp),(2026,11,6,1,19,15,int(digits.ljust(9,'0'))))
        self.assertLess(parse('2026-11-06T01:19:15.123456788Z'),parse('2026-11-06T01:19:15.123456789Z'))
        for stamp in ('2026-02-30T01:19:15Z','2026-11-06T25:19:15Z','2026-11-06T01:19:15.0Z',
                      '2026-11-06T01:19:15.1234567891Z','2026-11-06T01:19:15+00:00',None):
            with self.subTest(stamp=stamp),self.assertRaises(ValueError):parse(stamp)
        self.guard()

    def test_lock_required_and_no_foreign_directory_alias(self):
        with self.assertRaisesRegex(ValueError,'UNKNOWN/pending'):b.core_reload_guard(self.app)
        alias=self.app/'.core-reload-ffffffffffffffffffffffffffffffff';alias.symlink_to(self.root,target_is_directory=True)
        self.blocked();alias.unlink()
        saved=self.root.with_name('saved');self.root.rename(saved);self.root.symlink_to(saved,target_is_directory=True)
        self.blocked();self.root.unlink();saved.rename(self.root)


if __name__=='__main__':unittest.main()

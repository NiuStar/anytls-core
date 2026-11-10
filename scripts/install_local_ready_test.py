#!/usr/bin/env python3
"""LOCALONLY: new versioned transactions; frozen legacy fixtures stay strict."""
import copy
import contextlib
import io
import types
import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock


def load(name):
    spec = importlib.util.spec_from_file_location('local_ready_' + name, Path(__file__).with_name(name + '.py'))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m

w = load('install_core_reload_test')
o = load('install_operator_reconcile_test')
r = load('install_reconcile_test')
b = w.b


def local(d):
    return dict(d, stage='LOCAL_READY', reason='INTERNET_UNVERIFIED')


class LocalReady(unittest.TestCase):
    def fixture(self):
        c = w.Worker(); c.setUp(); self.addCleanup(c.doCleanups)
        return c

    def test_new_worker_accepts_local_ready_without_network_claim(self):
        c = self.fixture()
        c.job['receipt_schema'] = 2
        c.diag.update(stage='LOCAL_READY', reason='INTERNET_UNVERIFIED')
        self.assertEqual(c.run_worker(), 0)
        result = json.loads((c.tx/'result.json').read_bytes())
        self.assertEqual(result['receipt_schema'], 2)
        self.assertEqual(result['network'], 'NOT_TESTED')
        self.assertEqual(sum(q['action']=='reload' for q in c.requests), 1)

    def test_observing_parent_rejects_bad_result_versions_before_acceptance(self):
        for value in ['MISSING', True, '2', 3, None, 2]:
            with self.subTest(version=value):
                c = self.fixture()
                c.tx.rmdir()
                core = b.CoreReload.__new__(b.CoreReload)
                core.app, core.before = c.app, c.before
                def wait(timeout):
                    c.job = json.loads((c.tx/'job.json').read_bytes())
                    c.diag.update(stage='LOCAL_READY', reason='INTERNET_UNVERIFIED')
                    self.assertEqual(c.n['worker'](c.tx), 0)
                    result = json.loads((c.tx/'result.json').read_bytes())
                    if value == 'MISSING': result.pop('receipt_schema')
                    else: result['receipt_schema'] = value
                    (c.tx/'result.json').write_text(json.dumps(result))
                    return 0
                child = mock.Mock(); child.wait.side_effect = wait
                with b.installation_lock(c.app) as fd, \
                     mock.patch.object(b.i.uuid, 'uuid4', return_value=types.SimpleNamespace(hex=c.op)), \
                     mock.patch.object(b.subprocess, 'Popen', return_value=child), \
                     contextlib.redirect_stdout(io.StringIO()) as output:
                    core.lock_fd = fd
                    if type(value) is int and value == 2:
                        core.finish(c.digest, c.tag, c.rev)
                        b.core_reload_guard(c.app)
                        self.assertTrue((c.tx/'accepted.json').exists())
                        self.assertFalse((c.tx/'pending.json').exists())
                    else:
                        with self.assertRaisesRegex(ValueError, 'UNKNOWN'):
                            core.finish(c.digest, c.tag, c.rev)
                        self.assertFalse((c.tx/'accepted.json').exists())
                        self.assertTrue((c.tx/'pending.json').exists())
                        self.assertNotIn('Core reload SUCCEEDED:', output.getvalue())
                self.assertEqual(sum(q['action']=='reload' for q in c.requests), 1)

    def test_live_capture_and_installer_status_accept_exact_local_tuple(self):
        c = self.fixture()
        c.status['diagnostics'] = local(c.diag)
        b.validate_helper_status(json.dumps(c.status).encode(), c.digest, c.tag, c.identity)
        self.assertIs(c.n['status_check'](c.status, c.digest, c.tag, c.identity), c.status)
        for key, value in [('stage','NONE'), ('reason','NONE'), ('operation','STOP'), ('job','UNKNOWN'),
                           ('tun','UNKNOWN'), ('receipt','FAILED'), ('schema',True), ('outcome','UNKNOWN'),
                           ('cleanup','POISON')]:
            with self.subTest(key=key):
                r = copy.deepcopy(c.status); r['diagnostics'][key] = value
                with self.assertRaises(ValueError): b.validate_helper_status(json.dumps(r).encode(), c.digest, c.tag, c.identity)
                with self.assertRaises(ValueError): c.n['status_check'](r, c.digest, c.tag, c.identity)

    def test_unversioned_worker_cannot_admit_local_success(self):
        c = self.fixture(); c.diag.update(stage='LOCAL_READY',reason='INTERNET_UNVERIFIED')
        self.assertEqual(c.run_worker(), 1)
        self.assertEqual(json.loads((c.tx/'result.json').read_bytes())['state'], 'UNKNOWN')
        self.assertEqual(sum(q['action']=='reload' for q in c.requests), 1)

    def test_bad_transaction_versions_reject_before_dispatch(self):
        for version in [True, 1, '2', 3, None]:
            with self.subTest(version=version):
                c=self.fixture(); c.job['receipt_schema']=version
                self.assertEqual(c.run_worker(),1)
                self.assertFalse(any(q['action']=='reload' for q in c.requests))

    def test_new_accepted_schema_cannot_fall_back_to_legacy(self):
        c=self.fixture();c.job['receipt_schema']=2
        c.diag.update(stage='LOCAL_READY',reason='INTERNET_UNVERIFIED')
        self.assertEqual(c.run_worker(),0)
        b.CORE_RELOAD_SUPPORT['put'](c.tx,'accepted.json',dict(operation_id=c.op,result_sha256=b.sha256(c.tx/'result.json')))
        b.core_reload_guard(c.app)
        for value in [None, True, '2', 3]:
            with self.subTest(value=value):
                result=json.loads((c.tx/'result.json').read_bytes())
                if value is None: result.pop('receipt_schema',None)
                else: result['receipt_schema']=value
                (c.tx/'result.json').write_text(json.dumps(result))
                (c.tx/'accepted.json').write_text(json.dumps(dict(operation_id=c.op,result_sha256=b.sha256(c.tx/'result.json'))))
                with self.assertRaisesRegex(ValueError,'UNKNOWN/pending'):b.core_reload_guard(c.app)

    def test_new_worker_poison_is_unknown_without_resend(self):
        for key,value in [('stage','NONE'),('reason','NONE'),('operation','STOP'),('job','UNKNOWN'),
                          ('tun','UNKNOWN'),('receipt','FAILED'),('outcome','UNKNOWN')]:
            with self.subTest(key=key):
                c=self.fixture();c.job['receipt_schema']=2
                c.diag.update(stage='LOCAL_READY',reason='INTERNET_UNVERIFIED');c.diag[key]=value
                self.assertEqual(c.run_worker(),1)
                self.assertEqual(json.loads((c.tx/'result.json').read_bytes())['state'],'UNKNOWN')
                self.assertEqual(c.n['worker'](c.tx),1)
                self.assertEqual(sum(q['action']=='reload' for q in c.requests),1)

    def test_versioned_trace_and_ack_must_report_same_readiness(self):
        c=self.fixture();c.job['receipt_schema']=2
        c.response['diagnostics']=local(c.diag)
        self.assertEqual(c.run_worker(),1)
        self.assertEqual(json.loads((c.tx/'result.json').read_bytes())['state'],'UNKNOWN')
        self.assertEqual(sum(q['action']=='reload' for q in c.requests),1)

    def test_versioned_operator_readonly_legacy_stays_strict(self):
        c=o.OperatorReconciliation();c.setUp();self.addCleanup(c.doCleanups)
        c.records['response.json']['diagnostics']=local(c.records['response.json']['diagnostics'])
        c.records['timeline.json']['trace']['diagnostics']=copy.deepcopy(c.records['response.json']['diagnostics'])
        c.save();c.blocked()  # rehash cannot authorize an unversioned local tuple
        c.records['job.json']['receipt_schema']=2;c.save()
        before=c.snapshot();c.guard();self.assertEqual(c.snapshot(),before)
        self.assertEqual(c.records['result.json']['state'],'UNKNOWN')
        c.records['job.json']['receipt_schema']=True;c.save();c.blocked()

    def test_versioned_preflight_prior_local_status_legacy_stays_strict(self):
        c=r.Reconcile();c.setUp();self.addCleanup(c.doCleanups)
        c.records['job']['before']['status']=dict(c.w.status,diagnostics=local(c.w.diag))
        c.save();c.blocked()
        c.records['job']['receipt_schema']=2;c.save();c.guard()
        snapshot={p.name:p.read_bytes() for p in c.root.iterdir()}
        with mock.patch.dict(r.b.CORE_RELOAD_SUPPORT,request=mock.Mock(side_effect=AssertionError('read-only retained proof'))):
            c.guard()
        self.assertEqual({p.name:p.read_bytes() for p in c.root.iterdir()},snapshot)
        self.assertEqual(json.loads((c.root/'result.json').read_bytes())['state'],'UNKNOWN')


if __name__ == '__main__': unittest.main()

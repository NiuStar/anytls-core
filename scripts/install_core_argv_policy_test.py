#!/usr/bin/env python3
"""LOCALONLY: exercise the real reload worker with inert process/helper seams."""
import contextlib
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('argv_worker_fixture', Path(__file__).with_name('install_core_reload_test.py'))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class CoreArgvPolicy(unittest.TestCase):
    @contextlib.contextmanager
    def worker(self, insecure):
        c = fixture.Worker('runTest')
        c.setUp()
        try:
            # Build independently of core_command, in the exact Go serviceArgs order.
            args = [str(c.app/'service/anytls-macos'), '-config', str(c.app/'service/config.yaml'),
                    '-network', 'tun', '-record-service']
            if insecure:
                args.append('-allow-insecure')
            args += ['-startup-operation', c.op, '-startup-epoch', c.epoch, '-dns-observe-service', 'run']
            c.new['command'] = ' '.join(args)
            yield c
        finally:
            c.doCleanups()

    def check_result(self, c, success, code=None):
        self.assertEqual(c.run_worker(), 0 if success else 1)
        r = json.loads((c.tx/'result.json').read_bytes())
        self.assertEqual(r['state'], 'SUCCEEDED' if success else 'UNKNOWN')
        self.assertEqual(r['operation_id'], c.op)
        if code:
            self.assertEqual(r['code'], code)
        self.assertEqual(sum(q['action']=='reload' for q in c.requests), 1)
        intent = json.loads((c.tx/'intent.json').read_bytes())
        self.assertIs(intent['allow_insecure'], True)
        self.assertIs(intent['single_dispatch'], True)
        for q in c.requests:
            if q['action']=='status':
                self.assertIs(q['allow_insecure'], False)
        if success:
            self.assertEqual(r['new_core'], c.new)
            self.assertEqual(r['helper_epoch'], c.epoch)
            self.assertEqual(r['tun'], 'TUN')
            self.assertEqual(r['execution_mapping'], 'NOT_ATTESTED')
            self.assertEqual([q['action'] for q in c.requests],
                             ['status','startup.read','status','reload','startup.read','status'])
        # An existing successful OR uncertain journal must never redispatch.
        raw = (c.tx/'result.json').read_bytes()
        self.assertEqual(c.n['worker'](c.tx), 1)
        self.assertEqual((c.tx/'result.json').read_bytes(), raw)
        self.assertEqual(sum(q['action']=='reload' for q in c.requests), 1)

    def test_strict_no_flag_real_worker_succeeds(self):
        with self.worker(False) as c:
            self.check_result(c, True)

    def test_insecure_flag_real_worker_succeeds(self):
        with self.worker(True) as c:
            self.check_result(c, True)

    def test_duplicate_flags_rejected(self):
        for insecure in (False, True):
            for duplicate in ('-config extra', '-network tun', '-record-service',
                              '-allow-insecure -allow-insecure', '-startup-operation '+('a'*32),
                              '-startup-epoch '+('e'*32), '-dns-observe-service'):
                with self.subTest(insecure=insecure, duplicate=duplicate), self.worker(insecure) as c:
                    c.new['command'] = c.new['command'].replace(' run', ' '+duplicate+' run')
                    self.check_result(c, False, 'CORE_RELOAD_NEW_PROCESS')

    def test_wrong_order_rejected(self):
        for insecure in (False, True):
            for swap in ('startup', 'record', 'allow'):
                with self.subTest(insecure=insecure, swap=swap), self.worker(insecure) as c:
                    cmd = c.new['command']
                    if swap=='startup':
                        cmd = cmd.replace('-startup-operation '+c.op+' -startup-epoch '+c.epoch,
                                          '-startup-epoch '+c.epoch+' -startup-operation '+c.op)
                    elif swap=='record':
                        cmd = cmd.replace('-network tun -record-service', '-record-service -network tun')
                    else:
                        cmd = cmd.replace(' -allow-insecure', '')+' -allow-insecure'
                    c.new['command'] = cmd
                    self.check_result(c, False, 'CORE_RELOAD_NEW_PROCESS')

    def test_other_args_and_noncanonical_renderings_rejected(self):
        changes = [lambda s: s.replace('/service/anytls-macos', '/anytls-macos'),
                   lambda s: s.replace('/service/config.yaml', '/config.yaml'),
                   lambda s: s.replace('-network tun', '-network proxy'),
                   lambda s: s.replace(' -record-service', ''),
                   lambda s: s.replace(' -dns-observe-service', ''),
                   lambda s: s.replace(' run', ' check'),
                   lambda s: s+' -other', lambda s: 'env '+s,
                   lambda s: s.replace(' -config ', '  -config '),
                   lambda s: s.replace(' -config ', '\t-config '),
                   lambda s: s+' ', lambda s: s.replace(' run', ' -allow-insecure=true run')]
        for insecure in (False, True):
            for index, change in enumerate(changes):
                with self.subTest(insecure=insecure, index=index), self.worker(insecure) as c:
                    c.new['command'] = change(c.new['command'])
                    self.check_result(c, False, 'CORE_RELOAD_NEW_PROCESS')

    def test_foreign_operation_or_epoch_argv_rejected(self):
        for insecure in (False, True):
            for field in ('op', 'epoch'):
                with self.subTest(insecure=insecure, field=field), self.worker(insecure) as c:
                    c.new['command'] = c.new['command'].replace(getattr(c, field), 'f'*32)
                    self.check_result(c, False, 'CORE_RELOAD_NEW_PROCESS')

    def test_old_pid_and_nonroot_uid_rejected(self):
        for insecure in (False, True):
            for field, value in (('pid', 40), ('uid', 501), ('uid', -2)):
                with self.subTest(insecure=insecure, field=field, value=value), self.worker(insecure) as c:
                    c.new[field] = value
                    self.check_result(c, False, 'CORE_RELOAD_NEW_PROCESS')

    def test_full_census_cardinality_rejected(self):
        for insecure in (False, True):
            for mode in ('empty', 'duplicate', 'old-plus-new'):
                with self.subTest(insecure=insecure, mode=mode), self.worker(insecure) as c:
                    def processes(app):
                        if not any(q['action']=='reload' for q in c.requests):
                            return [c.old.copy()]
                        return [] if mode=='empty' else [c.new.copy(), c.old.copy() if mode=='old-plus-new' else c.new.copy()]
                    c.n['processes'] = processes
                    self.check_result(c, False, 'CORE_RELOAD_NEW_PROCESS')

    def test_reread_pid_uid_birth_command_or_census_drift_rejected(self):
        for insecure in (False, True):
            for read in (2, 3):
                for field in ('pid', 'uid', 'birth', 'command', 'census'):
                    with self.subTest(insecure=insecure, read=read, field=field), self.worker(insecure) as c:
                        reads = 0
                        def processes(app):
                            nonlocal reads
                            if not any(q['action']=='reload' for q in c.requests):
                                return [c.old.copy()]
                            reads += 1
                            row = c.new.copy()
                            if reads>=read:
                                if field=='census':
                                    return [row, c.old.copy()]
                                row[field] = row[field]+1 if field in ('pid','uid') else row[field]+' changed'
                            return [row]
                        c.n['processes'] = processes
                        self.check_result(c, False, 'CORE_RELOAD_PROCESS_DRIFT')

    def test_response_identity_and_diagnostics_still_rejected(self):
        changes = [('operation_id','f'*32), ('helper_epoch','f'*32), ('config_identity','0'*64),
                   ('helper_sha256','0'*64), ('helper_version','v0.0.0'), ('ok',1), ('loaded',1),
                   ('running',False), ('timeline_availability','UNAVAILABLE'), ('code','FAILED'),
                   ('diagnostics',None)]
        for insecure in (False, True):
            for key, value in changes:
                with self.subTest(insecure=insecure, key=key), self.worker(insecure) as c:
                    c.response[key] = value
                    self.check_result(c, False)

    def test_timeline_source_operation_epoch_and_provenance_still_rejected(self):
        changes = [('source','MANUAL_STOP'), ('operation','STOP'), ('operation_id','f'*32),
                   ('helper_epoch','f'*32), ('config_identity','0'*64), ('lifecycle_result','FAILED'),
                   ('helper_return','FAILED'), ('state','ACTIVE')]
        for insecure in (False, True):
            for key, value in changes:
                with self.subTest(insecure=insecure, key=key), self.worker(insecure) as c:
                    c.trace['trace'][key] = value
                    self.check_result(c, False)
            for key, value in (('sha256','0'*64), ('git_revision','0'*40), ('dirty',True),
                               ('version','v0.0.0'), ('sha_kind','UNKNOWN'), ('execution_mapping','ATTESTED')):
                with self.subTest(insecure=insecure, provenance=key), self.worker(insecure) as c:
                    c.trace['trace']['streams'][0]['provenance'][key] = value
                    self.check_result(c, False, 'CORE_RELOAD_PROVENANCE')


if __name__ == '__main__':
    unittest.main()

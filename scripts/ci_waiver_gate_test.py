"""Offline admission tests; all receipts here are explicitly synthetic."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
IDS = ('checkout', 'setup_go', 'pin_paths', 'real_box', 'wrapper_tests',
       'installer_tests', 'go_tests', 'race_contracts', 'full_race',
       'race_upload', 'vet', 'dist', 'build', 'app_build', 'swift_tests', 'native_upload')
COMMAND = ['python3', 'scripts/go-patched.py', 'test', '-p=2',
           '-tags=with_gvisor,with_utls,with_upstream_cleanup_patch,embedded_core',
           '-race', '-count=1', '-json', './...']
VERSION = 'v2026-11-11-01'


def fixture(root, code=0, command=None):
    if command is None:
        from ci_waiver_gate import COMMAND as command
    steps = {key: {'outputs': {}, 'outcome': 'success', 'conclusion': 'success'} for key in IDS}
    if code:
        steps['full_race']['outcome'] = 'failure'
    wrapped = ['/synthetic/go', 'test', '-modfile=/synthetic/build.mod', *command[3:]]
    begin = {'command': wrapped}
    end = dict(begin, rc=code, ephemeral_cleanup='ok', root_inputs_unchanged=True)
    events = [{'Action': 'start', 'Package': 'fixture'},
              {'Action': 'run', 'Package': 'fixture', 'Test': 'TestSynthetic'},
              {'Action': 'pass', 'Package': 'fixture', 'Test': 'TestSynthetic'},
              {'Action': 'fail' if code else 'pass', 'Package': 'fixture'}]
    raw = 'PATCHED_GO_BEGIN ' + json.dumps(begin) + '\n'
    raw += ''.join(json.dumps(e) + '\n' for e in events)
    raw += 'PATCHED_GO_END ' + json.dumps(end) + '\n'
    (root / 'go-race.jsonl').write_text(raw)
    result = {'command': command, 'returncode': code,
              'counts': {'named_pass': 1, 'named_fail': 0, 'named_skip': 0,
                         'package_pass': 0 if code else 1, 'package_fail': 1 if code else 0},
              'safe_failed_tests': [], 'release_acceptance': False}
    (root / 'result.json').write_text(json.dumps(result))
    return steps, result


class AuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('waiver', ROOT / 'scripts/ci_waiver_gate.py')
        cls.audit = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.audit)

    def test_exact_new_version_budget_and_closed_historical_identity(self):
        new = COMMAND[:-2] + ['-timeout=20m', *COMMAND[-2:]]
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as td:
            root = Path(td)
            for version, command in [('v2026-11-11-01', COMMAND),
                                     ('v2026-11-12-01', COMMAND),
                                     ('v2026-11-12-02', new), ('v2026-11-13-01', new)]:
                steps, _ = fixture(root, command=command)
                for matrix in ('macos-15', 'macos-15-intel'):
                    self.assertEqual(self.audit.validate(steps, matrix, root, version), 'FULL_RACE_PASS')
            for command in (COMMAND, new):
                steps, _ = fixture(root, command=command)
                for version in ('', 'v2026-11-12-03', 'unknown'):
                    with self.subTest(version=version, command=command), self.assertRaises(ValueError):
                        self.audit.validate(steps, 'macos-15', root, version)

    def test_new_version_rejects_missing_overridden_duplicate_or_filtered_budget(self):
        new = COMMAND[:-2] + ['-timeout=20m', *COMMAND[-2:]]
        variants = [COMMAND] + [[v.replace('20m', value) for v in new] for value in ('10m', '30m', '0')]
        variants += [new[:-1] + [flag, './...'] for flag in
                     ('-timeout=20m', '-timeout=30m', '-run=Subset', '-short', '-skip=Subset')]
        variants += [new[:-1] + ['./internal/...'], new[:-1] + ['.', './...']]
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as td:
            root = Path(td)
            for mutant in variants:
                for seam in ('both', 'result', 'raw'):
                    with self.subTest(command=mutant, seam=seam):
                        steps, result = fixture(root, command=mutant if seam != 'result' else new)
                        if seam == 'result':
                            result['command'] = mutant
                            (root / 'result.json').write_text(json.dumps(result))
                        if seam == 'raw':
                            result['command'] = new
                            (root / 'result.json').write_text(json.dumps(result))
                        for version in ('v2026-11-12-02', 'v2026-11-13-01'):
                            with self.subTest(version=version), self.assertRaises(ValueError):
                                self.audit.validate(steps, 'macos-15', root, version)
            for version, command in [('v2026-11-11-01', new), ('v2026-11-12-01', new)]:
                steps, _ = fixture(root, command=command)
                with self.assertRaises(ValueError):
                    self.audit.validate(steps, 'macos-15', root, version)
            steps, _ = fixture(root, 1, command=new)
            for matrix in ('macos-15', 'macos-15-intel'):
                with self.assertRaises(ValueError):
                    self.audit.validate(steps, matrix, root, 'v2026-11-12-02')
                with self.assertRaises(ValueError):
                    self.audit.validate(steps, matrix, root, 'v2026-11-13-01')

    def test_intel_failure_is_waived_not_pass_and_raw_unchanged(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as td:
            root = Path(td)
            steps, _ = fixture(root, 1, command=COMMAND)
            before = {p.name: p.read_bytes() for p in root.iterdir()}
            self.assertEqual(self.audit.validate(steps, 'macos-15-intel', root, VERSION),
                             'INTEL_RACE_FAIL_WAIVED_FOR_0_5_3')
            self.assertEqual(before, {p.name: p.read_bytes() for p in root.iterdir()})

    def cli(self, steps, root, matrix='macos-15-intel', text=None):
        env = dict(os.environ, STEPS_JSON=json.dumps(steps) if text is None else text,
                   MATRIX_OS=matrix, RACE_EVIDENCE=str(root), PYTHONDONTWRITEBYTECODE='1')
        return subprocess.run([sys.executable, str(ROOT / 'scripts/ci_waiver_gate.py')],
                              cwd=ROOT, env=env, capture_output=True, text=True, timeout=10)

    def test_actual_cli_positive_matrix(self):
        for matrix, code, label in [('macos-15-intel', 0, 'FULL_RACE_PASS'),
                                    ('macos-15', 0, 'FULL_RACE_PASS')]:
            with self.subTest(matrix=matrix, code=code), tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as td:
                steps, _ = fixture(Path(td), code)
                result = self.cli(steps, td, matrix)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), label)

    def test_current_release_rejects_legacy_intel_waiver_through_actual_cli(self):
        current = (ROOT / 'VERSION').read_text().strip()
        self.assertEqual(current, 'v2026-11-13-01')
        self.assertEqual(self.audit.VERSION, 'v2026-11-11-01')
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as td:
            root = Path(td)
            steps, _ = fixture(root, 1)
            for matrix in ('macos-15', 'macos-15-intel'):
                with self.subTest(matrix=matrix):
                    result = self.cli(steps, root, matrix)
                    self.assertEqual(result.returncode, 1)
                    self.assertNotIn('WAIVED', result.stdout)
                    with self.assertRaises(ValueError):
                        self.audit.validate(steps, matrix, root, current)

    def test_every_required_step_failure_skip_pending_cancelled_blocks(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as td:
            root = Path(td)
            steps, _ = fixture(root, 1, command=COMMAND)
            for key in IDS:
                for state in ('failure', 'skipped', 'pending', 'cancelled', None):
                    if key == 'full_race' and state == 'failure':
                        continue
                    with self.subTest(step=key, state=state):
                        bad = copy.deepcopy(steps)
                        bad[key]['outcome'] = state
                        with self.assertRaises(ValueError):
                            self.audit.validate(bad, 'macos-15-intel', root, VERSION)
                for state in ('failure', 'skipped', 'pending', 'cancelled', None):
                    bad = copy.deepcopy(steps)
                    bad[key]['conclusion'] = state
                    with self.assertRaises(ValueError):
                        self.audit.validate(bad, 'macos-15-intel', root, VERSION)

    def test_scope_inventory_and_context_schema(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as td:
            root = Path(td)
            steps, _ = fixture(root, 1, command=COMMAND)
            for matrix, version in [('macos-15', VERSION), ('ubuntu-latest', VERSION),
                                    ('macos-15-intel', 'v2026-11-11-02'), ('macos-15-intel', '')]:
                with self.subTest(matrix=matrix, version=version), self.assertRaises(ValueError):
                    self.audit.validate(steps, matrix, root, version)
            variants = [dict(steps, unknown=steps['vet']), {k: v for k, v in steps.items() if k != 'vet'}]
            for field in ('outputs', 'outcome', 'conclusion'):
                bad = copy.deepcopy(steps)
                del bad['vet'][field]
                variants.append(bad)
            bad = copy.deepcopy(steps)
            bad['vet']['ignored'] = True
            variants.append(bad)
            for bad in variants:
                with self.assertRaises(ValueError):
                    self.audit.validate(bad, 'macos-15-intel', root, VERSION)
            self.assertEqual(self.audit.validate(dict(steps, waiver_audit={}), 'macos-15-intel', root, VERSION),
                             'INTEL_RACE_FAIL_WAIVED_FOR_0_5_3')

    def test_cli_malformed_duplicate_json_and_missing_evidence(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as td:
            steps, _ = fixture(Path(td), 1)
            for text in ('{', '[]', '{"vet":{},"vet":{}}'):
                result = self.cli(steps, td, text=text)
                self.assertEqual(result.returncode, 1)
                self.assertNotIn('PASS', result.stdout)
            self.assertEqual(self.cli(steps, '').returncode, 1)
            self.assertEqual(self.cli(steps, str(Path(td) / 'absent')).returncode, 1)

    def test_receipt_mutations_and_symlinks_block(self):
        mutations = [lambda r: r.update(returncode=0), lambda r: r.update(returncode=True),
                     lambda r: r.update(command=COMMAND + ['-run=Subset']),
                     lambda r: r.update(release_acceptance=True),
                     lambda r: r['counts'].update(package_fail=2)]
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as td:
            root = Path(td)
            for mutate in mutations:
                steps, receipt = fixture(root, 1, command=COMMAND)
                mutate(receipt)
                (root / 'result.json').write_text(json.dumps(receipt))
                with self.assertRaises(ValueError):
                    self.audit.validate(steps, 'macos-15-intel', root, VERSION)
            for name in ('result.json', 'go-race.jsonl'):
                for payload in ('', '{', '{"command":[],"command":[]}'):
                    steps, _ = fixture(root, 1)
                    (root / name).write_text(payload)
                    self.assertEqual(self.cli(steps, root).returncode, 1)
                steps, _ = fixture(root, 1)
                saved = root / ('saved-' + name)
                (root / name).rename(saved)
                (root / name).symlink_to(saved)
                self.assertEqual(self.cli(steps, root).returncode, 1)
                (root / name).unlink()
                fixture(root, 1)
            alias = root / 'alias'
            alias.symlink_to(root, target_is_directory=True)
            self.assertEqual(self.cli(steps, alias).returncode, 1)

    def test_raw_truncation_no_execution_and_receipt_mismatch(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as td:
            root = Path(td)
            steps, _ = fixture(root, 1, command=COMMAND)
            raw = (root / 'go-race.jsonl').read_text()
            lines = raw.splitlines(keepends=True)
            variants = [''.join(lines[1:]), ''.join(lines[:-1]), raw[:-1],
                        ''.join([lines[0], lines[-1]]), raw + '{}\n',
                        raw.replace('"rc": 1', '"rc": 0'),
                        raw.replace('"-race"', '"-run=Subset"'),
                        raw.replace('"ephemeral_cleanup": "ok"', '"ephemeral_cleanup": "broken"'),
                        raw.replace('"root_inputs_unchanged": true', '"root_inputs_unchanged": false'),
                        raw.replace('"Action": "start"', '"Action": "output"'),
                        raw.replace(lines[2], ''),
                        raw.replace(lines[1], lines[1] + '{"Action": "start", "Action": "pass"}\n')]
            for index, mutant in enumerate(variants):
                with self.subTest(index=index):
                    (root / 'go-race.jsonl').write_text(mutant)
                    with self.assertRaises(ValueError):
                        self.audit.validate(steps, 'macos-15-intel', root, VERSION)

    def test_zero_exit_with_dirty_race_or_failure_blocks(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as td:
            root = Path(td)
            for marker in ('WARNING: DATA RACE', 'panic:', 'fatal error:'):
                steps, _ = fixture(root, command=COMMAND)
                path = root / 'go-race.jsonl'
                path.write_text(path.read_text().replace('PATCHED_GO_END ',
                    json.dumps({'Action': 'output', 'Package': 'fixture', 'Output': marker}) + '\nPATCHED_GO_END '))
                with self.assertRaises(ValueError):
                    self.audit.validate(steps, 'macos-15-intel', root, VERSION)
            steps, _ = fixture(root, command=COMMAND)
            steps['full_race']['outcome'] = 'failure'
            receipt = json.loads((root / 'result.json').read_text())
            receipt['returncode'] = 1
            (root / 'result.json').write_text(json.dumps(receipt))
            path = root / 'go-race.jsonl'
            path.write_text(path.read_text().replace('"rc": 0', '"rc": 1'))
            with self.assertRaises(ValueError):
                self.audit.validate(steps, 'macos-15-intel', root, VERSION)
            steps, _ = fixture(root, 1, command=COMMAND)
            steps['full_race']['outcome'] = 'success'
            with self.assertRaises(ValueError):
                self.audit.validate(steps, 'macos-15-intel', root, VERSION)

    def test_legitimate_nonjson_build_diagnostics_and_package_start(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as td:
            root = Path(td)
            steps, _ = fixture(root, 1, command=COMMAND)
            path = root / 'go-race.jsonl'
            path.write_text(path.read_text().replace('PATCHED_GO_END ', '# synthetic compiler diagnostic\nPATCHED_GO_END '))
            self.assertEqual(self.audit.validate(steps, 'macos-15-intel', root, VERSION),
                             'INTEL_RACE_FAIL_WAIVED_FOR_0_5_3')


if __name__ == '__main__':
    unittest.main(verbosity=2)

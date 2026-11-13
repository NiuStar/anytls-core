"""Offline full-race contract controls: no Go, network, or publication."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
BASE_WORKFLOW_SHA256 = '8427b9366435a23b1c9333bf161e8e4cd2b7a1031eb19129bbb510f58197ec44'
RACE = '''      - name: Full unfiltered native race qualification
        env:
          CGO_ENABLED: '1'
        run: python3 scripts/ci-race.py
'''
CONTROLS = '''      - name: Offline full-race CI contract regressions
        run: PYTHONDONTWRITEBYTECODE=1 python3 scripts/ci_race_test.py
'''
UPLOAD = '''      - name: Preserve full-race evidence on every platform
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: full-race-${{ matrix.os }}
          path: ${{ env.RACE_EVIDENCE }}
          if-no-files-found: warn
'''


def validate_workflow(text):
    # Remove only exact reviewed waiver additions, then authenticate every old byte.
    from ci_waiver_gate_test import IDS
    import re
    ids = re.findall(r'^        id: ([a-z_]+)$', text, re.M)
    if ids != [*IDS, 'waiver_audit']:
        raise ValueError('exact source step IDs required')
    for identifier in (*IDS, 'waiver_audit'):
        text = text.replace('        id: ' + identifier + '\n', '')
    exception = "        continue-on-error: ${{ matrix.os == 'macos-15-intel' && env.INTEL_RACE_WAIVER == 'v2026-11-11-01' }}\n"
    authority = '''          echo "INTEL_RACE_WAIVER=$(tr -d '\\r\\n' < VERSION)" >> "$GITHUB_ENV"
'''
    audit = '''      - name: Audit mandatory gates and scoped Intel race waiver
        if: always()
        env:
          STEPS_JSON: ${{ toJSON(steps) }}
          MATRIX_OS: ${{ matrix.os }}
        run: PYTHONDONTWRITEBYTECODE=1 python3 scripts/ci_waiver_gate.py
'''
    contracts = '''        run: |
          PYTHONDONTWRITEBYTECODE=1 python3 scripts/ci_race_test.py
          PYTHONDONTWRITEBYTECODE=1 python3 scripts/ci_waiver_gate_test.py
          PYTHONDONTWRITEBYTECODE=1 python3 scripts/release_ci_gate_test.py
'''
    for block in (exception, authority, audit, contracts):
        if text.count(block) != 1:
            raise ValueError('missing/changed scoped waiver contract')
        text = text.replace(block, '        run: PYTHONDONTWRITEBYTECODE=1 python3 scripts/ci_race_test.py\n' if block == contracts else '')
    replacements = (
        ('      - name: Checkout\n        uses:', '      - uses:'),
        ('      - name: Setup Go\n        uses:', '      - uses:'),
        ('      - name: Patched wrapper regressions\n        run:', '      - run:'),
        ('      - name: Non-race Go tests\n        run:', '      - run:'),
        ('      - name: Go vet\n        run:', '      - run:'),
        ('      - name: Prepare dist\n        run:', '      - run:'),
        ('      - name: Build Go core\n        run:', '      - run:'),
        (UPLOAD.replace('if-no-files-found: warn', 'if-no-files-found: error'), UPLOAD),
    )
    for before, after in replacements:
        if text.count(before) != 1:
            raise ValueError('missing/changed exact source step')
        text = text.replace(before, after)
    # Normalize only the exact user-authorized dual-Mac/fail-fast delta.
    strategy = '    strategy:\n      fail-fast: false\n      matrix:\n        os: [macos-15, macos-15-intel]\n'
    if text.count(strategy) != 1:
        raise ValueError('exact independent dual-Mac matrix required')
    text = text.replace(strategy, '    strategy:\n      matrix:\n        os: [ubuntu-latest, macos-15, macos-15-intel]\n')
    # Preserve the reviewed native-upload guard and original baseline hash.
    guarded = "        if: always() && runner.os == 'macOS' && env.MENUBAR_EVIDENCE != ''\n"
    if text.count(guarded) != 1:
        raise ValueError('native evidence upload requires an owned path')
    text = text.replace(guarded, "        if: always() && runner.os == 'macOS'\n")
    for block in (CONTROLS, RACE, UPLOAD):
        if text.count(block) != 1:
            raise ValueError('missing/changed qualification step')
        text = text.replace(block, '')
    if hashlib.sha256(text.encode()).hexdigest() != BASE_WORKFLOW_SHA256:
        raise ValueError('original workflow changed')


class WorkflowTests(unittest.TestCase):
    def test_authorized_dual_mac_and_all_original_steps_retained(self):
        text = (ROOT / '.github/workflows/ci.yml').read_text()
        self.assertIn('      fail-fast: false\n', text)
        self.assertIn('        os: [macos-15, macos-15-intel]\n', text)
        validate_workflow(text)

    def test_mac_scope_and_safety_mutants_rejected(self):
        text = (ROOT / '.github/workflows/ci.yml').read_text()
        mutations = (
            ('os: [macos-15, macos-15-intel]', 'os: [macos-15]'),
            ('os: [macos-15, macos-15-intel]', 'os: [macos-15-intel]'),
            ('os: [macos-15, macos-15-intel]', 'os: [ubuntu-latest, macos-15, macos-15-intel]'),
            ('fail-fast: false', 'fail-fast: true'),
            ('      fail-fast: false\n', ''),
            ('run: python3 scripts/ci-race.py', 'run: python3 scripts/ci-race.py -run=TestSubset'),
            ('run: python3 scripts/ci-race.py', 'run: python3 scripts/ci-race.py -timeout=30m'),
        )
        for old, new in mutations:
            with self.subTest(new=new):
                self.assertIn(old, text)
                with self.assertRaises(ValueError):
                    validate_workflow(text.replace(old, new))

    def test_waiver_cannot_broaden_or_lose_audit_or_upload(self):
        text = (ROOT / '.github/workflows/ci.yml').read_text()
        exception = "${{ matrix.os == 'macos-15-intel' && env.INTEL_RACE_WAIVER == 'v2026-11-11-01' }}"
        mutations = [(exception, '${{ true }}'),
                     (exception, "${{ matrix.os == 'macos-15' }}"),
                     (exception, "${{ matrix.os == 'macos-15-intel' }}"),
                     ('        id: vet\n', '        id: vet\n        continue-on-error: true\n'),
                     ('        if: always()\n', '        if: failure()\n'),
                     ('if-no-files-found: error', 'if-no-files-found: warn'),
                     ('path: ${{ env.RACE_EVIDENCE }}', 'path: missing'),
                     ('          STEPS_JSON: ${{ toJSON(steps) }}\n', ''),
                     ('        id: waiver_audit', '        id: unknown'),
                     ('run: PYTHONDONTWRITEBYTECODE=1 python3 scripts/ci_waiver_gate.py', 'run: true'),
                     ('        id: full_race\n', '        id: full_race\n        timeout-minutes: 30\n')]
        for old, new in mutations:
            with self.subTest(new=new):
                self.assertIn(old, text)
                with self.assertRaises(ValueError):
                    validate_workflow(text.replace(old, new))
        # Packaging/publish commands retain every byte except the reviewed label
        # and observer-only wait cap (not a Go test or production deadline).
        current = (ROOT / '.github/workflows/binary-release.yml').read_text()
        self.assertEqual(current.count('        timeout-minutes: 62\n'), 1)
        self.assertEqual(current.count('run: python3 scripts/release_ci_gate.py --seconds 3600 --interval 15'), 1)
        normalized = current.replace('Require exact tag push CI and both terminal-success Mac jobs with scoped Intel race audit',
                                     'Require exact tag push CI and all three terminal-success jobs')
        normalized = normalized.replace('        timeout-minutes: 62\n', '        timeout-minutes: 32\n')
        normalized = normalized.replace('run: python3 scripts/release_ci_gate.py --seconds 3600 --interval 15',
                                        'run: python3 scripts/release_ci_gate.py --seconds 1800 --interval 15')
        self.assertEqual(hashlib.sha256(normalized.encode()).hexdigest(),
                         'fe817a33c33af8818bd6ce191849ffbf535ae3e0ed024ca2b1c6ecf71b255511')

    def test_native_upload_requires_owned_evidence(self):
        text = (ROOT / '.github/workflows/ci.yml').read_text()
        block = text.split('- name: Preserve native evidence even on AppKit/GUI or assertion failure\n', 1)[1]
        guard = block.split('if:', 1)[1].splitlines()[0].strip()
        self.assertEqual(guard, "always() && runner.os == 'macOS' && env.MENUBAR_EVIDENCE != ''")
        for os_name, path, expected in [('macOS', '', False), ('macOS', '/owned/e', True), ('Linux', '/owned/e', False)]:
            self.assertEqual(True and os_name == 'macOS' and path != '', expected)
        for mutant in (text.replace(guard, 'always()'), text.replace("env.MENUBAR_EVIDENCE != ''", "env.MENUBAR_EVIDENCE == ''")):
            with self.assertRaises(ValueError):
                validate_workflow(mutant)

    def test_mutants_are_rejected(self):
        text = (ROOT / '.github/workflows/ci.yml').read_text()
        validate_workflow(text)
        for old, new in ((RACE, ''), ('CGO_ENABLED: \'1\'', "CGO_ENABLED: '0'"),
                         ('run: python3 scripts/ci-race.py', "if: false\n        run: python3 scripts/ci-race.py"),
                         ('macos-15-intel', 'macos-14'), (' -count=1', ''),
                         ('      - run: python3 scripts/go-patched.py vet', '      - run: echo vet')):
            mutant = text.replace(old, new)
            if mutant == text:
                continue
            with self.assertRaises(ValueError):
                validate_workflow(mutant)


class RunnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('ci_race', ROOT / 'scripts/ci-race.py')
        cls.runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.runner)

    def test_exact_full_command(self):
        self.assertEqual(self.runner.COMMAND, ['python3', 'scripts/go-patched.py', 'test', '-p=2',
            '-tags=with_gvisor,with_utls,with_upstream_cleanup_patch,embedded_core',
            '-race', '-count=1', '-timeout=20m', '-json', './...'])

    def test_exact_budget_reaches_child_and_receipts_without_raw_rewrite(self):
        import ci_waiver_gate as gate
        from ci_waiver_gate_test import fixture
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as td:
            root = Path(td)
            # Explicit synthetic wrapper bytes, not an executed native Go run.
            steps, _ = fixture(root, command=self.runner.COMMAND)
            raw = (root / 'go-race.jsonl').read_bytes()
            expected = ['python3', 'scripts/go-patched.py', 'test', '-p=2',
                '-tags=with_gvisor,with_utls,with_upstream_cleanup_patch,embedded_core',
                '-race', '-count=1', '-timeout=20m', '-json', './...']
            def child(argv, **kwargs):
                self.assertEqual(argv, expected)
                self.assertNotIn('timeout', kwargs)
                self.assertEqual(kwargs['stderr'], subprocess.STDOUT)
                kwargs['stdout'].write(raw)
                return subprocess.CompletedProcess(argv, 0)
            with patch.object(self.runner.subprocess, 'run', side_effect=child), patch('builtins.print'):
                self.assertEqual(self.runner.run(root), 0)
            self.assertEqual((root / 'go-race.jsonl').read_bytes(), raw)
            self.assertEqual(json.loads((root / 'result.json').read_text())['command'], expected)
            for version in ('v2026-11-12-02', 'v2026-11-13-01'):
                self.assertEqual(gate.validate(steps, 'macos-15', root, version), 'FULL_RACE_PASS')

    def test_preflight_rejects_noncanonical_or_cgo_off_before_child(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as td:
            home = Path(td)
            (home / '.aq-ci').mkdir()
            with patch.object(self.runner.Path, 'home', return_value=home), patch.object(self.runner.subprocess, 'run') as child:
                for settings in ({'TMPDIR': str(home / '.aq-ci'), 'CGO_ENABLED': '0'},
                                 {'TMPDIR': str(home / '.aq-ci') + '/', 'CGO_ENABLED': '1'}):
                    with patch.dict(os.environ, settings), self.assertRaises(ValueError):
                        self.runner.main()
                (home / '.aq-ci').rmdir()
                (home / 'other').mkdir()
                (home / '.aq-ci').symlink_to(home / 'other', target_is_directory=True)
                with self.assertRaises(ValueError):
                    self.runner.main()
                child.assert_not_called()

    def test_safe_failure_reporting_and_original_exit(self):
        for code in (0, 1, 2):
            with self.subTest(code=code), tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as td:
                def child(argv, **kwargs):
                    self.assertEqual(argv, self.runner.COMMAND)
                    self.assertNotIn('timeout', kwargs)
                    log = kwargs['stdout']
                    log.write(b'{"Action":"fail","Test":"TestSafeSynthetic"}\n')
                    log.write(b'{"Action":"fail","Test":"TestSecret/path/token"}\n')
                    log.write(b'{"Action":"pass","Package":"fixture"}\n')
                    log.write(b'PRIVATE RAW STDERR /private/token\n')
                    return subprocess.CompletedProcess(argv, code)
                with patch.object(self.runner.subprocess, 'run', side_effect=child), patch('builtins.print') as output:
                    result = self.runner.run(Path(td))
                self.assertEqual(result, code)
                self.assertIn(b'PRIVATE RAW STDERR', (Path(td) / 'go-race.jsonl').read_bytes())
                public = str(output.call_args_list)
                self.assertNotIn('PRIVATE', public)
                self.assertNotIn('path/token', public)
                if code:
                    self.assertIn('TestSafeSynthetic', public)
                else:
                    self.assertNotIn('::error', public)
                self.assertEqual(json.loads((Path(td) / 'result.json').read_text())['returncode'], code)


if __name__ == '__main__':
    unittest.main(verbosity=2)

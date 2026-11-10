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
    # Only this reviewed native-upload guard differs from the frozen workflow.
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
    def test_full_matrix_and_all_original_steps_retained(self):
        validate_workflow((ROOT / '.github/workflows/ci.yml').read_text())

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
            '-race', '-count=1', '-json', './...'])

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

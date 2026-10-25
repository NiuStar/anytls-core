"""Linux/macOS shell simulation: real Bash chain, fake curl/uname/Python; no install."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
PATHS = ('install-control-helper.sh', 'scripts/install.py', 'scripts/install-binary.py')
RAW = 'https://raw.githubusercontent.com/NiuStar/anytls-core/main/'
API = 'https://api.github.com/repos/NiuStar/anytls-core/contents/'
ARGS = ['--check-download', '--arch', 'amd64', '--version', 'v1.2.3', '--app-dir', 'space dir']

CURL = r'''
import json, os, pathlib, sys
args = sys.argv[1:]
url = next(a for a in args if a.startswith('https://'))
out = pathlib.Path(args[args.index('-o') + 1])
api = url.startswith('https://api.github.com/')
key = url.split('/contents/' if api else '/main/', 1)[1].split('?', 1)[0]
with open(os.environ['CALLS'], 'a') as f:
    f.write(json.dumps({'url': url, 'args': args, 'out': str(out)}) + '\n')
if key in json.loads(os.environ['FAIL_API' if api else 'FAIL_RAW']):
    # A failed transport may leave an executable prefix: never run it.
    out.write_text('#!/bin/bash\nprintf \'[]\' > "$RESULT"\nexit 0\n' if key.endswith('.sh')
                   else '#!/usr/bin/env python3\n# partial failed download\n')
    sys.exit(22 if api else 35)
if key in json.loads(os.environ.get('BAD_BODY', '[]')):
    out.write_text(os.environ.get('BODY', '{"type":"file","content":"not raw"}\n'))
else:
    out.write_bytes((pathlib.Path(os.environ['SOURCE']) / key).read_bytes())
'''
PYTHON = r'''
import json, os, pathlib, sys
if '-c' in sys.argv:
    sys.exit(1)
pathlib.Path(os.environ['RESULT']).write_text(json.dumps(sys.argv[1:]))
script = pathlib.Path(sys.argv[2])
assert sys.argv[1] == '-I', sys.argv
for name in ('install.py', 'install-binary.py'):
    assert (script.parent / name).read_bytes() == (pathlib.Path(os.environ['SOURCE']) / 'scripts' / name).read_bytes()
sys.exit(int(os.environ.get('PYTHON_RC', '0')))
'''


@unittest.skipIf(os.geteuid() == 0, 'entry intentionally refuses root')
class OfficialFallbackTests(unittest.TestCase):
    def invoke(self, entry='get.sh', fail_raw=(), fail_api=(), **extra):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp)
            binary = home / 'bin'
            binary.mkdir()
            programs = {
                'curl': CURL,
                'uname': "import sys; print('Darwin' if '-s' in sys.argv else 'x86_64')",
                'python3': PYTHON,
                'go': "raise AssertionError('Go must not run')",
                'sudo': "raise AssertionError('sudo must not run')",
            }
            for name, body in programs.items():
                target = binary / name
                target.write_text('#!' + sys.executable + '\n' + body)
                target.chmod(0o700)
            env = {'HOME': temp, 'TMPDIR': temp, 'PATH': str(binary) + ':/usr/bin:/bin',
                   'SOURCE': str(ROOT), 'CALLS': str(home / 'calls.jsonl'),
                   'RESULT': str(home / 'result.json'), 'SSL_CERT_FILE': '',
                   'FAIL_RAW': json.dumps(fail_raw), 'FAIL_API': json.dumps(fail_api)}
            env.update(extra)
            result = subprocess.run(['/bin/bash', str(ROOT / entry), *ARGS], env=env,
                                    capture_output=True, text=True, timeout=15)
            calls = [json.loads(line) for line in (home / 'calls.jsonl').read_text().splitlines()]
            output = json.loads((home / 'result.json').read_text()) if (home / 'result.json').exists() else None
            self.assertFalse(list(home.glob('anytls-entry.*')))
            self.assertFalse(list((home / '.anytls').glob('binary-bootstrap.*')))
            return result, calls, output

    def assert_requests(self, calls, keys, api=False):
        self.assertEqual([c['url'] for c in calls],
                         [(API + k + '?ref=main') if api else RAW + k for k in keys])
        for call in calls:
            args = call['args']
            for flag, value in (('--proto', '=https'), ('--tlsv1.2', None),
                                ('--connect-timeout', '20'), ('--max-time', '180'), ('--fail', None)):
                self.assertIn(flag, args)
                if value is not None:
                    self.assertEqual(args[args.index(flag) + 1], value)
            self.assertNotIn('--insecure', args)
            if api:
                self.assertEqual(args[args.index('-H') + 1], 'Accept: application/vnd.github.raw+json')

    def test_entry_falls_back_to_official_api_then_runs_real_bootstrap(self):
        result, calls, output = self.invoke(fail_raw=[PATHS[0]])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_requests(calls[:1], PATHS[:1])
        self.assert_requests(calls[1:2], PATHS[:1], api=True)
        self.assert_requests(calls[2:], PATHS[1:])
        self.assertEqual(calls[0]['out'], calls[1]['out'])
        self.assertEqual(output[2:], ARGS)
        self.assertIn('GitHub API', result.stderr)

    def test_python_components_fall_back_independently(self):
        for key in PATHS[1:]:
            with self.subTest(component=key):
                result, calls, output = self.invoke(fail_raw=[key])
                self.assertEqual(result.returncode, 0, result.stderr)
                raw_calls = [c for c in calls if c['url'].startswith(RAW)]
                api_calls = [c for c in calls if c['url'].startswith(API)]
                self.assert_requests(raw_calls, PATHS)
                self.assert_requests(api_calls, [key], api=True)
                original = next(c for c in raw_calls if c['url'] == RAW + key)
                self.assertEqual(original['out'], api_calls[0]['out'])
                self.assertIn('--progress-bar', original['args'])
                self.assertIn('--progress-bar', api_calls[0]['args'])
                self.assertEqual(output[2:], ARGS)

    def test_raw_success_never_requests_api(self):
        for entry, keys in (('get.sh', PATHS), ('install-control-helper.sh', PATHS[1:])):
            with self.subTest(entry=entry):
                result, calls, output = self.invoke(entry=entry)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assert_requests(calls, keys)
                self.assertEqual(output[2:], ARGS)
                self.assertNotIn('GitHub API', result.stderr)

    def test_all_raw_failures_use_api_with_original_arguments(self):
        result, calls, output = self.invoke(fail_raw=PATHS)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_requests(calls[::2], PATHS)
        self.assert_requests(calls[1::2], PATHS, api=True)
        self.assertEqual(output[2:], ARGS)

    def test_both_transports_fail_without_invoking_python(self):
        for key in PATHS:
            with self.subTest(component=key):
                result, calls, output = self.invoke(fail_raw=[key], fail_api=[key])
                self.assertEqual(result.returncode, 22, result.stderr)
                self.assertIsNone(output)
                self.assertEqual(calls[-2]['url'], RAW + key)
                self.assert_requests(calls[-1:], [key], api=True)
                self.assertNotIn('安装组件已下载', result.stderr)

    def test_python_failure_is_not_masked(self):
        result, _, output = self.invoke(fail_raw=PATHS, PYTHON_RC='17')
        self.assertEqual(result.returncode, 17, result.stderr)
        self.assertEqual(output[2:], ARGS)

    def test_bad_raw_success_body_is_also_rejected(self):
        for key in PATHS:
            with self.subTest(component=key):
                result, calls, output = self.invoke(BAD_BODY=json.dumps([key]))
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(output)
                self.assertFalse(any(c['url'].startswith(API) for c in calls))
                self.assertIn('Invalid installer', result.stderr)

    def test_wrong_media_or_empty_body_never_reaches_python(self):
        for key in PATHS:
            for body in ('', '{"type":"file","content":"base64"}\n', '<html>error</html>\n'):
                with self.subTest(component=key, body=body):
                    result, _, output = self.invoke(fail_raw=[key], BAD_BODY=json.dumps([key]), BODY=body)
                    self.assertNotEqual(result.returncode, 0, result.stderr)
                    self.assertIsNone(output)
                    self.assertIn('Invalid installer', result.stderr)


if __name__ == '__main__':
    unittest.main()

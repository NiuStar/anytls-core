"""Offline Bash-chain regression: real get.sh/bootstrap, never run an installer.

Fake curl serves the real bootstrap and inert Python fixtures; fake Python only
records argv. HOME/TMPDIR are private scratch. On root-only CI, replace exactly
one EUID guard in each scratch shell copy (explicitly SYNTHETIC_ROOT_GUARD),
leaving the checked-out scripts untouched; ordinary users run original bytes.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
COMPONENTS = ('install-control-helper.sh', 'scripts/install.py', 'scripts/install-binary.py')
RAW = 'https://raw.githubusercontent.com/NiuStar/anytls-core/main/'
API = 'https://api.github.com/repos/NiuStar/anytls-core/contents/'
RELOAD_ARGS = ['--reload-core', '--version', 'v1.2.3', '--webui-listen', '127.0.0.1']
PYTHON_FIXTURE = '#!/usr/bin/env python3\nraise AssertionError("installer fixture must never execute")\n'
ROOT_GUARD = '[[ "$EUID" != 0 ]] || { printf \'%s\\n\' \'Run as your normal user, never sudo/root.\' >&2; exit 1; }'

CURL = r'''
import json, os, pathlib, sys
args = sys.argv[1:]
urls = [a for a in args if a.startswith('https://')]
if len(urls) != 1:
    raise AssertionError(args)
url = urls[0]
raw = os.environ['RAW_PREFIX']
api = os.environ['API_PREFIX']
is_api = url.startswith(api)
if is_api:
    assert url.endswith('?ref=main'), url
    key = url[len(api):-len('?ref=main')]
else:
    assert url.startswith(raw), url
    key = url[len(raw):]
assert key in ('install-control-helper.sh', 'scripts/install.py', 'scripts/install-binary.py'), key
out = pathlib.Path(args[args.index('-o') + 1])
assert out.resolve().is_relative_to(pathlib.Path(os.environ['HOME']).resolve())
with open(os.environ['CALLS'], 'a') as stream:
    stream.write(json.dumps({'url': url, 'args': args, 'output': str(out)}) + '\n')
if key in json.loads(os.environ['FAIL_API' if is_api else 'FAIL_RAW']):
    out.write_text('partial failed transport\n')
    sys.exit(22 if is_api else 35)
if key == os.environ['BAD_KEY']:
    out.write_text(os.environ['BAD_BODY'])
elif key.endswith('.sh'):
    out.write_bytes(pathlib.Path(os.environ['BOOTSTRAP']).read_bytes())
else:
    out.write_text(os.environ['PYTHON_FIXTURE'])
'''

PYTHON = r'''
import json, os, pathlib, sys
if sys.argv[1:3] == ['-I', '-c']:
    sys.exit(1)  # CA probe is harmless and must never trigger the fallback.
assert sys.argv[1] == '-I', sys.argv
script = pathlib.Path(sys.argv[2])
assert script.name == 'install-binary.py', sys.argv
assert script.resolve().is_relative_to(pathlib.Path(os.environ['HOME']).resolve())
for name in ('install.py', 'install-binary.py'):
    assert (script.parent / name).read_text() == os.environ['PYTHON_FIXTURE']
pathlib.Path(os.environ['RESULT']).write_text(json.dumps(sys.argv[1:]))
sys.exit(int(os.environ['PYTHON_RC']))
'''


class BootstrapReloadArgsTests(unittest.TestCase):
    scenarios = 0

    @classmethod
    def tearDownClass(cls):
        mode = 'SYNTHETIC_ROOT_GUARD' if os.geteuid() == 0 else 'ORIGINAL_SHELL_BYTES'
        print(f'\nOFFLINE_SHELL_SCENARIOS={cls.scenarios} MODE={mode}', flush=True)

    def invoke(self, args=(), entry='get.sh', fail_raw=(), fail_api=(),
               bad_key='', bad_body='', python_rc=0):
        type(self).scenarios += 1
        # Never fall back to the operator HOME for shell temporary files.
        with tempfile.TemporaryDirectory(prefix='anytls-shell-args-',
                                         dir=os.environ['TMPDIR']) as temp:
            home = Path(temp)
            binary = home / 'bin'
            binary.mkdir()
            bootstrap = ROOT / 'install-control-helper.sh'
            entry_path = ROOT / entry
            if os.geteuid() == 0:
                for name in ('get.sh', 'install-control-helper.sh'):
                    source = (ROOT / name).read_text()
                    self.assertEqual(source.count(ROOT_GUARD), 1, 'root fixture guard drift')
                    (home / name).write_text(source.replace(
                        ROOT_GUARD, ': # SYNTHETIC_ROOT_GUARD: offline fixture only', 1))
                bootstrap = home / 'install-control-helper.sh'
                entry_path = home / entry
            programs = {
                'curl': CURL,
                'python3': PYTHON,
                'uname': "import sys; print('Darwin' if sys.argv[1:] == ['-s'] else 'x86_64')",
            }
            for name in ('sudo', 'ssh', 'scp', 'wget', 'go', 'launchctl'):
                programs[name] = 'raise AssertionError("forbidden offline command")'
            for name, body in programs.items():
                target = binary / name
                target.write_text('#!' + sys.executable + '\n' + body + '\n')
                target.chmod(0o700)
            env = {
                'HOME': temp, 'TMPDIR': temp, 'PATH': str(binary) + ':/usr/bin:/bin',
                'CALLS': str(home / 'calls.jsonl'), 'RESULT': str(home / 'result.json'),
                'BOOTSTRAP': str(bootstrap), 'RAW_PREFIX': RAW, 'API_PREFIX': API,
                'FAIL_RAW': json.dumps(fail_raw), 'FAIL_API': json.dumps(fail_api),
                'BAD_KEY': bad_key, 'BAD_BODY': bad_body, 'PYTHON_RC': str(python_rc),
                'PYTHON_FIXTURE': PYTHON_FIXTURE,
            }
            result = subprocess.run(['/bin/bash', str(entry_path), *args], env=env,
                                    capture_output=True, text=True, timeout=15)
            calls_path = home / 'calls.jsonl'
            calls = [json.loads(line) for line in calls_path.read_text().splitlines()] if calls_path.exists() else []
            output_path = home / 'result.json'
            output = json.loads(output_path.read_text()) if output_path.exists() else None
            self.assertFalse(list(home.glob('anytls-entry.*')), 'entry trap did not clean up')
            self.assertFalse(list((home / '.anytls').glob('binary-bootstrap.*')),
                             'bootstrap trap did not clean up')
            for call in calls:
                curl_args = call['args']
                for flag, value in (('--proto', '=https'), ('--connect-timeout', '20'),
                                    ('--max-time', '180')):
                    self.assertEqual(curl_args[curl_args.index(flag) + 1], value)
                self.assertIn('--fail', curl_args)
                self.assertIn('--tlsv1.2', curl_args)
                self.assertNotIn('--insecure', curl_args)
                if call['url'].startswith(API):
                    self.assertEqual(curl_args[curl_args.index('-H') + 1],
                                     'Accept: application/vnd.github.raw+json')
            print(json.dumps({'scenario': type(self).scenarios, 'entry': entry, 'args': list(args),
                              'fail_raw': list(fail_raw), 'fail_api': list(fail_api),
                              'bad_key': bad_key, 'bad_body': bad_body,
                              'returncode': result.returncode,
                              'received_args': output[2:] if output is not None else None,
                              'urls': [call['url'] for call in calls]}, ensure_ascii=True), flush=True)
            return result, calls, output

    def assert_forwarded(self, result, output, args, rc=0):
        self.assertEqual(result.returncode, rc, result.stderr)
        self.assertIsNotNone(output, result.stderr)
        self.assertEqual(output[0], '-I')
        self.assertTrue(output[1].endswith('/install-binary.py'))
        self.assertEqual(output[2:], list(args))

    def test_exact_arguments_through_both_entrypoints(self):
        variants = [[], ['--reload-core'], ['--no-reload-core'],
                    ['--no-reload-core', '--version', 'v1.2.3'], RELOAD_ARGS,
                    ['--webui-listen=0.0.0.0', '--version=v1.2.3', '--reload-core'],
                    RELOAD_ARGS + ['--app-dir', 'space dir/$literal;no-execution', '']]
        for entry in ('get.sh', 'install-control-helper.sh'):
            for args in variants:
                with self.subTest(entry=entry, args=args):
                    result, calls, output = self.invoke(args, entry=entry)
                    self.assert_forwarded(result, output, args)
                    keys = COMPONENTS if entry == 'get.sh' else COMPONENTS[1:]
                    self.assertEqual([c['url'] for c in calls], [RAW + k for k in keys])

    def test_each_official_api_fallback_preserves_reload_args(self):
        for key in COMPONENTS:
            with self.subTest(component=key):
                result, calls, output = self.invoke(RELOAD_ARGS, fail_raw=[key])
                self.assert_forwarded(result, output, RELOAD_ARGS)
                expected = []
                for component in COMPONENTS:
                    expected.append(RAW + component)
                    if component == key:
                        expected.append(API + key + '?ref=main')
                self.assertEqual([c['url'] for c in calls], expected)
                pair = [c for c in calls if c['url'] in (RAW + key, API + key + '?ref=main')]
                self.assertEqual(pair[0]['output'], pair[1]['output'])

    def test_all_official_fallbacks_with_reload_and_default_args(self):
        for args in (RELOAD_ARGS, []):
            with self.subTest(args=args):
                result, calls, output = self.invoke(args, fail_raw=COMPONENTS)
                self.assert_forwarded(result, output, args)
                self.assertEqual([c['url'] for c in calls],
                                 [url for k in COMPONENTS for url in (RAW + k, API + k + '?ref=main')])

    def test_both_transports_fail_before_recorder(self):
        for key in COMPONENTS:
            with self.subTest(component=key):
                result, calls, output = self.invoke(RELOAD_ARGS, fail_raw=[key], fail_api=[key])
                self.assertEqual(result.returncode, 22, result.stderr)
                self.assertIsNone(output)
                self.assertEqual(calls[-1]['url'], API + key + '?ref=main')

    def test_malformed_raw_and_api_responses_never_reach_recorder(self):
        for key in COMPONENTS:
            for use_api in (False, True):
                for body in ('', '<html>not a script</html>\n', '{"type":"file","content":"base64"}\n'):
                    with self.subTest(component=key, api=use_api, body=body):
                        result, calls, output = self.invoke(
                            RELOAD_ARGS, fail_raw=[key] if use_api else [],
                            bad_key=key, bad_body=body)
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIsNone(output)
                        self.assertIn('Invalid installer response', result.stderr)
                        self.assertEqual(calls[-1]['url'],
                                         API + key + '?ref=main' if use_api else RAW + key)

    def test_recorder_failure_exit_is_not_masked(self):
        result, _, output = self.invoke(RELOAD_ARGS, fail_raw=COMPONENTS, python_rc=17)
        self.assert_forwarded(result, output, RELOAD_ARGS, rc=17)


if __name__ == '__main__':
    unittest.main(verbosity=2)

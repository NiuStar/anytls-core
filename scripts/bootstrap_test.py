"""Bootstrap process tests: private HOME, stub transport/interpreter, no network/sudo."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent


class BootstrapTests(unittest.TestCase):
    def invoke(self, entry, extra=None):
        with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as temp:
            home = Path(temp)
            binary = home / 'bin'
            binary.mkdir()
            scripts = {
                'uname': "import sys;print('Darwin' if '-s' in sys.argv else 'x86_64')",
                'python3': "import os,sys,json\nif '-c' in sys.argv:sys.exit(int(os.environ.get('PROBE_RC','0')))\nopen(os.environ['RESULT'],'w').write(json.dumps({'args':sys.argv[1:],'ca':os.environ.get('SSL_CERT_FILE'),'dir':os.environ.get('SSL_CERT_DIR')}))",
                'curl': "import sys,os,shutil\na=sys.argv[1:];out=a[a.index('-o')+1]\nif out.endswith('/install.sh'):shutil.copyfile(os.environ['BOOTSTRAP'],out)\nelse:open(out,'w').write('# fixture only\\n')",
            }
            for name, code in scripts.items():
                target = binary / name
                target.write_text('#!' + sys.executable + '\n' + code + '\n')
                target.chmod(0o700)
            env = {'HOME': str(home), 'PATH': str(binary) + ':/usr/bin:/bin',
                   'TMPDIR': str(home), 'RESULT': str(home / 'result.json'),
                   'BOOTSTRAP': str(ROOT / 'install-control-helper.sh')}
            env.update(extra or {})
            p = subprocess.run(['/bin/bash', str(ROOT / entry), '--check-download', '--arch', 'amd64'],
                               env=env, capture_output=True, text=True, timeout=15)
            self.assertEqual(p.returncode, 0, p.stderr)
            data = json.loads((home / 'result.json').read_text())
            self.assertEqual(data['args'][-3:], ['--check-download', '--arch', 'amd64'])
            self.assertFalse(list(home.glob('anytls-entry.*')))
            self.assertFalse(list((home / '.anytls').glob('binary-bootstrap.*')))
            return data, p.stderr

    @unittest.skipUnless(Path('/etc/ssl/cert.pem').is_file(), 'needs macOS system PEM file')
    def test_missing_python_ca_uses_system_for_only_install(self):
        data, err = self.invoke('install-control-helper.sh')
        self.assertEqual(data['ca'], '/etc/ssl/cert.pem')
        self.assertIn('保持证书校验', err)

    def test_existing_python_ca_unchanged(self):
        data, _ = self.invoke('install-control-helper.sh', {'PROBE_RC': '1'})
        self.assertIsNone(data['ca'])

    def test_explicit_ca_is_preserved_even_if_bad(self):
        for value in ('/private/custom-ca.pem', ''):
            data, _ = self.invoke('install-control-helper.sh', {'SSL_CERT_FILE': value})
            self.assertEqual(data['ca'], value)

    def test_explicit_directory_is_preserved(self):
        data, _ = self.invoke('install-control-helper.sh', {'SSL_CERT_DIR': '/private/ca'})
        self.assertEqual(data['dir'], '/private/ca')
        self.assertIsNone(data['ca'])

    def test_short_entry_delegates_arguments_and_failure(self):
        data, _ = self.invoke('get.sh', {'PROBE_RC': '1'})
        self.assertIsNone(data['ca'])


if __name__ == '__main__':
    unittest.main()

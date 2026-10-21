#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
exec python3 - "$ROOT" "$@" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(sys.argv[1])
BASE = ROOT / 'artifacts/embedded-baseline/measurement-tooling'
if shutil.disk_usage(ROOT).free < 5 * 1024**3:
    raise SystemExit('tests require at least 5 GiB free')
BASE.mkdir(parents=True, exist_ok=True)
RUN = Path(tempfile.mkdtemp(prefix='quality-fix-fixtures-', dir=BASE))
SCRIPT = ROOT / 'scripts/measure-core.sh'

class MeasurementTests(unittest.TestCase):
    def setUp(self):
        self.work = Path(tempfile.mkdtemp(dir=RUN))
        self.binary = self.work / 'app'
        self.marker = self.work / 'EXECUTED'
        self.binary.write_text('#!/bin/sh\ntouch "' + str(self.marker) + '"\n')
        self.binary.chmod(0o700)
        self.output = self.work / 'output'

    def args(self):
        return ['sh', str(SCRIPT), '--group', 'A', '--output', str(self.output),
                '--app', str(self.binary), '--app-origin', 'official-release',
                '--app-revision', 'fixture-revision', '--app-toolchain', 'fixture-go',
                '--app-build-flags=UNKNOWN_RELEASE_FLAGS',
                '--app-goos', 'linux', '--app-goarch', 'amd64']

    def run_tool(self, extra=(), args=None):
        return subprocess.run((args or self.args()) + list(extra), cwd=self.work,
                              text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=15)

    def test_metadata_identity_without_execution(self):
        result = self.run_tool()
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads((self.output / 'metadata.json').read_text())
        app = data['artifacts']['app']
        self.assertEqual(app['sha256'], hashlib.sha256(self.binary.read_bytes()).hexdigest())
        self.assertEqual(app['bytes'], self.binary.stat().st_size)
        self.assertEqual(app['origin'], 'official-release')
        self.assertEqual(app['declared_target'], {'goos': 'linux', 'goarch': 'amd64'})
        self.assertEqual(app['go_version_m']['status'], 'NOT_MEASURED')
        self.assertEqual(data['host']['system'], platform.system())
        self.assertEqual(data['host']['machine'], platform.machine())
        self.assertEqual(data['resources']['cold_start_ms'], 'NOT_MEASURED')
        self.assertEqual(data['package_linkage']['status'], 'NOT_MEASURED')
        self.assertFalse(self.marker.exists(), 'input executable must never be run')

    def test_explicit_go_metadata(self):
        go = self.work / 'fixture-go'
        log = self.work / 'go-calls'
        go.write_text('#!/bin/sh\n'
                      'printf "%s\\n" "$*" >> "' + str(log) + '"\n'
                      'case "$1" in\n'
                      'version) if [ "$2" = "-m" ]; then\n'
                      'printf "fixture: go1.fixture\\n\\tbuild\\tGOOS=linux\\n\\tbuild\\tGOARCH=arm64\\n";\n'
                      'else printf "go version go1.fixture linux/amd64\\n"; fi ;;\n'
                      '*) exit 91 ;; esac\n')
        go.chmod(0o700)
        result = self.run_tool(['--go', str(go)])
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads((self.output / 'metadata.json').read_text())
        self.assertEqual(data['go_reader']['version']['status'], 'COLLECTED')
        self.assertEqual(data['artifacts']['app']['go_version_m']['status'], 'COLLECTED')
        self.assertEqual(data['artifacts']['app']['detected_target'], {'goos': 'linux', 'goarch': 'arm64'})
        self.assertEqual(log.read_text().splitlines(), ['version', 'version -m ' + str(self.binary)])
        self.assertFalse(self.marker.exists())

    def test_linkage_is_opt_in_offline_and_target_explicit(self):
        source = self.work / 'source'
        source.mkdir()
        go = self.work / 'fixture-go'
        log = self.work / 'deps-call.json'
        go.write_text('#!' + sys.executable + '\n'
                      'import json, os, sys\n'
                      'if sys.argv[1] == "list":\n'
                      ' json.dump({"argv": sys.argv[1:], "cwd": os.getcwd(), "env": dict(os.environ)}, open(' + repr(str(log)) + ', "w"))\n'
                      ' print("example/main\\nexample/dependency")\n'
                      'else: print("fixture Go metadata")\n')
        go.chmod(0o700)
        env = os.environ.copy()
        env['MEASUREMENT_SECRET'] = 'must-not-leak'
        args = self.args() + ['--go', str(go), '--list-deps', '--source-dir', str(source),
                             '--package', './cmd/fixture', '--deps-goos', 'linux',
                             '--deps-goarch', 'arm64', '--deps-tags', 'netgo,osusergo']
        result = subprocess.run(args, cwd=self.work, env=env, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        call = json.loads(log.read_text())
        self.assertEqual(call['cwd'], str(source))
        self.assertEqual(call['env']['GOPROXY'], 'off')
        self.assertEqual(call['env']['GOTOOLCHAIN'], 'local')
        self.assertEqual(call['env']['GOSUMDB'], 'off')
        self.assertEqual(call['env']['GOENV'], 'off')
        self.assertEqual(call['env']['GOOS'], 'linux')
        self.assertEqual(call['env']['GOARCH'], 'arm64')
        self.assertNotIn('MEASUREMENT_SECRET', call['env'])
        self.assertIn('-mod=readonly', call['argv'])
        self.assertIn('-deps', call['argv'])
        self.assertIn('-tags=netgo,osusergo', call['argv'])
        data = json.loads((self.output / 'metadata.json').read_text())
        self.assertEqual(data['package_linkage']['result']['status'], 'COLLECTED')
        self.assertEqual(data['package_linkage']['scope'], 'source_import_graph_not_binary_linkage_proof')
        self.assertNotIn('must-not-leak', (self.output / 'metadata.json').read_text())

    def test_missing_binary_leaves_no_partial(self):
        args = self.args()
        args[args.index('--app') + 1] = str(self.work / 'missing')
        result = self.run_tool(args=args)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('missing', result.stderr)
        self.assertFalse(self.output.exists())

    def test_non_executable_rejected(self):
        self.binary.chmod(0o600)
        self.assertNotEqual(self.run_tool().returncode, 0)
        self.assertFalse(self.output.exists())

    def test_duplicate_and_partial_outputs_refused_unchanged(self):
        self.assertEqual(self.run_tool().returncode, 0)
        original = (self.output / 'metadata.json').read_bytes()
        self.assertNotEqual(self.run_tool().returncode, 0)
        self.assertEqual((self.output / 'metadata.json').read_bytes(), original)
        partial = self.work / 'partial'
        partial.mkdir()
        marker = partial / 'metadata.json.partial'
        marker.write_text('incomplete evidence')
        args = self.args()
        args[args.index('--output') + 1] = str(partial)
        result = self.run_tool(args=args)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('already exists', result.stderr)
        self.assertEqual(marker.read_text(), 'incomplete evidence')
        self.assertEqual(list(partial.iterdir()), [marker])

    def test_output_symlink_refused(self):
        self.output.symlink_to(self.work / 'not-yet-present')
        result = self.run_tool()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('already exists', result.stderr)
        self.assertFalse((self.work / 'not-yet-present').exists())

    def instrumented(self, setup):
        # Run exactly the embedded Python program, with a test-only audit/FS shim.
        code = SCRIPT.read_text().split("<<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
        wrapper = setup + '\nexec(compile(' + repr(code) + ', "measure-core.sh", "exec"))'
        return subprocess.run([sys.executable, '-c', wrapper] + self.args()[2:], cwd=self.work,
                              capture_output=True, text=True, timeout=15)

    def test_disk_floor_before_output_creation(self):
        setup = ('import shutil\nfrom collections import namedtuple\n'
                 'shutil.disk_usage = lambda path: namedtuple("usage", "total used free")(10*1024**3, 6*1024**3, 5*1024**3-1)')
        result = self.instrumented(setup)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('at least 5 GiB', result.stderr)
        self.assertFalse(self.output.exists())
        result = self.instrumented(setup.replace('5*1024**3-1', '5*1024**3'))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_default_does_not_read_source_config_or_environment(self):
        secret = self.work / 'config.yaml'
        secret.write_text('credential: MUST_NOT_APPEAR')
        source = self.work / 'main.go'
        source.write_text('MUST_NOT_READ_SOURCE')
        setup = ('import sys, os\n'
                 'os.environ["SECRET_TOKEN"] = "MUST_NOT_APPEAR"\n'
                 'def audit(event, args):\n'
                 ' if event == "open" and str(args[0]) in ' + repr([str(secret), str(source)]) + ':\n'
                 '  raise RuntimeError("forbidden config/source read")\n'
                 ' if event in ("os.listdir", "os.scandir") and str(args[0]).startswith(' + repr(str(self.work)) + '):\n'
                 '  raise RuntimeError("no fixture directory traversal in default mode")\n'
                 ' if event == "subprocess.Popen":\n'
                 '  raise RuntimeError("no subprocess in default mode")\n'
                 'sys.addaudithook(audit)')
        result = self.instrumented(setup)
        self.assertEqual(result.returncode, 0, result.stderr)
        text = (self.output / 'metadata.json').read_text()
        self.assertNotIn('MUST_NOT', text)
        self.assertNotIn('SECRET_TOKEN', text)

    def test_core_is_separate_from_reconstructed_app(self):
        core = self.work / 'core'
        core.write_bytes(b'fixture external core, not a benchmark')
        core.chmod(0o700)
        args = self.args()
        args[args.index('--app-origin') + 1] = 'reconstructed-app'
        result = self.run_tool(['--core', str(core), '--core-origin', 'external-core',
                                '--core-revision', 'core-revision', '--core-toolchain', 'core-go',
                                '--core-build-flags=UNKNOWN_RELEASE_FLAGS',
                                '--core-goos', 'linux', '--core-goarch', 'arm64'], args=args)
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads((self.output / 'metadata.json').read_text())
        self.assertEqual(data['artifacts']['app']['origin'], 'reconstructed-app')
        self.assertEqual(data['artifacts']['core']['origin'], 'external-core')
        self.assertEqual(data['artifacts']['core']['sha256'], hashlib.sha256(core.read_bytes()).hexdigest())
        self.assertNotEqual(data['artifacts']['core']['sha256'], data['artifacts']['app']['sha256'])

    def test_dependencies_cannot_be_requested_implicitly(self):
        for extra in (['--source-dir', '/does-not-exist'], ['--list-deps'], ['--goos', 'linux']):
            with self.subTest(extra=extra):
                self.assertNotEqual(self.run_tool(extra).returncode, 0)
                self.assertFalse(self.output.exists())

    def test_go_failure_timeout_and_output_limit_are_not_measurements(self):
        go = self.work / 'fixture-go'
        for body, status in [('exit 7', 'FAILED'), ('sleep 10', 'TIMEOUT'),
                             ('exec ' + sys.executable + ' -c "import sys; sys.stdout.write(\'x\'*3000000)"', 'OUTPUT_LIMIT')]:
            with self.subTest(status=status):
                go.write_text('#!/bin/sh\n' + body + '\n')
                go.chmod(0o700)
                self.output = self.work / status
                result = self.run_tool(['--go', str(go), '--timeout-seconds', '0.3'])
                self.assertEqual(result.returncode, 0, result.stderr)
                data = json.loads((self.output / 'metadata.json').read_text())
                self.assertEqual(data['go_reader']['version']['status'], status)
                self.assertEqual(data['artifacts']['app']['go_version_m']['status'], status)
                self.assertEqual(data['artifacts']['app']['detected_target'], 'NOT_MEASURED')
                self.assertEqual(data['resources']['rss_bytes'], 'NOT_MEASURED')

    def test_actual_elf_target_is_not_declared_target(self):
        header = bytearray(64)
        header[:6] = b'\x7fELF\x02\x01'
        header[7] = 3  # Explicit Linux ELF OSABI, not generic System V.
        header[18:20] = (183).to_bytes(2, 'little')  # AArch64
        self.binary.write_bytes(header)
        result = self.run_tool()
        self.assertEqual(result.returncode, 0, result.stderr)
        app = json.loads((self.output / 'metadata.json').read_text())['artifacts']['app']
        self.assertEqual(app['detected_target'], {'goos': 'linux', 'goarch': 'arm64'})
        self.assertEqual(app['target_evidence'], 'ELF_header')
        self.assertEqual(app['declared_target']['goarch'], 'amd64')
        self.assertEqual(app['target_matches_declared'], False)

    def test_riscv64_header_requires_elfclass64(self):
        # Synthetic header-only fixtures, not real RISC-V executables or benchmarks.
        for elf_class, arch, matches in [(1, 'NOT_MEASURED', 'NOT_MEASURED'),
                                          (2, 'riscv64', True),
                                          (0, 'NOT_MEASURED', 'NOT_MEASURED'),
                                          (3, 'NOT_MEASURED', 'NOT_MEASURED')]:
            with self.subTest(elf_class=elf_class):
                header = bytearray(64)
                header[:6] = b'\x7fELF' + bytes([elf_class, 1])
                header[7] = 3  # Explicit Linux OSABI so only arch remains unknown.
                header[18:20] = (243).to_bytes(2, 'little')  # EM_RISCV
                self.binary.write_bytes(header)
                self.output = self.work / ('elf-class-' + str(elf_class))
                args = self.args()
                args[args.index('--app-goarch') + 1] = 'riscv64'
                result = self.run_tool(args=args)
                self.assertEqual(result.returncode, 0, result.stderr)
                app = json.loads((self.output / 'metadata.json').read_text())['artifacts']['app']
                self.assertEqual(app['detected_target'], {'goos': 'linux', 'goarch': arch})
                self.assertEqual(app['target_evidence'], 'ELF_header')
                self.assertEqual(app['declared_target'], {'goos': 'linux', 'goarch': 'riscv64'})
                self.assertEqual(app['target_matches_declared'], matches)
                self.assertEqual(app['go_version_m']['status'], 'NOT_MEASURED')

if __name__ == '__main__':
    print('fixture evidence:', RUN, flush=True)
    unittest.main(argv=[sys.argv[0]] + sys.argv[2:], verbosity=2)
PY

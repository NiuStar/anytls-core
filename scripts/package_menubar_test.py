"""Linux-portable fixture tests; no native qualification is claimed by this suite."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import plistlib
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile

spec = importlib.util.spec_from_file_location('menubar_packager', Path(__file__).with_name('package-menubar.py'))
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
TAG = 'v2026-11-07-02'


class DiagnosticTests(unittest.TestCase):
    def exercise(self, stdout, reason, *, rc=0, timeout=False, actual=None, label=None, summary_kind='file'):
        with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as tmp:
            root = Path(tmp)
            summary = root / 'summary'
            summary.write_text('existing\n')
            if summary_kind == 'symlink':
                link = root / 'link'
                link.symlink_to(summary)
                summary_env = str(link)
            else:
                summary_env = str(summary)
            captured, annotations = io.StringIO(), io.StringIO()
            error = subprocess.TimeoutExpired('fixture', 90, output=stdout.encode(), stderr=b'secret stderr /private/path')
            result = subprocess.CompletedProcess([], rc, stdout, 'secret stderr /private/path')
            with mock.patch.dict(os.environ, dict(GITHUB_ACTIONS='true', GITHUB_STEP_SUMMARY=summary_env)), \
                 mock.patch.object(p.subprocess, 'run', side_effect=error if timeout else None, return_value=result) as run, \
                 mock.patch('sys.stdout', captured), mock.patch('sys.stderr', annotations):
                with self.assertRaises(RuntimeError if rc or timeout else ValueError) as raised:
                    p.run_tests(root / 'binaries', root / 'evidence')
            self.assertEqual(run.call_count, 1)
            self.assertEqual(run.call_args.kwargs['timeout'], 90)
            if rc:
                self.assertEqual(str(raised.exception), 'AnyTLSMenuBarTests failed: ' + str(rc))
            if timeout:
                self.assertIs(raised.exception.__cause__, error)
            self.assertEqual((root / 'evidence/AnyTLSMenuBarTests.stdout').read_bytes(), stdout.encode())
            self.assertEqual((root / 'evidence/AnyTLSMenuBarTests.stderr').read_bytes(), b'secret stderr /private/path')
            annotation = annotations.getvalue()
            self.assertIn('::error::AnyTLSMenuBarTests reason=' + reason + ' expected=' + str(p.SUITES['AnyTLSMenuBarTests']) + ' actual=' + (str(actual) if actual is not None else 'unknown'), annotation)
            self.assertNotIn('secret stderr', annotation)
            self.assertNotIn('/private/path', annotation)
            if label:
                self.assertIn('label=' + label, annotation)
            text = summary.read_text()
            if summary_kind == 'symlink':
                self.assertEqual(text, 'existing\n')
            else:
                self.assertIn(reason, text)
                self.assertNotIn('secret stderr', text)
                self.assertNotIn('/private/path', text)
            return annotation, text

    def test_nonzero_fail_label_preserves_rc_and_raw_output(self):
        self.exercise('FAIL: first assertion 50%\nFAIL later\n', 'nonzero', rc=7, label='first assertion 50%25')

    def test_timeout_retains_output_and_cause(self):
        self.exercise('FAIL timed assertion\n', 'timeout', timeout=True, label='timed assertion')

    def test_count_mismatch_fails_fast(self):
        self.exercise(json.dumps(dict(status='PASS', checks=['one'])), 'count', actual=1)

    def test_malformed_json_fails_fast_without_payload_leak(self):
        annotation, text = self.exercise('{"private": "sensitive-json"', 'json')
        self.assertNotIn('sensitive-json', annotation + text)

    def test_inventory_failure_fails_fast(self):
        self.exercise(json.dumps(dict(status='FAIL', checks=[])), 'inventory')

    def test_sensitive_labels_redacted_before_truncation(self):
        for key in ('password', 'TOKEN', 'secret', 'credential', 'api_token'):
            annotation, text = self.exercise('FAIL: ' + 'x' * 220 + key + '=sensitive-value\n', 'nonzero', rc=1, label='[redacted]')
            self.assertNotIn('sensitive-value', annotation + text)

    def test_label_bounded_controls_removed(self):
        annotation, text = self.exercise('FAIL: a\x1bb' + 'x' * 300 + '\n', 'nonzero', rc=1)
        self.assertNotIn('\x1b', annotation + text)
        self.assertEqual(len(annotation.split('label=')[1].rstrip('\n')), 200)

    def test_local_failure_has_no_annotation_or_summary(self):
        with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as tmp:
            result = subprocess.CompletedProcess([], 3, 'FAIL: local assertion\n', 'raw stderr\n')
            stdout, stderr = io.StringIO(), io.StringIO()
            with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(p.subprocess, 'run', return_value=result), mock.patch('sys.stdout', stdout), mock.patch('sys.stderr', stderr):
                with self.assertRaisesRegex(RuntimeError, 'failed: 3'):
                    p.run_tests(Path(tmp) / 'test', Path(tmp) / 'evidence')
            self.assertEqual(stdout.getvalue(), result.stdout + result.stderr)
            self.assertEqual(stderr.getvalue(), '')

    def test_symlink_summary_not_followed(self):
        self.exercise('FAIL: assertion\n', 'nonzero', rc=1, summary_kind='symlink')


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ['TMPDIR'])
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.app = self.root / 'build/AnyTLSMenuBar.app'
        self.out = self.root / 'dist'
        self.out.mkdir()
        self.prefix = 'anytls-core-' + TAG
        for name in p.APP_SOURCES:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(TAG if name == 'VERSION' else 'fixture source ' + name)
        for command in (['git', 'init', '-q'], ['git', 'add', *p.APP_SOURCES],
                        ['git', '-c', 'user.email=fixture@example.invalid', '-c', 'user.name=Fixture', 'commit', '-qm', 'fixture']):
            subprocess.run(command, cwd=self.root, check=True, capture_output=True)
        source = self.out / (self.prefix + '-source.tar.gz')
        with source.open('wb') as stream:
            subprocess.run(['git', 'archive', '--format=tar.gz', '--prefix=' + self.prefix + '/', 'HEAD'], cwd=self.root, stdout=stream, check=True)
        with tarfile.open(self.out / (self.prefix + '-corresponding-source.tar.gz'), 'w:gz') as archive:
            archive.add(source, arcname=self.prefix + '/application-source.tar.gz')
        self.binary_archive = self.out / (self.prefix + '-darwin-arm64.tar.gz')
        with tarfile.open(self.binary_archive, 'w:gz') as archive:
            for name in ('LICENSE', 'THIRD_PARTY_NOTICES.md', 'licenses/module/LICENSE'):
                data = ('fixture license ' + name).encode()
                member = tarfile.TarInfo(self.prefix + '-darwin-arm64/' + name)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
            commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=self.root, text=True).strip()
            data = json.dumps(dict(source_commit=commit, platform='darwin-arm64', corresponding_source=self.prefix + '-corresponding-source.tar.gz', binary_sha256='a' * 64)).encode()
            member = tarfile.TarInfo(self.prefix + '-darwin-arm64/BUILD-INFO.json')
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
        self.reset_sums()
        for name in ('Contents/MacOS/AnyTLSMenuBar', 'Contents/Resources/runtime/anytls-macos'):
            path = self.app / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'fixture executable, NOT a native binary')
            path.chmod(0o755)
        self.info = dict(CFBundleIdentifier='org.anytls.menubar.candidate', CFBundleExecutable='AnyTLSMenuBar',
                         CFBundlePackageType='APPL', CFBundleShortVersionString='0.5.2',
                         CFBundleVersion='0.5.2.20261110.1', AnyTLSCoreVersion=TAG,
                         LSMinimumSystemVersion='13.0', LSUIElement=True)
        self.write_info()
        self.runtime = self.app / 'Contents/Resources/runtime/anytls-macos'
        self.manifest = self.app / 'Contents/Resources/runtime/manifest.json'
        self.manifest.write_text(json.dumps(dict(schema=1, binary='anytls-macos', arch='arm64', version=TAG, sha256=p.sha(self.runtime))))
        self.real_run = subprocess.run
        self.native_calls = []

    def reset_sums(self):
        self.names = {path.name for path in self.out.glob('*.tar.gz')}
        (self.out / 'SHA256SUMS').write_text(''.join(p.sha(self.out / name) + '  ' + name + '\n' for name in sorted(self.names)))

    def write_info(self):
        (self.app / 'Contents/Info.plist').write_bytes(plistlib.dumps(self.info))

    def native_output(self, args, **kwargs):
        if args[0] == '/usr/bin/uname':
            return 'Darwin' if args[1] == '-s' else 'arm64'
        if args[0] == '/usr/bin/lipo':
            return 'arm64'
        if args[-1] == '-version':
            return 'AnyTLS ' + TAG
        return self.real_run(args, check=True, capture_output=True, text=True, **kwargs).stdout.strip()

    def native_run(self, args, **kwargs):
        self.native_calls.append(args)
        if args[0] == '/usr/bin/codesign':
            return subprocess.CompletedProcess(args, 0)
        if args[:3] == ['/usr/bin/ditto', '-c', '-k']:
            app, target = Path(args[-2]), Path(args[-1])
            with zipfile.ZipFile(target, 'w') as archive:
                for path in app.rglob('*'):
                    if path.is_file():
                        archive.write(path, str(Path(app.name) / path.relative_to(app)))
            return subprocess.CompletedProcess(args, 0)
        if args[:3] == ['/usr/bin/ditto', '-x', '-k']:
            with zipfile.ZipFile(args[-2]) as archive:
                archive.extractall(args[-1])
                for member in archive.infolist():
                    (Path(args[-1]) / member.filename).chmod(member.external_attr >> 16 & 0o777)
            return subprocess.CompletedProcess(args, 0)
        raise AssertionError(args)

    def invoke(self):
        with mock.patch.object(p, 'output', side_effect=self.native_output), mock.patch.object(p.subprocess, 'run', side_effect=self.native_run):
            return p.package(self.root, self.app, self.out, TAG)

    def test_package_preserves_bundle_and_core_hashes_and_licenses(self):
        old = (self.out / 'SHA256SUMS').read_text().splitlines()
        result = self.invoke()
        self.assertEqual(result['asset'], self.prefix + '-menubar-darwin-arm64.zip')
        rows = (self.out / 'SHA256SUMS').read_text().splitlines()
        self.assertEqual(len(rows), 4)
        self.assertTrue(set(old) <= set(rows))
        self.assertEqual(rows, sorted(rows, key=lambda row: row.split('  ')[1]))
        with zipfile.ZipFile(self.out / result['asset']) as archive:
            self.assertEqual(archive.read('AnyTLSMenuBar.app/Contents/Resources/runtime/anytls-macos'), self.runtime.read_bytes())
            self.assertEqual(archive.read('licenses/module/LICENSE'), b'fixture license licenses/module/LICENSE')
            info = json.loads(archive.read('BUILD-INFO.json'))
            self.assertEqual(info['core_version'], TAG)
            self.assertEqual(info['signed_runtime_sha256'], p.sha(self.runtime))
            self.assertEqual(info['corresponding_source'], self.prefix + '-corresponding-source.tar.gz')
            self.assertIn(TAG.encode(), archive.read('SOURCE-LOCATION.txt'))
            self.assertIn(b'NOT Developer ID signed or notarized', archive.read('README.txt'))
        self.assertEqual(sum(args[0] == '/usr/bin/codesign' for args in self.native_calls), 6)

    def test_amd64_package_uses_native_intel_payload_and_source(self):
        source = self.out / (self.prefix + '-corresponding-source.tar.gz')
        source.rename(self.out / (self.prefix + '-darwin-amd64-corresponding-source.tar.gz'))
        old_archive = self.binary_archive
        self.binary_archive = self.out / (self.prefix + '-darwin-amd64.tar.gz')
        with tarfile.open(old_archive, 'r:gz') as old, tarfile.open(self.binary_archive, 'w:gz') as new:
            for member in old.getmembers():
                data = old.extractfile(member).read()
                member.name = member.name.replace('-darwin-arm64/', '-darwin-amd64/')
                if member.name.endswith('/BUILD-INFO.json'):
                    info = json.loads(data)
                    info.update(platform='darwin-amd64', corresponding_source=source.name.replace('-corresponding-source', '-darwin-amd64-corresponding-source'))
                    data = json.dumps(info).encode()
                member.size = len(data)
                new.addfile(member, io.BytesIO(data))
        old_archive.unlink()
        self.reset_sums()
        manifest = json.loads(self.manifest.read_text())
        manifest['arch'] = 'amd64'
        self.manifest.write_text(json.dumps(manifest))
        original = self.native_output
        def intel(args, **kwargs):
            if args == ['/usr/bin/uname', '-m'] or args[0] == '/usr/bin/lipo':
                return 'x86_64'
            return original(args, **kwargs)
        with mock.patch.object(p, 'output', side_effect=intel), mock.patch.object(p.subprocess, 'run', side_effect=self.native_run):
            result = p.package(self.root, self.app, self.out, TAG, arch='amd64')
        self.assertEqual(result['asset'], self.prefix + '-menubar-darwin-amd64.zip')
        self.assertEqual(len((self.out / 'SHA256SUMS').read_text().splitlines()), 4)
        with zipfile.ZipFile(self.out / result['asset']) as archive:
            info = json.loads(archive.read('BUILD-INFO.json'))
            self.assertEqual(info['architecture'], 'amd64')
            self.assertEqual(info['app_version'], '0.5.2')
            self.assertEqual(info['app_build'], '0.5.2.20261110.1')
            self.assertEqual(info['corresponding_source'], self.prefix + '-darwin-amd64-corresponding-source.tar.gz')
            self.assertIn(b'Intel x86_64 ONLY', archive.read('README.txt'))

    def test_invalid_arch_rejected_before_any_native_call(self):
        for arch in ('x86_64', 'ARM64', 'universal', '', 'amd64;id', None):
            with self.subTest(arch=arch), mock.patch.object(p, 'output') as native:
                with self.assertRaisesRegex(ValueError, 'architecture'):
                    p.package(self.root, self.app, self.out, TAG, arch=arch)
                native.assert_not_called()

    def test_payload_fat_foreign_and_mixed_rejected_before_runtime_execution(self):
        original = self.native_output
        for machine in ('arm64 x86_64', 'x86_64'):
            for suffix in ('/anytls-macos', '/AnyTLSMenuBar'):
                calls = []
                def bad(args, **kwargs):
                    calls.append(args)
                    if args[0] == '/usr/bin/lipo' and args[-1].endswith(suffix):
                        return machine
                    return original(args, **kwargs)
                with self.subTest(machine=machine, suffix=suffix), mock.patch.object(p, 'output', side_effect=bad), mock.patch.object(p.subprocess, 'run', side_effect=self.native_run):
                    with self.assertRaisesRegex(ValueError, 'arm64 only'):
                        p.verify_app(self.app, TAG, arch='arm64')
                self.assertFalse(any(args[-1] == '-version' for args in calls))

    def test_manifest_arch_is_canonical_and_checked_before_runtime_execution(self):
        for arch in ('amd64', 'x86_64', 'arm64 x86_64'):
            data = json.loads(self.manifest.read_text())
            data['arch'] = arch
            self.manifest.write_text(json.dumps(data))
            with self.subTest(arch=arch), self.assertRaisesRegex(ValueError, 'manifest'):
                self.invoke()

    def test_build_rejects_invalid_args_before_uname_and_host_before_core(self):
        script = Path(__file__).with_name('build-menubar.sh').resolve()
        tools = self.root / 'mock-tools'
        tools.mkdir()
        marker = self.root / 'uname-called'
        uname = tools / 'uname'
        uname.write_text('#!/bin/bash\nprintf called >> "$UNAME_MARKER"\nif [ "$1" = -s ]; then printf Darwin; else printf "%s" "$MOCK_MACHINE"; fi\n')
        uname.chmod(0o755)
        env = dict(os.environ, PATH=str(tools) + os.pathsep + os.environ['PATH'],
                   UNAME_MARKER=str(marker), MOCK_MACHINE='arm64')
        env.pop('CORE', None)
        for args in (['x86_64'], [''], ['arm64', 'unused', 'extra']):
            result = self.real_run(['bash', str(script), *args], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertFalse(marker.exists(), result.stderr)
        for arch, host in (('amd64', 'arm64'), ('arm64', 'x86_64')):
            result = self.real_run(['bash', str(script), arch], env=dict(env, MOCK_MACHINE=host), capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn('host required', result.stderr)
            self.assertNotIn('Set CORE', result.stderr)

    def test_intel_verifier_rejects_wrong_host_payload_and_manifest(self):
        original = self.native_output
        data = json.loads(self.manifest.read_text())
        data['arch'] = 'amd64'
        self.manifest.write_text(json.dumps(data))
        for fault in ('host', 'core', 'ui', 'fat', 'manifest'):
            calls = []
            def intel(args, **kwargs):
                calls.append(args)
                if args == ['/usr/bin/uname', '-m']:
                    return 'arm64' if fault == 'host' else 'x86_64'
                if args[0] == '/usr/bin/lipo':
                    if fault == 'fat':
                        return 'x86_64 arm64'
                    if (fault == 'core' and args[-1].endswith('/anytls-macos')) or (fault == 'ui' and args[-1].endswith('/AnyTLSMenuBar')):
                        return 'arm64'
                    return 'x86_64'
                return original(args, **kwargs)
            data['arch'] = 'x86_64' if fault == 'manifest' else 'amd64'
            self.manifest.write_text(json.dumps(data))
            with self.subTest(fault=fault), mock.patch.object(p, 'output', side_effect=intel), mock.patch.object(p.subprocess, 'run', side_effect=self.native_run):
                with self.assertRaises(ValueError):
                    p.verify_app(self.app, TAG, arch='amd64')
            self.assertFalse(any(args[-1] == '-version' for args in calls))

    def test_build_contract_has_explicit_targets_and_native_host_fence(self):
        script = Path(__file__).with_name('build-menubar.sh').read_text()
        self.assertIn('amd64) MACHINE=x86_64', script)
        self.assertIn('-target "$MACHINE-apple-macosx13.0"', script)
        self.assertEqual(script.count('-target "$MACHINE-apple-macosx13.0"'), 5)
        self.assertLess(script.index('uname -m'), script.index('CORE_VERSION='))
        self.assertIn('"$CORE" -verify_arch "$MACHINE"', script)
        self.assertLess(script.index('codesign --force --sign - "$APP/Contents/Resources/runtime/anytls-macos"'), script.index('runtime/"manifest.json"'))
        self.assertLess(script.index('runtime/"manifest.json"'), script.index('codesign --force --sign - "$APP"'))

    def test_malformed_tag_rejected_before_native_calls(self):
        for tag in ('v2026-11-07-01/../../x', 'candidate', TAG + '\n', 'v1.2.3;id'):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                p.package(self.root, self.app, self.out, tag)

    def test_metadata_fail_closed(self):
        for key, value in (('AnyTLSCoreVersion', 'old'), ('LSUIElement', False), ('LSMinimumSystemVersion', '12.0'), ('CFBundleVersion', '0.3.0')):
            with self.subTest(key=key):
                old = self.info[key]
                self.info[key] = value
                self.write_info()
                with self.assertRaisesRegex(ValueError, 'metadata'):
                    self.invoke()
                self.info[key] = old
        self.write_info()

    def test_manifest_and_runtime_version_fail_closed(self):
        data = json.loads(self.manifest.read_text())
        data['sha256'] = '0' * 64
        self.manifest.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, 'manifest'):
            self.invoke()

    def test_architecture_and_codesign_are_mandatory(self):
        original = self.native_output
        def intel(args, **kwargs):
            return 'x86_64' if args[0] == '/usr/bin/lipo' else original(args, **kwargs)
        self.native_output = intel
        with self.assertRaisesRegex(ValueError, 'arm64 only'):
            self.invoke()
        self.native_output = original
        with mock.patch.object(p, 'output', side_effect=self.native_output), mock.patch.object(p.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, 'codesign')):
            with self.assertRaises(subprocess.CalledProcessError):
                p.package(self.root, self.app, self.out, TAG)

    def test_source_closure_rejects_untracked_required_input(self):
        subprocess.run(['git', 'rm', '--cached', '-q', 'macos/FocusTests.swift'], cwd=self.root, check=True)
        with self.assertRaisesRegex(ValueError, 'tracked'):
            p.check_sources(self.root, self.out, TAG)

    def test_source_closure_rejects_missing_or_changed_swift(self):
        (self.root / 'macos/main.swift').write_text('changed after archive')
        with self.assertRaisesRegex(ValueError, 'bytes mismatch'):
            p.check_sources(self.root, self.out, TAG)

    def test_source_closure_rejects_wrong_nested_application_archive(self):
        with tarfile.open(self.out / (self.prefix + '-corresponding-source.tar.gz'), 'w:gz') as archive:
            data = b'wrong source'
            member = tarfile.TarInfo(self.prefix + '/application-source.tar.gz')
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
        with self.assertRaisesRegex(ValueError, 'exact app source'):
            p.check_sources(self.root, self.out, TAG)

    def test_manifest_refuses_duplicate_missing_tampered_and_extra_assets(self):
        manifest = self.out / 'SHA256SUMS'
        original = manifest.read_text()
        for text in (original + original.splitlines()[0] + '\n', '\n'.join(original.splitlines()[1:]) + '\n', original.replace(original[:64], '0' * 64, 1)):
            with self.subTest(text=text):
                manifest.write_text(text)
                with self.assertRaises(ValueError):
                    self.invoke()
        manifest.write_text(original)
        (self.out / 'extra.zip').write_bytes(b'bad')
        with self.assertRaisesRegex(ValueError, 'exactly'):
            self.invoke()

    def test_symlink_bundle_is_rejected(self):
        (self.app / 'Contents/alias').symlink_to('Info.plist')
        with self.assertRaisesRegex(ValueError, 'bundle entry'):
            self.invoke()

    def test_native_suite_runner_preserves_raw_and_checks_named_inventories(self):
        evidence = self.root / 'evidence'
        calls = []
        def fixture(args, **kwargs):
            name = Path(args[0]).name
            calls.append(args)
            n = p.SUITES[name]
            checks = ['fixture assertion'] * n
            if name in ('AnyTLSMenuBarTests', 'QuitTests'):
                stdout = json.dumps(dict(status='PASS', checks=checks))
            else:
                stdout = '\n'.join('PASS: ' + check for check in checks) + '\n'
                marker = {'ConnectivityTests': 'CONNECTIVITY_TESTS_PASS assertions=', 'FocusTests': 'FOCUS_TESTS_OK checks=', 'DesktopRuntimeTests': 'DESKTOP_TESTS_OK checks='}[name]
                stdout += marker + str(n) + '\n'
                if len(args) == 2:
                    root = Path(args[1])
                    root.mkdir()
                    filename = 'focus-checks.json' if name == 'FocusTests' else 'desktop-checks.json'
                    (root / filename).write_text(json.dumps(dict(count=n, checks=checks)))
            return subprocess.CompletedProcess(args, 0, stdout, '')
        captured, annotations = io.StringIO(), io.StringIO()
        with mock.patch.object(p.subprocess, 'run', side_effect=fixture), mock.patch('sys.stdout', captured), mock.patch('sys.stderr', annotations):
            self.assertEqual(p.run_tests(self.root / 'test', evidence), p.SUITES)
        self.assertEqual(annotations.getvalue(), '')
        self.assertEqual(captured.getvalue(), ''.join((evidence / (name + '.stdout')).read_text() for name in p.SUITES))
        self.assertEqual(p.SUITES, {'AnyTLSMenuBarTests': 529, 'QuitTests': 250,
                                    'ConnectivityTests': 61, 'FocusTests': 125,
                                    'DesktopRuntimeTests': 212})
        self.assertEqual(sum(p.SUITES.values()), 1177)
        self.assertEqual([Path(args[0]).name for args in calls], list(p.SUITES))
        self.assertEqual([len(args) for args in calls], [1, 1, 1, 2, 2])
        self.assertTrue((evidence / 'native-suites.json').is_file())
        for name in p.SUITES:
            self.assertTrue((evidence / (name + '.stdout')).is_file())

    def test_workflow_contract_and_real_manifest_merge(self):
        repo = Path(__file__).resolve().parents[1]
        ci = (repo / '.github/workflows/ci.yml').read_text()
        workflow = (repo / '.github/workflows/binary-release.yml').read_text()
        self.assertIn('os: [ubuntu-latest, macos-15, macos-15-intel]', ci)
        self.assertEqual(ci.count("runner.os == 'macOS'"), 3)
        self.assertIn('x86_64) app_arch=amd64', ci)
        self.assertIn('CORE="$PWD/dist/anytls-macos" bash scripts/build-menubar.sh "$app_arch"', ci)
        self.assertIn('--run-tests build/menubar/test --evidence', ci)
        self.assertNotIn("if: matrix.arch == 'arm64'", workflow)
        self.assertIn('if: always()', workflow)
        self.assertIn('CORE="$PWD/build/anytls-macos" bash scripts/build-menubar.sh "$GOARCH"', workflow)
        self.assertIn('--arch "$GOARCH" --app build/menubar/AnyTLSMenuBar.app --out dist --tag "$TAG"', workflow)
        self.assertIn('python3 -m unittest discover', workflow)
        self.assertLess(workflow.index('scripts/release_ci_gate.py'), workflow.index('gh release upload'))
        section = workflow.split('- name: Verify both manifests and merge exactly seven archives', 1)[1].split('      - name:', 1)[0]
        code = section.split("          python3 - <<'PY'\n", 1)[1].rsplit('          PY', 1)[0]
        code = '\n'.join(line[10:] for line in code.splitlines())
        work = self.root / 'merge-fixture'
        work.mkdir()
        common = self.prefix + '-source.tar.gz'
        expected = {
            'arm64': {common, self.prefix + '-darwin-arm64.tar.gz', self.prefix + '-corresponding-source.tar.gz', self.prefix + '-menubar-darwin-arm64.zip'},
            'amd64': {common, self.prefix + '-darwin-amd64.tar.gz', self.prefix + '-darwin-amd64-corresponding-source.tar.gz', self.prefix + '-menubar-darwin-amd64.zip'},
        }
        for arch, names in expected.items():
            root = work / 'incoming' / arch
            root.mkdir(parents=True)
            for name in names:
                (root / name).write_text('fixture bytes ' + name)
            (root / 'SHA256SUMS').write_text(''.join(p.sha(root / name) + '  ' + name + '\n' for name in sorted(names)))
        env = dict(os.environ, TAG=TAG)
        result = subprocess.run([os.sys.executable, '-c', code], cwd=work, env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual({path.name for path in (work / 'dist').iterdir()}, set.union(*expected.values()) | {'SHA256SUMS'})
        self.assertEqual(len((work / 'dist/SHA256SUMS').read_text().splitlines()), 7)
        (work / 'incoming/arm64' / (self.prefix + '-menubar-darwin-arm64.zip')).write_text('tampered')
        result = subprocess.run([os.sys.executable, '-c', code], cwd=work, env=env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('digest mismatch', result.stderr)

    def test_native_timeout_retains_output_and_blocks(self):
        evidence = self.root / 'timeout-evidence'
        error = subprocess.TimeoutExpired('fixture', 90, output=b'before hang', stderr=b'fixture timeout')
        with mock.patch.object(p.subprocess, 'run', side_effect=error):
            with self.assertRaisesRegex(RuntimeError, 'timed out'):
                p.run_tests(self.root / 'test', evidence)
        self.assertEqual((evidence / 'AnyTLSMenuBarTests.stdout').read_bytes(), b'before hang')

    def test_success_exit_without_assertions_is_rejected(self):
        with mock.patch.object(p.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, json.dumps(dict(status='PASS', checks=[])), '')):
            with self.assertRaisesRegex(ValueError, 'assertion count'):
                p.run_tests(self.root / 'test', self.root / 'empty-evidence')

    def test_signed_runtime_version_must_match_tag(self):
        original = self.native_output
        def wrong_version(args, **kwargs):
            return 'AnyTLS v0.0.0' if args[-1] == '-version' else original(args, **kwargs)
        self.native_output = wrong_version
        with self.assertRaisesRegex(ValueError, 'version mismatch'):
            self.invoke()

    def test_native_host_must_be_apple_silicon(self):
        original = self.native_output
        def intel_host(args, **kwargs):
            return 'x86_64' if args == ['/usr/bin/uname', '-m'] else original(args, **kwargs)
        self.native_output = intel_host
        with self.assertRaisesRegex(ValueError, 'native arm64'):
            self.invoke()

    def test_dirty_release_source_is_rejected(self):
        (self.root / 'macos/main.swift').write_text('dirty')
        with self.assertRaisesRegex(ValueError, 'dirty'):
            self.invoke()

    def test_native_failure_is_not_skipped_and_output_survives(self):
        evidence = self.root / 'failed-evidence'
        with mock.patch.object(p.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, 'native fail', 'AppKit unavailable')):
            with self.assertRaisesRegex(RuntimeError, 'failed'):
                p.run_tests(self.root / 'test', evidence)
        self.assertEqual((evidence / 'AnyTLSMenuBarTests.stderr').read_text(), 'AppKit unavailable')
        self.assertFalse((evidence / 'native-suites.json').exists())


if __name__ == '__main__':
    unittest.main()

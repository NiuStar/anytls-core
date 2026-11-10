#!/usr/bin/env python3
"""Package the native arm64 or amd64 unified app against the existing release source closure.

No download, installation, helper authorization or production runtime invocation.
The optional test mode runs only the five build-menubar.sh fixture executables.
"""
import argparse
import hashlib
import html
import sys
import json
import os
from pathlib import Path
import plistlib
import re
import stat
import subprocess
import tarfile
import tempfile
import zipfile

SUITES = {'AnyTLSMenuBarTests': 520, 'QuitTests': 250, 'ConnectivityTests': 61,
          'FocusTests': 125, 'DesktopRuntimeTests': 212}
APP_SOURCES = ('macos/Model.swift', 'macos/Connectivity.swift', 'macos/Client.swift',
               'macos/QuitCoordinator.swift', 'macos/DesktopMigration.swift',
               'macos/DesktopRuntime.swift', 'macos/main.swift', 'macos/Tests.swift',
               'macos/KnownFailureTests.swift', 'macos/QuitTests.swift', 'macos/ConnectivityTests.swift',
               'macos/FocusTests.swift', 'macos/DesktopRuntimeTests.swift',
               'scripts/build-menubar.sh', 'scripts/package-menubar.py',
               'scripts/package_menubar_test.py', 'VERSION')


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def output(args, **kwargs):
    return subprocess.check_output(args, text=True, **kwargs).strip()


def validate_arch(arch):
    if arch not in ('arm64', 'amd64'):
        raise ValueError('unsupported architecture')
    return {'arm64': 'arm64', 'amd64': 'x86_64'}[arch]


def validate_tag(tag):
    if not re.fullmatch(r'(?:v[0-9]+\.[0-9]+\.[0-9]+|v[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{2})', tag):
        raise ValueError('unsupported release tag')


def read_sums(out, names):
    rows = {}
    for line in (out / 'SHA256SUMS').read_text(encoding='ascii').splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  ([^/\\]+)', line)
        if not match or match[2] in rows or match[2] not in names:
            raise ValueError('invalid existing SHA256SUMS')
        rows[match[2]] = match[1]
    if set(rows) != names:
        raise ValueError('incomplete existing SHA256SUMS')
    for name, digest in rows.items():
        path = out / name
        if path.is_symlink() or not path.is_file() or sha(path) != digest:
            raise ValueError('existing asset digest mismatch: ' + name)
    return rows


def check_sources(root, out, tag, arch='arm64'):
    validate_arch(arch)
    prefix = 'anytls-core-' + tag
    source = out / (prefix + '-source.tar.gz')
    ccs = out / (prefix + ('-corresponding-source.tar.gz' if arch == 'arm64' else '-darwin-amd64-corresponding-source.tar.gz'))
    tracked = set(output(['git', 'ls-files', '-z'], cwd=root).split('\0')) - {''}
    if not set(APP_SOURCES) <= tracked:
        raise ValueError('app build/test/package sources must all be tracked')
    with tarfile.open(source, 'r:gz') as archive:
        members = {m.name: m for m in archive.getmembers() if not m.isdir()}
        if set(members) != {prefix + '/' + name for name in tracked}:
            raise ValueError('source archive does not cover every tracked file')
        for name in tracked:
            member = members[prefix + '/' + name]
            if not member.isfile() or archive.extractfile(member).read() != (root / name).read_bytes():
                raise ValueError('source archive bytes mismatch: ' + name)
    with tarfile.open(ccs, 'r:gz') as archive:
        member = archive.getmember(prefix + '/application-source.tar.gz')
        if not member.isfile():
            raise ValueError('corresponding source application is not regular')
        if hashlib.sha256(archive.extractfile(member).read()).hexdigest() != sha(source):
            raise ValueError('corresponding source does not contain exact app source')
    return ccs.name


def verify_app(app, tag, arch='arm64'):
    machine = validate_arch(arch)
    if output(['/usr/bin/uname', '-s']) != 'Darwin' or output(['/usr/bin/uname', '-m']) != machine:
        raise ValueError('native ' + machine + ' macOS required')
    if app.name != 'AnyTLSMenuBar.app' or app.is_symlink() or not app.is_dir():
        raise ValueError('expected regular AnyTLSMenuBar.app')
    for path in app.rglob('*'):
        if path.is_symlink() or not (path.is_dir() or path.is_file()):
            raise ValueError('unsupported bundle entry: ' + str(path))
    info = plistlib.loads((app / 'Contents/Info.plist').read_bytes())
    expected = dict(CFBundleIdentifier='org.anytls.menubar.candidate',
                    CFBundleExecutable='AnyTLSMenuBar', CFBundlePackageType='APPL',
                    CFBundleShortVersionString='0.5.2', CFBundleVersion='0.5.2.20261110.1',
                    AnyTLSCoreVersion=tag, LSMinimumSystemVersion='13.0', LSUIElement=True)
    if any(info.get(key) != value for key, value in expected.items()):
        raise ValueError('unexpected app metadata')
    runtime = app / 'Contents/Resources/runtime/anytls-macos'
    executable = app / 'Contents/MacOS/AnyTLSMenuBar'
    for path in (runtime, executable):
        if not path.is_file() or not path.stat().st_mode & stat.S_IXUSR:
            raise ValueError('missing executable payload')
        if output(['/usr/bin/lipo', '-archs', str(path)]) != machine:
            raise ValueError('app payload must be ' + machine + ' only')
        subprocess.run(['/usr/bin/codesign', '--verify', '--strict', str(path)], check=True)
    subprocess.run(['/usr/bin/codesign', '--verify', '--strict', '--deep', str(app)], check=True)
    manifest = json.loads((app / 'Contents/Resources/runtime/manifest.json').read_bytes())
    if manifest != dict(schema=1, binary='anytls-macos', arch=arch, version=tag, sha256=sha(runtime)):
        raise ValueError('runtime manifest mismatch')
    version = output([str(runtime), '-version']).removeprefix('anytls-macos ').removeprefix('AnyTLS ')
    if version != tag:
        raise ValueError('signed runtime version mismatch')
    return manifest


def suite_failure(name, reason, expected, actual, stdout):
    """Publish only bounded diagnostics, never exception text or raw payloads."""
    if name not in SUITES or reason not in ('nonzero', 'timeout', 'json', 'inventory', 'count'):
        return
    if isinstance(stdout, bytes):
        stdout = stdout.decode('utf-8', errors='replace')
    match = re.search(r'^FAIL:? (.*)$', stdout, re.MULTILINE)
    label = ''.join(c for c in match[1] if c.isprintable()) if match else ''
    if re.search(r'password|token|secret|credential', label, re.I):
        label = '[redacted]'
    elif re.search(r'[/\\]|[{}]', label):
        label = '[redacted]'
    label = label[:200]
    message = f'{name} reason={reason} expected={expected} actual={actual if actual is not None else "unknown"}'
    if label:
        message += ' label=' + label
    if os.environ.get('GITHUB_ACTIONS') == 'true':
        escaped = message.replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')
        print('::error::' + escaped, file=sys.stderr, flush=True)
    summary = os.environ.get('GITHUB_STEP_SUMMARY')
    if summary:
        try:
            fd = os.open(summary, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, 'a') as stream:
                if stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    # Plain text in HTML pre prevents labels from becoming Markdown/HTML.
                    stream.write('<pre>' + html.escape(message) + '</pre>\n')
        except OSError:
            pass  # Optional diagnostics must not replace the original failure.


def run_tests(test_dir, evidence):
    test_dir = Path(test_dir).resolve()
    evidence = Path(evidence).resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    temp = evidence / 'tmp'
    temp.mkdir(mode=0o700)
    env = dict(os.environ, TMPDIR=str(temp))
    results = {}
    for name, expected in SUITES.items():
        args = [str(test_dir / name)]
        if name in ('FocusTests', 'DesktopRuntimeTests'):
            args.append(str(evidence / name))
        try:
            run = subprocess.run(args, env=env, capture_output=True, text=True, timeout=90)
        except subprocess.TimeoutExpired as error:
            (evidence / (name + '.stdout')).write_bytes(error.stdout or b'')
            (evidence / (name + '.stderr')).write_bytes(error.stderr or b'')
            suite_failure(name, 'timeout', expected, None, error.stdout or b'')
            raise RuntimeError(name + ' timed out; retained raw output') from error
        (evidence / (name + '.stdout')).write_text(run.stdout)
        (evidence / (name + '.stderr')).write_text(run.stderr)
        print(run.stdout, end='', flush=True)
        print(run.stderr, end='', flush=True)
        if run.returncode:
            suite_failure(name, 'nonzero', expected, None, run.stdout)
            raise RuntimeError(name + ' failed: ' + str(run.returncode))
        reason, actual = 'inventory', None
        try:
            if name in ('AnyTLSMenuBarTests', 'QuitTests'):
                reason = 'json'
                data = json.loads(run.stdout)
                reason = 'inventory'
                if data.get('status') != 'PASS':
                    raise ValueError(name + ' missing PASS inventory')
                checks = data['checks']
            else:
                checks = [line for line in run.stdout.splitlines() if line.startswith(('PASS: ', 'PASS '))]
                actual = len(checks)
                marker = {'ConnectivityTests': 'CONNECTIVITY_TESTS_PASS assertions=',
                          'FocusTests': 'FOCUS_TESTS_OK checks=',
                          'DesktopRuntimeTests': 'DESKTOP_TESTS_OK checks='}[name]
                if not re.search(re.escape(marker) + str(expected) + r'(?:\s|$)', run.stdout):
                    raise ValueError(name + ' missing completion marker')
                if name != 'ConnectivityTests':
                    filename = 'focus-checks.json' if name == 'FocusTests' else 'desktop-checks.json'
                    reason = 'json'
                    data = json.loads((evidence / name / filename).read_text())
                    reason = 'inventory'
                    if data['count'] != expected or data['checks'] != [re.sub(r'^PASS:? ', '', line) for line in checks]:
                        raise ValueError(name + ' evidence inventory mismatch')
            reason, actual = 'count', len(checks)
            if len(checks) != expected:
                raise ValueError(name + ' assertion count mismatch')
        except (ValueError, KeyError, TypeError, AttributeError, OSError):
            suite_failure(name, reason, expected, actual, run.stdout)
            raise
        results[name] = len(checks)
    (evidence / 'native-suites.json').write_text(json.dumps(results, indent=2) + '\n')
    return results


def package(root, app, out, tag, arch='arm64'):
    validate_arch(arch)
    validate_tag(tag)
    root, app, out = Path(root).resolve(), Path(app).absolute(), Path(out).resolve()
    if (root / 'VERSION').read_text().strip() != tag:
        raise ValueError('VERSION/tag mismatch')
    if output(['git', 'status', '--porcelain', '--untracked-files=no'], cwd=root):
        raise ValueError('tracked release source is dirty')
    commit = output(['git', 'rev-parse', 'HEAD'], cwd=root)
    prefix = 'anytls-core-' + tag
    platform = 'darwin-' + arch
    ccs_suffix = '-corresponding-source.tar.gz' if arch == 'arm64' else '-darwin-amd64-corresponding-source.tar.gz'
    names = {prefix + suffix for suffix in ('-source.tar.gz', ccs_suffix, '-' + platform + '.tar.gz')}
    if {p.name for p in out.iterdir()} != names | {'SHA256SUMS'}:
        raise ValueError('expected exactly the three selected-architecture core archives and SHA256SUMS')
    sums = read_sums(out, names)
    source = check_sources(root, out, tag, arch)
    manifest = verify_app(app, tag, arch)
    with tarfile.open(out / (prefix + '-' + platform + '.tar.gz'), 'r:gz') as core:
        core_info = json.load(core.extractfile(prefix + '-' + platform + '/BUILD-INFO.json'))
    if core_info.get('source_commit') != commit or core_info.get('platform') != platform or core_info.get('corresponding_source') != source:
        raise ValueError('core archive identity mismatch')
    original_core_sha = core_info.get('binary_sha256', '')
    if not re.fullmatch(r'[0-9a-f]{64}', original_core_sha):
        raise ValueError('missing original core digest')
    target = out / (prefix + '-menubar-' + platform + '.zip')
    with tempfile.TemporaryDirectory(prefix='aqpkg-', dir=os.environ['TMPDIR']) as work:
        work = Path(work)
        archive = work / target.name
        subprocess.run(['/usr/bin/ditto', '-c', '-k', '--sequesterRsrc', '--keepParent', str(app), str(archive)], check=True)
        # Append delivery material without re-emitting signed bundle ZIP entries.
        with zipfile.ZipFile(archive, 'a', compression=zipfile.ZIP_DEFLATED) as delivery:
            with tarfile.open(out / (prefix + '-' + platform + '.tar.gz'), 'r:gz') as core:
                base = prefix + '-' + platform + '/'
                license_count = 0
                for member in core.getmembers():
                    relative = member.name.removeprefix(base)
                    if member.isfile() and (relative in ('LICENSE', 'THIRD_PARTY_NOTICES.md') or relative.startswith('licenses/')):
                        if '..' in Path(relative).parts or relative.startswith('/'):
                            raise ValueError('unsafe license member')
                        delivery.writestr(relative, core.extractfile(member).read())
                        license_count += 1
                if not license_count or 'LICENSE' not in delivery.namelist() or 'THIRD_PARTY_NOTICES.md' not in delivery.namelist():
                    raise ValueError('missing core license material')
            location = 'https://github.com/NiuStar/anytls-core/releases/download/' + tag + '/' + source
            delivery.writestr('SOURCE-LOCATION.txt', location + '\n')
            delivery.writestr('README.txt', 'AnyTLS unified windowless menu app 0.5.2\n' + {'arm64': 'Apple Silicon arm64', 'amd64': 'Intel x86_64'}[arch] + ' ONLY; macOS 13 or newer.\nAd-hoc signed; NOT Developer ID signed or notarized.\nNative administrator consent and production first-use/VPN end-to-end: NOT_RUN by packaging.\nNo credentials, Keychain data, configuration or helper installation is included.\nCorresponding source (full tracked Swift, tests, build tooling, Go dependencies and toolchain):\n' + location + '\n')
            delivery.writestr('BUILD-INFO.json', json.dumps(dict(source_commit=commit, core_version=tag, app_version='0.5.2', app_build='0.5.2.20261110.1', architecture=arch, original_core_sha256=original_core_sha, signed_runtime_sha256=manifest['sha256'], corresponding_source=source, signing='ad-hoc', notarization='NOT_RUN', production_end_to_end='NOT_RUN'), sort_keys=True, indent=2) + '\n')
        extracted = work / 'extracted'
        extracted.mkdir()
        subprocess.run(['/usr/bin/ditto', '-x', '-k', str(archive), str(extracted)], check=True)
        if verify_app(extracted / app.name, tag, arch) != manifest:
            raise ValueError('extracted runtime changed')
        before = {str(p.relative_to(app)): sha(p) for p in app.rglob('*') if p.is_file()}
        after = {str(p.relative_to(extracted / app.name)): sha(p) for p in (extracted / app.name).rglob('*') if p.is_file()}
        if before != after:
            raise ValueError('archive changed signed bundle bytes')
        target.write_bytes(archive.read_bytes())
    # Revalidate all original hashes; never replace/drop a core manifest row.
    read_sums(out, names)
    sums[target.name] = sha(target)
    (out / 'SHA256SUMS').write_text(''.join(sums[name] + '  ' + name + '\n' for name in sorted(sums)), encoding='ascii')
    return dict(asset=target.name, sha256=sums[target.name], corresponding_source=source, source_commit=commit)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('app', 'out', 'tag', 'run-tests', 'evidence'):
        parser.add_argument('--' + name)
    parser.add_argument('--arch', choices=('arm64', 'amd64'), default='arm64')
    args = parser.parse_args()
    if args.run_tests:
        if not args.evidence or any((args.app, args.out, args.tag)):
            parser.error('--run-tests requires --evidence and cannot package')
        result = run_tests(args.run_tests, args.evidence)
    else:
        if not all((args.app, args.out, args.tag)) or args.evidence:
            parser.error('packaging requires --app, --out and --tag')
        result = package(Path.cwd(), args.app, args.out, args.tag, arch=args.arch)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()

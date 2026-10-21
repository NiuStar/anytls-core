#!/bin/sh
# Metadata only: never execute the artifacts, build, or download.
set -eu
exec python3 -I - "$@" <<'PY'
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import selectors
import signal
import shutil
import subprocess
import sys
import time

p = argparse.ArgumentParser(description='Record executable identity, not benchmark performance.')
p.add_argument('--group', required=True, choices=['A', 'B', 'C'])
p.add_argument('--output', required=True)
p.add_argument('--go', help='explicit trusted Go executable; never auto-discovered')
p.add_argument('--timeout-seconds', type=float, default=30)
p.add_argument('--list-deps', action='store_true', help='opt in to offline source import graph inspection')
for field in ('source-dir', 'package', 'deps-goos', 'deps-goarch', 'deps-tags'):
    p.add_argument('--' + field)
p.add_argument('--module-cache', help='existing populated module cache, read-only Go mode')
for name in ('app', 'core'):
    p.add_argument('--' + name, required=name == 'app')
    p.add_argument('--' + name + '-origin', choices=['official-release', 'reconstructed-app', 'embedded-app', 'external-core'])
    for field in ('revision', 'toolchain', 'build-flags', 'goos', 'goarch'):
        p.add_argument('--' + name + '-' + field)
a = p.parse_args()

def fail(message):
    raise ValueError(message)

def header_target(header):
    if header[:4] == b'\x7fELF' and len(header) >= 20 and header[5] in (1, 2):
        machine = int.from_bytes(header[18:20], 'little' if header[5] == 1 else 'big')
        arch = {3: '386', 62: 'amd64', 40: 'arm', 183: 'arm64',
                243: 'riscv64' if header[4] == 2 else None}.get(machine)
        # System V ELF does NOT prove Linux. Go build info may resolve the OS later.
        os_name = {3: 'linux', 9: 'freebsd'}.get(header[7], 'NOT_MEASURED')
        return {'goos': os_name, 'goarch': arch or 'NOT_MEASURED'}, 'ELF_header'
    if header[:4] in (b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xce\xfa\xed\xfe', b'\xfe\xed\xfa\xce') and len(header) >= 8:
        machine = int.from_bytes(header[4:8], 'little' if header[0] in (0xcf, 0xce) else 'big')
        arch = {7: '386', 0x1000007: 'amd64', 12: 'arm', 0x100000c: 'arm64'}.get(machine)
        # Mach-O alone doesn't distinguish macOS from other Apple platforms.
        return {'goos': 'NOT_MEASURED', 'goarch': arch or 'NOT_MEASURED'}, 'Mach-O_header'
    return 'NOT_MEASURED', 'NOT_MEASURED'

def go_command(args, cwd=None, extra_env=None):
    # Do not inherit user Go configuration, credentials, proxy settings or GOFLAGS.
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(out), 'TMPDIR': str(out),
           'GOENV': 'off', 'GOTOOLCHAIN': 'local', 'GOPROXY': 'off',
           'GOSUMDB': 'off', 'GOWORK': 'off', 'GOTELEMETRY': 'off',
           'GOVCS': '*:off', 'CGO_ENABLED': '0'}
    env.update(extra_env or {})
    command = [str(go)] + args
    proc = subprocess.Popen(command, cwd=cwd or out, env=env, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
    chunks = bytearray()
    deadline = time.monotonic() + a.timeout_seconds
    status = 'COLLECTED'
    try:
        with selectors.DefaultSelector() as sel:
            sel.register(proc.stdout, selectors.EVENT_READ)
            while sel.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    status = 'TIMEOUT'
                    break
                if not sel.select(remaining):
                    continue
                chunk = os.read(proc.stdout.fileno(), 65536)
                if not chunk:
                    sel.unregister(proc.stdout)
                    break
                if len(chunks) + len(chunk) > 2 * 1024**2:
                    status = 'OUTPUT_LIMIT'
                    break
                chunks.extend(chunk)
        if status == 'COLLECTED':
            try:
                proc.wait(timeout=max(0.001, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                status = 'TIMEOUT'
    finally:
        # Also bound descendants holding stdout after the direct child exits.
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait()
        proc.stdout.close()
    if status == 'COLLECTED' and proc.returncode:
        status = 'FAILED'
    return {'status': status, 'argv': command, 'exit_code': proc.returncode,
            'output': chunks.decode('utf-8', errors='replace')}

try:
    if not 0.05 <= a.timeout_seconds <= 300:
        fail('timeout must be between 0.05 and 300 seconds')
    out = Path(a.output).absolute()
    if os.path.lexists(out):
        fail('output already exists (including partial output); choose a new directory')
    if not out.parent.is_dir():
        fail('output parent must already exist')
    free = shutil.disk_usage(out.parent).free
    if free < 5 * 1024**3:
        fail('disk preflight: at least 5 GiB free required')
    go = Path(a.go).resolve(strict=True) if a.go else None
    if go and (not go.is_file() or not os.access(go, os.X_OK)):
        fail('--go must be an executable regular file')
    deps_fields = (a.source_dir, a.package, a.deps_goos, a.deps_goarch, a.deps_tags, a.module_cache)
    if not a.list_deps and any(v is not None for v in deps_fields):
        fail('source/deps options require --list-deps; no implicit source access')
    if a.list_deps:
        if not go or any(v is None for v in deps_fields[:5]):
            fail('--list-deps requires --go, --source-dir, --package, --deps-goos, --deps-goarch and --deps-tags (empty allowed)')
        if not a.package or a.package.startswith('-') or any(c.isspace() for c in a.package):
            fail('provide exactly one package pattern, not Go options')
        source = Path(a.source_dir).resolve(strict=True)
        if not source.is_dir():
            fail('--source-dir must be a directory')
        module_cache = Path(a.module_cache).resolve(strict=True) if a.module_cache else None
        if module_cache and not module_cache.is_dir():
            fail('--module-cache must be an existing directory')
    artifacts = {}
    for name in ('app', 'core'):
        value = getattr(a, name)
        fields = {k: getattr(a, name + '_' + k.replace('-', '_')) for k in
                  ('origin', 'revision', 'toolchain', 'build-flags', 'goos', 'goarch')}
        if not value:
            if any(v is not None for v in fields.values()):
                fail('core metadata requires --core')
            continue
        if any(v is None or (not v and k != 'build-flags') for k, v in fields.items()):
            fail(name + ': explicit origin/revision/toolchain/build-flags/goos/goarch required')
        if (name == 'core') != (fields['origin'] == 'external-core'):
            fail('external-core origin is only valid for --core')
        path = Path(value).resolve(strict=True)
        if not path.is_file() or not os.access(path, os.X_OK):
            fail(name + ': input must be an executable regular file')
        start = time.monotonic()
        digest = hashlib.sha256()
        header = b''
        bytes_read = 0
        with path.open('rb') as f:
            before = os.fstat(f.fileno())
            if before.st_size > 2 * 1024**3:
                fail('input exceeds 2 GiB bound')
            while chunk := f.read(1024 * 1024):
                bytes_read += len(chunk)
                if bytes_read > 2 * 1024**3:
                    fail('input grew beyond 2 GiB bound')
                if not header:
                    header = chunk[:64]
                digest.update(chunk)
                if time.monotonic() - start > 30:
                    fail('hash timeout')
            after = os.fstat(f.fileno())
        if bytes_read != before.st_size or (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
            fail('input changed during hashing')
        artifacts[name] = {
            'path': str(path), 'bytes': before.st_size, 'sha256': digest.hexdigest(),
            'origin': fields['origin'], 'revision_declared': fields['revision'],
            'toolchain_declared': fields['toolchain'], 'build_flags_declared': fields['build-flags'],
            'declared_target': {'goos': fields['goos'], 'goarch': fields['goarch']},
            'detected_target': 'NOT_MEASURED',
            'go_version_m': {'status': 'NOT_MEASURED', 'reason': 'no --go executable supplied'},
        }
        artifacts[name]['detected_target'], artifacts[name]['target_evidence'] = header_target(header)
    report = {
        'schema_version': 1, 'kind': 'executable_metadata_only', 'group': a.group,
        'collected_at_utc': datetime.now(timezone.utc).isoformat(),
        'host': {'system': platform.system(), 'release': platform.release(), 'machine': platform.machine()},
        'disk_preflight': {'free_bytes': free, 'minimum_free_bytes': 5 * 1024**3},
        'artifacts': artifacts,
        'package_linkage': {'status': 'NOT_MEASURED'},
        'resources': {k: 'NOT_MEASURED' for k in ('cold_start_ms', 'warm_start_ms', 'rss_bytes',
                      'pss_bytes', 'process_tree_memory_bytes', 'throughput_bps', 'cpu_seconds')},
    }
    out.mkdir(mode=0o700)
    if go:
        report['go_reader'] = {'path': str(go), 'version': go_command(['version'])}
        for artifact in artifacts.values():
            result = go_command(['version', '-m', artifact['path']])
            artifact['go_version_m'] = result
            target = {}
            if result['status'] == 'COLLECTED':
                for line in result['output'].splitlines():
                    pieces = line.strip().split('\t')
                    if len(pieces) == 2 and pieces[0] == 'build' and pieces[1].startswith(('GOOS=', 'GOARCH=')):
                        key, value = pieces[1].split('=', 1)
                        target[key.lower()] = value
            if len(target) == 2:
                artifact['detected_target'] = target
                artifact['target_evidence'] = 'go_version_m'
    if a.list_deps:
        if shutil.disk_usage(out).free < 5 * 1024**3:
            fail('disk preflight before go list: at least 5 GiB free required; partial output preserved')
        # Cache writes stay inside this new output. No build or module downloads.
        cache = out / 'go-cache'
        cache.mkdir()
        deps_env = {'GOOS': a.deps_goos, 'GOARCH': a.deps_goarch,
                    'GOCACHE': str(cache), 'GOPATH': str(out / 'gopath'),
                    'GOMODCACHE': str(module_cache or out / 'module-cache')}
        args = ['list', '-deps', '-mod=readonly', '-buildvcs=false',
                '-tags=' + a.deps_tags, '-f={{.ImportPath}}', a.package]
        report['package_linkage'] = {
            'scope': 'source_import_graph_not_binary_linkage_proof',
            'source_dir': str(source), 'goos': a.deps_goos, 'goarch': a.deps_goarch,
            'tags': a.deps_tags, 'cgo_enabled': False,
            'module_cache': str(module_cache) if module_cache else 'isolated_empty_cache',
            'result': go_command(args, cwd=source, extra_env=deps_env),
        }
    for artifact in artifacts.values():
        target = artifact['detected_target']
        artifact['target_matches_declared'] = (
            target == artifact['declared_target']
            if isinstance(target, dict) and 'NOT_MEASURED' not in target.values() else 'NOT_MEASURED')
    partial = out / 'metadata.json.partial'
    with partial.open('x', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
        f.write('\n')
    partial.rename(out / 'metadata.json')
    print(str(out / 'metadata.json'))
except (OSError, ValueError) as e:
    print('measure-core: ' + str(e), file=sys.stderr)
    sys.exit(1)
PY

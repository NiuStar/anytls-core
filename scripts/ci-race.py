#!/usr/bin/env python3
"""One full native race run; raw output stays in the evidence artifact."""
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

COMMAND = ['python3', 'scripts/go-patched.py', 'test', '-p=2',
           '-tags=with_gvisor,with_utls,with_upstream_cleanup_patch,embedded_core',
           '-race', '-count=1', '-json', './...']


def run(evidence):
    logpath = evidence / 'go-race.jsonl'
    with logpath.open('wb') as log:
        process = subprocess.run(COMMAND, stdout=log, stderr=subprocess.STDOUT)
    counts = {'named_pass': 0, 'named_fail': 0, 'named_skip': 0, 'package_pass': 0, 'package_fail': 0}
    labels = set()
    with logpath.open('rb') as log:
        for line in log:
            try:
                event = json.loads(line)
            except (ValueError, UnicodeError):
                continue
            action = event.get('Action')
            if action not in ('pass', 'fail', 'skip'):
                continue
            name = event.get('Test')
            key = ('named_' if name else 'package_') + action
            if key in counts:
                counts[key] += 1
            if action == 'fail' and isinstance(name, str) and re.fullmatch(r'Test[A-Za-z0-9_]{1,150}', name):
                labels.add(name)
    result = {'command': COMMAND, 'returncode': process.returncode, 'counts': counts,
              'safe_failed_tests': sorted(labels)[:20], 'release_acceptance': False}
    (evidence / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    public = 'full-race ' + ' '.join(f'{key}={value}' for key, value in counts.items())
    if process.returncode:
        print('::error title=Full race qualification failed::' + public + ' tests=' + ','.join(result['safe_failed_tests']))
    else:
        print(public)
    return process.returncode


def main():
    # The inherited short cache/toolchain root must be owned, canonical and private.
    root = Path.home() / '.aq-ci'
    metadata = root.lstat()
    if (root.resolve() != root or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid() or metadata.st_mode & 0o022):
        raise ValueError('unsafe qualification TMPDIR')
    if os.environ.get('TMPDIR') != str(root) or os.environ.get('CGO_ENABLED') != '1':
        raise ValueError('explicit canonical TMPDIR and CGO_ENABLED=1 required')
    evidence = Path(tempfile.mkdtemp(prefix='race-', dir=root))
    with open(os.environ['GITHUB_ENV'], 'a') as env:
        env.write(f'RACE_EVIDENCE={evidence}\n')
    return run(evidence)


if __name__ == '__main__':
    raise SystemExit(main())

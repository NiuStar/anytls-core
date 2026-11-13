#!/usr/bin/env python3
"""Fail-closed 0.5.3 Intel full-race disposition; never changes raw evidence."""
import json
import os
from pathlib import Path
import re
import sys

VERSION = 'v2026-11-11-01'  # Exact core identity for App 0.5.3, not a future waiver.
STEP_IDS = ('checkout', 'setup_go', 'pin_paths', 'real_box', 'wrapper_tests',
            'installer_tests', 'go_tests', 'race_contracts', 'full_race',
            'race_upload', 'vet', 'dist', 'build', 'app_build', 'swift_tests', 'native_upload')
LEGACY_COMMAND = ['python3', 'scripts/go-patched.py', 'test', '-p=2',
           '-tags=with_gvisor,with_utls,with_upstream_cleanup_patch,embedded_core',
           '-race', '-count=1', '-json', './...']
COMMAND = LEGACY_COMMAND[:-2] + ['-timeout=20m', *LEGACY_COMMAND[-2:]]
# Explicit identities only: neither historical waivers nor budgets extend forward.
COMMAND_BY_VERSION = {VERSION: LEGACY_COMMAND, 'v2026-11-12-01': LEGACY_COMMAND,
                      'v2026-11-12-02': COMMAND}


def require(condition):
    if not condition:
        raise ValueError('invalid or incomplete qualification evidence')


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def decode(text):
    return json.loads(text, object_pairs_hook=strict_object)


def validate(steps, matrix, evidence, version):
    require(isinstance(version, str) and version in COMMAND_BY_VERSION)
    expected_command = COMMAND_BY_VERSION[version]
    require(matrix in ('macos-15', 'macos-15-intel'))
    require(isinstance(steps, dict))
    # GitHub normally supplies only prior steps; exclude only this known self ID.
    require(set(steps) - {'waiver_audit'} == set(STEP_IDS))
    for key in STEP_IDS:
        row = steps[key]
        require(isinstance(row, dict) and set(row) == {'outputs', 'outcome', 'conclusion'})
        require(isinstance(row['outputs'], dict))
        require(row['conclusion'] == 'success')
        if key != 'full_race':
            require(row['outcome'] == 'success')
    outcome = steps['full_race']['outcome']
    require(outcome in ('success', 'failure'))
    waived = outcome == 'failure'
    require(not waived or (matrix == 'macos-15-intel' and version == VERSION))
    require(evidence is not None)
    evidence = Path(evidence)
    require(evidence.is_dir() and not evidence.is_symlink())
    for name in ('result.json', 'go-race.jsonl'):
        target = evidence / name
        require(target.is_file() and not target.is_symlink() and target.stat().st_size > 0)
    result = decode((evidence / 'result.json').read_text())
    require(isinstance(result, dict) and result.get('command') == expected_command)
    rc = result.get('returncode')
    require(type(rc) is int and 0 <= rc <= 255 and ((rc != 0) == waived))
    require(result.get('release_acceptance') is False)
    counts = dict.fromkeys(('named_pass', 'named_fail', 'named_skip', 'package_pass', 'package_fail'), 0)
    labels, terminals, started = set(), set(), set()
    begin = end = None
    dirty = False
    with (evidence / 'go-race.jsonl').open() as raw:
        for line in raw:
            require(line.endswith('\n'))
            if line.startswith('PATCHED_GO_BEGIN '):
                require(begin is None and end is None)
                begin = decode(line[len('PATCHED_GO_BEGIN '):])
                require(isinstance(begin, dict))
                continue
            if line.startswith('PATCHED_GO_END '):
                require(begin is not None and end is None)
                end = decode(line[len('PATCHED_GO_END '):])
                require(isinstance(end, dict))
                continue
            require(begin is not None and end is None)
            try:
                event = decode(line)
            except (ValueError, UnicodeError):
                # Compiler/linker stderr can be non-JSON; never hide panic/race text.
                require(not line.lstrip().startswith(('{', '[')))
                dirty |= bool(re.search(r'WARNING: DATA RACE|panic:|fatal error:', line))
                continue
            require(isinstance(event, dict))
            action = event.get('Action')
            require(action in ('start', 'run', 'pause', 'cont', 'pass', 'fail', 'skip',
                               'output', 'bench', 'build-output', 'build-fail'))
            package = event.get('Package')
            require(isinstance(package, str) and bool(package) or
                    (action in ('build-output', 'build-fail') and isinstance(event.get('ImportPath'), str)))
            output = event.get('Output', '')
            require(isinstance(output, str))
            dirty |= bool(re.search(r'WARNING: DATA RACE|panic:|fatal error:', output))
            name = event.get('Test')
            require(name is None or isinstance(name, str) and bool(name))
            identity = (package, name)
            if action in ('start', 'run'):
                require((action == 'start') == (name is None))
                require(identity not in started and identity not in terminals)
                require(name is None or (package, None) in started)
                started.add(identity)
            if action not in ('pass', 'fail', 'skip'):
                continue
            # Go emits package skip without a start for packages without tests.
            require(identity in started or (action == 'skip' and name is None))
            require(identity not in terminals)
            terminals.add(identity)
            key = ('named_' if name else 'package_') + action
            if key in counts:
                counts[key] += 1
            if action == 'fail' and name and re.fullmatch(r'Test[A-Za-z0-9_]{1,150}', name):
                labels.add(name)
    require(begin is not None and end is not None)
    command = begin.get('command')
    require(isinstance(command, list) and len(command) == len(expected_command) and
            isinstance(command[0], str) and Path(command[0]).is_absolute() and
            Path(command[0]).name == 'go' and command[1] == 'test' and
            isinstance(command[2], str) and command[2].startswith('-modfile=/') and
            command[3:] == expected_command[3:])
    require(all(end.get(key) == value for key, value in begin.items()))
    require(type(end.get('rc')) is int and end['rc'] == rc and end.get('ephemeral_cleanup') == 'ok'
            and end.get('root_inputs_unchanged') is True)
    reported = result.get('counts')
    require(isinstance(reported, dict) and reported == counts and
            all(type(value) is int for value in reported.values()))
    require(result.get('safe_failed_tests') == sorted(labels)[:20])
    require(counts['package_pass'] + counts['package_fail'] > 0 and
            any(name is not None for _, name in started))
    require(rc != 0 or started <= terminals)
    require(rc != 0 or not (dirty or counts['named_fail'] or counts['package_fail']))
    require(rc == 0 or counts['package_fail'] > 0)
    return 'INTEL_RACE_FAIL_WAIVED_FOR_0_5_3' if waived else 'FULL_RACE_PASS'


def main():
    try:
        evidence = os.environ.get('RACE_EVIDENCE')
        require(bool(evidence))
        verdict = validate(decode(os.environ['STEPS_JSON']), os.environ['MATRIX_OS'],
                           Path(evidence), Path('VERSION').read_text().strip())
    except (KeyError, OSError, ValueError, TypeError, UnicodeError):
        print('BLOCKED: invalid or incomplete qualification evidence', file=sys.stderr)
        return 1
    print(verdict)  # Fixed labels only; no raw values or private paths.
    return 0


if __name__ == '__main__':
    sys.exit(main())

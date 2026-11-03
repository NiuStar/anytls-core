#!/usr/bin/env python3
"""Read-only baseline parsers. No Go, service mutations, or network by default."""
import argparse
import json
import math
import re
from collections import defaultdict
from pathlib import Path

DOMAINS = ('www.google.com', 'cloudflare.com', 'example.com')
FAMILIES = ('A', 'AAAA')


def number(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise ValueError('invalid measurement')
    return value


def ns(value):
    if not isinstance(value, str) or not re.fullmatch(r'0|[1-9][0-9]*', value):
        raise ValueError('invalid monotonic ns')
    result = int(value)
    if result > 2**64-1:
        raise ValueError('ns overflow')
    return result


def statistics(values):
    values = sorted(number(v) for v in values)
    n = len(values)
    return {'n': n, 'min': values[0] if n else None,
            'p50': values[math.ceil(.50*n)-1] if n else None,
            'p95': values[math.ceil(.95*n)-1] if n else None,
            'max': values[-1] if n else None,
            'mean': sum(values)/n if n else None,
            'method': 'nearest-rank; successful measured values only'}


def budget(domains=DOMAINS, families=FAMILIES, repeats=30, approved=False):
    if tuple(domains) != DOMAINS or tuple(families) != FAMILIES or type(repeats) is not int or repeats != 30:
        raise ValueError('fixed approved matrix required')
    if not approved:
        raise ValueError('explicit public approval required')
    count = len(domains)*len(families)*repeats
    if count > 180:
        raise ValueError('budget exceeded')
    return count


def parse_dig(text, returncode, elapsed_ms, family):
    number(elapsed_ms)
    if family not in FAMILIES:
        raise ValueError('invalid family')
    statuses = re.findall(r'status: ([A-Z0-9]+),', text)
    times = re.findall(r'Query time: ([0-9]+) msec', text)
    answers = [line for line in text.splitlines() if re.match(r'^\S+\s+\d+\s+IN\s+'+family+r'\s+\S+\s*$', line)]
    valid = returncode == 0 and len(statuses) == 1 and statuses[0] == 'NOERROR' and len(times) == 1
    return {'ok': valid, 'resolved': valid and bool(answers),
            'rcode': statuses[0] if len(statuses) == 1 else 'UNAVAILABLE',
            'answer_count': len(answers), 'query_ms': int(times[0]) if valid else None,
            'elapsed_ms': elapsed_ms, 'returncode': returncode,
            'error': None if valid else 'DNS_BUSINESS_OR_TRANSPORT_FAILURE'}


def dns_summary(records):
    grouped = defaultdict(list)
    seen = set()
    for r in records:
        key = (r['domain'], r['family'], r['repeat'])
        if r['domain'] not in DOMAINS or r['family'] not in FAMILIES or type(r['repeat']) is not int or not 0 <= r['repeat'] < 30 or key in seen:
            raise ValueError('unexpected/duplicate DNS record')
        seen.add(key)
        if type(r['ok']) is not bool or type(r['resolved']) is not bool or r['resolved'] and not r['ok']:
            raise ValueError('invalid DNS outcome')
        if r['ok']:
            number(r['query_ms']); number(r['elapsed_ms'])
        elif r['query_ms'] is not None:
            raise ValueError('failed query has latency')
        grouped[(r['domain'], r['family'])].append(r)
    rows = []
    for domain in DOMAINS:
        for family in FAMILIES:
            rr = grouped[(domain, family)]
            ok = [r for r in rr if r['ok']]
            rows.append({'domain': domain, 'family': family, 'attempted': len(rr),
                         'successful': len(ok), 'resolved': sum(r['resolved'] for r in rr),
                         'failures': len(rr)-len(ok),
                         'query_ms': statistics([r['query_ms'] for r in ok]),
                         'elapsed_ms': statistics([r['elapsed_ms'] for r in ok]),
                         'first': next((r for r in rr if r['repeat'] == 0), None),
                         'repeat_query_ms': statistics([r['query_ms'] for r in ok if r['repeat'] > 0])})
    return {'logical_attempts': len(seen), 'expected': 180, 'complete': len(seen) == 180,
            'engine': 'system dig through unchanged normal TUN; not independent SDK engine',
            'cache': 'first/repeat only; no cache flush and no cold-cache claim', 'rows': rows}


def timeline_summary(document):
    dto = document.get('timeline', document)
    if dto.get('code') != 'OK' or dto.get('timeline_schema') != 1:
        raise ValueError('timeline business failure')
    trace = dto['trace']
    streams = trace['streams']
    if not isinstance(streams, list) or len({s['role'] for s in streams}) != len(streams):
        raise ValueError('invalid stream roles')
    result = {'operation_id': trace['operation_id'], 'operation': trace['operation'],
              'lifecycle_result': trace['lifecycle_result'], 'state': trace['state'],
              'web_return': trace['web_return'], 'gap': trace['gap'], 'operation_samples': 1,
              'cross_process_subtraction': False, 'percentiles': 'NOT_ESTIMATED_SINGLE_OPERATION', 'streams': []}
    for stream in streams:
        if stream['role'] not in ('CORE', 'HELPER', 'WEB'):
            raise ValueError('invalid role')
        limit = ns(stream['elapsed_ns'])
        stack = []
        stages = defaultdict(lambda: {'count': 0, 'inclusive_ns': 0, 'exclusive_ns': 0, 'max_inclusive_ns': 0})
        previous = 0
        for e in stream['events']:
            now = ns(e['elapsed_ns'])
            if now < previous or now > limit:
                raise ValueError('nonmonotonic stream')
            previous = now
            if e['state'] == 'BEGIN':
                if any(x['event']['span_id'] == e['span_id'] for x in stack):
                    raise ValueError('duplicate span')
                stack.append({'event': e, 'children': 0})
            elif e['state'] == 'END':
                if not stack:
                    raise ValueError('unpaired END: incomplete stream')
                begin = stack.pop()
                b = begin['event']
                duration = ns(e['duration_ns'])
                if (b['span_id'], b['stage'], b['segment']) != (e['span_id'], e['stage'], e['segment']) or duration != now-ns(b['elapsed_ns']) or begin['children'] > duration:
                    raise ValueError('invalid paired span')
                if stack:
                    stack[-1]['children'] += duration
                row = stages[(e['segment'], e['stage'])]
                row['count'] += 1
                row['inclusive_ns'] += duration
                row['exclusive_ns'] += duration-begin['children']
                row['max_inclusive_ns'] = max(row['max_inclusive_ns'], duration)
            elif e['state'] != 'OBSERVATION':
                raise ValueError('invalid event state')
        result['streams'].append({'role': stream['role'], 'clock_id': stream['clock_id'],
                                  'elapsed_ns': limit, 'event_count': len(stream['events']),
                                  'gap': stream['gap'], 'open_spans': len(stack),
                                  'stages': [{'segment': key[0], 'stage': key[1], **v} for key, v in sorted(stages.items(), key=lambda item: -item[1]['exclusive_ns'])]})
    return result


def resource_summary(records):
    rows = defaultdict(list)
    for sample in records:
        for r in sample['processes']:
            rows[r['role']].append(r)
    return {'sample_ticks': len(records), 'memory_scope': 'per-process RSS KiB only; NOT physical footprint or summed peak',
            'cpu_scope': 'ps %cpu process-average indicator; not interval CPU utilization',
            'processes': {role: {'samples': len(rr), 'cpu_percent': statistics([r['cpu_percent'] for r in rr]),
                                  'rss_kib': statistics([r['rss_kib'] for r in rr]),
                                  'pids': sorted({r['pid'] for r in rr})} for role, rr in rows.items()}}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('kind', choices=('timeline', 'dns', 'resources'))
    p.add_argument('input', type=Path)
    a = p.parse_args()
    if a.kind == 'timeline':
        result = timeline_summary(json.loads(a.input.read_text()))
    else:
        events = [json.loads(line) for line in a.input.read_text().splitlines()]
        selected = [r['data'] for r in events if r.get('kind') == ('dns' if a.kind == 'dns' else 'resource')]
        result = dns_summary(selected) if a.kind == 'dns' else resource_summary(selected)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()

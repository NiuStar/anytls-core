import copy
import unittest
import baseline as b


class BaselineTests(unittest.TestCase):
    def test_nearest_rank(self):
        s = b.statistics(list(range(1, 31)))
        self.assertEqual((s['n'], s['p50'], s['p95']), (30, 15, 29))
        self.assertEqual(b.statistics(range(1, 101))['p95'], 95)

    def test_empty_not_zero(self):
        self.assertIsNone(b.statistics([])['p95'])
        d = b.dns_summary([])
        self.assertFalse(d['complete'])
        self.assertEqual(d['logical_attempts'], 0)
        self.assertIsNone(d['rows'][0]['query_ms']['mean'])

    def test_bad_measurements(self):
        for value in (True, -1, float('nan'), float('inf'), None, '3'):
            with self.assertRaises(ValueError):
                b.statistics([value])
        for value in ('01', '-1', '1.0', 1, str(2**64)):
            with self.assertRaises(ValueError):
                b.ns(value)

    def test_budget_negative_offline(self):
        with self.assertRaises(ValueError): b.budget()
        with self.assertRaises(ValueError): b.budget(domains=('secret.invalid',), approved=True)
        with self.assertRaises(ValueError): b.budget(repeats=31, approved=True)
        with self.assertRaises(ValueError): b.budget(families=('A',), approved=True)
        self.assertEqual(b.budget(approved=True), 180)

    def test_dns_business_not_exit(self):
        text = ';; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 1\n;; Query time: 4 msec\n'
        result = b.parse_dig(text, 0, 5, 'A')
        self.assertFalse(result['ok'])
        self.assertIsNone(result['query_ms'])
        for text in ('', 'status: NOERROR,', 'status: NOERROR,\n;; Query time: nope msec'):
            self.assertFalse(b.parse_dig(text, 0, 1, 'A')['ok'])

    def test_dns_success_and_nodata(self):
        text = ';; status: NOERROR,\nexample.com. 60 IN A 192.0.2.1\n;; Query time: 3 msec\n'
        self.assertTrue(b.parse_dig(text, 0, 4, 'A')['resolved'])
        self.assertFalse(b.parse_dig(text, 1, 4, 'A')['ok'])
        self.assertFalse(b.parse_dig(text, 0, 4, 'AAAA')['resolved'])

    def test_dns_coverage_and_failures(self):
        records = []
        for domain in b.DOMAINS:
            for family in b.FAMILIES:
                for repeat in range(30):
                    records.append(dict(domain=domain, family=family, repeat=repeat, ok=repeat != 0,
                                        resolved=repeat != 0, query_ms=repeat if repeat else None, elapsed_ms=repeat+1))
        result = b.dns_summary(records)
        self.assertTrue(result['complete'])
        self.assertEqual(result['logical_attempts'], 180)
        self.assertEqual(result['rows'][0]['failures'], 1)
        self.assertEqual(result['rows'][0]['query_ms']['n'], 29)
        with self.assertRaises(ValueError): b.dns_summary(records+[records[0]])

    def fixture(self):
        def e(state, span, stage, n, duration=None):
            return dict(state=state, span_id=span, stage=stage, segment='START', elapsed_ns=str(n), duration_ns=duration)
        return dict(timeline_schema=1, code='OK', trace=dict(operation_id='fixture', operation='START', lifecycle_result='SUCCEEDED',
            state='FINISHED', web_return='NOT_ATTEMPTED', gap=False, streams=[dict(role='HELPER', clock_id='fixture', elapsed_ns='20', gap=False,
            events=[e('BEGIN', '1', 'PARENT', 0), e('BEGIN', '2', 'CHILD', 2), e('END', '2', 'CHILD', 7, '5'), e('END', '1', 'PARENT', 10, '10')])]))

    def test_monotonic_nested_no_double_count(self):
        result = b.timeline_summary(self.fixture())
        stages = {x['stage']: x for x in result['streams'][0]['stages']}
        self.assertEqual(stages['PARENT']['exclusive_ns'], 5)
        self.assertEqual(sum(x['exclusive_ns'] for x in stages.values()), 10)
        self.assertFalse(result['cross_process_subtraction'])
        self.assertEqual(result['operation_samples'], 1)

    def test_timeline_malformed_failure(self):
        for mutate in (lambda d: d.update(code='UNAVAILABLE'),
                       lambda d: d['trace']['streams'][0]['events'][-1].update(duration_ns='11'),
                       lambda d: d['trace']['streams'][0]['events'][1].update(elapsed_ns='30'),
                       lambda d: d['trace']['streams'][0]['events'][-1].update(span_id='9')):
            d = copy.deepcopy(self.fixture()); mutate(d)
            with self.assertRaises(ValueError): b.timeline_summary(d)

    def test_resources_separate_rss(self):
        records = [dict(processes=[dict(role='core', pid=1, cpu_percent=2, rss_kib=100),
                                  dict(role='helper', pid=2, cpu_percent=1, rss_kib=50)])]
        result = b.resource_summary(records)
        self.assertEqual(result['processes']['core']['rss_kib']['max'], 100)
        self.assertNotIn('total_peak', result)
        self.assertEqual(b.resource_summary([])['processes'], {})


if __name__ == '__main__':
    unittest.main()

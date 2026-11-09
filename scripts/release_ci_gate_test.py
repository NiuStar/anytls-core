#!/usr/bin/env python3
"""Offline HTTP-injected release gate regressions; never contact GitHub."""
import copy
import io
import json
from pathlib import Path
import unittest
from unittest import mock
import urllib.error
import urllib.parse

import release_ci_gate as gate

SHA = "a" * 40
TAG = "v2026-11-05-01"
WORKFLOW = {"id": 42, "name": "CI", "path": gate.WORKFLOW_PATH, "state": "active"}
RUN = {"id": 71, "workflow_id": 42, "name": "CI", "path": gate.WORKFLOW_PATH,
       "head_sha": SHA, "head_branch": TAG, "event": "push", "run_attempt": 1,
       "status": "completed", "conclusion": "success",
       # Synthetic API metadata, not a recorded GitHub response.
       "repository": {"full_name": "owner/repo"},
       "head_repository": {"full_name": "owner/repo"}}
JOBS = [{"id": i, "name": name, "run_id": 71, "head_sha": SHA,
         "status": "completed", "conclusion": "success"}
        for i, name in enumerate(sorted(gate.EXPECTED_JOBS), 101)]


class FakeClock:
    def __init__(self):
        self.now = 0
        self.sleeps = []

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


class HTTP:
    def __init__(self):
        self.run = copy.deepcopy(RUN)
        self.jobs = copy.deepcopy(JOBS)
        self.workflow = copy.deepcopy(WORKFLOW)
        self.runs = None
        self.requests = []
        self.handler = None
        self.polls = 0
        self.tag_sha = SHA

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        parsed = urllib.parse.urlsplit(request.full_url)
        path = parsed.path.split("/repos/owner/repo/", 1)[1]
        query = urllib.parse.parse_qs(parsed.query)
        if self.handler:
            result = self.handler(path, query)
            if result is not None:
                return result
        if path == "git/ref/tags/" + TAG:
            data = {"ref": "refs/tags/" + TAG, "object": {"type": "commit", "sha": self.tag_sha}}
        elif path == "actions/workflows/ci.yml":
            data = self.workflow
        elif path == "actions/workflows/42/runs":
            self.polls += 1
            assert query["head_sha"] == [SHA]
            assert query["branch"] == [TAG]
            assert query["event"] == ["push"]
            rows = [self.run] if self.runs is None else self.runs
            data = {"total_count": len(rows), "workflow_runs": rows}
        elif path == "actions/runs/71/attempts/1/jobs":
            data = {"total_count": len(self.jobs), "jobs": self.jobs}
        else:
            raise AssertionError("unhandled request: " + path)
        return io.BytesIO(json.dumps(data).encode())


class GateTests(unittest.TestCase):
    def setUp(self):
        self.clock, self.http, self.logs = FakeClock(), HTTP(), []
        # Even accidental fallback to the real transport must fail offline.
        self.network = mock.patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("network forbidden"))
        self.network.start()
        self.addCleanup(self.network.stop)

    def make(self, **kwargs):
        return gate.Gate("owner/repo", SHA, TAG, "not-a-real-token", seconds=5,
                         interval=2, opener=self.http, clock=self.clock,
                         sleep=self.clock.sleep, log=self.logs.append, **kwargs)

    def blocked(self, message=None):
        with self.assertRaisesRegex(gate.GateError, message or "."):
            self.make().wait()
        self.assertFalse(any(line.startswith("PASS:") for line in self.logs))

    def test_success_requires_all_jobs_and_read_only_headers(self):
        self.make().wait()
        self.assertEqual(self.http.polls, 1)
        self.assertFalse(self.clock.sleeps)
        self.assertTrue(self.logs[-1].startswith("PASS:"))
        for request, timeout in self.http.requests:
            self.assertEqual(request.get_method(), "GET")
            self.assertIsNone(request.data)
            self.assertEqual(request.get_header("Authorization"), "Bearer not-a-real-token")
            self.assertEqual(request.get_header("Cache-control"), "no-cache")
            self.assertGreater(timeout, 0)
            self.assertLessEqual(timeout, 5)

    def test_workflow_success_with_pending_jobs_waits(self):
        self.http.jobs[0].update(status="in_progress", conclusion=None)
        original_sleep = FakeClock.sleep
        def advance(seconds):
            original_sleep(self.clock, seconds)
            self.http.jobs[0].update(status="completed", conclusion="success")
        self.clock.sleep = advance
        self.make().wait()
        self.assertEqual(self.clock.sleeps, [2])
        self.assertEqual(self.http.polls, 2)

    def test_workflow_success_pending_jobs_times_out(self):
        self.http.jobs[0].update(status="queued", conclusion=None)
        self.blocked("deadline")
        self.assertEqual(self.clock.now, 5)
        self.assertEqual(self.clock.sleeps, [2, 2, 1])

    def test_run_pending_even_when_jobs_success(self):
        self.http.run.update(status="in_progress", conclusion=None)
        self.blocked("deadline")

    def test_terminal_workflow_failures_are_immediate(self):
        for conclusion in ("failure", "cancelled", "timed_out", "skipped", "neutral", "action_required", "startup_failure", None):
            with self.subTest(conclusion=conclusion):
                self.http.run["conclusion"] = conclusion
                self.blocked("terminal non-success")
                self.assertEqual(self.clock.now, 0)

    def test_terminal_job_failure_even_when_run_or_other_jobs_pending(self):
        self.http.run.update(status="in_progress", conclusion=None)
        self.http.jobs[0].update(status="queued", conclusion=None)
        self.http.jobs[1]["conclusion"] = "failure"
        self.blocked("terminal non-success")
        self.assertFalse(self.clock.sleeps)

    def test_non_success_job_conclusions_block(self):
        for value in ("cancelled", "timed_out", "skipped", "neutral", None, "unknown"):
            with self.subTest(conclusion=value):
                self.http.jobs[0]["conclusion"] = value
                self.blocked("terminal non-success")

    def test_run_identity_fields_are_all_required(self):
        for key, value in (("head_sha", "b" * 40), ("head_branch", "main"),
                           ("event", "workflow_dispatch"), ("path", ".github/workflows/fake.yml"),
                           ("name", "Other"), ("workflow_id", 99)):
            with self.subTest(key=key):
                self.http.run = copy.deepcopy(RUN)
                self.http.run[key] = value
                self.blocked("identity mismatch")

    def test_foreign_run_repositories_block(self):
        for key in ("repository", "head_repository"):
            with self.subTest(key=key):
                self.http.run = copy.deepcopy(RUN)
                self.http.run[key] = {"full_name": "foreign/repository"}
                self.blocked("CI run repository identity mismatch")
                self.assertFalse(self.clock.sleeps)
                self.assertFalse(any("/jobs" in r.full_url for r, _ in self.http.requests))

    def test_missing_or_malformed_run_repositories_block(self):
        missing = object()
        for key in ("repository", "head_repository"):
            for value in (missing, None, [], "owner/repo", True, 1, {},
                          {"full_name": None}, {"full_name": []}, {"full_name": {}},
                          {"full_name": True}, {"full_name": 1}, {"full_name": ""},
                          {"full_name": "Owner/repo"}, {"full_name": "owner/Repo"},
                          {"full_name": "owner/repo "}):
                with self.subTest(key=key, value=value):
                    self.http.run = copy.deepcopy(RUN)
                    if value is missing:
                        self.http.run.pop(key)
                    else:
                        self.http.run[key] = value
                    self.blocked("^CI run repository identity mismatch$")
                    self.assertFalse(self.clock.sleeps)
                    self.assertFalse(any("/jobs" in r.full_url for r, _ in self.http.requests))

    def test_original_attempt_required_in_all_initial_run_states(self):
        missing = object()
        for status, conclusion in (("completed", "success"), ("queued", None),
                                   ("in_progress", None)):
            for value in (missing, None, True, False, 0, -1, "1", 1.0, 2, 3):
                with self.subTest(status=status, attempt=value):
                    self.http.run = copy.deepcopy(RUN)
                    self.http.run.update(status=status, conclusion=conclusion)
                    if value is missing:
                        self.http.run.pop("run_attempt")
                    else:
                        self.http.run["run_attempt"] = value
                    self.blocked("numeric identity|original attempt 1")
                    self.assertFalse(self.clock.sleeps)
                    self.assertFalse(any("/jobs" in r.full_url for r, _ in self.http.requests))

    def test_run_identity_drift_after_pending_retry_or_pagination_blocks(self):
        for seam in ("pending", "retry", "pagination"):
            for key in ("repository", "head_repository", "run_attempt"):
                with self.subTest(seam=seam, key=key):
                    self.clock, self.http, self.logs = FakeClock(), HTTP(), []
                    self.http.run.update(status="in_progress", conclusion=None)
                    job_pages = []
                    def handle(path, query):
                        if path.endswith("/jobs"):
                            job_pages.append(int(query["page"][0]))
                            if seam == "retry":
                                raise urllib.error.URLError("synthetic offline retry")
                            if seam == "pagination":
                                batch = JOBS[:2] if job_pages[-1] == 1 else JOBS[2:]
                                return io.BytesIO(json.dumps({"total_count": 3, "jobs": batch}).encode())
                    self.http.handler = handle
                    def advance(seconds):
                        FakeClock.sleep(self.clock, seconds)
                        self.http.run.update(status="completed", conclusion="success")
                        self.http.run[key] = 2 if key == "run_attempt" else {"full_name": "foreign/repository"}
                    self.clock.sleep = advance
                    self.blocked("attempt changed|repository identity mismatch")
                    self.assertEqual(self.http.polls, 2)
                    self.assertEqual(self.clock.sleeps, [2])
                    self.assertEqual(job_pages, [1, 2] if seam == "pagination" else [1])
                    if seam == "retry":
                        self.assertTrue(any("retrying within fixed deadline" in line for line in self.logs))

    def test_workflow_identity_fields_are_all_required(self):
        for key, value in (("name", "Other"), ("path", "ci.yml"), ("state", "disabled_manually"), ("id", True)):
            with self.subTest(key=key):
                self.http.workflow = copy.deepcopy(WORKFLOW)
                self.http.workflow[key] = value
                self.blocked()

    def test_wrong_tag_target_blocks(self):
        self.http.tag_sha = "b" * 40
        self.blocked("tag does not resolve")
        self.assertEqual(self.http.polls, 0)

    def test_wrong_tag_ref_blocks(self):
        self.http.handler = lambda p, q: io.BytesIO(json.dumps({"ref": "refs/heads/" + TAG,
            "object": {"type": "commit", "sha": SHA}}).encode()) if p.startswith("git/ref/") else None
        self.blocked("tag ref mismatch")

    def test_annotated_tag_peels_to_exact_commit(self):
        tag_object = "c" * 40
        def handle(path, query):
            if path.startswith("git/ref/"):
                return io.BytesIO(json.dumps({"ref": "refs/tags/" + TAG,
                    "object": {"type": "tag", "sha": tag_object}}).encode())
            if path == "git/tags/" + tag_object:
                return io.BytesIO(json.dumps({"object": {"type": "commit", "sha": SHA}}).encode())
        self.http.handler = handle
        self.make().wait()
        self.assertTrue(self.logs[-1].startswith("PASS:"))

    def test_tag_rechecked_before_pass(self):
        def handle(path, query):
            if path.endswith("/jobs"):
                self.http.tag_sha = "b" * 40
        self.http.handler = handle
        self.blocked("tag does not resolve")

    def test_multiple_runs_are_ambiguous_not_latest_wins(self):
        other = dict(RUN, id=72)
        self.http.runs = [self.http.run, other]
        self.blocked("ambiguous")

    def test_absent_run_registration_wait_is_bounded(self):
        self.http.runs = []
        self.blocked("deadline")
        self.assertEqual(self.clock.now, 5)

    def test_no_checks_or_missing_job_never_pass(self):
        for rows in ([], copy.deepcopy(JOBS[:2])):
            with self.subTest(count=len(rows)):
                self.http.jobs = rows
                self.blocked("missing required jobs")

    def test_pending_run_can_register_missing_jobs(self):
        self.http.run.update(status="queued", conclusion=None)
        self.http.jobs = []
        original_sleep = FakeClock.sleep
        def advance(seconds):
            original_sleep(self.clock, seconds)
            self.http.run = copy.deepcopy(RUN)
            self.http.jobs = copy.deepcopy(JOBS)
        self.clock.sleep = advance
        self.make().wait()
        self.assertEqual(self.clock.sleeps, [2])

    def test_duplicate_extra_and_wrong_job_identity_block(self):
        variants = [JOBS + [dict(JOBS[0], id=201)], JOBS + [dict(JOBS[0], id=201, name="extra")],
                    [dict(JOBS[0], head_sha="b" * 40)] + JOBS[1:],
                    [dict(JOBS[0], run_id=72)] + JOBS[1:]]
        for rows in variants:
            with self.subTest(rows=rows):
                self.http.jobs = copy.deepcopy(rows)
                self.blocked()

    def test_unknown_or_inconsistent_status_blocks(self):
        for status, conclusion in (("unknown", None), ("queued", "success")):
            self.http.jobs[0].update(status=status, conclusion=conclusion)
            self.blocked("malformed state")

    def test_first_observed_attempt_two_blocks(self):
        self.http.run["run_attempt"] = 2
        # Serve valid attempt-two jobs, reproducing preflight's actual wait() gap.
        self.http.handler = lambda p, q: io.BytesIO(json.dumps({
            "total_count": len(self.http.jobs), "jobs": self.http.jobs,
        }).encode()) if p == "actions/runs/71/attempts/2/jobs" else None
        self.blocked("CI run must use original attempt 1")
        self.assertFalse(self.clock.sleeps)
        self.assertFalse(any("/jobs" in r.full_url for r, _ in self.http.requests))

    def test_run_attempt_change_does_not_replay_acceptance(self):
        self.http.jobs[0].update(status="queued", conclusion=None)
        original_sleep = FakeClock.sleep
        def advance(seconds):
            original_sleep(self.clock, seconds)
            self.http.run["run_attempt"] = 2
        self.clock.sleep = advance
        self.blocked("attempt changed")

    def test_observed_run_cannot_disappear(self):
        self.http.jobs[0].update(status="queued", conclusion=None)
        original_sleep = FakeClock.sleep
        def advance(seconds):
            original_sleep(self.clock, seconds)
            self.http.runs = []
        self.clock.sleep = advance
        self.blocked("disappeared")

    def test_paginates_declared_job_count(self):
        pages = []
        def handle(path, query):
            if path.endswith("/jobs"):
                page = int(query["page"][0])
                pages.append(page)
                batch = JOBS[:2] if page == 1 else JOBS[2:]
                return io.BytesIO(json.dumps({"total_count": 3, "jobs": batch}).encode())
        self.http.handler = handle
        self.make().wait()
        self.assertEqual(pages, [1, 2])

    def test_paginates_runs_and_finds_ambiguity_on_later_page(self):
        def handle(path, query):
            if path.endswith("/runs"):
                page = int(query["page"][0])
                return io.BytesIO(json.dumps({"total_count": 2,
                    "workflow_runs": [dict(RUN, id=70 + page)]}).encode())
        self.http.handler = handle
        self.blocked("ambiguous")

    def test_malformed_pagination_and_json_fail_closed(self):
        for data in ({"total_count": True, "jobs": JOBS}, {"total_count": 4, "jobs": []},
                     {"total_count": 1, "jobs": JOBS}, {"total_count": 1, "jobs": [None]},
                     {"total_count": 2, "jobs": [JOBS[0], JOBS[0]]}, [], "invalid"):
            with self.subTest(data=data):
                raw = b"not JSON" if data == "invalid" else json.dumps(data).encode()
                self.http.handler = lambda p, q, raw=raw: io.BytesIO(raw) if p.endswith("/jobs") else None
                self.blocked()

    def test_changed_pagination_count_fails_closed(self):
        def handle(path, query):
            if path.endswith("/jobs"):
                page = int(query["page"][0])
                return io.BytesIO(json.dumps({"total_count": 3 if page == 1 else 4,
                    "jobs": JOBS[:2] if page == 1 else JOBS[2:]}).encode())
        self.http.handler = handle
        self.blocked("count changed")

    def test_http_unavailable_retries_only_within_original_deadline(self):
        def unavailable(path, query):
            raise urllib.error.HTTPError("https://api.github.com", 503, "Unavailable", {}, io.BytesIO(b"fixture"))
        self.http.handler = unavailable
        self.blocked("deadline")
        self.assertEqual(self.clock.now, 5)
        self.assertEqual(len(self.http.requests), 3)
        self.assertEqual(self.clock.sleeps, [2, 2, 1])

    def test_transport_recovery_and_rate_limit_can_pass(self):
        for failure in (urllib.error.URLError("offline"), TimeoutError(),
                        urllib.error.HTTPError("https://api.github.com", 429, "rate limited", {}, io.BytesIO(b"fixture"))):
            with self.subTest(failure=type(failure).__name__):
                self.clock = FakeClock()
                self.http = HTTP()
                remaining = [failure]
                def once(path, query):
                    if remaining:
                        raise remaining.pop()
                self.http.handler = once
                self.make().wait()
                self.assertEqual(self.clock.sleeps, [2])

    def test_auth_and_nonretryable_http_errors_fail_immediately(self):
        for status in (401, 403, 404, 422):
            def unavailable(path, query):
                raise urllib.error.HTTPError("https://api.github.com", status, "Denied", {}, io.BytesIO(b"fixture"))
            self.http.handler = unavailable
            self.blocked("HTTP " + str(status))
            self.assertFalse(self.clock.sleeps)

    def test_http_error_closes_response_body_and_preserves_classification(self):
        class Body(io.BytesIO):
            def __init__(self):
                super().__init__(b"fixture")
                self.close_calls = 0

            def close(self):
                self.close_calls += 1
                super().close()

        for status in (401, 403, 404, 422, 429, 500, 503, 999):
            for has_body in (False, True):
                with self.subTest(status=status, has_body=has_body):
                    body = Body() if has_body else None
                    error = urllib.error.HTTPError("https://api.github.com", status, "fixture", {}, body)
                    self.http.handler = mock.Mock(side_effect=error)
                    expected = gate.Unavailable if status == 429 or 500 <= status <= 599 else gate.GateError
                    with self.assertRaisesRegex(expected, "HTTP " + str(status)):
                        self.make().get("fixture")
                    if body is not None:
                        self.assertTrue(body.closed)
                        self.assertEqual(body.close_calls, 1)
                        # Repeated HTTPError cleanup is idempotent, not a second body close.
                        error.close()
                        self.assertEqual(body.close_calls, 1)
                    self.assertFalse(self.clock.sleeps)
                    self.assertFalse(any(line.startswith("PASS:") for line in self.logs))

    def test_http_error_cleanup_failure_is_not_ignored(self):
        body = io.BytesIO(b"fixture")
        error = urllib.error.HTTPError("https://api.github.com", 503, "fixture", {}, body)
        self.http.handler = mock.Mock(side_effect=error)
        failure = OSError("fixture cleanup failed")
        with mock.patch.object(error, "close", side_effect=failure) as close:
            with self.assertRaises(OSError) as caught:
                self.make().get("fixture")
        self.assertIs(caught.exception, failure)
        close.assert_called_once_with()
        error.close()
        self.assertTrue(body.closed)
        self.assertFalse(self.clock.sleeps)

    def test_slow_reads_cannot_pass_after_deadline(self):
        def slow(path, query):
            self.clock.now += 6
        self.http.handler = slow
        self.blocked("deadline")

    def test_invalid_configuration_has_no_requests(self):
        for kwargs in ({"sha": "short"}, {"tag": "main"}, {"repository": "bad/repo/path"},
                       {"token": ""}, {"seconds": float("inf")}, {"interval": 0}):
            config = dict(repository="owner/repo", sha=SHA, tag=TAG, token="fake")
            config.update(kwargs)
            with self.assertRaises(gate.GateError):
                gate.Gate(**config, opener=self.http)
        self.assertFalse(self.http.requests)

    def test_cli_failure_exit_code_and_no_secret_in_output(self):
        with mock.patch.dict("os.environ", {}, clear=True), mock.patch("sys.argv", ["gate"]), mock.patch("sys.stderr", new_callable=io.StringIO) as stderr:
            self.assertEqual(gate.main(), 1)
        self.assertIn("BLOCKED:", stderr.getvalue())

    def test_workflow_gates_publish_and_discovers_this_suite(self):
        workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/binary-release.yml").read_text()
        publish = workflow.split("\n  publish:\n", 1)[1]
        self.assertIn("actions: read", publish)
        self.assertIn("GITHUB_TOKEN: ${{ github.token }}", publish)
        self.assertLess(publish.index("python3 scripts/release_ci_gate.py"), publish.index('gh release upload'))
        self.assertLess(publish.index("python3 scripts/release_ci_gate.py"), publish.index('gh release create'))
        self.assertIn("python3 -m unittest discover -s scripts -p '*_test.py' -v", workflow)


if __name__ == "__main__":
    unittest.main(verbosity=2)

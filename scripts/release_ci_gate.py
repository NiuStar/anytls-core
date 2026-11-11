#!/usr/bin/env python3
"""Read-only, fail-closed publication gate for the exact tag push's CI matrix."""
import argparse
import json
import math
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

WORKFLOW_PATH = ".github/workflows/ci.yml"
WORKFLOW_NAME = "CI"
EXPECTED_JOBS = frozenset({
    "test (macos-15)", "test (macos-15-intel)",
})
PENDING = {"queued", "in_progress", "waiting", "requested", "pending"}
REQUIRED_STEPS = (
    'Checkout', 'Setup Go', 'Pin wrapper toolchain and cache paths',
    'Real Box patch regression', 'Patched wrapper regressions',
    'Installer safety and preservation regressions', 'Non-race Go tests',
    'Offline full-race CI contract regressions', 'Full unfiltered native race qualification',
    'Preserve full-race evidence on every platform', 'Go vet', 'Prepare dist', 'Build Go core',
    'Build actual native macOS app and all five Swift fixtures',
    'Run native Swift suites without production installation or WAN',
    'Preserve native evidence even on AppKit/GUI or assertion failure',
    'Audit mandatory gates and scoped Intel race waiver',
)
# Only these GitHub-generated lifecycle steps may surround source-owned steps.
HOUSEKEEPING = frozenset({'Set up job', 'Post Setup Go', 'Post Checkout', 'Complete job'})


class GateError(Exception):
    """Unacceptable or unverifiable evidence; publication must not proceed."""


class Unavailable(Exception):
    """Retryable read-only transport failure, within the original deadline."""


def positive_id(value):
    if type(value) is not int or value <= 0:
        raise GateError("missing or invalid numeric identity")
    return value


class Gate:
    def __init__(self, repository, sha, tag, token, seconds=1800, interval=15,
                 *, opener=None, clock=time.monotonic, sleep=time.sleep,
                 log=print):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
            raise GateError("invalid repository")
        if not re.fullmatch(r"[0-9a-f]{40}", sha):
            raise GateError("expected exact lowercase 40-character commit SHA")
        if not re.fullmatch(r"(?:v[0-9]+\.[0-9]+\.[0-9]+|v[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{2})", tag):
            raise GateError("unsupported release tag")
        if not token:
            raise GateError("GITHUB_TOKEN is required")
        if not all(math.isfinite(v) and v > 0 for v in (seconds, interval)):
            raise GateError("deadline and poll interval must be finite and positive")
        self.repository = repository
        self.base = "https://api.github.com/repos/" + repository + "/"
        self.sha, self.tag, self.token = sha, tag, token
        self.clock, self.sleep, self.log = clock, sleep, log
        self.deadline, self.interval = clock() + seconds, interval
        self.opener = opener if opener is not None else urllib.request.build_opener()
        self.run_identity = None
        self.workflow_id = None

    def remaining(self):
        left = self.deadline - self.clock()
        if left <= 0:
            raise GateError("deadline expired without verified terminal CI success")
        return left

    def get(self, path):
        request = urllib.request.Request(self.base + path, method="GET", headers={
            "Authorization": "Bearer " + self.token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "anytls-release-ci-gate",
            "Cache-Control": "no-cache",
        })
        try:
            with self.opener.open(request, timeout=min(20, self.remaining())) as response:
                data = json.load(response)
        except urllib.error.HTTPError as exc:
            status = exc.code
            # Bodyless HTTPError is valid, but Python 3.9 cannot close its wrapper.
            if exc.fp is not None:
                exc.close()
            if status == 429 or 500 <= status <= 599:
                raise Unavailable("GitHub HTTP " + str(status)) from exc
            raise GateError("GitHub HTTP " + str(status)) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise Unavailable(type(exc).__name__) from exc
        except (ValueError, UnicodeError) as exc:
            raise GateError("malformed GitHub JSON") from exc
        self.remaining()
        if not isinstance(data, dict):
            raise GateError("expected GitHub JSON object")
        return data

    def pages(self, path, key):
        rows, total, page = [], None, 1
        while True:
            separator = "&" if "?" in path else "?"
            data = self.get(path + separator + "per_page=100&page=" + str(page))
            count, batch = data.get("total_count"), data.get(key)
            if type(count) is not int or count < 0 or not isinstance(batch, list):
                raise GateError("malformed pagination")
            if total is not None and count != total:
                raise GateError("pagination count changed during read")
            total = count
            if len(batch) > 100 or any(not isinstance(row, dict) for row in batch):
                raise GateError("malformed page rows")
            rows.extend(batch)
            ids = [positive_id(row.get("id")) for row in rows]
            if len(set(ids)) != len(ids) or len(rows) > total:
                raise GateError("duplicate rows or inconsistent declared count")
            if len(rows) == total:
                return rows
            if not batch:
                raise GateError("empty page before declared count")
            page += 1

    def verify_tag(self):
        ref = self.get("git/ref/tags/" + urllib.parse.quote(self.tag, safe=""))
        if ref.get("ref") != "refs/tags/" + self.tag:
            raise GateError("tag ref mismatch")
        obj = ref.get("object")
        seen = set()
        for _ in range(8):
            if not isinstance(obj, dict) or not re.fullmatch(r"[0-9a-f]{40}", str(obj.get("sha", ""))):
                raise GateError("malformed tag object")
            sha, kind = obj["sha"], obj.get("type")
            if kind == "commit":
                if sha != self.sha:
                    raise GateError("tag does not resolve to release SHA")
                return
            if kind != "tag" or sha in seen:
                raise GateError("invalid tag object chain")
            seen.add(sha)
            obj = self.get("git/tags/" + sha).get("object")
        raise GateError("tag object chain too deep")

    @staticmethod
    def terminal(row, label):
        status, conclusion = row.get("status"), row.get("conclusion")
        if status == "completed":
            if conclusion != "success":
                raise GateError(label + " terminal non-success: " + str(conclusion))
            return True
        if status not in PENDING or conclusion is not None:
            raise GateError(label + " malformed state")
        return False

    def observe(self):
        self.verify_tag()
        workflow = self.get("actions/workflows/ci.yml")
        workflow_id = positive_id(workflow.get("id"))
        if (workflow.get("path") != WORKFLOW_PATH or workflow.get("name") != WORKFLOW_NAME
                or workflow.get("state") != "active"):
            raise GateError("CI workflow identity mismatch")
        if self.workflow_id is not None and workflow_id != self.workflow_id:
            raise GateError("CI workflow identity changed")
        self.workflow_id = workflow_id
        query = urllib.parse.urlencode({"head_sha": self.sha, "event": "push", "branch": self.tag})
        runs = self.pages("actions/workflows/" + str(workflow_id) + "/runs?" + query, "workflow_runs")
        if len(runs) > 1:
            raise GateError("ambiguous CI runs for release tag push")
        if not runs:
            if self.run_identity is not None:
                raise GateError("previously observed CI run disappeared")
            return False
        run = runs[0]
        for key in ("repository", "head_repository"):
            repository = run.get(key)
            if not isinstance(repository, dict) or repository.get("full_name") != self.repository:
                raise GateError("CI run repository identity mismatch")
        if any(run.get(key) != expected for key, expected in {
            "workflow_id": workflow_id, "path": WORKFLOW_PATH, "name": WORKFLOW_NAME,
            "head_sha": self.sha, "head_branch": self.tag, "event": "push",
        }.items()):
            raise GateError("CI run SHA/tag/push/workflow identity mismatch")
        identity = (positive_id(run.get("id")), positive_id(run.get("run_attempt")))
        if self.run_identity is not None and identity != self.run_identity:
            raise GateError("CI run or attempt changed during gate")
        if identity[1] != 1:
            raise GateError("CI run must use original attempt 1")
        self.run_identity = identity
        run_done = self.terminal(run, "CI run")
        run_id, attempt = identity
        jobs = self.pages(f"actions/runs/{run_id}/attempts/{attempt}/jobs", "jobs")
        names = [job.get("name") for job in jobs]
        if any(not isinstance(name, str) for name in names):
            raise GateError("malformed CI job name")
        if len(set(names)) != len(names) or set(names) - EXPECTED_JOBS:
            raise GateError("unexpected or duplicate CI jobs")
        jobs_done = True
        for job in jobs:
            if job.get("run_id") != run_id or job.get("head_sha") != self.sha:
                raise GateError("CI job run/SHA identity mismatch")
            # Do not short-circuit: any failed job is immediately fatal.
            done = self.terminal(job, job["name"])
            if done:
                self.verify_steps(job)
            jobs_done = done and jobs_done
        exact = set(names) == EXPECTED_JOBS
        if run_done and not exact:
            raise GateError("completed CI run missing required jobs (no checks is not success)")
        self.log(json.dumps({"run_id": run_id, "attempt": attempt,
                             "run_completed": run_done, "jobs": [
                                 {k: j.get(k) for k in ("id", "name", "status", "conclusion")}
                                 for j in jobs]}, sort_keys=True))
        if run_done and exact and jobs_done:
            self.verify_tag()
            return True
        return False

    @staticmethod
    def verify_steps(job):
        steps = job.get('steps')
        if not isinstance(steps, list) or not steps:
            raise GateError('missing CI step inventory')
        names, numbers = [], []
        for step in steps:
            if not isinstance(step, dict):
                raise GateError('malformed CI step inventory')
            name, number = step.get('name'), step.get('number')
            if not isinstance(name, str) or name not in (*REQUIRED_STEPS, *HOUSEKEEPING):
                raise GateError('unexpected CI step')
            if type(number) is not int or number <= 0:
                raise GateError('malformed CI step number')
            if step.get('status') != 'completed' or step.get('conclusion') != 'success':
                raise GateError('required CI step non-success')
            names.append(name)
            numbers.append(number)
        if (len(names) != len(set(names)) or numbers != sorted(set(numbers)) or
                tuple(name for name in names if name not in HOUSEKEEPING) != REQUIRED_STEPS):
            raise GateError('incomplete or reordered CI step inventory')

    def wait(self):
        while True:
            self.remaining()
            try:
                if self.observe():
                    self.remaining()
                    self.log("PASS: exact tag push CI and both required Mac jobs with mandatory audit completed successfully; race disposition is separate")
                    return
            except Unavailable as exc:
                self.log("CI read unavailable; retrying within fixed deadline: " + str(exc))
            self.sleep(min(self.interval, self.remaining()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", ""))
    parser.add_argument("--sha", default=os.environ.get("GITHUB_SHA", ""))
    parser.add_argument("--tag", default=os.environ.get("GITHUB_REF_NAME", ""))
    parser.add_argument("--seconds", type=float, default=1800)
    parser.add_argument("--interval", type=float, default=15)
    args = parser.parse_args()
    try:
        Gate(args.repository, args.sha, args.tag, os.environ.get("GITHUB_TOKEN", ""),
             args.seconds, args.interval).wait()
    except GateError as exc:
        print("BLOCKED: " + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

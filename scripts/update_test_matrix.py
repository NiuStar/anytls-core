"""UNIT matrix: simulate platform defaults; never execute release binaries."""
import contextlib
import io
import json
import platform
from pathlib import Path
import sys
import unittest
from unittest import mock

root = Path(__file__).resolve().parents[1]
out = root / "artifacts/web-prebuilt-update-v1/python-logs"
records = []
for machine in (None, "arm64", "x86_64"):
    label = "linux" if machine is None else "darwin-" + machine
    suite = unittest.defaultTestLoader.discover(str(root / "scripts"), pattern="*_test.py")
    with (out / (label + "-final.log")).open("w") as log, contextlib.ExitStack() as stack:
        if machine:
            stack.enter_context(mock.patch.object(platform, "system", return_value="Darwin"))
            stack.enter_context(mock.patch.object(platform, "machine", return_value=machine))
        stack.enter_context(contextlib.redirect_stdout(log))
        stack.enter_context(contextlib.redirect_stderr(log))
        result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
        records.append({"label": label, "tests": result.testsRun, "failures": len(result.failures),
                        "errors": len(result.errors), "skipped": len(result.skipped), "rc": 0 if result.wasSuccessful() else 1})
print(json.dumps(records, indent=2))
raise SystemExit(any(item["rc"] for item in records))

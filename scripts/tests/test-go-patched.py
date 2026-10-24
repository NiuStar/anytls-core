#!/usr/bin/env python3
"""Validation-only tests. Real cached box.go; no fabricated Go responses."""
import ast
import base64
import shutil
import hashlib
import importlib.util
import io
import stat
import zipfile
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "go-patched.py"
spec = importlib.util.spec_from_file_location("go_patched", SCRIPT)
wrapper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wrapper)
core_spec = importlib.util.spec_from_file_location("core_slim_tests", SCRIPT.with_name("core_slim_test.py"))
core_tests = importlib.util.module_from_spec(core_spec)
core_spec.loader.exec_module(core_tests)
CoreSlimTests = core_tests.CoreSlimTests  # Existing explicit CI entry runs all patch contracts.
chrome_spec = importlib.util.spec_from_file_location("chrome_patch_tests", SCRIPT.parent / "tests/test-chrome-patched.py")
chrome_tests = importlib.util.module_from_spec(chrome_spec)
chrome_spec.loader.exec_module(chrome_tests)
ChromePatchTests = chrome_tests.ChromePatchTests


class ValidationTests(unittest.TestCase):
    def setUp(self):
        self.manifest, self.patch = wrapper.identity()
        fixture = wrapper.ROOT / 'scripts/tests/fixtures/sing-box-v1.14.3/box.go.txt'
        self.source = fixture.read_bytes()
        self.assertEqual(wrapper.sha(self.source), self.manifest['source_sha256'])

    def test_real_source_exact_patch(self):
        result = wrapper.transform(self.source, self.manifest, self.patch)
        self.assertEqual(wrapper.sha(result), self.manifest["result_sha256"])
        self.assertIn(b"return errors.Join(err, s.Close())", result)
        self.assertIn(b'\t"errors"\n', result)

    def test_wrong_source_rejected(self):
        with self.assertRaisesRegex(ValueError, "source SHA"):
            wrapper.transform(self.source + b"\n", self.manifest, self.patch)

    def test_patch_actually_controls_result(self):
        # Synthetic tampered patch, deliberately retaining the trusted result SHA.
        changed = self.patch.replace(b"errors.Join", b"errors.New")
        with self.assertRaisesRegex(ValueError, "patched source SHA"):
            wrapper.transform(self.source, self.manifest, changed)

    def test_changed_manifest_and_patch_rejected(self):
        base = os.environ.get("TMPDIR") or str(Path.home() / ".hermes/cache/scratch")
        with tempfile.TemporaryDirectory(prefix="anytls-wrapper-test-", dir=base) as tmp:
            root = Path(tmp)
            dest = root / "patches/sing-box"
            dest.mkdir(parents=True)
            manifest = wrapper.ROOT / "patches/sing-box/identity.json"
            (dest / "identity.json").write_bytes(manifest.read_bytes())
            (dest / "box-start.patch.json").write_bytes(self.patch + b"\n")
            with self.assertRaisesRegex(ValueError, "patch SHA"):
                wrapper.identity(root)
            (dest / "identity.json").write_bytes(manifest.read_bytes() + b"\n")
            with self.assertRaisesRegex(ValueError, "manifest SHA"):
                wrapper.identity(root)

    def test_synthetic_metadata_negatives(self):
        # These are validation fixtures only, never successful Go responses.
        fixture = {"Path": wrapper.MODULE, "Version": wrapper.VERSION,
                   "Sum": self.manifest["module_sum"], "GoModSum": self.manifest["go_mod_sum"]}
        for change in ({"Version": "v1.14.4"}, {"Replace": {"Dir": "/synthetic"}},
                       {"Sum": "h1:synthetic"}, {"Origin": {"Hash": "synthetic"}}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                wrapper.metadata(dict(fixture, **change), self.manifest)

    def test_explicit_tags_and_selection_preserved(self):
        env = dict(os.environ, GOTOOLCHAIN="local", GOFLAGS="", GOWORK="off")
        args = ["test", "-tags=with_gvisor", "-run", "^TestUTLSConstructor$", "./internal/engine"]
        with mock.patch.object(wrapper.Path, "is_file", return_value=True), mock.patch.object(wrapper.os, "access", return_value=True):
            _, actual, output = wrapper.arguments(args, dict(env, GO_BIN="/validation-only/go-not-executed"))
        self.assertEqual(actual, args)
        self.assertIsNone(output)

    @mock.patch.object(wrapper.Path, "is_file", return_value=True)
    @mock.patch.object(wrapper.os, "access", return_value=True)
    def test_unsupported_invocations_rejected(self, _access, _is_file):
        env = dict(os.environ, GOTOOLCHAIN="local", GOFLAGS="", GOWORK="off",
                   GO_BIN="/validation-only/go-not-executed")
        for args in (["run", "."], ["test", "-overlay=other.json", "./..."],
                     ["test", "-modfile=other.mod", "./..."], ["test", "-run"],
                     ["build", "."], ["test", "example.com/foreign@v1"]):
            with self.subTest(args=args), self.assertRaises(ValueError):
                wrapper.arguments(args, env)
        for change in ({"GOFLAGS": "-overlay=other.json"}, {"GOTOOLCHAIN": "auto"},
                       {"GO_BIN": "go"}, {"GOWORK": "/synthetic/go.work"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                wrapper.arguments(["test", "./..."], dict(env, **change))


class ArchiveTests(unittest.TestCase):
    """Synthetic ZIP staging only: no fake Go invocations or success receipts."""

    def archive(self, entries):
        data = io.BytesIO()
        with zipfile.ZipFile(data, "w") as z:
            for name, content, mode in entries:
                item = zipfile.ZipInfo(name)
                item.external_attr = mode << 16
                z.writestr(item, content)
        return data.getvalue()

    def check(self, entries, expected=None):
        raw = self.archive(entries)
        # Independent, explicit dirhash formula for synthetic content.
        if expected is None:
            lines = b"".join((hashlib.sha256(content).hexdigest() + "  " + name + "\n").encode()
                             for name, content, _ in sorted(entries) if not name.endswith("/"))
            expected = "h1:" + base64.b64encode(hashlib.sha256(lines).digest()).decode()
        base = os.environ.get("TMPDIR") or str(Path.home() / ".hermes/cache/scratch")
        with tempfile.TemporaryDirectory(prefix="anytls-archive-test-", dir=base) as tmp:
            archive = Path(tmp) / "module.zip"
            archive.write_bytes(raw)
            dest = Path(tmp) / "source"
            dest.mkdir()
            result = wrapper.stage_archive(archive, dest, expected)
            return result, {str(p.relative_to(dest)): p.read_bytes() for p in dest.rglob("*") if p.is_file()}

    def test_synthetic_sorted_h1_and_directory_exclusion(self):
        prefix = wrapper.MODULE + "@" + wrapper.VERSION + "/"
        result, files = self.check([(prefix + "z", b"last", stat.S_IFREG | 0o644),
                                    (prefix + "dir/", b"", stat.S_IFDIR | 0o755),
                                    (prefix + "dir/a", b"first", stat.S_IFREG | 0o644)])
        self.assertEqual(files, {"z": b"last", "dir/a": b"first"})
        self.assertEqual(result["files"], 2)
        self.assertEqual(result["bytes"], 9)

    def test_synthetic_wrong_hash(self):
        with self.assertRaisesRegex(ValueError, "archive h1"):
            self.check([(wrapper.MODULE + "@" + wrapper.VERSION + "/a", b"x", stat.S_IFREG)], "h1:wrong")

    def test_synthetic_unsafe_zip_paths_and_types(self):
        prefix = wrapper.MODULE + "@" + wrapper.VERSION + "/"
        for name, mode in [("/absolute", stat.S_IFREG), (prefix + "../escape", stat.S_IFREG),
                           (prefix + "a/../../escape", stat.S_IFREG), (prefix + "a\\b", stat.S_IFREG),
                           (prefix + "a\nb", stat.S_IFREG), (prefix + "a//b", stat.S_IFREG),
                           (prefix + "./a", stat.S_IFREG), (prefix + "link", stat.S_IFLNK),
                           (prefix + "fifo", stat.S_IFIFO), (prefix.replace("v1.14.3", "v1.14.4") + "a", stat.S_IFREG)]:
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.check([(name, b"synthetic", mode)])

    def test_synthetic_duplicate_and_file_directory_conflict(self):
        prefix = wrapper.MODULE + "@" + wrapper.VERSION + "/"
        for names in [("a", "a"), ("a", "a/b")]:
            with self.subTest(names=names), self.assertRaises(ValueError):
                self.check([(prefix + name, b"x", stat.S_IFREG) for name in names])

    def test_synthetic_bounded_before_extract(self):
        old = wrapper.MAX_ARCHIVE_BYTES
        wrapper.MAX_ARCHIVE_BYTES = 4
        try:
            with self.assertRaisesRegex(ValueError, "archive size"):
                self.check([(wrapper.MODULE + "@" + wrapper.VERSION + "/a", b"12345", stat.S_IFREG)])
        finally:
            wrapper.MAX_ARCHIVE_BYTES = old


class OutputReservationTests(unittest.TestCase):
    """Execute the actual publisher/cleanup blocks on real files, without Go stubs."""

    def setUp(self):
        tree = ast.parse(SCRIPT.read_text())
        main = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "main")
        transaction = next(n for n in main.body if isinstance(n, ast.Try))
        publish = transaction.body[-1]
        self.assertIsInstance(publish, ast.If)
        self.publish = compile(ast.Module(body=[publish], type_ignores=[]), str(SCRIPT), "exec")
        self.cleanup = compile(ast.Module(body=transaction.finalbody, type_ignores=[]), str(SCRIPT), "exec")
        base = os.environ.get("TMPDIR") or str(Path.home() / ".hermes/cache/scratch")
        self.tmp = tempfile.TemporaryDirectory(prefix="anytls-output-test-", dir=base)
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        output = root / "artifact"
        reservation = output.open("xb")
        self.addCleanup(reservation.close)
        work = root / "work"
        work.mkdir()
        private = work / "output"
        private.write_bytes(b"real file publication probe\n")
        private.chmod(0o700)
        source = root / "source"
        source.write_bytes(b"unchanged")
        self.ctx = dict(output=output, reservation=reservation, work=work, private_output=private,
                        rc=0, published=False, receipt={}, source=source, original=b"unchanged",
                        cache_debug=source, original_debug=b"unchanged",
                        cache_chrome=source, original_chrome=b"unchanged",
                        root_inputs={}, ROOT=root, os=os, shutil=shutil,
                        require=wrapper.require, sha=wrapper.sha)

    def test_python39_nofollow_api(self):
        tree = ast.parse(SCRIPT.read_text())
        incompatible = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
                        and isinstance(n.func, ast.Attribute) and n.func.attr == "stat"
                        and any(k.arg == "follow_symlinks" for k in n.keywords)]
        self.assertEqual(incompatible, [], "Path.stat(follow_symlinks=...) requires Python 3.10")

    def test_publish_reserved_inode(self):
        exec(self.publish, self.ctx)
        self.assertTrue(self.ctx["published"])
        self.assertEqual(self.ctx["output"].read_bytes(), self.ctx["private_output"].read_bytes())
        self.assertEqual(self.ctx["output"].stat().st_mode & 0o777, 0o700)
        exec(self.cleanup, self.ctx)
        self.assertTrue(self.ctx["output"].is_file())
        self.assertFalse(self.ctx["work"].exists())

    def test_failure_removes_only_owned_output(self):
        self.ctx["rc"] = 1
        exec(self.publish, self.ctx)
        exec(self.cleanup, self.ctx)
        self.assertFalse(self.ctx["output"].exists())
        self.assertFalse(self.ctx["work"].exists())

    def test_symlink_and_replacement_inode_refused_and_preserved(self):
        output = self.ctx["output"]
        target = output.parent / "other"
        target.write_bytes(b"do not modify")
        for symlink in (True, False):
            with self.subTest(symlink=symlink):
                if output.exists() or output.is_symlink():
                    output.unlink()
                if symlink:
                    output.symlink_to(target)
                else:
                    output.write_bytes(b"replacement inode")
                before = output.read_bytes()
                with self.assertRaisesRegex(ValueError, "output reservation changed"):
                    exec(self.publish, self.ctx)
                self.assertEqual(output.read_bytes(), before)
        exec(self.cleanup, self.ctx)
        self.assertEqual(output.read_bytes(), b"replacement inode")
        self.assertEqual(target.read_bytes(), b"do not modify")

    def test_failure_preserves_symlink(self):
        output = self.ctx["output"]
        target = output.parent / "other"
        target.write_bytes(b"do not modify")
        output.unlink()
        output.symlink_to(target)
        exec(self.cleanup, self.ctx)
        self.assertTrue(output.is_symlink())
        self.assertEqual(target.read_bytes(), b"do not modify")


if __name__ == "__main__":
    unittest.main(verbosity=2)

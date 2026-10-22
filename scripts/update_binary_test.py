"""UNIT-SIMULATED: real files, in-memory HTTP, no network/candidate execution."""
import contextlib
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import socket
import subprocess
import types
import unittest
from unittest import mock
import tempfile

SOURCE = Path(os.environ.get("UPDATE_SOURCE_DIR", Path(__file__).parent))
spec = importlib.util.spec_from_file_location("update_installer", SOURCE / "install-binary.py")
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)


class BackupTests(unittest.TestCase):
    def test_backup_sha_readback_precedes_publish(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = Path(tmp)
            target, candidate = app / "anytls", app / "candidate"
            target.write_bytes(b"old executable")
            candidate.write_bytes(b"new executable")
            opened = Path.open
            replaced = []
            def corrupt_read(path, mode="r", *args, **kwargs):
                if path.parent.name == "backups" and mode == "rb":
                    return io.BytesIO(b"corrupt backup")
                return opened(path, mode, *args, **kwargs)
            try:
                with mock.patch.object(Path, "open", corrupt_read):
                    b.i.publish_binary(candidate, target, app, replace=lambda *a: replaced.append(a))
            except ValueError:
                pass
            self.assertEqual(replaced, [], "backup SHA must be independently verified BEFORE replace")
            self.assertEqual(target.read_bytes(), b"old executable")
            self.assertEqual(candidate.read_bytes(), b"new executable")


# Reuse the established archive fixture, but run only this module's tests.
fixture_spec = importlib.util.spec_from_file_location("update_fixture", Path(__file__).with_name("install_binary_test.py"))
f = importlib.util.module_from_spec(fixture_spec)
fixture_spec.loader.exec_module(f)
f.b = b


class UpdateTests(unittest.TestCase):
    def setUp(self):
        self.fixture = f.InstallerTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.app.mkdir()
        self.app = self.fixture.app
        self.target = self.app / "anytls-macos"
        self.target.write_bytes(b"old executable")
        self.protected = {}
        for name in ("config.yaml", "config.selected", "subscription.json", "webui-password", "auth.json"):
            path = self.app / name
            path.write_bytes(b"private unchanged " + name.encode())
            self.protected[path] = (path.read_bytes(), path.stat().st_mode, path.stat().st_ino)
        self.args = types.SimpleNamespace(update_only=True, app_dir=str(self.app), target=str(self.target),
                                          update_arch="arm64", version=f.TAG, check_download=False, arch=None)
        self.processes = []
        def runner(args, **kwargs):
            self.assertEqual(args[1:], ["version"], "only bounded version probes are permitted")
            self.assertEqual(kwargs["timeout"], 20)
            self.processes.append(args)
            return types.SimpleNamespace(stdout=(f.TAG + "\n").encode())
        self.runner = runner
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(b, "install_verified", side_effect=AssertionError("full installer forbidden")).start()
        mock.patch.object(b, "configure_shell_path", side_effect=AssertionError("PATH writes forbidden")).start()
        mock.patch.object(b.i, "install_config", side_effect=AssertionError("config writes forbidden")).start()

    def update(self, **kwargs):
        return b.run(self.args, transport=kwargs.pop("transport", self.fixture.transport),
                     runner=kwargs.pop("runner", self.runner), system="Darwin", machine="arm64",
                     euid=501, home=self.fixture.home, env={"HOME": str(self.fixture.home), "PATH": ""}, **kwargs)

    def assert_protected(self):
        for path, expected in self.protected.items():
            self.assertEqual((path.read_bytes(), path.stat().st_mode, path.stat().st_ino), expected)

    def test_update_only_keeps_private_state_and_retains_verified_materials(self):
        result = self.update()
        self.assertEqual(result["version"], f.TAG)
        self.assertEqual(result["status"], "UPDATED")
        self.assertTrue(result["restartRequired"])
        self.assertEqual(self.target.read_bytes(), f.BINARY)
        self.assertEqual(len(self.processes), 2)
        self.assertEqual(next((self.app / "backups").iterdir()).read_bytes(), b"old executable")
        kept = next((self.app / "releases").iterdir())
        for name, raw in (("SHA256SUMS", self.fixture.sums.encode()),
                          (self.fixture.source_name, self.fixture.source),
                          (self.fixture.ccs_name, self.fixture.source),
                          (self.fixture.binary_name, self.fixture.binary_archive)):
            self.assertEqual(hashlib.sha256((kept / name).read_bytes()).hexdigest(), hashlib.sha256(raw).hexdigest())
        self.assert_protected()
        self.fixture.webui_factory.assert_not_called()
        self.assertFalse((self.fixture.home / ".local").exists())


    def assert_code(self, code, action):
        with self.assertRaises(b.UpdateFailed) as caught:
            action()
        self.assertEqual(caught.exception.code, code)
        self.assert_protected()

    def test_legacy_target(self):
        self.target.rename(self.app / "anytls")
        self.target = self.app / "anytls"
        self.args.target = str(self.target)
        self.update()
        self.assertEqual(self.target.read_bytes(), f.BINARY)
        self.assertFalse((self.app / "anytls-macos").exists())

    def test_symlink_app_and_target_rejected(self):
        self.target.unlink()
        self.target.symlink_to(self.app / "config.yaml")
        self.assert_code(44, self.update)
        self.target.unlink()
        self.target.write_bytes(b"old executable")
        alias = self.app.parent / "alias"
        alias.symlink_to(self.app, target_is_directory=True)
        self.args.app_dir, self.args.target = str(alias), str(alias / self.target.name)
        self.assert_code(44, self.update)
        self.assertFalse(self.fixture.calls)

    def test_missing_target_and_outside_target_rejected(self):
        self.target.unlink()
        self.assert_code(44, self.update)
        self.args.target = str(self.app.parent / "anytls")
        self.assert_code(44, self.update)

    def test_missing_package_typed_42_duplicate_or_bad_url_44(self):
        original = list(self.fixture.release["assets"])
        self.fixture.release["assets"] = original[1:]
        self.assert_code(42, self.update)
        self.fixture.release["assets"] = original + [original[0]]
        self.assert_code(44, self.update)
        self.fixture.release["assets"] = original[1:]
        self.fixture.release["assets"][1]["browser_download_url"] = "https://evil.invalid/SECRET"
        self.assert_code(44, self.update)

    def test_network_open_and_read_are_43_disk_write_is_45(self):
        def fail(*args):
            raise OSError("SECRET")
        self.assert_code(43, lambda: self.update(transport=fail))
        class Broken(io.BytesIO):
            def read(self, *args):
                raise OSError("SECRET")
        self.assert_code(43, lambda: self.update(transport=lambda *a: Broken()))
        opened = Path.open
        def disk_error(path, mode="r", *a, **kw):
            if path.name == "SHA256SUMS" and mode == "xb":
                raise OSError("SECRET")
            return opened(path, mode, *a, **kw)
        with mock.patch.object(Path, "open", disk_error):
            self.assert_code(45, self.update)

    def test_pre_post_version_failure_and_timeout_stage(self):
        for phase, code in ((1, 44), (2, 46)):
            for timeout in (False, True):
                with self.subTest(phase=phase, timeout=timeout):
                    self.target.write_bytes(b"old executable")
                    count = [0]
                    def runner(args, **kw):
                        count[0] += 1
                        if count[0] == phase:
                            if timeout:
                                raise subprocess.TimeoutExpired(args, 20)
                            return types.SimpleNamespace(stdout=b"SECRET wrong-version")
                        return self.runner(args, **kw)
                    self.assert_code(code, lambda: self.update(runner=runner))
                    self.assertEqual(self.target.read_bytes(), b"old executable" if phase == 1 else f.BINARY)

    def test_retained_sha_failure_never_executes_or_publishes(self):
        copy = b.shutil.copyfile
        def corrupt(src, dst, *a, **kw):
            result = copy(src, dst, *a, **kw)
            if Path(dst).name == "LICENSE":
                Path(dst).write_bytes(b"corrupt")
            return result
        with mock.patch.object(b.shutil, "copyfile", corrupt):
            self.assert_code(45, self.update)
        self.assertEqual(self.target.read_bytes(), b"old executable")
        self.assertFalse(self.processes)

    def test_publish_failure_45_unknown_47_and_fixed_stderr(self):
        with mock.patch.object(b.i, "publish_binary", side_effect=OSError("SECRET")):
            self.assert_code(45, self.update)
        with mock.patch.object(b, "verified_download", side_effect=RuntimeError("SECRET")):
            self.assert_code(47, self.update)
        argv = ["--update-only", "--app-dir", str(self.app), "--target", str(self.target),
                "--update-arch", "arm64", "--version", f.TAG]
        with mock.patch.object(b, "run", side_effect=b.UpdateFailed(46)), contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(b.main(argv), 46)
        self.assertNotIn("SECRET", err.getvalue())
        self.assertEqual(err.getvalue().strip(), "UPDATE_VERIFY_FAILED")

    def test_lock_is_nonblocking_and_fifo_open_has_nonblock(self):
        with b.installation_lock(self.app):
            self.assert_code(45, self.update)
        lock = self.app / ".install.lock"
        lock.unlink()
        os.mkfifo(lock)
        original = os.open
        flags_seen = []
        def guarded(path, flags, *a, **kw):
            if Path(path) == lock:
                flags_seen.append(flags)
                # Fail before a buggy blocking FIFO open can hang the suite.
                self.assertTrue(flags & os.O_NONBLOCK, "FIFO must be opened nonblocking")
            return original(path, flags, *a, **kw)
        with mock.patch.object(b.os, "open", guarded):
            self.assert_code(45, self.update)
        self.assertTrue(flags_seen)

    def test_pinned_amd64_on_arm64_does_not_redetect_hardware(self):
        self.args.update_arch = "amd64"
        with mock.patch.object(b, "detect_arch", side_effect=AssertionError("no hardware reselect")):
            self.assert_code(42, self.update)
        self.assertFalse(self.processes)

    def test_truncated_network_read_is_download_failure(self):
        import http.client
        class Broken(io.BytesIO):
            def read(self, *args):
                raise http.client.IncompleteRead(b"SECRET", 10)
        self.assert_code(43, lambda: self.update(transport=lambda *a: Broken()))

    def test_invalid_update_flags_have_fixed_code_and_no_input_echo(self):
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(b.main(["--update-only", "--version", "SECRET"]), 44)
        self.assertEqual(err.getvalue().strip(), "UPDATE_VALIDATION_FAILED")

    def test_pinned_amd64_success(self):
        self.args.update_arch = "amd64"
        self.fixture.prefix = f.NAME + "-darwin-amd64"
        self.fixture.binary_name = self.fixture.prefix + ".tar.gz"
        self.fixture.ccs_name = f.NAME + "-darwin-amd64-corresponding-source.tar.gz"
        binary = __import__("struct").pack("<IIIIIIII", 0xfeedfacf, 0x01000007, 0, 2, 0, 0, 0, 0) + b"unit fixture"
        self.fixture.files["bin/anytls-macos"] = binary
        self.fixture.info.update(platform="darwin-amd64", binary_sha256=hashlib.sha256(binary).hexdigest())
        self.fixture.files["BUILD-INFO.json"] = b.i.json.dumps(self.fixture.info).encode()
        self.fixture.release["assets"] = [{"name": name, "browser_download_url": self.fixture.url(name)} for name in (
            self.fixture.binary_name, self.fixture.source_name, self.fixture.ccs_name, "SHA256SUMS")]
        self.fixture.rebuild()
        self.assertEqual(self.update()["platform"], "darwin-amd64")
        self.assertEqual(self.target.read_bytes(), binary)
        self.assert_protected()

    def test_truncated_archive_is_validation_not_unknown(self):
        self.fixture.binary_archive = b"not gzip"
        self.fixture.sums = "".join(hashlib.sha256(raw).hexdigest() + "  " + name + "\n" for name, raw in (
            (self.fixture.binary_name, self.fixture.binary_archive), (self.fixture.source_name, self.fixture.source),
            (self.fixture.ccs_name, self.fixture.source)))
        self.assert_code(44, self.update)

    def test_missing_manifest_is_validation_not_storage(self):
        del self.fixture.files["BUILD-INFO.json"]
        self.fixture.rebuild()
        self.assert_code(44, self.update)

    def test_version_error_message_is_neutral_after_publish(self):
        with self.assertRaises(ValueError) as caught:
            b.command_version(self.target, f.TAG, lambda *a, **k: types.SimpleNamespace(stdout=b"wrong"), {})
        self.assertNotIn("preserved", str(caught.exception))

    def test_wrong_bundle_arch_is_validation_failure(self):
        self.fixture.files["bin/anytls-macos"] = b"not mach-o"
        self.fixture.info["binary_sha256"] = hashlib.sha256(b"not mach-o").hexdigest()
        self.fixture.files["BUILD-INFO.json"] = b.i.json.dumps(self.fixture.info).encode()
        self.fixture.rebuild()
        self.assert_code(44, self.update)


if __name__ == "__main__":
    unittest.main()

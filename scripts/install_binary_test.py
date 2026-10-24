#!/usr/bin/env python3
"""Simulated installer tests plus isolated bash startup; no install/SSH/Go/network."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import tarfile
import tempfile
import types
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("binary_installer", Path(__file__).with_name("install-binary.py"))
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)
TAG = "v1.2.3"
COMMIT = "a" * 40
NAME = "anytls-core-" + TAG
BINARY = struct.pack("<IIIIIIII", 0xfeedfacf, 0x0100000c, 0, 2, 0, 0, 0, 0) + b"unit-fixture-not-executable"


def archive(entries):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as tf:
        for name, value in entries:
            item = tarfile.TarInfo(name)
            item.mode = 0o755
            if isinstance(value, tarfile.TarInfo):
                value.name = name
                tf.addfile(value)
            else:
                item.size = len(value)
                tf.addfile(item, io.BytesIO(value))
    return out.getvalue()


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="binary-installer-unit-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / "home"
        self.home.mkdir()
        self.app = self.home / ".anytls"
        self.prefix = NAME + "-darwin-arm64"
        self.binary_name = self.prefix + ".tar.gz"
        self.source_name = NAME + "-source.tar.gz"
        self.ccs_name = NAME + "-corresponding-source.tar.gz"
        self.info = {"source_commit": COMMIT, "platform": "darwin-arm64", "binary_sha256": hashlib.sha256(BINARY).hexdigest()}
        self.files = {"VERSION": (TAG + "\n").encode(), "BUILD-INFO.json": json.dumps(self.info).encode(),
                      "bin/anytls-macos": BINARY, "config.example.yaml": b"nodes: []\n",
                      "LICENSE": b"UNIT license", "THIRD_PARTY_NOTICES.md": b"UNIT notices"}
        self.source = archive([(NAME + "/VERSION", TAG.encode())])
        self.release = {"tag_name": TAG, "draft": False, "prerelease": False,
                        "html_url": "https://github.com/" + b.i.REPO + "/releases/tag/" + TAG,
                        "assets": [{"name": n, "browser_download_url": self.url(n)} for n in (self.binary_name, self.source_name, self.ccs_name, "SHA256SUMS")]}
        self.rebuild()
        self.calls = []
        self.addCleanup(mock.patch.stopall)
        self.webui_factory = mock.patch.object(b, "WebUI").start()
        mock.patch.object(socket, "socket", side_effect=AssertionError("network forbidden in UNIT tests")).start()
        mock.patch.object(subprocess, "Popen", side_effect=AssertionError("process forbidden in UNIT tests")).start()

    def url(self, name):
        return "https://github.com/" + b.i.REPO + "/releases/download/" + TAG + "/" + name

    def rebuild(self, extra=()):
        self.binary_archive = archive([(self.prefix + "/" + n, v) for n, v in self.files.items()] + list(extra))
        self.sums = "".join(hashlib.sha256(data).hexdigest() + "  " + name + "\n" for name, data in ((self.binary_name, self.binary_archive), (self.source_name, self.source), (self.ccs_name, self.source)))

    def transport(self, url, kind):
        b.i.trusted_url(url, kind)
        self.calls.append(url)
        if kind == "api":
            value = {"sha": COMMIT} if "/commits/" in url else self.release
            return io.BytesIO(json.dumps(value).encode())
        return io.BytesIO({self.url(self.binary_name): self.binary_archive,
                           self.url(self.source_name): self.source,
                           self.url(self.ccs_name): self.source,
                           self.url("SHA256SUMS"): self.sums.encode()}[url])

    def verified(self):
        work = self.root / ("work-" + str(len(list(self.root.iterdir()))))
        work.mkdir()
        return b.verified_download(work, TAG, self.transport)

    def runner(self, args, **kwargs):
        self.processes.append((args, kwargs))
        if args[1:] == ["version"]:
            return types.SimpleNamespace(stdout=(TAG + "\n").encode(), returncode=0)
        if args[1:] == ["helper", "install"]:
            self.assertIsNotNone(kwargs["stdin"])
            self.assertTrue((self.home / ".local/bin/anytls").is_symlink())
            self.assertEqual(Path(args[0]).parent, self.app)
            self.assertEqual(Path(args[0]).stat().st_mode & 0o777, 0o700)
        return types.SimpleNamespace(stdout=b"{}", returncode=0)

    def install(self, bundle, runner=None):
        self.app.mkdir(exist_ok=True)
        self.processes = []
        return b.install_verified(bundle, TAG, self.app, self.home, runner or self.runner,
                                  env={"HOME": str(self.home)}, tty=lambda: io.BytesIO())

    def assert_binary_only_requests(self):
        self.assertEqual([url for url in self.calls if "/releases/download/" in url],
                         [self.url("SHA256SUMS"), self.url(self.binary_name)])
        self.assertEqual([url for url in self.calls if "/releases/" in url and "/download/" not in url],
                         [b.i.API + "/releases/latest"])

    def binary_only_transport(self, url, kind):
        self.assertNotIn("source.tar.gz", url, "source archives must never be requested automatically")
        return self.transport(url, kind)

    def test_binary_only_exact_asset_set_full_and_check_both_arches(self):
        for arch in ("arm64", "amd64"):
            if arch == "amd64":
                self.use_intel_fixture()
            for check in (True, False):
                with self.subTest(arch=arch, check=check):
                    self.home = self.root / (arch + str(check))
                    self.home.mkdir()
                    self.app = self.home / ".anytls"
                    self.calls.clear()
                    self.processes = []
                    if not check:
                        self.release["assets"] = [a for a in self.release["assets"]
                                                   if a["name"] in (self.binary_name, "SHA256SUMS")]
                        self.sums = self.sums.splitlines()[0] + "\n"
                    def runner(args, **kwargs):
                        self.assertFalse(check, "check-download must not spawn a process")
                        if args[0] == "/usr/sbin/sysctl":
                            return types.SimpleNamespace(stdout=b"0\n", returncode=0)
                        return self.runner(args, **kwargs)
                    with contextlib.redirect_stdout(io.StringIO()):
                        result = b.run(types.SimpleNamespace(version=None, check_download=check),
                                       self.binary_only_transport, runner, system="Darwin",
                                       machine="arm64" if arch == "arm64" else "x86_64", euid=501,
                                       home=self.home, tty=lambda: io.BytesIO(), env={"HOME": str(self.home)})
                    self.assertEqual(result["executed"], not check)
                    self.assert_binary_only_requests()
                    if not check:
                        kept, = (self.app / "releases").iterdir()
                        self.assertEqual((kept / self.binary_name).read_bytes(), self.binary_archive)
                        self.assertFalse((kept / self.source_name).exists())
                        self.assertFalse((kept / self.ccs_name).exists())

    def test_binary_only_release_without_source_metadata_or_checksums(self):
        for arch in ("arm64", "amd64"):
            if arch == "amd64":
                self.use_intel_fixture()
            self.release["assets"] = [a for a in self.release["assets"] if a["name"] in (self.binary_name, "SHA256SUMS")]
            self.sums = self.sums.splitlines()[0] + "\n"
            work = self.root / ("binary-only-" + arch)
            work.mkdir()
            with self.subTest(arch=arch):
                b.verified_download(work, transport=self.binary_only_transport, arch=arch)

    def test_authorization_uses_real_terminal_without_heartbeat(self):
        _, bundle, _, _ = self.verified()
        terminal = io.BytesIO()
        seen = []
        original = self.runner
        def runner(args, **kwargs):
            if args[0] == "/usr/bin/sudo" or args[1:] == ["helper", "install"]:
                self.assertIs(kwargs["stdin"], terminal)
                self.assertIs(kwargs["stdout"], terminal)
                self.assertIs(kwargs["stderr"], terminal)
                self.assertFalse(any(t.name == "anytls-auth-heartbeat" for t in __import__('threading').enumerate()))
                seen.append(args)
            return original(args, **kwargs)
        self.app.mkdir(exist_ok=True)
        self.processes = []
        def stages(message, **kwargs):
            self.assertNotIn("受限助手", message)
            return contextlib.nullcontext()
        with mock.patch.object(b, "stage", side_effect=stages), mock.patch.object(b.WebUI, "restart"):
            b.install_verified(bundle, TAG, self.app, self.home, runner, {"HOME": str(self.home)}, tty=lambda: terminal)
        self.assertEqual(seen[0][:2], ["/usr/bin/sudo", "-v"])
        self.assertEqual(seen[1][1:], ["helper", "install"])

    def test_authorization_denial_preserves_binary_and_does_not_install_helper(self):
        _, bundle, _, _ = self.verified()
        self.app.mkdir(exist_ok=True)
        target = self.app / "anytls-macos"
        target.write_bytes(b"old-binary")
        original = self.runner
        self.processes = []
        def runner(args, **kwargs):
            if args[:2] == ["/usr/bin/sudo", "-v"]:
                raise subprocess.CalledProcessError(1, args)
            return original(args, **kwargs)
        with self.assertRaisesRegex(ValueError, "系统授权未完成"):
            b.install_verified(bundle, TAG, self.app, self.home, runner, {"HOME": str(self.home)}, tty=lambda: io.BytesIO())
        self.assertEqual(target.read_bytes(), b"old-binary")
        self.assertFalse(any(args[1:] == ["helper", "install"] for args, _ in self.processes))
        self.assertFalse(list(self.app.glob(".anytls-bin-candidate-*")))
        self.webui_factory.return_value.restart.assert_not_called()

    def test_verified_download_no_execute_permissions(self):
        tag, bundle, digest, commit = self.verified()
        self.assertEqual((tag, digest, commit), (TAG, self.info["binary_sha256"], COMMIT))
        self.assertEqual((bundle / "bin/anytls-macos").stat().st_mode & 0o777, 0o600)
        self.assertNotIn(self.url(self.source_name), self.calls)

    def test_check_download_no_config_no_process(self):
        args = types.SimpleNamespace(version=TAG, check_download=True, arch="arm64")
        with contextlib.redirect_stdout(io.StringIO()) as stdout:
            result = b.run(args, self.transport, runner=lambda *a, **k: self.fail("executed"), home=self.home)
        self.assertTrue(result["download_verified"])
        self.assertFalse(result["executed"])
        self.assertFalse(self.app.exists())
        self.webui_factory.assert_not_called()
        self.assertEqual(json.loads(stdout.getvalue()), result)

    def test_source_only_release_fails_no_compile(self):
        self.release["assets"] = self.release["assets"][1:]
        with self.assertRaisesRegex(ValueError, "legacy source-only"):
            self.verified()

    def test_binary_asset_url_rejected(self):
        self.release["assets"][0]["browser_download_url"] = "https://evil.invalid/a"
        with self.assertRaisesRegex(ValueError, "URL mismatch"):
            self.verified()

    def test_unused_source_asset_url_ignored(self):
        self.release["assets"][1]["browser_download_url"] = self.url("../source.tar.gz")
        self.verified()
        self.assertNotIn(self.url("../source.tar.gz"), self.calls)

    def test_duplicate_binary_asset(self):
        self.release["assets"].append(self.release["assets"][0])
        with self.assertRaises(ValueError):
            self.verified()

    def test_checksum_asset_duplicate_missing_or_deceptive_url_rejected(self):
        original = self.release["assets"]
        sums = original[-1]
        for entries in (original + [sums], original[:-1],
                        original[:-1] + [{**sums, "browser_download_url": self.url("SHA256SUMS") + "?evil=1"}]):
            self.release["assets"] = entries
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                self.verified()
        self.assertFalse(any("/releases/download/" in url for url in self.calls))

    def test_release_identity_rejected_before_assets_download(self):
        original = dict(self.release)
        for change in ({"draft": True}, {"prerelease": True}, {"tag_name": "v1.2.4"},
                       {"tag_name": "v1.2.3-rc1"}, {"html_url": original["html_url"] + "?evil=1"}):
            self.release = {**original, **change}
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.verified()
        self.assertFalse(any("/releases/download/" in url for url in self.calls))

    def test_prerelease_rejected(self):
        self.release["prerelease"] = True
        with self.assertRaises(ValueError):
            self.verified()

    def test_missing_checksum(self):
        self.sums = self.sums.splitlines()[1] + "\n"
        with self.assertRaisesRegex(ValueError, "checksum"):
            self.verified()

    def test_malformed_checksum(self):
        self.sums += "not a checksum\n"
        with self.assertRaisesRegex(ValueError, "malformed"):
            self.verified()

    def test_duplicate_checksum(self):
        self.sums += self.sums.splitlines()[0] + "\n"
        with self.assertRaisesRegex(ValueError, "checksum"):
            self.verified()

    def test_archive_hash_mismatch(self):
        self.binary_archive += b"tampered"
        with self.assertRaisesRegex(ValueError, "SHA256 mismatch"):
            self.verified()

    def test_traversal(self):
        self.rebuild([(self.prefix + "/../escape", b"bad")])
        with self.assertRaises(ValueError):
            self.verified()
        self.assertFalse((self.root / "escape").exists())

    def test_symlink(self):
        entry = tarfile.TarInfo()
        entry.type, entry.linkname = tarfile.SYMTYPE, "/etc/passwd"
        self.rebuild([(self.prefix + "/link", entry)])
        with self.assertRaisesRegex(ValueError, "links/special"):
            self.verified()

    def test_wrong_version(self):
        self.files["VERSION"] = b" v1.2.3\n"
        self.rebuild()
        with self.assertRaisesRegex(ValueError, "VERSION"):
            self.verified()

    def test_missing_manifest(self):
        del self.files["BUILD-INFO.json"]
        self.rebuild()
        with self.assertRaises(OSError):
            self.verified()

    def test_manifest_binary_mismatch(self):
        self.info["binary_sha256"] = "0" * 64
        self.files["BUILD-INFO.json"] = json.dumps(self.info).encode()
        self.rebuild()
        with self.assertRaisesRegex(ValueError, "binary SHA256"):
            self.verified()

    def test_manifest_commit_mismatch(self):
        self.info["source_commit"] = "b" * 40
        self.files["BUILD-INFO.json"] = json.dumps(self.info).encode()
        self.rebuild()
        with self.assertRaisesRegex(ValueError, "source_commit"):
            self.verified()

    def test_macho_wrong_arch(self):
        self.files["bin/anytls-macos"] = b"not-mach-o"
        self.info["binary_sha256"] = hashlib.sha256(self.files["bin/anytls-macos"]).hexdigest()
        self.files["BUILD-INFO.json"] = json.dumps(self.info).encode()
        self.rebuild()
        with self.assertRaisesRegex(ValueError, "Mach-O"):
            self.verified()

    def test_install_backups_preserves_config(self):
        _, bundle, _, _ = self.verified()
        self.app.mkdir()
        (self.app / "anytls-macos").write_bytes(b"previous binary")
        (self.app / "config.yaml").write_bytes(b"private-real-config")
        backup = self.install(bundle)
        self.assertEqual(backup.read_bytes(), b"previous binary")
        self.assertEqual((self.app / "anytls-macos").read_bytes(), BINARY)
        self.assertEqual((self.app / "config.yaml").read_bytes(), b"private-real-config")
        self.assertFalse(list(self.app.glob(".anytls-bin-candidate-*")))
        self.assertEqual([args[1:] for args, _ in self.processes], [["version"], ["-v"], ["helper", "install"], ["helper", "status"], ["version"]])

    def test_first_install_example_and_link(self):
        _, bundle, _, _ = self.verified()
        self.assertIsNone(self.install(bundle))
        self.assertEqual((self.app / "config.yaml").read_bytes(), b"nodes: []\n")
        self.assertEqual((self.app / "config.yaml").stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.home / ".local/bin/anytls").resolve(), (self.app / "anytls-macos").resolve())

    def test_link_conflict_before_privileged_install(self):
        _, bundle, _, _ = self.verified()
        link = self.home / ".local/bin/anytls"
        link.parent.mkdir(parents=True)
        link.write_bytes(b"other app")
        with self.assertRaisesRegex(ValueError, "conflicts"):
            self.install(bundle)
        self.assertEqual(self.processes, [])
        self.assertFalse((self.app / "config.yaml").exists())

    def test_helper_failure_preserves_binary(self):
        _, bundle, _, _ = self.verified()
        self.app.mkdir()
        target = self.app / "anytls-macos"
        target.write_bytes(b"old")
        def fail(args, **kwargs):
            if args[1:] == ["helper", "install"]:
                raise subprocess.CalledProcessError(1, args)
            return self.runner(args, **kwargs)
        with self.assertRaises(subprocess.CalledProcessError):
            self.install(bundle, fail)
        self.webui_factory.return_value.restart.assert_not_called()
        self.assertEqual(target.read_bytes(), b"old")
        self.assertFalse(list(self.app.glob(".anytls-bin-candidate-*")))

    def test_bad_executable_version_preserves_binary(self):
        _, bundle, _, _ = self.verified()
        self.app.mkdir()
        (self.app / "anytls-macos").write_bytes(b"old")
        with self.assertRaisesRegex(ValueError, "version mismatch"):
            self.install(bundle, lambda *a, **k: types.SimpleNamespace(stdout=b"v0.0.0\n"))
        self.assertEqual((self.app / "anytls-macos").read_bytes(), b"old")
        self.assertFalse((self.app / "config.yaml").exists())

    def test_config_symlink_rejected(self):
        _, bundle, _, _ = self.verified()
        self.app.mkdir()
        (self.app / "config.yaml").symlink_to(self.root / "outside")
        with self.assertRaisesRegex(ValueError, "regular file"):
            self.install(bundle)
        self.assertEqual(self.processes, [])

    def test_retention_failure_precedes_helper_and_binary_publication(self):
        self.processes = []
        self.app.mkdir()
        (self.app / "anytls-macos").write_bytes(b"old")
        (self.app / "config.yaml").write_bytes(b"private")
        (self.app / "releases").write_bytes(b"path conflict")
        args = types.SimpleNamespace(version=TAG, check_download=False)
        with self.assertRaises(FileExistsError):
            b.run(args, self.transport, self.runner, system="Darwin", machine="arm64",
                  euid=501, home=self.home, tty=lambda: io.BytesIO(), env={"HOME": str(self.home)})
        self.assertEqual(self.processes, [])
        self.assertEqual((self.app / "anytls-macos").read_bytes(), b"old")
        self.assertEqual((self.app / "config.yaml").read_bytes(), b"private")
        self.assertFalse(list(self.app.glob(".anytls-bin-candidate-*")))

    def test_default_install_starts_webui_after_publish(self):
        _, bundle, _, _ = self.verified()
        self.app.mkdir()
        self.processes = []
        starts = []
        # Patch the production restart boundary, not install_verified itself.
        with mock.patch.object(b, "WebUI", create=True) as factory:
            factory.return_value.restart.side_effect = lambda: starts.append((self.app / "anytls-macos").read_bytes())
            b.install_verified(bundle, TAG, self.app, self.home, self.runner,
                               env={"HOME": str(self.home)}, tty=lambda: io.BytesIO())
        self.assertEqual(starts, [BINARY], "successful binary installation must start the new WebUI")

    def test_complete_run_retains_binary_package_and_license(self):
        self.processes = []
        args = types.SimpleNamespace(version=TAG, check_download=False)
        with contextlib.redirect_stdout(io.StringIO()):
            report = b.run(args, self.transport, self.runner, system="Darwin", machine="arm64",
                           euid=501, home=self.home, tty=lambda: io.BytesIO(), env={"HOME": str(self.home)})
        self.assertTrue(report["executed"])
        self.webui_factory.return_value.preflight.assert_called_once()
        self.webui_factory.return_value.restart.assert_called_once()
        self.assertEqual([args[1:] for args, _ in self.processes], [["version"], ["-v"], ["helper", "install"], ["helper", "status"], ["version"]])
        kept = list((self.app / "releases").iterdir())
        self.assertEqual(len(kept), 1)
        self.assertFalse((kept[0] / self.source_name).exists())
        self.assertEqual((kept[0] / self.binary_name).read_bytes(), self.binary_archive)
        self.assertEqual((kept[0] / "LICENSE").read_bytes(), self.files["LICENSE"])
        self.assertFalse((kept[0] / self.ccs_name).exists())
        self.assertEqual((kept[0] / "THIRD_PARTY_NOTICES.md").read_bytes(), self.files["THIRD_PARTY_NOTICES.md"])
        self.assertEqual((kept[0] / "SHA256SUMS").read_text(), self.sums)
        self.assertEqual((self.app / "anytls-macos").read_bytes(), BINARY)

    def test_helper_status_failure_blocks_publish(self):
        _, bundle, _, _ = self.verified()
        self.app.mkdir()
        target = self.app / "anytls-macos"
        target.write_bytes(b"old")
        def fail(args, **kwargs):
            if args[1:] == ["helper", "status"]:
                raise subprocess.CalledProcessError(1, args)
            return self.runner(args, **kwargs)
        with self.assertRaises(subprocess.CalledProcessError):
            self.install(bundle, fail)
        self.webui_factory.return_value.restart.assert_not_called()
        self.assertEqual(target.read_bytes(), b"old")
        self.assertFalse(list(self.app.glob(".anytls-bin-candidate-*")))

    def test_webui_preflight_failure_precedes_helper_publish(self):
        _, bundle, _, _ = self.verified()
        self.webui_factory.return_value.preflight.side_effect = ValueError("foreign listener")
        with self.assertRaisesRegex(ValueError, "foreign listener"):
            self.install(bundle)
        self.assertEqual(self.processes, [])
        self.assertFalse((self.app / "anytls-macos").exists())
        self.webui_factory.return_value.restart.assert_not_called()

    def test_webui_start_failure_reports_binary_already_installed(self):
        _, bundle, _, _ = self.verified()
        self.webui_factory.return_value.restart.side_effect = ValueError("readiness failed")
        with self.assertRaisesRegex(ValueError, "binary installed but WebUI start failed"):
            self.install(bundle)
        self.assertEqual((self.app / "anytls-macos").read_bytes(), BINARY)
        for name in (".bash_profile", ".bashrc", ".zprofile", ".zshrc"):
            self.assertFalse((self.home / name).exists())

    def test_repeated_install_configures_path_only_after_webui(self):
        _, bundle, _, _ = self.verified()
        self.app.mkdir()
        self.processes = []
        env = {"HOME": str(self.home), "SHELL": "/bin/bash"}
        self.webui_factory.return_value.restart.side_effect = lambda: self.assertFalse((self.home / ".bash_profile").exists())
        with contextlib.redirect_stdout(io.StringIO()):
            b.install_verified(bundle, TAG, self.app, self.home, self.runner, env, tty=lambda: io.BytesIO())
        before = {name: (self.home / name).read_bytes() for name in (".bash_profile", ".bashrc")}
        self.webui_factory.return_value.restart.side_effect = None
        with contextlib.redirect_stdout(io.StringIO()):
            b.install_verified(bundle, TAG, self.app, self.home, self.runner, env, tty=lambda: io.BytesIO())
        self.assertEqual(before, {name: (self.home / name).read_bytes() for name in before})
        self.assertEqual(before[".bash_profile"], b.PATH_BLOCK)

    def test_path_failure_is_warning_not_install_failure_and_instructions_always_print(self):
        self.processes = []
        outside = self.root / "outside"
        outside.write_bytes(b"unchanged")
        (self.home / ".bash_profile").symlink_to(outside)
        args = types.SimpleNamespace(version=TAG, check_download=False)
        with contextlib.redirect_stdout(io.StringIO()) as stdout, contextlib.redirect_stderr(io.StringIO()) as stderr:
            report = b.run(args, self.transport, self.runner, system="Darwin", machine="arm64", euid=501,
                           home=self.home, tty=lambda: io.BytesIO(), env={"SHELL": "/bin/bash", "HOME": str(self.home)})
        self.assertTrue(report["executed"])
        self.assertIn("Warning", stderr.getvalue())
        self.assertEqual(outside.read_bytes(), b"unchanged")
        self.assertIn(str(self.app / "anytls-macos"), stdout.getvalue())
        self.assertIn("export PATH=", stdout.getvalue())
        self.assertIn("current terminal PATH is unchanged", stdout.getvalue())

    def test_filtered_environment_retains_shell_and_zdotdir(self):
        self.processes = []
        directory = self.home / "shell config"
        directory.mkdir()
        args = types.SimpleNamespace(version=TAG, check_download=False)
        with mock.patch.dict(os.environ, {"HOME": str(self.home), "SHELL": "/bin/zsh", "ZDOTDIR": str(directory)}, clear=True), \
                contextlib.redirect_stdout(io.StringIO()):
            b.run(args, self.transport, self.runner, system="Darwin", machine="arm64", euid=501,
                  home=self.home, tty=lambda: io.BytesIO())
        self.assertEqual((directory / ".zprofile").read_bytes(), b.PATH_BLOCK)
        self.assertEqual((directory / ".zshrc").read_bytes(), b.PATH_BLOCK)
        for _, kwargs in self.processes:
            self.assertEqual(kwargs["env"]["SHELL"], "/bin/zsh")
            self.assertEqual(kwargs["env"]["ZDOTDIR"], str(directory))

    def test_unknown_shell_install_still_prints_manual_and_absolute_commands(self):
        self.processes = []
        args = types.SimpleNamespace(version=TAG, check_download=False)
        with contextlib.redirect_stdout(io.StringIO()) as stdout, contextlib.redirect_stderr(io.StringIO()) as stderr:
            result = b.run(args, self.transport, self.runner, system="Darwin", machine="arm64", euid=501,
                           home=self.home, tty=lambda: io.BytesIO(), env={"SHELL": "/bin/fish"})
        self.assertTrue(result["executed"])
        self.assertIn("unsupported login shell", stderr.getvalue())
        self.assertIn(str(self.app / "anytls-macos"), stdout.getvalue())
        self.assertIn("export PATH=", stdout.getvalue())
        self.assertFalse((self.home / ".bash_profile").exists())

    def test_check_download_preserves_existing_shell_config(self):
        path = self.home / ".bash_profile"
        path.write_bytes(b"# untouched\xff")
        before = {p.name: p.read_bytes() for p in self.home.iterdir()}
        with mock.patch.object(b, "configure_shell_path", side_effect=AssertionError("check-only configured PATH")), \
                mock.patch.object(b.pwd, "getpwuid", side_effect=AssertionError("check-only shell lookup")), \
                contextlib.redirect_stdout(io.StringIO()):
            b.run(types.SimpleNamespace(version=TAG, check_download=True, arch="arm64"), self.transport,
                  runner=lambda *a, **k: self.fail("process"), home=self.home)
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.home.iterdir()})

    def test_unused_source_archive_hash_mismatch_ignored(self):
        self.source += b"tampered-source"
        self.verified()
        self.assertNotIn(self.url(self.source_name), self.calls)
        self.assertNotIn(self.url(self.ccs_name), self.calls)

    def use_intel_fixture(self):
        self.prefix = NAME + "-darwin-amd64"
        self.binary_name = self.prefix + ".tar.gz"
        self.ccs_name = NAME + "-darwin-amd64-corresponding-source.tar.gz"
        self.files["bin/anytls-macos"] = struct.pack("<IIIIIIII", 0xfeedfacf, 0x01000007, 3, 2, 0, 0, 0, 0) + b"intel-unit-fixture"
        self.info.update(platform="darwin-amd64", binary_sha256=hashlib.sha256(self.files["bin/anytls-macos"]).hexdigest())
        self.files["BUILD-INFO.json"] = json.dumps(self.info).encode()
        self.release["assets"] = [{"name": n, "browser_download_url": self.url(n)} for n in (self.binary_name, self.source_name, self.ccs_name, "SHA256SUMS")]
        self.rebuild()

    def test_intel_complete_run_retains_only_intel_binary_package(self):
        self.use_intel_fixture()
        self.processes = []
        def runner(args, **kwargs):
            if args[0] == "/usr/sbin/sysctl":
                return types.SimpleNamespace(stdout=b"0\n", returncode=0)
            return self.runner(args, **kwargs)
        args = types.SimpleNamespace(version=TAG, check_download=False)
        with contextlib.redirect_stdout(io.StringIO()):
            report = b.run(args, self.transport, runner, system="Darwin", machine="x86_64",
                           euid=501, home=self.home, tty=lambda: io.BytesIO(), env={"HOME": str(self.home)})
        self.assertEqual(report["platform"], "darwin-amd64")
        self.assertTrue(report["executed"])
        self.assertIn(self.url(self.binary_name), self.calls)
        kept, = (self.app / "releases").iterdir()
        self.assertFalse((kept / self.ccs_name).exists())
        self.assertEqual((kept / self.binary_name).read_bytes(), self.binary_archive)
        self.assertEqual((self.app / "anytls-macos").read_bytes(), self.files["bin/anytls-macos"])
        self.assertEqual([command[1:] for command, _ in self.processes], [["version"], ["-v"], ["helper", "install"], ["helper", "status"], ["version"]])
        self.webui_factory.return_value.restart.assert_called_once()

    def test_platform_and_root_rejected_before_download(self):
        args = types.SimpleNamespace(version=None, check_download=False)
        for system, machine, uid in (("Linux", "arm64", 501), ("Darwin", "unsupported", 501), ("Darwin", "arm64", 0), ("Darwin", "x86_64", 0)):
            with self.subTest(system=system, machine=machine, uid=uid), self.assertRaises(ValueError):
                b.run(args, self.transport, runner=lambda *a, **k: self.fail("unexpected process"), system=system, machine=machine, euid=uid, home=self.home)
        self.assertEqual(self.calls, [])

    def test_intel_check_download_explicit_arch_on_linux(self):
        self.use_intel_fixture()
        args = types.SimpleNamespace(version=TAG, check_download=True, arch="amd64")
        with contextlib.redirect_stdout(io.StringIO()):
            result = b.run(args, self.transport, runner=lambda *a, **k: self.fail("executed"), system="Linux", machine="x86_64", home=self.home)
        self.assertEqual(result["platform"], "darwin-amd64")
        self.assertFalse(result["executed"])
        self.assertFalse(self.app.exists())

    def test_intel_check_download_native_default_never_spawns(self):
        self.use_intel_fixture()
        args = types.SimpleNamespace(version=TAG, check_download=True)
        with contextlib.redirect_stdout(io.StringIO()):
            result = b.run(args, self.transport, runner=lambda *a, **k: self.fail("check-download spawned a process"), system="Darwin", machine="x86_64", home=self.home)
        self.assertEqual(result["platform"], "darwin-amd64")
        self.assertFalse(result["executed"])
        self.assertFalse(self.app.exists())

    def test_unresolved_hardware_stops_full_install_before_download(self):
        args = types.SimpleNamespace(version=TAG, check_download=False)
        for rc, value in ((1, b""), (0, b""), (0, b"invalid")):
            runner = mock.Mock(return_value=types.SimpleNamespace(returncode=rc, stdout=value))
            with self.subTest(rc=rc, value=value), self.assertRaisesRegex(ValueError, "cannot establish"):
                b.run(args, self.transport, runner, system="Darwin", machine="x86_64", euid=501, home=self.home)
        self.assertEqual(self.calls, [])
        self.assertFalse(self.app.exists())
        self.webui_factory.assert_not_called()

    def test_intel_missing_keys_complete_install_selects_intel(self):
        self.use_intel_fixture()
        self.processes = []
        def runner(args, **kwargs):
            if args[0] == "/usr/sbin/sysctl":
                key = args[-1]
                if key == "hw.optional.x86_64":
                    return types.SimpleNamespace(returncode=0, stdout=b"1\n", stderr=b"")
                return types.SimpleNamespace(returncode=1, stdout=b"", stderr=("sysctl: unknown oid '" + key + "'").encode())
            return self.runner(args, **kwargs)
        with contextlib.redirect_stdout(io.StringIO()):
            result = b.run(types.SimpleNamespace(version=TAG, check_download=False), self.transport, runner,
                           system="Darwin", machine="x86_64", euid=501, home=self.home, tty=lambda: io.BytesIO())
        self.assertEqual(result["platform"], "darwin-amd64")
        self.assertTrue(result["executed"])
        self.assertIn(self.url(self.binary_name), self.calls)
        self.webui_factory.return_value.restart.assert_called_once()

    def test_install_arch_override_rejected_even_if_matching_host(self):
        for arch in ("arm64", "amd64"):
            args = types.SimpleNamespace(version=TAG, check_download=False, arch=arch)
            with self.assertRaisesRegex(ValueError, "only with --check-download"):
                b.run(args, self.transport, runner=lambda *a, **k: self.fail("executed"), system="Darwin", machine="arm64", euid=501, home=self.home)
        self.assertFalse(self.app.exists())
        self.assertEqual(self.calls, [])

    def test_intel_missing_asset_rejects_legacy_arm64_release(self):
        args = types.SimpleNamespace(version=TAG, check_download=False)
        runner = lambda *a, **k: types.SimpleNamespace(stdout=b"0\n", returncode=0)
        with self.assertRaisesRegex(ValueError, "amd64 binary.*legacy"):
            b.run(args, self.transport, runner, system="Darwin", machine="x86_64", euid=501, home=self.home)
        self.assertFalse(any("/releases/download/" in url for url in self.calls))
        self.webui_factory.assert_not_called()

    def test_rosetta_complete_run_selects_arm64(self):
        self.processes = []
        def runner(args, **kwargs):
            if args[0] == "/usr/sbin/sysctl":
                return types.SimpleNamespace(stdout=b"1\n", returncode=0)
            return self.runner(args, **kwargs)
        with contextlib.redirect_stdout(io.StringIO()):
            result = b.run(types.SimpleNamespace(version=TAG, check_download=False), self.transport, runner,
                           system="Darwin", machine="x86_64", euid=501, home=self.home, tty=lambda: io.BytesIO())
        self.assertEqual(result["platform"], "darwin-arm64")
        self.assertIn(self.url(self.binary_name), self.calls)
        self.assertNotIn(self.url(NAME + "-corresponding-source.tar.gz"), self.calls)

    def test_metadata_platform_requires_exact_architecture(self):
        for arch in ("arm64", "amd64"):
            if arch == "amd64":
                self.use_intel_fixture()
            for platform_value in (None, "darwin", "darwin-" + ("amd64" if arch == "arm64" else "arm64"), "darwin-" + arch + " "):
                self.info["platform"] = platform_value
                self.files["BUILD-INFO.json"] = json.dumps(self.info).encode()
                self.rebuild()
                work = self.root / ("metadata-" + str(len(list(self.root.iterdir()))))
                work.mkdir()
                with self.subTest(arch=arch, value=platform_value), self.assertRaisesRegex(ValueError, "BUILD-INFO.platform"):
                    b.verified_download(work, TAG, self.transport, arch=arch)

    def test_intel_macho_mismatch_rejected_before_execution(self):
        self.use_intel_fixture()
        for magic, cpu, filetype in ((0xfeedfacf, 0x0100000c, 2), (0xfeedface, 0x01000007, 2), (0xcffaedfe, 0x01000007, 2), (0xfeedfacf, 0x01000007, 6)):
            self.files["bin/anytls-macos"] = struct.pack("<IIIIIIII", magic, cpu, 0, filetype, 0, 0, 0, 0)
            self.info["binary_sha256"] = hashlib.sha256(self.files["bin/anytls-macos"]).hexdigest()
            self.files["BUILD-INFO.json"] = json.dumps(self.info).encode()
            self.rebuild()
            def runner(args, **kwargs):
                self.assertEqual(args[0], "/usr/sbin/sysctl", "downloaded binary executed before architecture validation")
                return types.SimpleNamespace(stdout=b"0\n", returncode=0)
            with self.subTest(magic=magic, cpu=cpu, filetype=filetype), self.assertRaisesRegex(ValueError, "amd64 Mach-O"):
                b.run(types.SimpleNamespace(version=TAG, check_download=False), self.transport, runner,
                      system="Darwin", machine="x86_64", euid=501, home=self.home)
        self.assertFalse((self.app / "anytls-macos").exists())
        self.webui_factory.assert_not_called()

    def test_arm64_rejects_intel_macho_with_valid_arm64_metadata(self):
        self.files["bin/anytls-macos"] = struct.pack("<IIIIIIII", 0xfeedfacf, 0x01000007, 0, 2, 0, 0, 0, 0)
        self.info["binary_sha256"] = hashlib.sha256(self.files["bin/anytls-macos"]).hexdigest()
        self.files["BUILD-INFO.json"] = json.dumps(self.info).encode()
        self.rebuild()
        with self.assertRaisesRegex(ValueError, "arm64 Mach-O"):
            self.verified()

    def test_intel_corresponding_source_is_optional_and_never_downloaded(self):
        self.use_intel_fixture()
        work = self.root / "intel-ccs"
        work.mkdir()
        self.sums = "\n".join(self.sums.splitlines()[:-1]) + "\n"
        b.verified_download(work, TAG, self.binary_only_transport, arch="amd64")
        self.release["assets"] = [a for a in self.release["assets"] if a["name"] != self.ccs_name]
        _, _, assets = b.binary_release(TAG, self.transport, arch="amd64")
        self.assertEqual(set(assets), {"SHA256SUMS", self.binary_name})


class ShellPathTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="shell-path-unit-")
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name) / "home with spaces ' [x] $d"
        self.home.mkdir()
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(subprocess, "Popen", side_effect=AssertionError("process forbidden")).start()
        mock.patch.object(socket, "socket", side_effect=AssertionError("network forbidden")).start()

    def configure(self, shell="/bin/bash", **env):
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            b.configure_shell_path(self.home, {"SHELL": shell, **env})
        return output.getvalue()

    def test_bash_login_precedence_and_nonlogin(self):
        for existing, chosen in (((), ".bash_profile"), ((".profile",), ".profile"),
                                 ((".bash_login", ".profile"), ".bash_login"),
                                 ((".bash_profile", ".bash_login", ".profile"), ".bash_profile")):
            with self.subTest(existing=existing):
                for path in self.home.iterdir():
                    path.unlink()
                for name in existing:
                    (self.home / name).write_bytes(b"# existing\n")
                self.configure()
                self.assertTrue((self.home / chosen).read_bytes().endswith(b.PATH_BLOCK))
                self.assertEqual((self.home / ".bashrc").read_bytes(), b.PATH_BLOCK)
                for name in existing:
                    if name != chosen:
                        self.assertEqual((self.home / name).read_bytes(), b"# existing\n")
                self.assertEqual(set(p.name for p in self.home.iterdir()), set(existing) | {chosen, ".bashrc"})

    def test_zsh_and_safe_zdotdir(self):
        self.configure("/bin/zsh")
        for name in (".zprofile", ".zshrc"):
            self.assertEqual((self.home / name).read_bytes(), b.PATH_BLOCK)
            (self.home / name).unlink()
        directory = self.home / "zsh config"
        directory.mkdir()
        self.configure("/bin/zsh", ZDOTDIR=str(directory))
        self.assertEqual(set(p.name for p in self.home.iterdir()), {directory.name})
        self.assertEqual(set(p.name for p in directory.iterdir()), {".zprofile", ".zshrc"})

    def test_invalid_and_external_zdotdir_warn_without_writes(self):
        outside = Path(self.temp.name) / "outside"
        outside.mkdir()
        (self.home / "escape").symlink_to(outside, target_is_directory=True)
        for value in ("relative", str(outside), str(self.home / "escape")):
            with self.subTest(value=value):
                self.assertIn("Warning", self.configure("/bin/zsh", ZDOTDIR=value))
                self.assertEqual(list(outside.iterdir()), [])
                self.assertFalse((self.home / ".zprofile").exists())
        self.assertIn("Warning", self.configure("/bin/zsh", ZDOTDIR=str(self.home / "missing")))
        self.assertFalse((self.home / "missing").exists())

    def test_unknown_shell_and_account_fallback(self):
        for shell in ("/bin/fish", "/custom path/bash", "/bin/zsh --login"):
            self.assertIn("configure PATH manually", self.configure(shell))
            self.assertEqual(list(self.home.iterdir()), [])
        with mock.patch.object(b.pwd, "getpwuid", return_value=types.SimpleNamespace(pw_shell="/bin/zsh")) as lookup:
            self.configure("")
        lookup.assert_called_once_with(os.getuid())
        self.assertTrue((self.home / ".zprofile").exists())

    def test_preserve_nonutf8_bytes_modes_and_idempotence(self):
        path = self.home / ".bash_profile"
        original = b"# user bytes \xff\xfe\r\n# no final newline"
        path.write_bytes(original)
        path.chmod(0o640)
        self.configure()
        first = {p.name: (p.read_bytes(), p.stat().st_mode) for p in self.home.iterdir()}
        self.configure()
        self.assertEqual(first, {p.name: (p.read_bytes(), p.stat().st_mode) for p in self.home.iterdir()})
        self.assertEqual(path.read_bytes(), original + b"\n" + b.PATH_BLOCK)
        self.assertEqual(path.stat().st_mode & 0o777, 0o640)
        self.assertEqual((self.home / ".bashrc").stat().st_mode & 0o777, 0o600)

    def test_malformed_markers_never_duplicate(self):
        path = self.home / ".bash_profile"
        for original in (b.PATH_BEGIN, b.PATH_END + b"\n", b.PATH_BEGIN + b"\ncustom\n" + b.PATH_END + b"\n",
                         b.PATH_BLOCK * 2, b"# prefix " + b.PATH_BLOCK):
            path.write_bytes(original)
            self.assertIn("malformed", self.configure())
            self.assertEqual(path.read_bytes(), original)

    def test_symlink_fifo_directory_rejected_without_following_or_blocking(self):
        outside = Path(self.temp.name) / "outside"
        outside.write_bytes(b"untouched")
        path = self.home / ".bash_profile"
        path.symlink_to(outside)
        self.assertIn("Warning", self.configure())
        self.assertEqual(outside.read_bytes(), b"untouched")
        self.assertFalse((self.home / ".bash_login").exists())
        path.unlink()
        path.symlink_to(self.home / "missing")
        self.assertIn("Warning", self.configure())
        self.assertFalse((self.home / "missing").exists())
        path.unlink()
        os.mkfifo(path)
        self.assertIn("regular file", self.configure())
        self.assertTrue(b.stat.S_ISFIFO(path.lstat().st_mode))
        path.unlink()
        path.mkdir()
        self.assertIn("Warning", self.configure())
        self.assertEqual(list(path.iterdir()), [])

    def test_foreign_owner_rejected(self):
        path = self.home / ".bash_profile"
        path.write_bytes(b"unchanged")
        with mock.patch.object(b.os, "fstat", return_value=types.SimpleNamespace(st_mode=b.stat.S_IFREG | 0o600, st_uid=os.getuid() + 1)):
            self.assertIn("owned by", self.configure())
        self.assertEqual(path.read_bytes(), b"unchanged")

    def test_new_files_are_0600_even_under_restrictive_umask(self):
        previous = os.umask(0o777)
        try:
            self.configure()
        finally:
            os.umask(previous)
        for path in self.home.iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)


class RealShellPathTests(unittest.TestCase):
    """Only these tests spawn a real isolated bash; no installer/executable runs."""
    @unittest.skipUnless(Path("/bin/bash").is_file(), "bash unavailable")
    def test_actual_bash_resolution_guard_and_no_installer_rc_execution(self):
        with tempfile.TemporaryDirectory(prefix="shell-path-real-") as temp:
            home = Path(temp) / "home with spaces ' [x] $d"
            home.mkdir()
            sentinel = home / "rc-executed"
            # The installer must append without executing this existing command.
            (home / ".profile").write_text('printf executed > "$HOME/rc-executed"\n')
            with contextlib.redirect_stderr(io.StringIO()):
                b.configure_shell_path(home, {"SHELL": "/bin/bash"})
            self.assertFalse(sentinel.exists())
            binary = home / ".local/bin/anytls"
            binary.parent.mkdir(parents=True)
            binary.write_text("#!/bin/sh\nprintf 'isolated-anytls\\n'\n")
            binary.chmod(0o700)
            for rc in (".profile", ".bashrc"):
                # --rcfile isolates the actual shell from the host's /etc/profile.
                for path in ("/usr/bin:/bin", str(binary.parent) + ":/usr/bin:/bin", "/usr/bin:" + str(binary.parent), ""):
                    with self.subTest(rc=rc, path=path):
                        result = subprocess.run(["/bin/bash", "--noprofile", "--rcfile", str(home / rc), "-ic",
                                                 'command -v anytls; anytls; printf "%s\\n" "$PATH"'],
                                                env={"HOME": str(home), "PATH": path}, cwd=home,
                                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                                timeout=5, check=True)
                        lines = result.stdout.decode().splitlines()
                        self.assertEqual(lines[:2], [str(binary), "isolated-anytls"])
                        self.assertEqual(lines[2].split(":").count(str(binary.parent)), 1)
            self.assertEqual(sentinel.read_text(), "executed")


class ArchitectureTests(unittest.TestCase):
    def test_native_arm64_does_not_probe_sysctl(self):
        self.assertEqual(b.detect_arch("Darwin", "arm64", lambda *a, **k: self.fail("unexpected process")), "arm64")

    def test_x86_aliases_and_rosetta_sysctl_signals(self):
        for machine in ("x86_64", "amd64"):
            for values, expected in (((b"0\n", b"0\n"), "amd64"), ((b"1\n",), "arm64"), ((b"0\n", b"1\n"), "arm64")):
                runner = mock.Mock(side_effect=[types.SimpleNamespace(stdout=v, returncode=0) for v in values])
                self.assertEqual(b.detect_arch("Darwin", machine, runner), expected)
                self.assertEqual([call.args[0] for call in runner.call_args_list], [["/usr/sbin/sysctl", "-n", key] for key in ("hw.optional.arm64", "sysctl.proc_translated")[:len(values)]])

    def test_intel_missing_arm_keys_uses_affirmative_x86_probe(self):
        def runner(args, **kwargs):
            key = args[-1]
            if key == "hw.optional.x86_64":
                return types.SimpleNamespace(returncode=0, stdout=b"1\n", stderr=b"")
            return types.SimpleNamespace(returncode=1, stdout=b"", stderr=("sysctl: unknown oid '" + key + "'\n").encode())
        self.assertEqual(b.detect_arch("Darwin", "x86_64", runner), "amd64")
        bad = lambda *a, **k: types.SimpleNamespace(returncode=1, stdout=b"", stderr=b"sysctl: permission denied")
        with self.assertRaisesRegex(ValueError, "cannot establish"):
            b.detect_arch("Darwin", "x86_64", bad)

    def test_missing_capability_with_translation_signals(self):
        for translated, expected in ((b"0", "amd64"), (b"1", "arm64")):
            def runner(args, **kwargs):
                key = args[-1]
                if key == "hw.optional.arm64":
                    return types.SimpleNamespace(returncode=1, stdout=b"", stderr=b"sysctl: unknown oid 'hw.optional.arm64'")
                return types.SimpleNamespace(returncode=0, stdout=translated if key == "sysctl.proc_translated" else b"1", stderr=b"")
            self.assertEqual(b.detect_arch("Darwin", "x86_64", runner), expected)
        for detail in (b"sysctl: permission denied", b"sysctl: operation not permitted", b"sysctl: unknown oid 'OTHER'"):
            def runner(args, **kwargs):
                return types.SimpleNamespace(returncode=1, stdout=b"", stderr=detail)
            with self.assertRaisesRegex(ValueError, "cannot establish"):
                b.detect_arch("Darwin", "x86_64", runner)

    def test_cli_arch_check_only(self):
        with mock.patch.object(b, "run") as run:
            self.assertEqual(b.main(["--check-download", "--arch", "amd64"]), 0)
            self.assertEqual(run.call_args.args[0].arch, "amd64")
            run.reset_mock()
            for argv in (["--arch", "arm64"], ["--arch", "amd64"], ["--check-download", "--arch", "x86_64"]):
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    b.main(argv)
            run.assert_not_called()

    def test_bootstrap_accepts_intel_without_changing_root_https_guards(self):
        script = Path(__file__).resolve().parents[1].joinpath("install-control-helper.sh").read_text()
        self.assertIn("x86_64", script)
        self.assertIn('[[ "$EUID" != 0 ]]', script)
        self.assertEqual(script.count("--proto '=https'"), 2)
        self.assertIn("--tlsv1.2", script)


class ProgressTests(unittest.TestCase):
    def test_read_all_preserves_http_response_no_argument_semantics(self):
        class HTTPResponse(io.BytesIO):
            def read(self, *args):
                if args and args[0] < 0:
                    raise ValueError("negative count")
                return super().read(*args)
        with contextlib.redirect_stderr(io.StringIO()):
            with b.progress_transport(lambda *args: HTTPResponse(b'{}'))("https://api.github.com/repos/NiuStar/anytls-core/releases/latest", "api") as response:
                self.assertEqual(response.read(), b'{}')

    def test_waiting_download_heartbeat_and_final_bytes_go_to_stderr(self):
        import threading
        started, release = threading.Event(), threading.Event()
        class Delayed(io.BytesIO):
            headers = {"Content-Length": "3"}
            def read(self, n=-1):
                started.set()
                if not release.wait(2):
                    raise AssertionError("fixture was not released")
                return super().read(n)
        output = io.StringIO()
        errors = []
        with contextlib.redirect_stderr(output):
            transport = b.progress_transport(lambda *args: Delayed(b"abc"), interval=0.02)
            def download():
                try:
                    with transport("https://github.com/NiuStar/anytls-core/releases/download/v1.2.3/file.tar.gz", "asset") as response:
                        self.assertEqual(response.read(), b"abc")
                except BaseException as error:
                    errors.append(error)
            thread = threading.Thread(target=download)
            thread.start()
            self.assertTrue(started.wait(1))
            try:
                import time
                deadline = time.monotonic() + 1
                while "已接收" not in output.getvalue() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertIn("已接收", output.getvalue())
                self.assertIn("0 B", output.getvalue())
            finally:
                release.set()
                thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertIn("3 B", output.getvalue())
        self.assertIn("完成", output.getvalue())

    def test_download_failure_is_not_reported_as_complete(self):
        def fail(*args):
            raise OSError("network failed")
        output = io.StringIO()
        with contextlib.redirect_stderr(output), self.assertRaises(OSError):
            with b.progress_transport(fail)("https://api.github.com/repos/NiuStar/anytls-core/releases/latest", "api"):
                self.fail("opened")
        self.assertIn("失败", output.getvalue())
        self.assertNotIn("完成", output.getvalue())


class WebUITests(unittest.TestCase):
    """Real lifecycle code with OS process/HTTP boundaries simulated."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="webui-unit-")
        self.addCleanup(self.temp.cleanup)
        self.app = Path(self.temp.name)
        self.target = self.app / "anytls-macos"
        self.ui = b.WebUI(self.target, {"HOME": str(self.app)})
        self.identity = (str(os.getuid()), "Wed Oct 21 10:00:00 2026", str(self.target) + " webui")
        self.addCleanup(mock.patch.stopall)
        self.kill = mock.patch.object(os, "kill").start()
        self.run = mock.patch.object(subprocess, "run", side_effect=AssertionError("unexpected process")).start()
        self.popen = mock.patch.object(subprocess, "Popen").start()
        mock.patch.object(socket, "socket", side_effect=AssertionError("network forbidden")).start()
        mock.patch.object(b.time, "sleep").start()

    def test_listener_and_full_ps_fields(self):
        self.run.side_effect = [types.SimpleNamespace(returncode=0, stdout=b"42\n", stderr=b"")] + [
            types.SimpleNamespace(returncode=0, stdout=(field + "\n").encode(), stderr=b"") for field in self.identity]
        self.assertEqual(self.ui.listeners(), {42})
        self.assertEqual(self.ui.identity(42), self.identity)
        self.assertEqual(self.run.call_args_list[0].args[0], ["/usr/sbin/lsof", "-t", "-nP", "-iTCP:18089", "-sTCP:LISTEN"])
        self.assertEqual([call.args[0][-1] for call in self.run.call_args_list[1:]], ["uid=", "lstart=", "command="])

    def test_bad_lsof_cannot_masquerade_as_free_port(self):
        for rc, out, err in [(1, b"", b"denied"), (0, b"", b""), (0, b"p42\nccommand\n", b"")]:
            self.run.side_effect = None
            self.run.return_value = types.SimpleNamespace(returncode=rc, stdout=out, stderr=err)
            with self.assertRaises(ValueError):
                self.ui.listeners()

    def test_foreign_uid_path_args_and_multiple_listeners_rejected(self):
        invalid = [("0" if os.getuid() else "999", self.identity[1], self.identity[2]),
                   (self.identity[0], self.identity[1], "/other/anytls-macos webui"),
                   (self.identity[0], self.identity[1], "anytls-macos webui"),
                   (self.identity[0], self.identity[1], self.identity[2] + " --port 19000"),
                   (self.identity[0], self.identity[1], self.identity[2] + " --unknown")]
        with mock.patch.object(self.ui, "listeners", return_value={42}), mock.patch.object(self.ui, "identity") as identity:
            for value in invalid:
                identity.return_value = value
                with self.subTest(value=value), self.assertRaisesRegex(ValueError, "unknown"):
                    self.ui.preflight()
        with mock.patch.object(self.ui, "listeners", return_value={42, 43}), self.assertRaisesRegex(ValueError, "multiple"):
            self.ui.preflight()
        self.kill.assert_not_called()

    def test_known_exact_default_argument_forms(self):
        for suffix in (" webui", " webui --port 18089", " webui --port=18089"):
            self.assertTrue(self.ui.known((self.identity[0], self.identity[1], str(self.target) + suffix)))

    def test_lan_preflight_restart_preserves_listen_and_readiness(self):
        identity = ("501", self.identity[1],
                    str(self.target) + " webui --port 18089 --listen 192.168.5.2")
        child, opener, _ = self.start_fixture()
        with mock.patch.object(os, "getuid", return_value=501), \
                mock.patch.object(b, "private_append", side_effect=lambda path: io.BytesIO()), \
                mock.patch.object(self.ui, "listeners", side_effect=[{99074}, {99074}, set(), {77}, {77}]), \
                mock.patch.object(self.ui, "identity", side_effect=[identity, identity, identity, None]):
            self.ui.preflight()
            self.ui.restart()
        self.kill.assert_called_once_with(99074, b.signal.SIGTERM)
        self.assertEqual(self.popen.call_args.args[0],
                         [str(self.target), "webui", "--port", "18089", "--listen", "192.168.5.2"])
        opener.open.assert_called_once_with("http://192.168.5.2:18089/", timeout=1)
        child.terminate.assert_not_called()

    def test_noncanonical_ip_rejected_even_with_permissive_parser(self):
        canonical = b.ipaddress.IPv4Address("192.168.5.2")
        identity = (*self.identity[:2], str(self.target) + " webui --listen 192.168.005.2")
        with mock.patch.object(b.ipaddress, "IPv4Address", return_value=canonical), \
                mock.patch.object(self.ui, "listeners", return_value={42}), \
                mock.patch.object(self.ui, "identity", return_value=identity):
            with self.assertRaisesRegex(ValueError, "unknown"):
                self.ui.preflight()
        self.kill.assert_not_called()
        self.popen.assert_not_called()

    def test_alternate_loopback_rejected_before_any_signal(self):
        for host in ("127.0.0.2", "127.1.2.3", "127.255.255.254"):
            identity = (*self.identity[:2], str(self.target) + " webui --listen " + host)
            with self.subTest(host=host), \
                    mock.patch.object(self.ui, "listeners", return_value={42}), \
                    mock.patch.object(self.ui, "identity", return_value=identity), \
                    self.assertRaisesRegex(ValueError, "unknown"):
                self.ui.preflight()
        self.kill.assert_not_called()
        self.popen.assert_not_called()

    def test_listen_forms_preserved_through_preflight_restart(self):
        hosts = ("127.0.0.1", "10.0.0.1", "10.255.255.254",
                 "172.16.0.1", "172.31.255.254", "192.168.5.2")
        for host in hosts:
            for suffix in (" --listen " + host, " --listen=" + host,
                           " --port=18089 --listen " + host,
                           " --listen=" + host + " --port 18089"):
                with self.subTest(suffix=suffix):
                    self.ui = b.WebUI(self.target, {"HOME": str(self.app)})
                    identity = (*self.identity[:2], str(self.target) + " webui" + suffix)
                    child, opener, _ = self.start_fixture()
                    self.kill.reset_mock()
                    with mock.patch.object(self.ui, "listeners", side_effect=[{42}, {42}, set(), {77}, {77}]), \
                            mock.patch.object(self.ui, "identity", side_effect=[identity, identity, identity, None]):
                        self.ui.preflight()
                        self.ui.restart()
                    self.assertEqual(self.popen.call_args.args[0],
                                     [str(self.target), "webui", "--port", "18089", "--listen", host])
                    self.assertNotIn("shell", self.popen.call_args.kwargs)
                    opener.open.assert_called_once_with("http://" + host + ":18089/", timeout=1)
                    self.kill.assert_called_once_with(42, b.signal.SIGTERM)
                    child.terminate.assert_not_called()

    def test_unsafe_listen_and_ambiguous_arguments_never_signal(self):
        hosts = ("0.0.0.0", "localhost", "example.com", "8.8.8.8", "::1", "fc00::1",
                 "::ffff:192.168.5.2", "169.254.1.1", "192.0.0.1", "192.0.2.1",
                 "198.51.100.1", "203.0.113.1", "100.64.0.1", "198.18.0.1",
                 "224.0.0.1", "240.0.0.1", "255.255.255.255", "0.1.2.3",
                 "172.15.255.255", "172.32.0.1", "192.167.1.1", "192.169.1.1",
                 "192.168.005.2", "127.1", "2130706433", "192.168.5.256",
                 "192.168.5.2/24", "192.168.5.2:18089", "192.168.5.2%en0")
        suffixes = [" --listen=" + host for host in hosts] + [
            " --listen", " --listen=", " --port", " --port=", " --port=018089",
            " --port=+18089", " --port=18089 --port 18089",
            " --listen=192.168.5.2 --listen 192.168.5.2",
            " --port 18089 --listen=192.168.5.2 --unknown",
            " --listen='192.168.5.2'", ' --listen="192.168.5.2"',
            " --listen 192.168.5.2;id", " --listen $(id)", " --listen 192.168.5.2 extra",
            " --listen=192.168.5.2 --", " -- --listen=192.168.5.2",
            " --listen=192.168.5.2\n", " --listen=192.168.5.2\x00",
            " --listen=192.168.5.2\r --port=18089", " --listen==192.168.5.2",
            " --listen =192.168.5.2", "x --listen=192.168.5.2"]
        with mock.patch.object(self.ui, "listeners", return_value={42}), \
                mock.patch.object(self.ui, "identity") as identity:
            for suffix in suffixes:
                identity.return_value = (*self.identity[:2], str(self.target) + " webui" + suffix)
                with self.subTest(suffix=suffix), self.assertRaisesRegex(ValueError, "unknown"):
                    self.ui.preflight()
        self.assertIsNone(self.ui.old)
        self.kill.assert_not_called()
        self.popen.assert_not_called()

    def test_exact_target_prefix_preserves_spaces_without_shell_parsing(self):
        target = self.app / "home with spaces ' [x] $d" / "anytls-macos"
        ui = b.WebUI(target, {})
        command = str(target) + " webui --listen=192.168.5.2 --port=18089"
        self.assertTrue(ui.known((*self.identity[:2], command)))
        foreign_uid = str(os.getuid() + 1)
        invalid = [(foreign_uid, self.identity[1], command)] + [
            (*self.identity[:2], value) for value in (
                command.replace(str(target), "/other/anytls-macos"),
                command.replace(str(target), "anytls-macos"),
                command.replace(str(target), str(target) + "-other"),
                command.replace(str(target), '"' + str(target) + '"'),
                command.replace(" webui ", " webui-other "))]
        with mock.patch.object(ui, "listeners", return_value={42}), mock.patch.object(ui, "identity") as identity:
            for value in invalid:
                identity.return_value = value
                with self.subTest(value=value), self.assertRaisesRegex(ValueError, "unknown"):
                    ui.preflight()
        self.kill.assert_not_called()
        self.popen.assert_not_called()

    def test_lan_identity_or_port_changes_before_restart_never_signal(self):
        identity = (*self.identity[:2], str(self.target) + " webui --listen=192.168.5.2")
        changed = (*self.identity[:2], str(self.target) + " webui --listen=192.168.5.3")
        for pids, identities in (({88}, [identity]), ({42}, [changed]),
                                 ({42}, [identity, changed]),
                                 ({42}, [(str(os.getuid() + 1), *identity[1:])])):
            with self.subTest(pids=pids, identities=identities):
                self.ui = b.WebUI(self.target, {})
                with mock.patch.object(self.ui, "listeners", side_effect=[{42}, pids]), \
                        mock.patch.object(self.ui, "identity", side_effect=[identity] + identities):
                    self.ui.preflight()
                    with self.assertRaisesRegex(ValueError, "changed"):
                        self.ui.restart()
        self.kill.assert_not_called()
        self.popen.assert_not_called()

    def test_lan_failed_start_never_falls_back_to_loopback(self):
        identity = (*self.identity[:2], str(self.target) + " webui --listen=192.168.5.2")
        for failure in ("exited", "timed out"):
            with self.subTest(failure=failure):
                self.ui = b.WebUI(self.target, {})
                with mock.patch.object(self.ui, "listeners", return_value={42}), \
                        mock.patch.object(self.ui, "identity", return_value=identity):
                    self.ui.preflight()
                self.popen.reset_mock()
                child, opener, _ = self.start_fixture()
                child.poll.return_value = 1 if failure == "exited" else None
                with mock.patch.object(self.ui, "listeners", side_effect=[{77}, {88}]), \
                        mock.patch.object(b.time, "monotonic", side_effect=[0, 0, 11]), \
                        self.assertRaisesRegex(ValueError, failure):
                    self.ui.start()
                self.popen.assert_called_once()
                self.assertEqual(self.popen.call_args.args[0][-2:], ["--listen", "192.168.5.2"])
                if failure == "exited":
                    opener.open.assert_not_called()
                    child.terminate.assert_not_called()
                else:
                    opener.open.assert_called_once_with("http://192.168.5.2:18089/", timeout=1)
                    child.terminate.assert_called_once()
        self.kill.assert_not_called()

    def test_initial_start_ignores_stale_pidfile(self):
        (self.app / "webui.pid").write_text("42\n")
        with mock.patch.object(self.ui, "listeners", return_value=set()), mock.patch.object(self.ui, "start") as start:
            self.ui.preflight()
            self.ui.restart()
        start.assert_called_once()
        self.kill.assert_not_called()
        self.assertEqual((self.app / "webui.pid").read_text(), "42\n")

    def test_restart_only_terms_exact_old_webui(self):
        self.ui.old = (42, self.identity)
        with mock.patch.object(self.ui, "listeners", side_effect=[{42}, set()]), \
                mock.patch.object(self.ui, "identity", side_effect=[self.identity, self.identity, None]), \
                mock.patch.object(self.ui, "start") as start:
            self.ui.restart()
        self.kill.assert_called_once_with(42, b.signal.SIGTERM)
        start.assert_called_once()

    def test_birth_change_never_signals(self):
        self.ui.old = (42, self.identity)
        changed = (self.identity[0], "new birth", self.identity[2])
        for identities in ([changed], [self.identity, changed]):
            with mock.patch.object(self.ui, "listeners", return_value={42}), \
                    mock.patch.object(self.ui, "identity", side_effect=identities), self.assertRaisesRegex(ValueError, "birth"):
                self.ui.restart()
        self.kill.assert_not_called()

    def test_term_timeout_never_kills_or_starts(self):
        self.ui.old = (42, self.identity)
        self.ui.timeout = 0
        with mock.patch.object(self.ui, "listeners", return_value={42}), \
                mock.patch.object(self.ui, "identity", return_value=self.identity), \
                mock.patch.object(self.ui, "start") as start, self.assertRaisesRegex(ValueError, "no SIGKILL"):
            self.ui.restart()
        self.kill.assert_called_once_with(42, b.signal.SIGTERM)
        start.assert_not_called()

    def start_fixture(self):
        child = self.popen.return_value
        child.pid = 77
        child.poll.return_value = None
        response = mock.MagicMock()
        response.__enter__.return_value.status = 200
        response.__enter__.return_value.read.return_value = b"<title>AnyTLS actual console</title>"
        opener = mock.Mock()
        opener.open.return_value = response
        mock.patch.object(b.urllib.request, "build_opener", return_value=opener).start()
        return child, opener, response

    def test_ready_requires_child_listener_and_real_console(self):
        child, opener, _ = self.start_fixture()
        with mock.patch.object(self.ui, "listeners", return_value={77}):
            self.ui.start()
        args, kwargs = self.popen.call_args
        self.assertEqual(args[0], [str(self.target), "webui", "--port", "18089"])
        self.assertTrue(kwargs["start_new_session"])
        self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
        self.assertEqual(kwargs["env"], self.ui.env)
        self.assertIs(kwargs["stdout"], kwargs["stderr"])
        self.assertEqual((self.app / "webui.log").stat().st_mode & 0o777, 0o600)
        opener.open.assert_called_once_with("http://127.0.0.1:18089/", timeout=1)
        child.terminate.assert_not_called()
        self.kill.assert_not_called()

    def test_foreign_listener_never_satisfies_http_readiness(self):
        child, opener, _ = self.start_fixture()
        with mock.patch.object(self.ui, "listeners", return_value={88}), \
                mock.patch.object(b.time, "monotonic", side_effect=[0, 0, 11]), \
                self.assertRaisesRegex(ValueError, "timed out"):
            self.ui.start()
        opener.open.assert_not_called()
        child.terminate.assert_called_once()
        child.wait.assert_called_once_with(timeout=3)
        self.kill.assert_not_called()

    def test_http_readiness_race_rejected_and_owned_child_cleaned(self):
        child, _, _ = self.start_fixture()
        with mock.patch.object(self.ui, "listeners", side_effect=[{77}, {88}]), \
                mock.patch.object(b.time, "monotonic", side_effect=[0, 0, 11]), \
                self.assertRaisesRegex(ValueError, "timed out"):
            self.ui.start()
        child.terminate.assert_called_once()
        child.wait.assert_called_once_with(timeout=3)

    def test_http_200_without_marker_is_not_ready(self):
        child, _, response = self.start_fixture()
        response.__enter__.return_value.read.return_value = b"foreign page"
        with mock.patch.object(self.ui, "listeners", return_value={77}), \
                mock.patch.object(b.time, "monotonic", side_effect=[0, 0, 11]), self.assertRaisesRegex(ValueError, "timed out"):
            self.ui.start()
        child.terminate.assert_called_once()

    def test_starting_child_exit_fails_without_external_signals(self):
        child, _, _ = self.start_fixture()
        child.poll.return_value = 1
        with self.assertRaisesRegex(ValueError, "exited"):
            self.ui.start()
        child.terminate.assert_not_called()
        self.kill.assert_not_called()

    def test_lock_excludes_concurrent_installer_and_rejects_symlink(self):
        with b.installation_lock(self.app):
            with self.assertRaisesRegex(ValueError, "another"):
                with b.installation_lock(self.app):
                    self.fail("concurrent installer")
        lock = self.app / ".install.lock"
        self.assertEqual(lock.stat().st_mode & 0o777, 0o600)
        lock.unlink()
        lock.symlink_to(self.app / "outside")
        with self.assertRaises(OSError):
            with b.installation_lock(self.app):
                self.fail("symlink lock")


if __name__ == "__main__":
    unittest.main(verbosity=2)

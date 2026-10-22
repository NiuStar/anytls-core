#!/usr/bin/env python3
"""UNIT-SIMULATED transport/process tests; no real install, SSH, Go or network."""
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

    def test_verified_download_no_execute_permissions(self):
        tag, bundle, digest, commit = self.verified()
        self.assertEqual((tag, digest, commit), (TAG, self.info["binary_sha256"], COMMIT))
        self.assertEqual((bundle / "bin/anytls-macos").stat().st_mode & 0o777, 0o600)
        self.assertIn(self.url(self.source_name), self.calls)

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

    def test_source_asset_url_rejected(self):
        self.release["assets"][1]["browser_download_url"] = self.url("../source.tar.gz")
        with self.assertRaises(ValueError):
            self.verified()

    def test_duplicate_binary_asset(self):
        self.release["assets"].append(self.release["assets"][0])
        with self.assertRaises(ValueError):
            self.verified()

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
        self.assertEqual([args[1:] for args, _ in self.processes], [["version"], ["helper", "install"], ["helper", "status"], ["version"]])

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

    def test_complete_run_retains_source_and_license(self):
        self.processes = []
        args = types.SimpleNamespace(version=TAG, check_download=False)
        with contextlib.redirect_stdout(io.StringIO()):
            report = b.run(args, self.transport, self.runner, system="Darwin", machine="arm64",
                           euid=501, home=self.home, tty=lambda: io.BytesIO(), env={"HOME": str(self.home)})
        self.assertTrue(report["executed"])
        self.webui_factory.return_value.preflight.assert_called_once()
        self.webui_factory.return_value.restart.assert_called_once()
        self.assertEqual([args[1:] for args, _ in self.processes], [["version"], ["helper", "install"], ["helper", "status"], ["version"]])
        kept = list((self.app / "releases").iterdir())
        self.assertEqual(len(kept), 1)
        self.assertEqual((kept[0] / self.source_name).read_bytes(), self.source)
        self.assertEqual((kept[0] / "LICENSE").read_bytes(), self.files["LICENSE"])
        self.assertEqual((kept[0] / self.ccs_name).read_bytes(), self.source)
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

    def test_source_archive_hash_mismatch(self):
        self.source += b"tampered-source"
        with self.assertRaisesRegex(ValueError, "SHA256 mismatch"):
            self.verified()

    def use_intel_fixture(self):
        self.prefix = NAME + "-darwin-amd64"
        self.binary_name = self.prefix + ".tar.gz"
        self.ccs_name = NAME + "-darwin-amd64-corresponding-source.tar.gz"
        self.files["bin/anytls-macos"] = struct.pack("<IIIIIIII", 0xfeedfacf, 0x01000007, 3, 2, 0, 0, 0, 0) + b"intel-unit-fixture"
        self.info.update(platform="darwin-amd64", binary_sha256=hashlib.sha256(self.files["bin/anytls-macos"]).hexdigest())
        self.files["BUILD-INFO.json"] = json.dumps(self.info).encode()
        self.release["assets"] = [{"name": n, "browser_download_url": self.url(n)} for n in (self.binary_name, self.source_name, self.ccs_name, "SHA256SUMS")]
        self.rebuild()

    def test_intel_complete_run_uses_intel_binary_and_corresponding_source(self):
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
        self.assertEqual((kept / self.ccs_name).read_bytes(), self.source)
        self.assertEqual((self.app / "anytls-macos").read_bytes(), self.files["bin/anytls-macos"])
        self.assertEqual([command[1:] for command, _ in self.processes], [["version"], ["helper", "install"], ["helper", "status"], ["version"]])
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
        self.assertIn(self.url(NAME + "-corresponding-source.tar.gz"), self.calls)

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

    def test_intel_corresponding_source_is_required_and_checksum_verified(self):
        self.use_intel_fixture()
        work = self.root / "intel-ccs"
        work.mkdir()
        self.sums = "\n".join(self.sums.splitlines()[:-1]) + "\n"
        with self.assertRaisesRegex(ValueError, "checksum"):
            b.verified_download(work, TAG, self.transport, arch="amd64")
        self.release["assets"] = [a for a in self.release["assets"] if a["name"] != self.ccs_name]
        with self.assertRaisesRegex(ValueError, "corresponding source"):
            b.binary_release(TAG, self.transport, arch="amd64")


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

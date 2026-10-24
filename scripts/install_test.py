"""UNIT: in-memory transport; no network, compiler or service execution."""
import importlib.util
import io
import json
import hashlib
import os
from pathlib import Path
import tarfile
import tempfile
from unittest import mock
import unittest

spec = importlib.util.spec_from_file_location("installer", Path(__file__).with_name("install.py"))
i = importlib.util.module_from_spec(spec)
spec.loader.exec_module(i)


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.network = mock.patch("socket.socket", side_effect=AssertionError("UNIT forbids network"))
        self.process = mock.patch.object(i.subprocess, "Popen", side_effect=AssertionError("UNIT forbids exec"))
        self.network.start(); self.process.start()
        self.addCleanup(self.network.stop); self.addCleanup(self.process.stop)

    def test_date_release(self):
        self.assertEqual(i.validate_version("v2026-10-21-02"), "v2026-10-21-02")
        for value in ("v2026-02-30-02", "v2026-1-21-02", "v2026-10-21-2", "https://evil/v1.0.0", "v01.2.3", "v1.2.3-rc1"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                i.validate_version(value)
    def temp(self):
        return tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"])

    def archive(self, path, entries):
        with tarfile.open(path, "w:gz") as tar:
            for name, kind, data in entries:
                entry = tarfile.TarInfo(name)
                entry.type = kind
                entry.linkname = "../../outside" if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE) else ""
                entry.size = len(data) if kind == tarfile.REGTYPE else 0
                tar.addfile(entry, io.BytesIO(data))

    def fixture_release(self):
        tag = "v2026-10-21-02"
        return {"tag_name": tag, "draft": False, "prerelease": False,
                "html_url": "https://github.com/" + i.REPO + "/releases/tag/" + tag,
                "assets": [{"name": n, "browser_download_url": "https://github.com/" + i.REPO + "/releases/download/" + tag + "/" + n} for n in ("anytls-core-" + tag + "-source.tar.gz", "SHA256SUMS")]}

    def test_source_release_transport(self):
        fixture = self.fixture_release()
        calls = []
        def transport(url, kind):
            calls.append((url, kind))
            return io.BytesIO(json.dumps(fixture).encode())
        tag, url, assets = i.release(transport=transport)
        self.assertEqual(tag, fixture["tag_name"])
        self.assertEqual(len(assets), 2)
        self.assertEqual(calls, [(i.API + "/releases/latest", "api")])
        for field in ("draft", "prerelease"):
            fixture[field] = True
            with self.assertRaises(ValueError):
                i.release(transport=transport)
            fixture[field] = False
        fixture["assets"][0]["browser_download_url"] = "https://evil/source.tar.gz"
        with self.assertRaises(ValueError):
            i.release(transport=transport)

    def test_malformed_json(self):
        for raw in (b'{', b'{"draft":false,"draft":true}', b'{}{}', b'[]'):
            with self.subTest(raw=raw), self.assertRaises((ValueError, TypeError)):
                i.release(transport=lambda *args: io.BytesIO(raw))

    def test_download_hash_stream(self):
        with self.temp() as tmp:
            p = Path(tmp) / "download"
            data = b"data" * 400000
            digest = hashlib.sha256(data).hexdigest()
            self.assertEqual(i.download("fixture", p, digest, lambda *args: io.BytesIO(data)), digest)
            self.assertEqual(p.read_bytes(), data)
            with self.assertRaises(ValueError):
                i.download("fixture", Path(tmp) / "bad", "0" * 64, lambda *args: io.BytesIO(data))

    def test_checksum_strict(self):
        name = "archive.tar.gz"
        line = "a" * 64 + "  " + name
        self.assertEqual(i.checksum(line, name), "a" * 64)
        for data in ("invalid", line + "\n" + line, "a" * 64 + "  wrong"):
            with self.assertRaises(ValueError):
                i.checksum(data, name)

    def test_extract_safe(self):
        with self.temp() as tmp:
            root = Path(tmp)
            archive = root / "source.tar.gz"
            self.archive(archive, [("anytls-core-v1.2.3", tarfile.DIRTYPE, b""), ("anytls-core-v1.2.3/VERSION", tarfile.REGTYPE, b"v1.2.3")])
            source = i.extract(archive, root / "source", "anytls-core-v1.2.3")
            self.assertEqual((source / "VERSION").read_bytes(), b"v1.2.3")
            self.assertEqual((source / "VERSION").stat().st_mode & 0o777, 0o600)

    def test_official_go_archive_filenames(self):
        with self.temp() as tmp:
            root = Path(tmp)
            archive = root / "go.tar.gz"
            self.archive(archive, [("go/test/Þmain.go", tarfile.REGTYPE, b"source"), ("go/src/rsc.io_!c!g!o.txt", tarfile.REGTYPE, b"fixture")])
            source = i.extract(archive, root / "extract", "go")
            self.assertEqual((source / "test/Þmain.go").read_bytes(), b"source")

    def test_extract_attack_cases(self):
        prefix = "anytls-core-v1.2.3"
        cases = [[(name, tarfile.REGTYPE, b"x")] for name in ("/absolute", prefix + "/../escape", prefix + "/./x", prefix + "//x", "other/VERSION", prefix + "/a\\b")]
        cases += [[(prefix + "/link", kind, b"")] for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE)]
        cases += [[(prefix + "/a", tarfile.REGTYPE, b"x"), (prefix + "/a", tarfile.REGTYPE, b"x")], [(prefix + "/a", tarfile.REGTYPE, b"x"), (prefix + "/a/b", tarfile.REGTYPE, b"x")], [(prefix + "/a/b", tarfile.REGTYPE, b"x"), (prefix + "/a", tarfile.REGTYPE, b"x")], [(prefix + "/a/", tarfile.DIRTYPE, b""), (prefix + "/a", tarfile.REGTYPE, b"x")]]
        for entries in cases:
            with self.subTest(entries=entries), self.temp() as tmp:
                archive = Path(tmp) / "source.tar.gz"
                self.archive(archive, entries)
                with self.assertRaises(ValueError):
                    i.extract(archive, Path(tmp) / "extract", prefix)
                self.assertFalse((Path(tmp) / "escape").exists())

    def test_atomic_backup_and_config_preserved(self):
        with self.temp() as tmp:
            app = Path(tmp)
            target, candidate = app / "anytls", app / "new"
            target.write_bytes(b"old-binary")
            candidate.write_bytes(b"new-binary")
            for name in ("config.yaml", "config.selected", "auth.json", "CA.pem", "rules.json"):
                (app / name).write_bytes(b"unchanged")
            backup = i.publish_binary(candidate, target, app)
            self.assertEqual(backup.read_bytes(), b"old-binary")
            self.assertEqual(target.read_bytes(), b"new-binary")
            self.assertTrue(backup.name.startswith("update-"))
            for name in ("config.yaml", "config.selected", "auth.json", "CA.pem", "rules.json"):
                self.assertEqual((app / name).read_bytes(), b"unchanged")

    def test_atomic_failure_keeps_old_executable(self):
        with self.temp() as tmp:
            app = Path(tmp)
            target, candidate = app / "anytls", app / "new"
            target.write_bytes(b"old")
            candidate.write_bytes(b"new")
            def fail(*args):
                raise OSError("UNIT rename failure")
            with self.assertRaises(OSError):
                i.publish_binary(candidate, target, app, replace=fail)
            self.assertEqual(target.read_bytes(), b"old")
            self.assertEqual(len(list((app / "backups").iterdir())), 1)
            target.unlink()
            target.symlink_to(candidate)
            with self.assertRaises(ValueError):
                i.publish_binary(candidate, target, app)

    def test_config_only_if_absent(self):
        with self.temp() as tmp:
            root = Path(tmp)
            source, app = root / "source", root / "app"
            source.mkdir(); app.mkdir()
            (source / "config.example.yaml").write_bytes(b"example")
            self.assertTrue(i.install_config(source, app))
            self.assertEqual((app / "config.yaml").stat().st_mode & 0o777, 0o600)
            (app / "config.yaml").write_bytes(b"private")
            self.assertFalse(i.install_config(source, app))
            self.assertEqual((app / "config.yaml").read_bytes(), b"private")

    def test_link_conflict(self):
        with self.temp() as tmp:
            app = Path(tmp)
            target, link = app / "anytls", app / "bin/anytls"
            target.write_bytes(b"binary")
            i.ensure_link(target, link)
            i.ensure_link(target, link)
            link.unlink(); link.write_bytes(b"other")
            with self.assertRaises(ValueError):
                i.ensure_link(target, link)
            self.assertEqual(link.read_bytes(), b"other")

    def test_trusted_urls(self):
        for url, kind in (("http://api.github.com/repos/" + i.REPO + "/releases/latest", "api"), ("https://evil/go.tar.gz", "go"), ("https://github.com/other/repo/releases/download/v1.0.0/x", "asset"), ("https://user:password@go.dev/dl/go.tar.gz", "go")):
            with self.assertRaises(ValueError):
                i.trusted_url(url, kind)

    def test_private_toolchain_official_manifest(self):
        with self.temp() as tmp:
            app = Path(tmp); work = app / "work"; work.mkdir()
            archive = work / "fixture.tar.gz"
            self.archive(archive, [("go/bin/go", tarfile.REGTYPE, b"UNIT-NOT-EXECUTABLE"), ("go/pkg/tool/darwin_arm64/compile", tarfile.REGTYPE, b"UNIT-NOT-EXECUTABLE")])
            data = archive.read_bytes()
            digest = hashlib.sha256(data).hexdigest()
            manifest = [{"version": i.GO_VERSION, "files": [{"filename": i.GO_VERSION + ".darwin-arm64.tar.gz", "os": "darwin", "arch": "arm64", "kind": "archive", "sha256": digest}]}]
            calls = []
            def transport(url, kind):
                calls.append((url, kind))
                return io.BytesIO(json.dumps(manifest).encode() if "mode=json" in url else data)
            go = i.install_go(app, work, transport)
            self.assertEqual(go, app / "toolchains/go1.26.8/go/bin/go")
            self.assertEqual(go.stat().st_mode & 0o777, 0o700)
            self.assertEqual(len(calls), 2)
            self.assertTrue(all(kind == "go" for _, kind in calls))

    def test_driver_failure_preserves_config_and_cleans_own_work(self):
        with self.temp() as tmp:
            app = Path(tmp)
            (app / "anytls").write_bytes(b"old")
            (app / "config.yaml").write_bytes(b"private")
            unrelated = app / "unrelated-temp"; unrelated.mkdir()
            args = type("Args", (), {"app_dir": str(app), "target": str(app / "anytls"), "update": True, "version": None, "install_toolchain": False})()
            with mock.patch.object(i.platform, "system", return_value="Darwin"), mock.patch.object(i.platform, "machine", return_value="arm64"), mock.patch.object(i, "find_go", return_value=None):
                with self.assertRaisesRegex(ValueError, "Go 1.26.8"):
                    i.run(args, transport=lambda *args: self.fail("must not download without toolchain consent"))
            self.assertEqual((app / "anytls").read_bytes(), b"old")
            self.assertEqual((app / "config.yaml").read_bytes(), b"private")
            self.assertTrue(unrelated.is_dir())
            self.assertFalse(list(app.glob("update-*")))

    def test_embedded_python_c_entry_without_file(self):
        namespace = {"__name__": "UNIT_EMBEDDED"}
        exec(compile(Path(i.__file__).read_text(), "UNIT_EMBEDDED", "exec"), namespace)
        # CLI supplies --wrapper, but argparse defaults are evaluated eagerly.
        with mock.patch("sys.stdout", new=io.StringIO()):
            with self.assertRaises(SystemExit) as exited:
                namespace["main"](["--help"])
        self.assertEqual(exited.exception.code, 0)

    def test_update_driver_with_unit_build_boundary(self):
        # UNIT-SIMULATED build only: the orchestration/download/extract/backup
        # paths are real, but no compiler or generated executable is run.
        with self.temp() as tmp:
            app = Path(tmp)
            target = app / "anytls"; target.write_bytes(b"UNIT-OLD")
            (app / "config.yaml").write_bytes(b"private")
            (app / "auth.json").write_bytes(b"credential")
            tag = "v2026-10-21-02"
            prefix = "anytls-core-" + tag
            fixture = app / "fixture.tar.gz"
            materials = ["patches/sing-box/identity.json", "patches/sing-box/box-start.patch.json",
                         "patches/sing-box/core-slim.identity.json", "patches/sing-box/core-slim.patch.json"]
            root = Path(i.__file__).resolve().parent.parent
            self.archive(fixture, [(prefix + "/VERSION", tarfile.REGTYPE, tag.encode()), (prefix + "/LICENSE", tarfile.REGTYPE, b"UNIT license"), (prefix + "/scripts/go-patched.py", tarfile.REGTYPE, b"ARCHIVE WRAPPER MUST NEVER EXECUTE")] +
                         [(prefix + "/" + name, tarfile.REGTYPE, (root / name).read_bytes()) for name in materials])
            data = fixture.read_bytes()
            name = prefix + "-source.tar.gz"
            sums = (hashlib.sha256(data).hexdigest() + "  " + name + "\n").encode()
            wrapper = app / "trusted-wrapper.py"; wrapper.write_bytes((root / "scripts/go-patched.py").read_bytes())
            args = type("Args", (), {"app_dir": str(app), "target": str(target), "update": True, "version": tag, "install_toolchain": False, "wrapper": str(wrapper)})()
            def transport(url, kind):
                if "/releases/tags/" in url:
                    return io.BytesIO(json.dumps(self.fixture_release()).encode())
                if "/commits/" in url:
                    return io.BytesIO(json.dumps({"sha": "a" * 40}).encode())
                return io.BytesIO(sums if url.endswith("SHA256SUMS") else data)
            def unit_build(command, **kwargs):
                self.assertEqual(command[1], "-I")
                self.assertEqual(Path(command[2]).read_bytes(), wrapper.read_bytes())
                spec = importlib.util.spec_from_file_location("trusted_wrapper_unit", wrapper)
                trusted = importlib.util.module_from_spec(spec); spec.loader.exec_module(trusted)
                source = Path(kwargs["cwd"])
                self.assertEqual(trusted.identity(source)[0]["result_sha256"], trusted.core_identity(source)[0]["start_result_sha256"])
                core = trusted.core_identity(source)[0]
                self.assertEqual([pin["result_sha256"] for pin in core["files"]],
                                 ["00f3a0ae747cafea89123aac2f4aff2bc5a04046225a5252d5fc4a3b54c99da0", "13832fb094c2bbab38704b0b97781075fbe5eb70e5845d734f600acf91582a9f"])
                self.assertEqual(command[command.index("-tags") + 1], i.TAGS)
                self.assertEqual(kwargs["env"]["GO_BIN"], "/UNIT/go")
                Path(command[command.index("-o") + 1]).write_bytes(b"UNIT-NEW-NOT-EXECUTED")
            with mock.patch.object(i.platform, "system", return_value="Darwin"), mock.patch.object(i.platform, "machine", return_value="arm64"), mock.patch.object(i, "find_go", return_value=Path("/UNIT/go")), mock.patch.object(i.subprocess, "run", side_effect=unit_build), mock.patch.object(i.subprocess, "check_output", return_value=tag.encode()), mock.patch("sys.stdout", new=io.StringIO()):
                self.assertEqual(i.run(args, transport), tag)
            self.assertEqual(target.read_bytes(), b"UNIT-NEW-NOT-EXECUTED")
            self.assertEqual((app / "config.yaml").read_bytes(), b"private")
            self.assertEqual((app / "auth.json").read_bytes(), b"credential")
            self.assertEqual(next((app / "backups").iterdir()).read_bytes(), b"UNIT-OLD")
            self.assertEqual(next((app / "sources").iterdir()).joinpath("LICENSE").read_bytes(), b"UNIT license")
            self.assertFalse(list(app.glob("update-*")))

    def test_redirect_trust_domains(self):
        req = i.urllib.request.Request("https://github.com/" + i.REPO + "/releases/download/v1.0.0/x")
        for kind, url in (("api", "https://api.github.com/repos/" + i.REPO + "/releases/latest"),
                          ("asset", "https://go.dev/dl/x"),
                          ("go", "https://github.com/" + i.REPO + "/releases/download/v1.0.0/x"),
                          ("asset", "https://evil/x"), ("asset", "http://release-assets.githubusercontent.com/x"),
                          ("asset", "https://user:secret@release-assets.githubusercontent.com/x")):
            with self.subTest(kind=kind, url=url), self.assertRaises(ValueError):
                i.Redirects(kind).redirect_request(req, None, 302, "", {}, url)
        for kind, url in (("asset", "https://release-assets.githubusercontent.com/x?signature=fixture"),
                          ("go", "https://dl.google.com/go/x")):
            redirected = i.Redirects(kind).redirect_request(req, None, 302, "", {}, url)
            self.assertEqual(redirected.full_url, url)
        with self.assertRaises(ValueError):
            i.trusted_url("https://evil/x", "unknown")

    def test_root_rejected_before_directory_or_network(self):
        with self.temp() as tmp:
            app = Path(tmp) / "not-created"
            args = type("Args", (), {"app_dir": str(app)})()
            with mock.patch.object(i.platform, "system", return_value="Darwin"), mock.patch.object(i.platform, "machine", return_value="arm64"), mock.patch.object(i.os, "geteuid", return_value=0):
                with self.assertRaisesRegex(ValueError, "never root"):
                    i.run(args, lambda *args: self.fail("no network"))
            self.assertFalse(app.exists())

    def install_fixture(self, app, home, *, failure=None, legacy=False, update=False):
        tag = "v2026-10-21-02"
        prefix = "anytls-core-" + tag
        archive = app / "fixture.tar.gz"
        self.archive(archive, [(prefix + "/VERSION", tarfile.REGTYPE, tag.encode()),
                               (prefix + "/LICENSE", tarfile.REGTYPE, b"license fixture"),
                               (prefix + "/config.example.yaml", tarfile.REGTYPE, b"example fixture"),
                               (prefix + "/scripts/go-patched.py", tarfile.REGTYPE, b"UNTRUSTED ARCHIVE PYTHON"),
                               (prefix + "/scripts/json.py", tarfile.REGTYPE, b"raise RuntimeError('archive import must not run')")])
        data = archive.read_bytes()
        name = prefix + "-source.tar.gz"
        sums = (("0" * 64 if failure == "checksum" else hashlib.sha256(data).hexdigest()) + "  " + name + "\n").encode()
        wrapper = app / "trusted.py"; wrapper.write_bytes(b"TRUSTED LOCAL WRAPPER")
        args = type("Args", (), {"app_dir": str(app), "target": str(app / "anytls") if legacy else None,
                                "update": update, "version": None, "install_toolchain": False, "wrapper": str(wrapper)})()
        def transport(url, kind):
            if url.endswith("/releases/latest"):
                return io.BytesIO(json.dumps(self.fixture_release()).encode())
            if "/commits/" in url:
                return io.BytesIO(json.dumps({"sha": "a" * 40}).encode())
            return io.BytesIO(sums if url.endswith("SHA256SUMS") else data)
        def build(command, **kwargs):
            self.assertEqual(command[1], "-I")
            self.assertEqual(Path(command[2]).read_bytes(), b"TRUSTED LOCAL WRAPPER")
            self.assertEqual(kwargs["env"]["GO_BIN"], "/UNIT/go")
            if failure == "build":
                raise i.subprocess.CalledProcessError(1, command)
            Path(command[command.index("-o") + 1]).write_bytes(b"BUILT FIXTURE NOT EXECUTED")
        version = (b"legacy usage text" if failure == "wrong-version" else tag.encode())
        with mock.patch.object(i.platform, "system", return_value="Darwin"), mock.patch.object(i.platform, "machine", return_value="arm64"), mock.patch.object(i.os, "geteuid", return_value=1024), mock.patch.object(i.Path, "home", return_value=home), mock.patch.object(i, "find_go", return_value=Path("/UNIT/go")), mock.patch.object(i.subprocess, "run", side_effect=build), mock.patch.object(i.subprocess, "check_output", side_effect=i.subprocess.CalledProcessError(2, ["version"]) if failure == "no-version" else None, return_value=version), mock.patch("sys.stdout", new=io.StringIO()) as stdout:
            if failure:
                with self.assertRaisesRegex(ValueError, "SHA256|version|source build"):
                    i.run(args, transport)
                self.assertNotIn("Installed ", stdout.getvalue())
            else:
                self.assertEqual(i.run(args, transport), tag)
                self.assertIn("Installed " + tag, stdout.getvalue())

    def test_initial_install_real_files_and_reinstall(self):
        with self.temp() as tmp:
            home = Path(tmp); app = home / ".anytls"; app.mkdir()
            self.install_fixture(app, home)
            self.assertEqual((app / "anytls-macos").read_bytes(), b"BUILT FIXTURE NOT EXECUTED")
            self.assertEqual((home / ".local/bin/anytls").readlink(), app / "anytls-macos")
            self.assertEqual((app / "config.yaml").read_bytes(), b"example fixture")
            self.assertEqual((app / "config.yaml").stat().st_mode & 0o777, 0o600)
            (app / "config.yaml").write_bytes(b"private original")
            (app / "anytls-macos").write_bytes(b"old production executable")
            (app / "config.yaml.selected").write_bytes(b"selected")
            self.install_fixture(app, home)
            self.assertEqual((app / "config.yaml").read_bytes(), b"private original")
            self.assertEqual((app / "config.yaml.selected").read_bytes(), b"selected")
            self.assertEqual(next((app / "backups").iterdir()).read_bytes(), b"old production executable")
            self.assertEqual(len(list((app / "sources").iterdir())), 2)
            self.assertFalse(list(app.glob("install-*")))

    def test_initial_and_update_failures_never_publish(self):
        for update in (False, True):
            for failure in ("checksum", "build", "wrong-version", "no-version"):
                with self.subTest(update=update, failure=failure), self.temp() as tmp:
                    home = Path(tmp); app = home / ".anytls"; app.mkdir()
                    (app / "anytls-macos").write_bytes(b"original executable")
                    (app / "config.yaml").write_bytes(b"original config")
                    self.install_fixture(app, home, failure=failure, update=update)
                    self.assertEqual((app / "anytls-macos").read_bytes(), b"original executable")
                    self.assertEqual((app / "config.yaml").read_bytes(), b"original config")
                    self.assertFalse((app / "backups").exists())
                    self.assertFalse((home / ".local").exists())
                    self.assertFalse(list(app.glob("install-*")) + list(app.glob("update-*")))

    def test_explicit_legacy_install_target(self):
        with self.temp() as tmp:
            home = Path(tmp); app = home / ".anytls"; app.mkdir()
            (app / "anytls").write_bytes(b"legacy")
            self.install_fixture(app, home, legacy=True)
            self.assertEqual((home / ".local/bin/anytls").readlink(), app / "anytls")
            self.assertFalse((app / "anytls-macos").exists())

    def test_conflicting_link_fails_before_download(self):
        with self.temp() as tmp:
            home = Path(tmp); app = home / ".anytls"; app.mkdir()
            link = home / ".local/bin/anytls"; link.parent.mkdir(parents=True); link.write_bytes(b"other")
            args = type("Args", (), {"app_dir": str(app), "target": None, "update": False})()
            with mock.patch.object(i.platform, "system", return_value="Darwin"), mock.patch.object(i.platform, "machine", return_value="arm64"), mock.patch.object(i.Path, "home", return_value=home):
                with self.assertRaisesRegex(ValueError, "conflicts"):
                    i.run(args, lambda *args: self.fail("must fail before download"))
            self.assertEqual(link.read_bytes(), b"other")

    def test_build_environment_isolated(self):
        with self.temp() as tmp:
            app = Path(tmp)
            work = app / "work"; work.mkdir()
            with mock.patch.dict(os.environ, {"GOFLAGS": "-overlay=evil", "GOWORK": "evil", "TOKEN": "private"}):
                env = i.build_env(app, work)
            self.assertEqual(env["GOTOOLCHAIN"], "local")
            self.assertEqual(env["GOFLAGS"], "")
            self.assertEqual(env["GOWORK"], "off")
            self.assertEqual(env["TMPDIR"], str(work / "tmp"))
            self.assertNotIn("TOKEN", env)


if __name__ == "__main__":
    unittest.main()

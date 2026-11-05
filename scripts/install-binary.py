#!/usr/bin/env python3
"""Install the official macOS arm64/amd64 binary; never compile or run archive scripts."""
import argparse
import contextlib
import fcntl
import gzip
import signal
import time
import urllib.request

import hashlib
import http.client
import importlib.util
import ipaddress
import os
from pathlib import Path
import platform
import pwd
import re
import shlex
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import urllib.parse


def progress(message):
    print("[AnyTLS] " + message, file=sys.stderr, flush=True)


def byte_text(value):
    return ("%.1f MiB" % (value / (1024 * 1024))) if value >= 1024 * 1024 else (str(value) + " B")


@contextlib.contextmanager
def stage(message, interval=5):
    progress(message)
    stop = threading.Event()
    started = time.monotonic()
    def heartbeat():
        while not stop.wait(interval):
            progress(message + "（仍在处理，已等待 %ds）" % (time.monotonic() - started))
    worker = threading.Thread(target=heartbeat, daemon=True)
    worker.start()
    try:
        yield
    finally:
        stop.set()
        worker.join()


def progress_transport(transport, interval=5):
    @contextlib.contextmanager
    def opened(url, kind):
        # Display only the official path basename, never signed redirect queries.
        path = urllib.parse.urlsplit(url).path
        label = path.rsplit("/", 1)[-1]
        label = label if re.fullmatch(r"[A-Za-z0-9._-]+", label) else "GitHub"
        received = 0
        total = None
        started = time.monotonic()
        stop = threading.Event()
        def status():
            suffix = "/" + byte_text(total) if total is not None else ""
            return label + "：已接收 " + byte_text(received) + suffix + "，耗时 %ds" % (time.monotonic() - started)
        def heartbeat():
            while not stop.wait(interval):
                progress(status() + "（正在连接或接收数据）")
        progress("正在获取 " + label + " …")
        worker = threading.Thread(target=heartbeat, daemon=True)
        worker.start()
        try:
            with transport(url, kind) as src:
                raw_total = getattr(src, "headers", {}).get("Content-Length")
                if raw_total and re.fullmatch(r"[0-9]+", raw_total):
                    total = int(raw_total)
                class Response:
                    def read(self, size=-1):
                        nonlocal received
                        data = src.read() if size < 0 else src.read(size)
                        received += len(data)
                        return data
                yield Response()
        except BaseException:
            stop.set()
            worker.join()
            progress(status() + "，失败／已取消")
            raise
        else:
            stop.set()
            worker.join()
            progress(status() + "，完成")
    return opened

# This sibling is fetched by the trusted bootstrap, NEVER from a release archive.
sys.dont_write_bytecode = True
_spec = importlib.util.spec_from_file_location("anytls_trusted_installer", Path(__file__).resolve().with_name("install.py"))
i = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(i)


def detect_arch(system, machine, runner=subprocess.run):
    i.require(system == "Darwin", "binary installation supports macOS only")
    if machine == "arm64":
        return "arm64"
    i.require(machine in ("x86_64", "amd64"), "unsupported macOS architecture")
    # A translated Python reports x86_64 on Apple Silicon. Prefer native arm64.
    hardware_intel = False
    translation_zero = False
    missing = set()
    for key in ("hw.optional.arm64", "sysctl.proc_translated"):
        result = runner(["/usr/sbin/sysctl", "-n", key], stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, timeout=5, check=False)
        value = result.stdout.strip()
        if result.returncode == 0 and value == b"1":
            return "arm64"
        if key == "hw.optional.arm64" and result.returncode == 0 and value == b"0":
            hardware_intel = True
        # -n (without -i) preserves ENOENT as an exact missing-key diagnostic.
        # Never confuse permission errors, empty success or malformed output
        # with a legitimately absent Apple Silicon capability/translation key.
        if key == "sysctl.proc_translated" and result.returncode == 0 and value == b"0":
            translation_zero = True
        expected = ("sysctl: unknown oid '" + key + "'").encode()
        if result.returncode == 1 and not value and getattr(result, "stderr", b"").strip() == expected:
            missing.add(key)
    if not hardware_intel and "hw.optional.arm64" in missing and (translation_zero or "sysctl.proc_translated" in missing):
        result = runner(["/usr/sbin/sysctl", "-n", "hw.optional.x86_64"], stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, timeout=5, check=False)
        hardware_intel = result.returncode == 0 and result.stdout.strip() == b"1"
    i.require(hardware_intel, "cannot establish native macOS architecture; no download or installation performed")
    return "amd64"


class BinaryUnavailable(ValueError):
    """A required platform package is absent, not malformed or duplicated."""


class DownloadFailed(OSError):
    """Only transport opening/reading failures, never local disk failures."""


class UpdateFailed(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__("UPDATE_FAILED")


def update_transport(transport):
    @contextlib.contextmanager
    def opened(url, kind):
        # Enter/exit transport separately: exceptions thrown by the consumer's
        # disk writes or validators must NEVER be relabelled as network errors.
        with contextlib.ExitStack() as stack:
            try:
                src = stack.enter_context(i.open_download(url, kind, transport))
            except (OSError, http.client.HTTPException) as exc:
                raise DownloadFailed() from exc
            class Response:
                headers = getattr(src, "headers", {})
                def read(self, size=-1):
                    try:
                        return src.read() if size < 0 else src.read(size)
                    except (OSError, http.client.HTTPException) as exc:
                        raise DownloadFailed() from exc
            yield Response()
    return opened


def binary_release(version=None, transport=i.open_url, arch="arm64"):
    i.require(arch in ("arm64", "amd64"), "unsupported binary architecture")
    if version is not None:
        i.validate_version(version)
    # Select once, without the explicit source-build installer's asset contract.
    release = i.read_json(i.API + ("/releases/tags/" + version if version else "/releases/latest"), transport=transport)
    i.require(isinstance(release, dict) and release.get("draft") is False and
              release.get("prerelease") is False, "not a stable published release")
    tag = i.validate_version(release.get("tag_name"))
    i.require(version is None or tag == version, "release tag mismatch")
    page = "https://github.com/" + i.REPO + "/releases/tag/" + tag
    i.require(release.get("html_url") == page, "binary release URL mismatch")
    name = "anytls-core-" + tag + "-darwin-" + arch + ".tar.gz"
    entries = release.get("assets")
    i.require(isinstance(entries, list) and all(isinstance(a, dict) for a in entries), "invalid binary release assets")
    assets = {}
    for asset_name in ("SHA256SUMS", name):
        matches = [a for a in entries if a.get("name") == asset_name]
        i.require(len(matches) <= 1, "duplicate required binary release asset")
        if not matches:
            continue
        url = "https://github.com/" + i.REPO + "/releases/download/" + tag + "/" + asset_name
        i.require(matches[0].get("browser_download_url") == url, "binary asset tag/URL mismatch")
        assets[asset_name] = i.trusted_url(url, "asset")
    i.require("SHA256SUMS" in assets, "release must contain SHA256SUMS")
    if name not in assets:
        raise BinaryUnavailable("release has no macOS " + arch + " binary; legacy source-only releases are not compiled automatically")
    return tag, page, assets


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as src:
        for block in iter(lambda: src.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def regular(path):
    i.require(stat.S_ISREG(Path(path).lstat().st_mode), "required path is not a regular file")


def validate_bundle(bundle, tag, commit, arch="arm64"):
    i.require(arch in ("arm64", "amd64"), "unsupported binary architecture")
    for name in ("VERSION", "BUILD-INFO.json", "bin/anytls-macos", "config.example.yaml", "LICENSE", "THIRD_PARTY_NOTICES.md"):
        regular(bundle / name)
    i.require((bundle / "VERSION").read_bytes() in (tag.encode(), (tag + "\n").encode()), "binary VERSION does not match exact release tag")
    info = i.strict_json((bundle / "BUILD-INFO.json").read_bytes())
    i.require(isinstance(info, dict) and re.fullmatch(r"[0-9a-f]{40}", info.get("source_commit", "")) and
              info["source_commit"] == commit, "binary source_commit does not match release commit")
    i.require(info.get("platform") == "darwin-" + arch, "binary BUILD-INFO.platform must exactly match darwin-" + arch)
    binary = bundle / "bin/anytls-macos"
    digest = sha256(binary)
    i.require(info.get("binary_sha256") == digest, "binary SHA256 does not match BUILD-INFO.json")
    with binary.open("rb") as src:
        header = src.read(32)
    cpu = {"arm64": 0x0100000c, "amd64": 0x01000007}[arch]
    i.require(len(header) == 32 and struct.unpack("<IIII", header[:16])[:2] == (0xfeedfacf, cpu) and
              struct.unpack("<IIII", header[:16])[3] == 2, "binary must be a thin " + arch + " Mach-O executable")
    return digest


def verified_download(work, version=None, transport=i.open_url, arch="arm64"):
    progress("[1/6] 检查官方发行版本，仅下载校验和及当前架构预编译程序包")
    transport = progress_transport(transport)
    tag, page, assets = binary_release(version, transport, arch=arch)
    commit = i.read_json(i.API + "/commits/" + tag, transport=transport)
    i.require(isinstance(commit, dict) and re.fullmatch(r"[0-9a-f]{40}", commit.get("sha", "")), "invalid release commit")
    sums = work / "SHA256SUMS"
    i.download(assets["SHA256SUMS"], sums, transport=transport)
    text = sums.read_text(encoding="ascii")
    name = "anytls-core-" + tag + "-darwin-" + arch + ".tar.gz"
    expected = i.checksum(text, name)
    i.download(assets[name], work / name, expected, transport)
    name = "anytls-core-" + tag + "-darwin-" + arch
    progress("[2/6] 下载摘要已核对，正在安全解压并验证程序身份")
    bundle = i.extract(work / (name + ".tar.gz"), work / "extracted", name)
    digest = validate_bundle(bundle, tag, commit["sha"], arch=arch)
    return tag, bundle, digest, commit["sha"]


def check_link(target, link):
    if link.exists() or link.is_symlink():
        i.require(link.is_symlink() and link.resolve() == target.resolve(), "~/.local/bin/anytls conflicts with another program; not overwritten")


PATH_BEGIN = b"# >>> AnyTLS PATH >>>"
PATH_END = b"# <<< AnyTLS PATH <<<"
PATH_BLOCK = (PATH_BEGIN + b'\ncase ":${PATH-}:" in\n'
              b'    *:"$HOME/.local/bin":*) ;;\n'
              b'    *) export PATH="$HOME/.local/bin${PATH:+:$PATH}" ;;\n'
              b'esac\n' + PATH_END + b'\n')


def append_shell_path(path):
    # No truncation/decoding: preserve user bytes and existing permissions.
    # NONBLOCK matters for FIFOs, which must be rejected before any read/write.
    flags = os.O_RDWR | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK
    created = False
    try:
        fd = os.open(path, flags | os.O_CREAT | os.O_EXCL, 0o600)
        created = True
    except FileExistsError:
        fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        i.require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid(),
                  "shell config must be a regular file owned by the current user")
        if created:
            os.fchmod(fd, 0o600)
        stream = os.fdopen(fd, "a+b")
    except BaseException:
        os.close(fd)
        raise
    with stream:
        stream.seek(0)
        original = stream.read()
        if PATH_BEGIN in original or PATH_END in original:
            start = original.find(PATH_BLOCK)
            i.require(original.count(PATH_BEGIN) == original.count(PATH_END) == 1 and
                      start >= 0 and (start == 0 or original[start - 1:start] == b"\n"),
                      "malformed AnyTLS PATH markers; repair manually (not appended)")
            return
        stream.write((b"\n" if original and not original.endswith(b"\n") else b"") + PATH_BLOCK)
        stream.flush()
        os.fsync(stream.fileno())


def configure_shell_path(home, env):
    """Best-effort startup configuration only; never source or execute an rc file."""
    try:
        shell = env.get("SHELL") or pwd.getpwuid(os.getuid()).pw_shell
        if shell == "/bin/bash":
            candidates = [home / name for name in (".bash_profile", ".bash_login", ".profile")]
            # lexists includes dangling symlinks: do not bypass an unsafe first file.
            login = next((p for p in candidates if os.path.lexists(p)), candidates[0])
            paths = [login, home / ".bashrc"]
        elif shell == "/bin/zsh":
            directory = home
            if env.get("ZDOTDIR"):
                directory = Path(env["ZDOTDIR"])
                i.require(directory.is_absolute() and
                          (directory == home or home in directory.parents) and
                          (directory.resolve() == home.resolve() or home.resolve() in directory.resolve().parents),
                          "ZDOTDIR must be absolute and within home; configure PATH manually")
            paths = [directory / ".zprofile", directory / ".zshrc"]
        else:
            raise ValueError("unsupported login shell " + repr(shell) + "; configure PATH manually")
    except (OSError, ValueError, KeyError, RuntimeError) as exc:
        progress("Warning: PATH configuration skipped: " + str(exc))
        return
    for path in paths:
        try:
            append_shell_path(path)
            progress("PATH startup configuration ready: " + str(path) + " (new shells only)")
        except (OSError, ValueError) as exc:
            progress("Warning: could not configure PATH in " + str(path) + ": " + str(exc) + "; configure manually")


def command_version(binary, tag, runner, env):
    result = runner([str(binary), "version"], check=True, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, timeout=20, env=env)
    i.require(result.stdout.decode("utf-8").strip() == tag, "executable version mismatch")


def private_append(path):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        i.require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid(), "unsafe installer log/lock file")
        os.fchmod(fd, 0o600)
        return os.fdopen(fd, "ab", buffering=0)
    except BaseException:
        os.close(fd)
        raise


_INSTALL_LOCKS = threading.local()


@contextlib.contextmanager
def installation_lock(app):
    with private_append(app / ".install.lock") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("another binary installer is running") from None
        # Close only: LOCK_UN would release the worker's inherited open-file
        # description too, leaving a detached reload unprotected.
        owned = getattr(_INSTALL_LOCKS, 'owned', {})
        _INSTALL_LOCKS.owned = owned
        key = str(app.resolve(strict=True))
        owned[key] = (os.getpid(), lock.fileno())
        try:
            yield lock.fileno()
        finally:
            owned.pop(key, None)


def reconciliation_lock_required(app):
    entry = getattr(_INSTALL_LOCKS, 'owned', {}).get(str(app.resolve(strict=True)))
    i.require(entry is not None and entry[0] == os.getpid(), 'CORE_RELOAD_RECONCILE_LOCK_REQUIRED')
    os.fstat(entry[1])


def core_reload_guard(app):
    # No journal means no helper/process reads, including explicit opt-out.
    for root in app.glob('.core-reload-*'):
        try:
            regular(root/'result.json')
            regular(root/'accepted.json')
            result = i.strict_json((root/'result.json').read_bytes())
            accepted = i.strict_json((root/'accepted.json').read_bytes())
            safe = (not os.path.lexists(root/'pending.json') and type(result) is dict and
                    result.get('state') == 'SUCCEEDED' and
                    root.name == '.core-reload-' + result.get('operation_id', '') and
                    accepted == dict(operation_id=result['operation_id'], result_sha256=sha256(root/'result.json')))
        except (OSError, ValueError, KeyError, TypeError):
            safe = False
        if not safe:
            try:
                reconciliation_lock_required(app)
                safe = reconcile_preflight(app, root)
            except (OSError, ValueError, KeyError, TypeError, UnicodeError, RecursionError, subprocess.SubprocessError):
                safe = False
        i.require(safe, 'Core reload UNKNOWN/pending; do not install or dispatch again; inspect receipt: '+str(root))


def canonical_ipv4(host):
    """Require a canonical IPv4 literal; never normalize operator input."""
    try:
        address = ipaddress.IPv4Address(host)
    except ipaddress.AddressValueError:
        raise ValueError("listen address must be a canonical IPv4 literal") from None
    i.require(str(address) == host, "listen address must be a canonical IPv4 literal")
    return host


class WebUIPreflightRejected(ValueError):
    """No installer lifecycle mutation has been dispatched at this boundary."""


class CoreReloadPreflightRejected(ValueError):
    """Original core capture failed before helper/publication/reload mutation."""


class WebUI:
    """Only manage the exact current user's default-port WebUI, never the VPN."""
    def __init__(self, target, env, listen="0.0.0.0"):
        self.target, self.env = target, env
        self.timeout = 10
        self.old = None
        self.managed = None
        self.published_digest = None
        self.listen = canonical_ipv4(listen)

    def listeners(self):
        result = subprocess.run(["/usr/sbin/lsof", "-t", "-nP", "-iTCP:18089", "-sTCP:LISTEN"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        lines = result.stdout.decode("ascii").splitlines()
        if result.returncode == 1 and not lines and not result.stderr:
            return set()
        i.require(result.returncode == 0 and lines and all(re.fullmatch(r"[1-9][0-9]*", line) for line in lines),
                  "cannot safely identify port 18089 listener")
        return {int(line) for line in lines}

    def identity(self, pid):
        fields = []
        for field in ("uid", "lstart", "command"):
            result = subprocess.run(["/bin/ps", "-ww", "-p", str(pid), "-o", field + "="],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
                                    env={**(self.env or {}), "LC_ALL": "C"})
            if result.returncode == 1 and not result.stdout.strip() and not result.stderr:
                return None
            i.require(result.returncode == 0 and result.stdout.strip() and not result.stderr,
                      "cannot safely identify WebUI process")
            fields.append(result.stdout.decode("utf-8").strip())
        return tuple(fields)

    def listen_args(self, identity):
        if identity is None or identity[0] != str(os.getuid()):
            return None
        prefix = str(self.target) + " webui"
        if not identity[2].startswith(prefix):
            return None
        tail = identity[2][len(prefix):]
        # ps command is not shell-quoted argv: preserve the exact path prefix,
        # then accept only unquoted, unambiguous flag/value tokens; never eval.
        if tail and (tail[0] not in " \t" or not re.fullmatch(r"[ \tA-Za-z0-9.=-]*", tail)):
            return None
        tokens = iter(tail.split())
        options = {}
        for token in tokens:
            key, sep, value = token.partition("=")
            if key not in ("--port", "--listen", "--managed-agent") or key in options:
                return None
            options[key] = value if sep else next(tokens, "")
        if options.get("--port", "18089") != "18089":
            return None
        # This parser establishes old process identity only, not the new bind.
        host = options.get("--listen", "0.0.0.0")
        try:
            canonical_ipv4(host)
        except ValueError:
            return None
        if "--managed-agent" in options:
            # A locator is not authority. Match Go's canonical self/config label;
            # agent-status below verifies secure plist bytes AND the loaded job.
            try:
                label, _, _ = self.managed_spec()
            except (OSError, ValueError, RuntimeError):
                return None
            if options["--managed-agent"] != label:
                return None
            return host, "--listen" in options, label
        # Match the console's canonical IPv4 syntax, including wildcard/public.
        return host, "--listen" in options

    def managed_spec(self):
        target = self.target.resolve(strict=True)
        config = (target.parent / "config.yaml").resolve(strict=True)
        i.require(target == self.target and config == target.parent / "config.yaml",
                  "MANAGED_WEBUI_PATH")
        home = Path((os.environ if self.env is None else self.env).get("HOME") or pwd.getpwuid(os.getuid()).pw_dir)
        i.require(home.is_absolute() and home.resolve(strict=True) == home, "MANAGED_WEBUI_PATH")
        label = "com.anytls.webui." + hashlib.sha256(
            (str(os.getuid()) + "\0" + str(target) + "\0" + str(config)).encode("utf-8")).hexdigest()[:24]
        return label, "gui/%d/%s" % (os.getuid(), label), home / "Library/LaunchAgents" / (label + ".plist")

    def managed_status(self, pid):
        try:
            label, target, plist = self.managed_spec()
            regular(self.target)
            regular(plist)
            before = plist.read_bytes()
            result = subprocess.run([str(self.target), "webui", "agent-status", "--listen", self.listen,
                                     "--port", "18089"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    timeout=10, check=False, env=self.env)
            i.require(result.returncode == 0 and not result.stderr, "MANAGED_WEBUI_STATUS")
            dto = i.strict_json(result.stdout)
            i.require(type(dto) is dict and dto.keys() == {"label", "target", "plist", "pid", "restartManaged"} and
                      type(dto["pid"]) is int and dto["pid"] == pid and pid > 0 and
                      dto["restartManaged"] is True and type(dto["label"]) is str and dto["label"] == label and
                      type(dto["target"]) is str and dto["target"] == target and
                      type(dto["plist"]) is str and dto["plist"] == str(plist), "MANAGED_WEBUI_STATUS")
            regular(plist)
            i.require(plist.read_bytes() == before, "MANAGED_WEBUI_STATUS")
            return before
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, UnicodeError):
            raise ValueError("MANAGED_WEBUI_STATUS: existing CLI, secure plist and loaded job must verify") from None

    def known(self, identity):
        return self.listen_args(identity) is not None

    def preflight(self):
        pids = self.listeners()
        i.require(len(pids) <= 1, "port 18089 has multiple listeners; refusing WebUI replacement")
        if pids:
            pid = next(iter(pids))
            identity = self.identity(pid)
            listen = self.listen_args(identity)
            i.require(listen is not None, "port 18089 is occupied by an unknown process/arguments or UID; close it yourself")
            if len(listen) == 3:
                i.require(listen[0] == self.listen, "MANAGED_WEBUI_LISTEN_MIGRATION_UNSUPPORTED: keep the existing managed listen address")
                digest = sha256(self.target)
                plist = self.managed_status(pid)
                i.require(self.listeners() == {pid} and self.identity(pid) == identity and
                          sha256(self.target) == digest, "managed WebUI identity/binary changed during preflight")
                self.managed = (listen, plist)
            # Old argv establishes process authority, not this install's policy.
            self.old = (pid, identity)
        # Historical webui.pid is never read: a PID is not process authority.

    def managed_unchanged(self, pid, identity):
        i.require(self.published_digest is not None and sha256(self.target) == self.published_digest,
                  "managed WebUI published binary changed")
        i.require(self.managed_status(pid) == self.managed[1], "managed WebUI plist changed")
        # Status may take seconds: re-read the exact full identity and listener
        # after it returns, not just its PID (KeepAlive may have respawned).
        i.require(sha256(self.target) == self.published_digest and
                  self.listeners() == {pid} and self.identity(pid) == identity,
                  "managed WebUI process birth/identity/listener changed")

    def restart_managed(self):
        pid, identity = self.old
        i.require(self.listeners() == {pid} and self.identity(pid) == identity,
                  "managed WebUI process birth/identity/listener changed; no process was signalled")
        self.managed_unchanged(pid, identity)
        # No bootout/kickstart: TERM lets the old app drain active actions; the
        # existing, verified KeepAlive job alone owns replacement startup.
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            raise ValueError("MANAGED_WEBUI_UNKNOWN: old process disappeared before TERM; no retry") from None
        deadline = time.monotonic() + self.timeout
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            while time.monotonic() < deadline:
                old = self.identity(pid)
                i.require(old is None or old == identity, "old process identity changed")
                pids = self.listeners()
                if old is None and pids:
                    i.require(len(pids) == 1 and pid not in pids, "managed listener ownership changed")
                    new_pid = next(iter(pids))
                    new = self.identity(new_pid)
                    i.require(new is not None and new[0] == identity[0] and new[2] == identity[2] and
                              self.listen_args(new) == self.managed[0], "foreign managed listener")
                    self.managed_unchanged(new_pid, new)
                    try:
                        host = "127.0.0.1" if self.listen == "0.0.0.0" else self.listen
                        with opener.open("http://" + host + ":18089/", timeout=1) as response:
                            ready = response.status == 200 and b"<title>AnyTLS" in response.read(1024 * 1024)
                    except OSError:
                        ready = False
                    if ready:
                        self.managed_unchanged(new_pid, new)
                        i.require(self.identity(pid) is None and time.monotonic() < deadline,
                                  "old WebUI still exists or readiness deadline expired")
                        return
                elif old is not None and not pids <= {pid}:
                    # TERM/drain can finish between the ps and lsof reads.
                    # Never accept the replacement until the next full pass.
                    i.require(self.identity(pid) is None, "foreign listener during old WebUI drain")
                time.sleep(0.1)
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            raise ValueError("MANAGED_WEBUI_UNKNOWN: readiness/identity not verified; no SIGKILL or second start") from exc
        raise ValueError("MANAGED_WEBUI_UNKNOWN: old WebUI drain/KeepAlive readiness timed out; no SIGKILL or second start")

    def restart(self):
        if self.managed is not None:
            return self.restart_managed()
        pids = self.listeners()
        if self.old:
            pid, identity = self.old
            i.require(pids <= {pid}, "port 18089 ownership changed; no process was signalled")
            current = self.identity(pid)
            i.require(current is None or current == identity, "WebUI process birth/identity changed; no process was signalled")
            if current is not None:
                # Recheck the full birth/UID/command immediately before the sole signal.
                i.require(self.identity(pid) == identity, "WebUI process birth/identity changed; no process was signalled")
                try:
                    os.kill(pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
            deadline = time.monotonic() + self.timeout
            while True:
                gone = self.identity(pid) != identity
                if gone and not self.listeners():
                    break
                i.require(time.monotonic() < deadline, "old WebUI did not stop or port 18089 is not free; no SIGKILL sent")
                time.sleep(0.1)
        else:
            i.require(not pids, "port 18089 ownership changed; no process was signalled")
        self.start()

    def start(self):
        child = None
        try:
            args = [str(self.target), "webui", "--port", "18089", "--listen", self.listen]
            with private_append(self.target.parent / "webui.log") as log:
                child = subprocess.Popen(args,
                                         stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                         start_new_session=True, env=self.env)
            deadline = time.monotonic() + self.timeout
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            while time.monotonic() < deadline:
                i.require(child.poll() is None, "new WebUI exited before readiness")
                if self.listeners() == {child.pid}:
                    try:
                        probe_host = "127.0.0.1" if self.listen == "0.0.0.0" else self.listen
                        with opener.open("http://" + probe_host + ":18089/", timeout=1) as response:
                            ready = response.status == 200 and b"<title>AnyTLS" in response.read(1024 * 1024)
                        if ready and child.poll() is None and self.listeners() == {child.pid}:
                            return
                    except OSError:
                        pass
                time.sleep(0.1)
            raise ValueError("new WebUI readiness timed out (child must own port 18089 and serve the actual console)")
        except (OSError, ValueError, subprocess.SubprocessError):
            if child is not None and child.poll() is None:
                # This Popen handle is our own unreaped child, never an external PID hint.
                child.terminate()
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    raise ValueError("new WebUI failed and did not terminate; no SIGKILL sent; inspect webui.log") from None
            raise


def helper_config_identity(config):
    """Match controlHelperConfigIdentity: SHA256(canonical absolute path), not YAML."""
    try:
        path = Path(config)
        i.require(path.is_absolute() and not any(c in str(path) for c in "\x00\n\r"), "HELPER_STATUS_CONFIG")
        canonical = path.resolve(strict=True)
        i.require(str(canonical) != "/" and not any(c in str(canonical) for c in "\x00\n\r") and
                  canonical.is_file(), "HELPER_STATUS_CONFIG")
        return hashlib.sha256(str(canonical).encode("utf-8")).hexdigest()
    except (OSError, ValueError, RuntimeError, UnicodeError):
        raise ValueError("HELPER_STATUS_CONFIG") from None


def validate_helper_status(raw, digest, tag, identity):
    """Validate the existing ordinary status DTO; never echo helper-controlled data."""
    try:
        # CLI JSON is re-encoded/indented, so do not impose the IPC wire-byte cap.
        response = i.strict_json(raw)
        required = {"ok", "code", "message", "loaded", "running", "helper_version", "helper_sha256", "config_identity"}
        i.require(type(response) is dict and required <= response.keys() and
                  response.keys() <= required | {"diagnostics"}, "invalid")
        i.require(all(type(response[k]) is bool for k in ("ok", "loaded", "running")) and
                  all(type(response[k]) is str for k in required - {"ok", "loaded", "running"}), "invalid")
        i.require(response["ok"] is True and response["code"] == "", "invalid")
        if "diagnostics" in response:
            d = response["diagnostics"]
            fields = {"schema", "operation", "outcome", "stage", "reason", "rollback", "restoration", "cleanup", "receipt", "job", "tun"}
            i.require(type(d) is dict and d.keys() == fields and type(d["schema"]) is int and d["schema"] == 1 and
                      all(type(d[k]) is str for k in fields - {"schema"}), "invalid")
            # startDiagnostics.valid(true), with the same fixed enum allowlists.
            allowed = {"operation": "START RELOAD STOP", "outcome": "SUCCEEDED", "stage": "NONE", "reason": "NONE",
                       "rollback": "NOT_ATTEMPTED VERIFIED FAILED UNKNOWN", "restoration": "NOT_ATTEMPTED VERIFIED FAILED UNKNOWN",
                       "cleanup": "NOT_ATTEMPTED VERIFIED FAILED UNKNOWN", "receipt": "NOT_ATTEMPTED WRITTEN FAILED UNKNOWN",
                       "job": "NOT_OBSERVED RUNNING NOT_RUNNING UNLOADED UNKNOWN", "tun": "NOT_OBSERVED TUN NOT_TUN UNKNOWN"}
            i.require(all(d[k] in values.split() for k, values in allowed.items()), "invalid")
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        raise ValueError("HELPER_STATUS_INVALID") from None
    i.require(response["helper_sha256"] == digest, "HELPER_STATUS_SHA_MISMATCH")
    i.require(response["helper_version"] == tag, "HELPER_STATUS_VERSION_MISMATCH")
    i.require(response["config_identity"] == identity, "HELPER_STATUS_CONFIG_MISMATCH")


# Self-contained stdlib worker: never imports a deleted bootstrap/sibling script.
# Native boundaries have named Python seams for LOCALONLY synthetic tests only;
# no CLI/env setting can replace the production peer, process or hash checks.
CORE_RELOAD_WORKER = r'''
import ctypes, hashlib, json, os, re, signal, socket, stat, struct, subprocess, sys, time
from pathlib import Path
HELPER = Path('/Library/PrivilegedHelperTools/com.nousresearch.anytls-control/anytls-control')
SOCKET = HELPER.parent / 'run/control.sock'

def need(value, code='CORE_RELOAD_INVALID'):
    if not value:
        raise ValueError(code)

def strict(raw):
    def pairs(items):
        obj = {}
        for k, v in items:
            need(k not in obj)
            obj[k] = v
        return obj
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda value: need(False))

def shape(obj, keys):
    need(type(obj) is dict and obj.keys() == set(keys.split()))

def hexstr(value, count):
    return type(value) is str and re.fullmatch('[0-9a-f]{%d}' % count, value) is not None

def file_hash(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as f:
        st = os.fstat(f.fileno())
        need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1, 'CORE_RELOAD_FILE')
        h = hashlib.sha256()
        for chunk in iter(lambda: f.read(1024*1024), b''):
            h.update(chunk)
        def stable(v):
            return (v.st_dev,v.st_ino,v.st_mode,v.st_uid,v.st_gid,v.st_nlink,v.st_size,v.st_mtime_ns,v.st_ctime_ns)
        need(stable(os.fstat(f.fileno())) == stable(st) and stable(Path(path).lstat()) == stable(st), 'CORE_RELOAD_FILE_DRIFT')
        return h.hexdigest()

def config_pin(app):
    config = app / 'config.yaml'
    need(config.is_absolute() and config.resolve(strict=True) == config, 'CORE_RELOAD_CONFIG')
    selection = app / 'config.yaml.selected'
    return dict(identity=hashlib.sha256(str(config).encode()).hexdigest(),
                config=file_hash(config), selection=file_hash(selection) if os.path.lexists(selection) else None)

def helper_hash():
    st = HELPER.lstat()
    need(st.st_uid == 0 and not st.st_mode & 0o022, 'CORE_RELOAD_HELPER_FILE')
    return file_hash(HELPER)

def root_peer(sock):
    lib = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
    fn = lib.getpeereid
    fn.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_uint), ctypes.POINTER(ctypes.c_uint)]
    fn.restype = ctypes.c_int
    uid, gid = ctypes.c_uint(), ctypes.c_uint()
    need(fn(sock.fileno(), ctypes.byref(uid), ctypes.byref(gid)) == 0 and uid.value == 0,
         'CORE_RELOAD_PEER_NOT_ROOT')

def request(q, timeout=5):
    action = q.get('action')
    if action == 'status':
        need(q == dict(action='status', allow_insecure=False) and q['allow_insecure'] is False)
    elif action == 'startup.read':
        shape(q, 'timeline_schema action operation_id')
        need(type(q['timeline_schema']) is int and q['timeline_schema'] == 1 and
             (q['operation_id'] is None or hexstr(q['operation_id'], 32)))
    else:
        shape(q, 'timeline_schema action operation_id allow_insecure')
        need(action in ('reload','stop') and type(q['timeline_schema']) is int and q['timeline_schema'] == 1 and
             hexstr(q['operation_id'], 32) and q['allow_insecure'] is (action=='reload'))
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        # Absolute deadline, not a per-recv timeout susceptible to a slow peer.
        deadline = time.monotonic() + timeout
        s.settimeout(timeout)
        s.connect(str(SOCKET))
        root_peer(s)  # authenticate before writing ANY request
        s.sendall(json.dumps(q, separators=(',', ':')).encode())
        s.shutdown(socket.SHUT_WR)
        limit = 768*1024 if action == 'startup.read' else 4096
        raw = bytearray()
        while True:
            left = deadline - time.monotonic()
            need(left > 0, 'CORE_RELOAD_TIMEOUT')
            s.settimeout(left)
            chunk = s.recv(min(65536, limit + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
            need(len(raw) <= limit, 'CORE_RELOAD_FRAME')
        return strict(raw.decode('utf-8'))

def status_check(r, digest, tag, identity):
    required = 'ok code message loaded running helper_version helper_sha256 config_identity'
    need(type(r) is dict and set(required.split()) <= r.keys() and r.keys() <= set((required+' diagnostics').split()))
    need(all(type(r[k]) is bool for k in ('ok','loaded','running')) and
         all(type(r[k]) is str for k in ('code','message','helper_version','helper_sha256','config_identity')))
    need(r['ok'] is True and r['code'] == '' and hexstr(r['helper_sha256'],64) and
         r['helper_sha256'] == digest and r['helper_version'] == tag and r['config_identity'] == identity,
         'CORE_RELOAD_STATUS_IDENTITY')
    need(not r['running'] or r['loaded'], 'CORE_RELOAD_STATUS_STATE')
    if 'diagnostics' in r:
        diagnostics(r['diagnostics'], reload=False)
    return r

def diagnostics(d, reload=True):
    shape(d, 'schema operation outcome stage reason rollback restoration cleanup receipt job tun')
    need(type(d['schema']) is int and d['schema'] == 1 and
         all(type(v) is str for k,v in d.items() if k != 'schema'))
    enums = dict(operation='START RELOAD STOP', outcome='SUCCEEDED', stage='NONE', reason='NONE',
                 rollback='NOT_ATTEMPTED VERIFIED FAILED UNKNOWN', restoration='NOT_ATTEMPTED VERIFIED FAILED UNKNOWN',
                 cleanup='NOT_ATTEMPTED VERIFIED FAILED UNKNOWN', receipt='NOT_ATTEMPTED WRITTEN FAILED UNKNOWN',
                 job='NOT_OBSERVED RUNNING NOT_RUNNING UNLOADED UNKNOWN', tun='NOT_OBSERVED TUN NOT_TUN UNKNOWN')
    need(all(d[k] in values.split() for k,values in enums.items()))
    if reload:
        need(d['operation']=='RELOAD' and d['outcome']=='SUCCEEDED' and d['job']=='RUNNING' and
             d['tun']=='TUN' and d['receipt']=='WRITTEN', 'CORE_RELOAD_DIAGNOSTICS')

def timeline_shape(r):
    # Source DTO shapes (internal/startuptimeline/types.go). Reject drift and
    # wrong primitive/null types at every depth; this is not lifecycle authority.
    event = dict.fromkeys('seq segment stage state code at elapsed_ns job tun'.split(),str)
    event.update(dict.fromkeys('span_id duration_ns round ordinal rule_count completed_count'.split(),(str,type(None))))
    phase = dict.fromkeys('stage segment span_id began_at began_elapsed_ns'.split(),str)
    provenance = dict(version=(str,type(None)),git_revision=(str,type(None)),dirty=(bool,type(None)),
                      sha256=(str,type(None)),sha_kind=str,execution_mapping=str)
    terminal = dict(result=str,at=str,elapsed_ns=str)
    stream = dict(role=str,clock_id=str,origin_at=str,elapsed_ns=str,provenance=provenance,
                  current=(phase,type(None)),events=[event],generated_events=str,dropped_events=str,
                  first_missing_seq=(str,type(None)),retained_ranges=[dict(first=str,last=str)],
                  terminal=(terminal,type(None)),gap=bool)
    observation = dict(availability=str,captured_at=(str,type(None)),helper_receive_elapsed_ns=(str,type(None)),
                       age_ns=(str,type(None)),clock_id=(str,type(None)),phase=(phase,type(None)),gap=bool)
    diagnostic = dict.fromkeys('operation outcome stage reason rollback restoration cleanup receipt job tun'.split(),str)
    diagnostic['schema']=int
    trace = dict.fromkeys('authority operation_id operation source started_at state lifecycle_result helper_return web_return receipt_result'.split(),str)
    trace.update(helper_epoch=(str,type(None)),config_identity=(str,type(None)),finished_at=(str,type(None)),
                 diagnostics=(diagnostic,type(None)),streams=[stream],core_observation=observation,gap=bool)
    def typed(value, schema, depth=0):
        need(depth<=24)
        if type(schema) is tuple:
            return any(typed(value,part,depth+1) for part in schema)
        if type(schema) is dict:
            return type(value) is dict and value.keys()==schema.keys() and all(typed(value[k],v,depth+1) for k,v in schema.items())
        if type(schema) is list:
            return type(value) is list and len(value)<=1024 and all(typed(v,schema[0],depth+1) for v in value)
        return type(value) is schema
    schema=dict(timeline_schema=int,code=str,helper_epoch=(str,type(None)),config_identity=(str,type(None)),
                operation_id=(str,type(None)),trace=(trace,type(None)))
    need(typed(r,schema), 'CORE_RELOAD_TRACE_SCHEMA')

def read_check(r, identity, operation=None, epoch=None):
    timeline_shape(r)
    shape(r, 'timeline_schema code helper_epoch config_identity operation_id trace')
    need(type(r['timeline_schema']) is int and r['timeline_schema']==1 and hexstr(r['helper_epoch'],32) and
         r['config_identity']==identity and (r['operation_id'] is None or hexstr(r['operation_id'],32)))
    need(r['code'] in ('OK','NO_OPERATION'), 'CORE_RELOAD_CAPABILITY')
    need((r['code']=='NO_OPERATION' and r['operation_id'] is None and r['trace'] is None) or
         (r['code']=='OK' and type(r['trace']) is dict and r['operation_id'] is not None))
    if operation is not None:
        need(r['code']=='OK' and r['operation_id']==operation and r['helper_epoch']==epoch,
             'CORE_RELOAD_OPERATION_MISMATCH')
    return r['helper_epoch']

def processes(app, timeout=5):
    raw = subprocess.run(['/bin/ps','-ww','-axo','pid=,uid=,lstart=,command='], check=True,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
                         env={'PATH':'/usr/bin:/bin','LC_ALL':'C','LANG':'C'}).stdout.decode('utf-8')
    rows = []
    paths = (str(app/'service/anytls-macos'), str(app/'anytls-macos'))
    for line in raw.splitlines():
        f = line.split(None, 7)
        # Darwin can render system UIDs as signed values (for example -2).
        # Retain the numeric UID; capture still requires the scoped core UID 0.
        need(len(f)==8 and f[0].isdigit() and re.fullmatch(r'-?[0-9]+', f[1]) is not None,
             'CORE_RELOAD_PROCESS_READ')
        cmd = f[7]
        # Every service-path process, and any direct user-binary TUN run, counts.
        if cmd == paths[0] or cmd.startswith(paths[0]+' ') or ((cmd == paths[1] or cmd.startswith(paths[1]+' ')) and re.search(r'(^| )run( |$)',cmd)):
            rows.append(dict(pid=int(f[0]), uid=int(f[1]), birth=' '.join(f[2:7]), command=cmd))
    return rows

def core_command(app, op, epoch):
    return str(app/'service/anytls-macos')+' -config '+str(app/'service/config.yaml')+' -network tun -record-service -allow-insecure -startup-operation '+op+' -startup-epoch '+epoch+' -dns-observe-service run'

def tun_readback():
    # Kernel route lookup only: this sends no packet and performs no DNS/TLS.
    raw = subprocess.run(['/sbin/route','-n','get','1.1.1.1'],check=True,stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,timeout=5,env={'LC_ALL':'C','LANG':'C','PATH':'/usr/bin:/bin'}).stdout.decode('ascii')
    interfaces = re.findall(r'^\s*interface: (\S+)\s*$',raw,re.MULTILINE)
    need(len(interfaces)==1 and re.fullmatch(r'utun[0-9]+',interfaces[0]), 'CORE_RELOAD_TUN_UNAVAILABLE')
    return interfaces[0]

def capture(app):
    # Missing socket is not a stopped helper. Only a completely absent helper,
    # launchd job AND core census qualifies as a first install.
    cores = processes(app)
    if not os.path.lexists(SOCKET):
        need(not os.path.lexists(HELPER) and not cores and
             not os.path.lexists('/Library/LaunchDaemons/com.nousresearch.anytls-control.plist'), 'CORE_RELOAD_HELPER_UNAVAILABLE')
        for label in ('com.nousresearch.anytls-macos','com.nousresearch.anytls-control'):
            result = subprocess.run(['/bin/launchctl','print','system/'+label],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
                                    env={'LC_ALL':'C','LANG':'C','PATH':'/usr/bin:/bin'})
            # Match launchctl's service-absent diagnostic, never generic nonzero.
            diagnostic = result.stderr.decode('utf-8').strip()
            absent = 'Could not find service "'+label+'" in domain for system'
            need(result.returncode != 0 and not result.stdout and diagnostic in (absent,'Bad request.\n'+absent),
                 'CORE_RELOAD_ABSENCE_UNPROVEN')
        return dict(state='ABSENT', config=None, core=None, status=None)
    pin = config_pin(app)
    r = request(dict(action='status', allow_insecure=False))
    need(type(r) is dict and type(r.get('helper_version')) is str and
         re.fullmatch(r'[A-Za-z0-9.+_-]{1,128}',r['helper_version']))
    status_check(r, helper_hash(), r['helper_version'], pin['identity'])
    need(len(cores)==int(r['running']), 'CORE_RELOAD_PROCESS_STATE')
    if cores:
        need(cores[0]['uid']==0, 'CORE_RELOAD_PROCESS_UID')
    need(config_pin(app)==pin and processes(app)==cores, 'CORE_RELOAD_CAPTURE_DRIFT')
    return dict(state='RUNNING' if r['running'] else 'STOPPED', config=pin, core=cores[0] if cores else None, status=r)

def put(root, name, value):
    # Exclusive, private and fsynced before any request can mutate service state.
    fd = os.open(root/name, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd,'w') as f:
        json.dump(value,f,sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    fd = os.open(root, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def trace_check(r, job, epoch):
    op, identity = job['operation_id'], job['before']['config']['identity']
    read_check(r, identity, op, epoch)
    t = r['trace']
    shape(t, 'authority operation_id helper_epoch config_identity operation source started_at finished_at state lifecycle_result helper_return web_return receipt_result diagnostics streams core_observation gap')
    need(t['authority']=='AUXILIARY_NOT_AUTHORITY' and t['operation_id']==op and t['helper_epoch']==epoch and
         t['config_identity']==identity and t['operation']=='RELOAD' and t['source']=='MANUAL_RELOAD' and
         t['state']=='FINISHED' and t['lifecycle_result']=='SUCCEEDED' and t['helper_return']=='SUCCEEDED')
    diagnostics(t['diagnostics'])
    need(type(t['streams']) is list)
    cores = [s for s in t['streams'] if type(s) is dict and s.get('role')=='CORE']
    need(len(cores)==1, 'CORE_RELOAD_PROVENANCE')
    s = cores[0]
    shape(s, 'role clock_id origin_at elapsed_ns provenance current events generated_events dropped_events first_missing_seq retained_ranges terminal gap')
    p = s['provenance']
    shape(p, 'version git_revision dirty sha256 sha_kind execution_mapping')
    need(p['sha_kind']=='FILE_BYTES' and p['sha256']==job['digest'] and p['version']==job['tag'] and
         p['git_revision']==job['revision'] and p['dirty'] is False and p['execution_mapping']=='NOT_ATTESTED',
         'CORE_RELOAD_PROVENANCE')
    # CORE_WAIT is a live core, not a completed process; its terminal may be null.
    need(type(s['events']) is list and any(type(e) is dict and e.get('stage')=='CORE_START' and
         e.get('state')=='END' and e.get('code')=='OK' for e in s['events']), 'CORE_RELOAD_CORE_START')

def worker(root):
    sent = False
    claimed = False
    op = None
    try:
        st = root.lstat()
        need(stat.S_ISDIR(st.st_mode) and st.st_uid==os.getuid() and stat.S_IMODE(st.st_mode)==0o700)
        need(not os.path.lexists(root/'intent.json') and not os.path.lexists(root/'result.json'), 'CORE_RELOAD_ALREADY_CLAIMED')
        put(root,'claim.json',dict(pid=os.getpid()))
        claimed = True
        job = strict((root/'job.json').read_bytes())
        shape(job, 'app operation_id digest tag revision before')
        op = job['operation_id']
        need(hexstr(op,32) and hexstr(job['digest'],64) and hexstr(job['revision'],40) and
             type(job['tag']) is str and re.fullmatch(r'v[0-9A-Za-z.+_-]+',job['tag']))
        app = Path(job['app'])
        need(app.is_absolute() and app.resolve(strict=True)==app and job['before']['state']=='RUNNING')
        pin = job['before']['config']
        def unchanged():
            need(config_pin(app)==pin and file_hash(app/'anytls-macos')==job['digest'] and
                 helper_hash()==job['digest'], 'CORE_RELOAD_IDENTITY_DRIFT')
        unchanged()
        status = status_check(request(dict(action='status',allow_insecure=False)),job['digest'],job['tag'],pin['identity'])
        need(status['loaded'] and status['running'], 'CORE_RELOAD_NOT_RUNNING')
        need(processes(app)==[job['before']['core']], 'CORE_RELOAD_PROCESS_DRIFT')
        epoch = read_check(request(dict(timeline_schema=1,action='startup.read',operation_id=None)),pin['identity'])
        unchanged()
        status = status_check(request(dict(action='status',allow_insecure=False)),job['digest'],job['tag'],pin['identity'])
        need(status['loaded'] and status['running'], 'CORE_RELOAD_NOT_RUNNING')
        need(processes(app)==[job['before']['core']], 'CORE_RELOAD_PROCESS_DRIFT')
        put(root,'intent.json',dict(operation_id=op,helper_epoch=epoch,action='reload',allow_insecure=True,single_dispatch=True))
        sent = True  # even a partial write/disconnect is UNKNOWN; NEVER resend.
        response = request(dict(timeline_schema=1,action='reload',operation_id=op,allow_insecure=True),300)
        put(root,'response.json',response)
        shape(response,'timeline_schema code ok helper_epoch operation_id timeline_availability helper_version helper_sha256 config_identity loaded running diagnostics')
        need(type(response['timeline_schema']) is int and response['timeline_schema']==1 and
             response['ok'] is True and response['code']=='' and response['loaded'] is True and response['running'] is True and
             response['operation_id']==op and response['helper_epoch']==epoch and response['timeline_availability']=='AVAILABLE' and
             response['helper_sha256']==job['digest'] and response['helper_version']==job['tag'] and response['config_identity']==pin['identity'])
        diagnostics(response['diagnostics'])
        timeline = request(dict(timeline_schema=1,action='startup.read',operation_id=op))
        put(root,'timeline.json',timeline)
        trace_check(timeline,job,epoch)
        status = status_check(request(dict(action='status',allow_insecure=False)),job['digest'],job['tag'],pin['identity'])
        need(status['loaded'] and status['running'])
        unchanged()
        rows = processes(app)
        need(len(rows)==1 and rows[0]['uid']==0 and rows[0]['pid']!=job['before']['core']['pid'] and
             rows[0]['command']==core_command(app,op,epoch), 'CORE_RELOAD_NEW_PROCESS')
        # Re-read the entire census: old PID/identity must be absent, no second core.
        need(processes(app)==rows, 'CORE_RELOAD_PROCESS_DRIFT')
        interface = tun_readback()
        unchanged()
        need(processes(app)==rows, 'CORE_RELOAD_PROCESS_DRIFT')
        put(root,'result.json',dict(state='SUCCEEDED',operation_id=op,helper_epoch=epoch,new_core=rows[0],
                                  tun='TUN',interface=interface,sha_kind='FILE_BYTES',execution_mapping='NOT_ATTESTED',network='NOT_TESTED'))
        return 0
    except Exception as exc:
        if claimed and not os.path.lexists(root/'result.json'):
            code = str(exc) if type(exc) is ValueError and re.fullmatch(r'CORE_RELOAD_[A-Z_]+',str(exc)) else 'CORE_RELOAD_UNAVAILABLE'
            put(root,'result.json',dict(state='UNKNOWN' if sent else 'REJECTED',operation_id=op,error_class=type(exc).__name__,code=code))
        return 1

if __name__ == '__main__':
    os.umask(0o077)
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    # Hard total worker bound includes all observations. On an alarm while a
    # request is in flight, the ordinary exception path retains UNKNOWN.
    def expired(signum, frame):
        raise TimeoutError('CORE_RELOAD_DEADLINE')
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(350)
    raise SystemExit(worker(Path(sys.argv[1])))
'''
CORE_RELOAD_SUPPORT = {'__name__': 'installer_reload_support'}
exec(CORE_RELOAD_WORKER, CORE_RELOAD_SUPPORT)


def reconciliation_receipt(root, name):
    """Bounded no-follow read, binding inode/security metadata and complete bytes."""
    n = CORE_RELOAD_SUPPORT
    path = root / name
    before = path.lstat()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as f:
        def stamp(st):
            return (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid,
                    st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
        st = os.fstat(f.fileno())
        n['need'](stamp(before)==stamp(st) and stat.S_ISREG(st.st_mode) and st.st_nlink==1 and
                  st.st_uid==os.getuid() and stat.S_IMODE(st.st_mode)==0o600 and st.st_size<=768*1024)
        raw = f.read(768*1024+1)
        n['need'](len(raw)==st.st_size and stamp(os.fstat(f.fileno()))==stamp(st) and
                  stamp(path.lstat())==stamp(st))
    return n['strict'](raw), hashlib.sha256(raw).hexdigest()


def rejection_trace(r, job, epoch, diag):
    n = CORE_RELOAD_SUPPORT
    need = n['need']
    n['timeline_shape'](r)
    if r['code']=='OPERATION_MISMATCH':
        # The cache retains only the latest operation (for example a later manual
        # stop). This response is NOT rejection evidence. The original strictly
        # bound root-peer response above is authority; fresh same-binary status,
        # config/selection and census are still mandatory before committing.
        need(type(r['timeline_schema']) is int and r['timeline_schema']==1 and
             r['helper_epoch']==epoch and r['config_identity']==job['before']['config']['identity'] and
             n['hexstr'](r['operation_id'],32) and r['operation_id']!=job['operation_id'] and r['trace'] is None)
        return
    n['read_check'](r, job['before']['config']['identity'], job['operation_id'], epoch)
    t = r['trace']
    need(t['authority']=='AUXILIARY_NOT_AUTHORITY' and t['operation_id']==job['operation_id'] and
         t['helper_epoch']==epoch and t['config_identity']==job['before']['config']['identity'] and
         t['operation']=='RELOAD' and t['source']=='MANUAL_RELOAD' and t['state']=='FINISHED' and
         t['lifecycle_result']=='FAILED' and t['helper_return']=='FAILED' and
         t['web_return']=='NOT_ATTEMPTED' and t['receipt_result']=='NOT_ATTEMPTED' and t['diagnostics']==diag and
         type(t['finished_at']) is str)
    # No CORE stream is expected: global gap may ONLY describe missing CORE observation.
    need(len(t['streams'])==1 and t['streams'][0]['role']=='HELPER')
    observation = t['core_observation']
    need(observation==dict(availability='NOT_OBSERVED', captured_at=None, helper_receive_elapsed_ns=None,
                          age_ns=None, clock_id=None, phase=None, gap=True) and t['gap'] is True)
    s = t['streams'][0]
    need(s['gap'] is False and s['dropped_events']=='0' and s['first_missing_seq'] is None and
         s['current'] is None and n['hexstr'](s['clock_id'],32))
    p = s['provenance']
    need(p==dict(version=job['tag'], git_revision=job['revision'], dirty=False, sha256=job['digest'],
                 sha_kind='FILE_BYTES', execution_mapping='NOT_ATTESTED'))
    # Only this complete source-confirmed pre-stop sequence qualifies. New stages
    # require review; absence of CORE events alone is never evidence of no stop.
    expected = [('HELPER_ACCEPT','OBSERVATION','OK','PREFLIGHT',None),
                ('HELPER_PREFLIGHT_CAPTURE','BEGIN','NONE','PREFLIGHT','1'),
                ('HELPER_PREFLIGHT_CAPTURE','END','OK','PREFLIGHT','1'),
                ('HELPER_PREFLIGHT_COMPILE','BEGIN','NONE','PREFLIGHT','2'),
                ('HELPER_PREFLIGHT_COMPILE','END','FAILED','PREFLIGHT','2'),
                ('HELPER_FINISH','OBSERVATION','FAILED','FINALIZE',None)]
    need(s['generated_events']=='6' and s['retained_ranges']==[dict(first='1',last='6')] and len(s['events'])==6)
    reconciliation_stream(t,s,expected,'FAILED')


def reconciliation_stream(t, s, expected, result):
    """Shared narrow complete HELPER stream scalar/span/terminal checks."""
    need = CORE_RELOAD_SUPPORT['need']
    # Match Go's canonical UTC RFC3339Nano and uint64 decimal codecs.
    import calendar
    def decimal(value):
        need(type(value) is str and re.fullmatch(r'0|[1-9][0-9]{0,19}',value) is not None)
        value = int(value)
        need(value <= 18446744073709551615)
        return value
    def wall(value):
        need(type(value) is str)
        m = re.fullmatch(r'([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{0,8}[1-9]))?Z',value)
        need(m is not None)
        year, month, day, hour, minute, second = map(int,m.groups()[:6])
        need(1<=month<=12 and 1<=day<=calendar.monthrange(year,month)[1] and hour<24 and minute<60 and second<60)
        return (year,month,day,hour,minute,second,int((m[7] or '').ljust(9,'0')))
    started, finished, origin = wall(t['started_at']), wall(t['finished_at']), wall(s['origin_at'])
    need(started<=origin<=finished)
    previous, previous_at, spans = -1, origin, {}
    for seq, e in enumerate(s['events'], 1):
        if expected is not None:
            need(tuple(e[k] for k in ('stage','state','code','segment','span_id'))==expected[seq-1] and
                 e['job']=='NOT_OBSERVED' and e['tun']=='NOT_OBSERVED' and
                 all(e[k] is None for k in ('round','ordinal','rule_count','completed_count')))
        need(e['seq']==str(seq) and e['state'] in ('BEGIN','END','OBSERVATION'))
        for k in ('round','ordinal','rule_count','completed_count'):
            if e[k] is not None:
                decimal(e[k])
        elapsed, at = decimal(e['elapsed_ns']), wall(e['at'])
        need(elapsed>=previous and previous_at<=at<=finished)
        if e['state']=='BEGIN':
            need(e['span_id'] is not None and decimal(e['span_id'])>0 and e['span_id'] not in spans and
                 len(spans)<16 and e['duration_ns'] is None)
            spans[e['span_id']] = e
        elif e['state']=='END':
            need(bool(spans) and e['span_id']==next(reversed(spans)))
            begin = spans.pop(e['span_id'])
            need(decimal(e['duration_ns'])==elapsed-decimal(begin['elapsed_ns']) and
                 all(e[k]==begin[k] for k in ('span_id','stage','segment')))
        else:
            need(e['span_id']==(next(reversed(spans)) if spans else None) and e['duration_ns'] is None)
        previous, previous_at = elapsed, at
    need(not spans)
    terminal = s['terminal']
    need(type(terminal) is dict and terminal['result']==result and
         decimal(terminal['elapsed_ns'])>=previous and s['elapsed_ns']==terminal['elapsed_ns'] and
         previous_at<=wall(terminal['at'])<=finished)


def reconciliation_worker_absent(pid, timeout=5):
    # A reused PID also blocks; never signal it or break a lock. Require a full,
    # nonempty successfully parsed census, not an ambiguous ps -p nonzero exit.
    i.require(type(pid) is int and pid>0, 'CORE_RELOAD_CLAIM')
    result = subprocess.run(['/bin/ps','-ww','-axo','pid=,uid=,lstart=,command='],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
                            env={'PATH':'/usr/bin:/bin','LC_ALL':'C','LANG':'C'})
    i.require(result.returncode==0 and not result.stderr, 'CORE_RELOAD_WORKER_READ')
    rows = result.stdout.decode('utf-8').splitlines()
    i.require(bool(rows), 'CORE_RELOAD_WORKER_READ')
    pids = set()
    for row in rows:
        f = row.split(None,7)
        i.require(len(f)==8 and re.fullmatch(r'[1-9][0-9]*',f[0]) and
                  re.fullmatch(r'-?[0-9]+',f[1]) and
                  re.fullmatch(r'(Mon|Tue|Wed|Thu|Fri|Sat|Sun) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2} [0-9]{4}', ' '.join(f[2:7])) and
                  int(f[0]) not in pids, 'CORE_RELOAD_WORKER_READ')
        pids.add(int(f[0]))
    i.require(pid not in pids, 'CORE_RELOAD_WORKER_PRESENT')


def reconciliation_config(pin):
    n = CORE_RELOAD_SUPPORT
    n['shape'](pin,'identity config selection')
    n['need'](n['hexstr'](pin['identity'],64) and n['hexstr'](pin['config'],64) and
              (pin['selection'] is None or n['hexstr'](pin['selection'],64)))


def reconciliation_core(core, app):
    n = CORE_RELOAD_SUPPORT
    n['shape'](core,'pid uid birth command')
    n['need'](type(core['pid']) is int and core['pid']>0 and type(core['uid']) is int and core['uid']==0 and
              type(core['birth']) is str and bool(core['birth']) and type(core['command']) is str and
              core['command'].startswith(str(app/'service/anytls-macos')+' '))


def reconciliation_stop_response(r, op, epoch, job):
    n = CORE_RELOAD_SUPPORT
    n['shape'](r,'timeline_schema code ok helper_epoch operation_id timeline_availability helper_version helper_sha256 config_identity loaded running diagnostics')
    n['need'](type(r['timeline_schema']) is int and r['timeline_schema']==1 and r['code']=='' and
              r['ok'] is True and r['loaded'] is False and r['running'] is False and
              r['operation_id']==op and r['helper_epoch']==epoch and r['timeline_availability']=='AVAILABLE' and
              r['helper_sha256']==job['digest'] and r['helper_version']==job['tag'] and
              r['config_identity']==job['before']['config']['identity'])
    reconciliation_stop_diagnostics(r['diagnostics'])


def reconciliation_stop_diagnostics(d):
    n = CORE_RELOAD_SUPPORT
    n['diagnostics'](d,reload=False)
    n['need'](d['operation']=='STOP' and d['job']=='UNLOADED' and d['tun'] in ('NOT_OBSERVED','NOT_TUN','UNKNOWN'))


def reconciliation_stop_trace(r, op, epoch, job):
    n = CORE_RELOAD_SUPPORT
    identity = job['before']['config']['identity']
    n['read_check'](r,identity,op,epoch)
    t = r['trace']
    n['need'](t['authority']=='AUXILIARY_NOT_AUTHORITY' and t['operation_id']==op and
              t['helper_epoch']==epoch and t['config_identity']==identity and t['operation']=='STOP' and
              t['source']=='MANUAL_STOP' and t['state']=='FINISHED' and
              t['lifecycle_result']=='SUCCEEDED' and t['helper_return']=='SUCCEEDED' and
              t['web_return']=='NOT_ATTEMPTED')
    reconciliation_stop_diagnostics(t['diagnostics'])
    n['need'](len(t['streams'])==1 and t['streams'][0]['role']=='HELPER')
    s = t['streams'][0]
    n['need'](s['provenance']==dict(version=job['tag'],git_revision=job['revision'],dirty=False,
              sha256=job['digest'],sha_kind='FILE_BYTES',execution_mapping='NOT_ATTESTED') and
              s['gap'] is False and s['dropped_events']=='0' and s['first_missing_seq'] is None and
              s['current'] is None and n['hexstr'](s['clock_id'],32) and len(s['events'])>=4 and
              s['generated_events']==str(len(s['events'])) and
              s['retained_ranges']==[dict(first='1',last=str(len(s['events'])))])
    # STOP may include lifecycle STOP/RESTORE spans, not RELOAD's preflight.
    n['need'](s['events'][0]['stage']=='HELPER_ACCEPT' and s['events'][-1]['stage']=='HELPER_FINISH' and
              s['events'][-1]['code']=='OK' and
              any(e['stage']=='HELPER_FINAL_STATE' and e['state']=='END' and e['code']=='OK' for e in s['events']))
    reconciliation_stream(t,s,None,'SUCCEEDED')


def reconcile_preflight(app, root):
    """No archive/replay: append one distinct terminal proof, unlink pending LAST."""
    reconciliation_lock_required(app)
    n = CORE_RELOAD_SUPPORT
    need, shape = n['need'], n['shape']
    deadline = time.monotonic()+25
    def remaining():
        left = deadline-time.monotonic()
        need(left>0, 'CORE_RELOAD_DEADLINE')
        return min(5,left)
    op = root.name.removeprefix('.core-reload-')
    need(n['hexstr'](op,32) and root.parent.resolve(strict=True)==app.resolve(strict=True))
    st = root.lstat()
    need(stat.S_ISDIR(st.st_mode) and st.st_uid==os.getuid() and stat.S_IMODE(st.st_mode)==0o700)
    need(root.resolve(strict=True)==root and not os.path.lexists(root/'accepted.json') and
         not os.path.lexists(root/'timeline.json'))
    names = ('job.json','intent.json','response.json','result.json','claim.json')
    receipts = {name:reconciliation_receipt(root,name) for name in names}
    hashes = {name:value[1] for name,value in receipts.items()}
    job, intent, response, result, claim = [receipts[name][0] for name in names]
    shape(job,'app operation_id digest tag revision before')
    shape(intent,'operation_id helper_epoch action allow_insecure single_dispatch')
    shape(result,'state operation_id error_class code')
    shape(claim,'pid')
    need(result==dict(state='UNKNOWN',operation_id=op,error_class='ValueError',code='CORE_RELOAD_INVALID') and
         job['app']==str(app) and job['operation_id']==op and n['hexstr'](job['digest'],64) and
         n['hexstr'](job['revision'],40) and type(job['tag']) is str and re.fullmatch(r'v[0-9A-Za-z.+_-]+',job['tag']))
    shape(job['before'],'state config core' + (' status' if 'status' in job['before'] else ''))
    need(job['before']['state']=='RUNNING' and type(claim['pid']) is int and claim['pid']>0)
    if 'status' in job['before']:
        prior = job['before']['status']
        need(type(prior) is dict and n['hexstr'](prior.get('helper_sha256'),64) and
             type(prior.get('helper_version')) is str and re.fullmatch(r'v[0-9A-Za-z.+_-]+',prior['helper_version']))
        n['status_check'](prior,prior['helper_sha256'],prior['helper_version'],job['before']['config']['identity'])
        need(prior['loaded'] is True and prior['running'] is True)
    pin, old = job['before']['config'], job['before']['core']
    reconciliation_config(pin)
    reconciliation_core(old,app)
    epoch = intent['helper_epoch']
    need(intent['operation_id']==op and n['hexstr'](epoch,32) and intent['action']=='reload' and
         type(intent['allow_insecure']) is bool and intent['single_dispatch'] is True)
    shape(response,'timeline_schema code ok helper_epoch operation_id timeline_availability helper_version helper_sha256 config_identity loaded running diagnostics')
    diag = dict(schema=1, operation='RELOAD', outcome='FAILED', stage='HELPER_PREFLIGHT', reason='PREFLIGHT_REJECTED',
                rollback='NOT_ATTEMPTED',restoration='NOT_ATTEMPTED',cleanup='NOT_ATTEMPTED',
                receipt='NOT_ATTEMPTED',job='NOT_OBSERVED',tun='NOT_OBSERVED')
    shape(response['diagnostics'],'schema operation outcome stage reason rollback restoration cleanup receipt job tun')
    need(type(response['diagnostics']['schema']) is int and response['diagnostics']==diag and
         type(response['timeline_schema']) is int and response['timeline_schema']==1 and
         response['code']=='PREFLIGHT_FAILED' and response['ok'] is False and
         response['loaded'] is False and response['running'] is False and response['operation_id']==op and
         response['helper_epoch']==epoch and response['timeline_availability']=='AVAILABLE' and
         response['helper_sha256']==job['digest'] and response['helper_version']==job['tag'] and response['config_identity']==pin['identity'])
    marker_path = root/'reconciled.json'
    if os.path.lexists(marker_path):
        marker, _ = reconciliation_receipt(root,'reconciled.json')
        shape(marker,'schema status operation_id helper_epoch receipt_sha256 helper_read current stop_sha256')
        need(type(marker['schema']) is int and marker['schema']==1 and marker['status']=='RECONCILED_PREFLIGHT_REJECTED' and
             marker['operation_id']==op and marker['helper_epoch']==epoch and marker['receipt_sha256']==hashes and
             not os.path.lexists(root/'pending.json'))
        rejection_trace(marker['helper_read'],job,epoch,diag)
        shape(marker['current'],'state config core status')
        current = marker['current']
        n['status_check'](current['status'],job['digest'],job['tag'],pin['identity'])
        reconciliation_config(current['config'])
        need(current['config']['identity']==pin['identity'])
        if current['core'] is not None:
            reconciliation_core(current['core'],app)
        need(current['state']=='STOPPED' and current['core'] is None and
             current['status']['loaded'] is False and current['status']['running'] is False)
        stop_names = {name for name in ('stop-intent.json','stop-read.json','stop-response.json') if os.path.lexists(root/name)}
        need(type(marker['stop_sha256']) is dict and set(marker['stop_sha256'])==stop_names and
             stop_names in (set(),{'stop-intent.json','stop-read.json'},{'stop-intent.json','stop-read.json','stop-response.json'}))
        if marker['stop_sha256']:
            stop_intent = reconciliation_receipt(root,'stop-intent.json')[0]
            shape(stop_intent,'operation_id helper_epoch action allow_insecure single_dispatch')
            need(n['hexstr'](stop_intent['operation_id'],32) and stop_intent['operation_id']!=op and
                 stop_intent==dict(operation_id=stop_intent['operation_id'],helper_epoch=epoch,action='stop',allow_insecure=False,single_dispatch=True) and
                 stop_intent['allow_insecure'] is False and stop_intent['single_dispatch'] is True)
            reconciliation_stop_trace(reconciliation_receipt(root,'stop-read.json')[0],stop_intent['operation_id'],epoch,job)
            if 'stop-response.json' in stop_names:
                reconciliation_stop_response(reconciliation_receipt(root,'stop-response.json')[0],stop_intent['operation_id'],epoch,job)
            need(all(n['hexstr'](digest,64) and reconciliation_receipt(root,name)[1]==digest for name,digest in marker['stop_sha256'].items()))
        return True
    pending, _ = reconciliation_receipt(root,'pending.json')
    need(pending==dict(operation_id=op))
    reconciliation_worker_absent(claim['pid'],timeout=remaining())
    fresh_pin = n['config_pin'](app)
    reconciliation_config(fresh_pin)
    need(fresh_pin['identity']==pin['identity'])
    def unchanged():
        need(n['config_pin'](app)==fresh_pin and n['file_hash'](app/'anytls-macos')==job['digest'] and
             n['helper_hash']()==job['digest'])
        remaining()  # Hashing/filesystem calls are not interruptible by this budget.
    def current_read():
        unchanged()
        status = n['status_check'](n['request'](dict(action='status',allow_insecure=False),timeout=remaining()),job['digest'],job['tag'],pin['identity'])
        cores = n['processes'](app,timeout=remaining())
        for core in cores:
            reconciliation_core(core,app)
        need((status['loaded'] is False and status['running'] is False and cores==[]) or
             (status['loaded'] is True and status['running'] is True and len(cores)==1))
        unchanged()
        return dict(state='RUNNING' if cores else 'STOPPED',config=fresh_pin,core=cores[0] if cores else None,status=status)
    current = current_read()
    timeline = n['request'](dict(timeline_schema=1,action='startup.read',operation_id=op),timeout=remaining())
    rejection_trace(timeline,job,epoch,diag)  # original epoch MUST still be known
    stop_hashes = {}
    need(os.path.lexists(root/'stop-intent.json') or
         not any(os.path.lexists(root/name) for name in ('stop-read.json','stop-response.json')))
    if current['state']=='RUNNING' or os.path.lexists(root/'stop-intent.json'):
        # One new STOP, never replay the rejected reload or an uncertain STOP.
        if not os.path.lexists(root/'stop-intent.json'):
            unchanged()
            n['put'](root,'stop-intent.json',dict(operation_id=i.uuid.uuid4().hex,helper_epoch=epoch,
                     action='stop',allow_insecure=False,single_dispatch=True))
            new_stop = True
        else:
            new_stop = False
        stop_intent = reconciliation_receipt(root,'stop-intent.json')[0]
        shape(stop_intent,'operation_id helper_epoch action allow_insecure single_dispatch')
        stop_op = stop_intent['operation_id']
        need(n['hexstr'](stop_op,32) and stop_op!=op and stop_intent['helper_epoch']==epoch and
             stop_intent['action']=='stop' and stop_intent['allow_insecure'] is False and stop_intent['single_dispatch'] is True)
        received = False
        if new_stop:
            began = time.monotonic()
            try:
                reply = n['request'](dict(timeline_schema=1,action='stop',operation_id=stop_op,allow_insecure=False),timeout=300)
                received = True
            except OSError:
                pass  # Transport loss only; decode/frame/peer errors must HOLD.
            finally:
                deadline += time.monotonic()-began  # STOP has its own bounded lifecycle budget.
            if received:
                n['put'](root,'stop-response.json',reply)
                need(os.path.lexists(root/'stop-response.json'))
        if os.path.lexists(root/'stop-response.json'):
            reconciliation_stop_response(reconciliation_receipt(root,'stop-response.json')[0],stop_op,epoch,job)
        stopped = n['request'](dict(timeline_schema=1,action='startup.read',operation_id=stop_op),timeout=remaining())
        reconciliation_stop_trace(stopped,stop_op,epoch,job)
        if not os.path.lexists(root/'stop-read.json'):
            n['put'](root,'stop-read.json',stopped)
        else:
            reconciliation_stop_trace(reconciliation_receipt(root,'stop-read.json')[0],stop_op,epoch,job)
        stop_hashes = {name:reconciliation_receipt(root,name)[1] for name in
                       ('stop-intent.json','stop-read.json','stop-response.json') if os.path.lexists(root/name)}
        current = current_read()
    need(current['state']=='STOPPED' and current_read()==current)
    reconciliation_worker_absent(claim['pid'],timeout=remaining())
    need(all(reconciliation_receipt(root,name)==receipts[name] for name in names) and
         reconciliation_receipt(root,'pending.json')[0]==pending and
         all(getattr(root.lstat(),k)==getattr(st,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid')))
    unchanged()
    proof = dict(schema=1,status='RECONCILED_PREFLIGHT_REJECTED',operation_id=op,helper_epoch=epoch,
                 receipt_sha256=hashes,helper_read=timeline,current=current,stop_sha256=stop_hashes)
    remaining()
    n['put'](root,'reconciled.json',proof)
    need(reconciliation_receipt(root,'reconciled.json')[1]==hashlib.sha256(n['json'].dumps(proof,sort_keys=True).encode()).hexdigest())
    need(all(reconciliation_receipt(root,name)==receipts[name] for name in names) and current_read()==current and
         reconciliation_receipt(root,'pending.json')[0]==pending)
    reconciliation_worker_absent(claim['pid'],timeout=remaining())
    reconciliation_lock_required(app)
    need(all(reconciliation_receipt(root,name)[1]==digest for name,digest in stop_hashes.items()))
    unchanged()  # full installed app SHA and current content fence before unlink
    remaining()
    # No subsequent operation may fail: crash resurrection is conservative HOLD.
    # A marker plus pending is NOT automatically resumed after uncertain fsync.
    (root/'pending.json').unlink()
    return True


class CoreReload:
    def __init__(self, app):
        self.app = app.resolve(strict=True)
        core_reload_guard(self.app)
        self.before = CORE_RELOAD_SUPPORT['capture'](self.app)

    def finish(self, digest, tag, revision):
        if self.before['state'] != 'RUNNING':
            print('Core reload SKIPPED: original VPN '+self.before['state']+'; no VPN start/stop/reload requested.')
            return
        # install_verified owns this fd for the complete install/activation.
        # pass_fds retains the SAME flock open-file description after parent loss.
        lock_fd = self.lock_fd
        op = i.uuid.uuid4().hex
        root = self.app / ('.core-reload-' + op)
        root.mkdir(mode=0o700)  # never reuse a consumed/uncertain transaction
        parent_fd = os.open(self.app, os.O_RDONLY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        CORE_RELOAD_SUPPORT['put'](root, 'job.json', dict(app=str(self.app),operation_id=op,digest=digest,
                                                       tag=tag,revision=revision,before=self.before))
        CORE_RELOAD_SUPPORT['put'](root, 'pending.json', dict(operation_id=op))
        progress('Core reload single-dispatch receipt: '+str(root))
        try:
            with private_append(root/'worker.log') as log:
                child = subprocess.Popen([sys.executable,'-I','-B','-c',CORE_RELOAD_WORKER,str(root)],
                                         stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True,
                                         cwd=str(root),env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'},
                                         pass_fds=(lock_fd,))
            rc = child.wait(timeout=360)
            result = i.strict_json((root/'result.json').read_bytes())
        except (OSError, ValueError, subprocess.SubprocessError):
            raise ValueError('Core reload UNKNOWN; do not retry/reload/rollback. Read-only recovery of operation '+op+'; receipt: '+str(root)) from None
        i.require(type(result) is dict, 'Core reload UNKNOWN; receipt: '+str(root))
        i.require(rc==0 and result.get('state')=='SUCCEEDED' and result.get('operation_id')==op,
                  'Core reload '+('REJECTED' if result.get('state')=='REJECTED' else 'UNKNOWN')+'; no automatic retry/rollback; receipt: '+str(root))
        try:
            # Only THIS observing parent may accept exit 0. Complete result bytes
            # or a worker-created marker alone never clear UNKNOWN. Re-sync and
            # read back the result before committing an operation/hash-bound ack.
            regular(root/'result.json')
            with (root/'result.json').open('rb') as receipt:
                os.fsync(receipt.fileno())
                i.require(i.strict_json(receipt.read()) == result, 'CORE_RELOAD_RESULT_DRIFT')
            CORE_RELOAD_SUPPORT['put'](root, 'accepted.json',
                                      dict(operation_id=op,result_sha256=sha256(root/'result.json')))
            accepted = i.strict_json((root/'accepted.json').read_bytes())
            i.require(accepted == dict(operation_id=op,result_sha256=sha256(root/'result.json')),
                      'CORE_RELOAD_ACCEPTANCE_DRIFT')
            # Durable commit is the synced acceptance with the pre-existing
            # pending sentinel still present. Unlink is LAST and needs no sync:
            # crash may resurrect pending (conservative HOLD), never acceptance.
            # No automatic recovery, even if the child later succeeds.
            (root/'pending.json').unlink()
        except (OSError, ValueError):
            raise ValueError('Core reload UNKNOWN; acceptance not committed; inspect receipt: '+str(root)) from None
        print('Core reload SUCCEEDED: authenticated helper, matching operation/epoch, new core PID, old core gone and TUN readback; receipt: '+str(root)+'. FILE_BYTES provenance only; execution mapping NOT_ATTESTED; external network NOT_TESTED.')


def install_verified(bundle, tag, app, home, runner=subprocess.run, env=None, tty=None, webui_listen="0.0.0.0", reload_core=True):
    """Only called after every downloaded byte and manifest has been verified."""
    with installation_lock(app) as lock_fd:
        core_reload_guard(app)
        return _install_verified(bundle, tag, app, home, runner, env, tty, webui_listen, reload_core, lock_fd)


def _install_verified(bundle, tag, app, home, runner, env, tty, webui_listen, reload_core, lock_fd):
    target, config, link = app / "anytls-macos", app / "config.yaml", home / ".local/bin/anytls"
    check_link(target, link)
    if target.exists() or target.is_symlink():
        regular(target)
    if config.exists() or config.is_symlink():
        regular(config)
    webui = WebUI(target, env, listen=webui_listen)
    try:
        webui.preflight()
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        raise WebUIPreflightRejected("WEBUI_PREFLIGHT_REJECTED: no helper install, binary publish, WebUI signal or core reload dispatched: " + str(exc)) from exc
    # Capture BEFORE helper replacement; explicit opt-out performs no helper read.
    try:
        activation = CoreReload(app) if reload_core else None
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        reason = str(exc) if type(exc) is ValueError and re.fullmatch(r'CORE_RELOAD_[A-Z_]+', str(exc)) else 'CORE_RELOAD_UNAVAILABLE'
        raise CoreReloadPreflightRejected('core reload preflight rejected; CORE_RELOAD_PREFLIGHT_REJECTED: ' + reason +
                                         '; no helper install, binary publish, WebUI signal or core reload dispatched') from exc
    if activation is not None:
        activation.lock_fd = lock_fd
    # A unique, regular candidate in appdir matches the helper's fixed path policy.
    fd, name = tempfile.mkstemp(prefix=".anytls-bin-candidate-", dir=app)
    candidate = Path(name)
    try:
        with os.fdopen(fd, "wb") as out, (bundle / "bin/anytls-macos").open("rb") as src:
            shutil.copyfileobj(src, out, 1024 * 1024)
            out.flush()
            os.fsync(out.fileno())
        candidate.chmod(0o700)
        candidate_digest = sha256(candidate)
        i.require(candidate_digest == sha256(bundle / "bin/anytls-macos"), "HELPER_STATUS_CANDIDATE_MISMATCH")
        command_version(candidate, tag, runner, env)
        created = i.install_config(bundle, app)
        regular(config)
        # Both executable names must select the same physical sibling config.
        i.require(candidate.resolve(strict=True).parent == app.resolve(strict=True), "HELPER_STATUS_CONFIG")
        config_identity = helper_config_identity(config)
        i.require(helper_config_identity(candidate.resolve(strict=True).parent / "config.yaml") == config_identity,
                  "HELPER_STATUS_CONFIG_MISMATCH")
        # Resolve the CLI collision before making any privileged change. The
        # first-install symlink may be dangling until the atomic publish below.
        i.ensure_link(target, link)
        opener = tty or (lambda: open("/dev/tty", "r+b", buffering=0))
        progress("[4/6] 系统授权：请在当前终端完成 sudo 提示；此时暂停进度刷屏，输入不回显。")
        with opener() as terminal:
            # Give native sudo exclusive use of the controlling terminal. Do not
            # read a password, pipe it through Python, or print over its prompt.
            try:
                runner(["/usr/bin/sudo", "-v"], check=True, stdin=terminal,
                       stdout=terminal, stderr=terminal, env=env)
            except subprocess.CalledProcessError:
                raise ValueError("系统授权未完成；未执行助手安装或程序替换，请检查本机终端的 sudo 提示") from None
            progress("系统授权已完成，正在安装并验证受限助手；终端由助手独占，不刷等待进度。")
            runner([str(candidate), "helper", "install"], check=True, stdin=terminal,
                   stdout=terminal, stderr=terminal, env=env)
        progress("正在验证助手认证与配置绑定")
        result = runner([str(candidate), "helper", "status"], check=True, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, timeout=30, env=env)
        i.require(result.returncode == 0, "HELPER_STATUS_EXIT")
        validate_helper_status(result.stdout, candidate_digest, tag, config_identity)
        i.require(sha256(candidate) == candidate_digest, "HELPER_STATUS_CANDIDATE_MISMATCH")
        i.require(stat.S_ISREG(config.lstat().st_mode), "HELPER_STATUS_CONFIG")
        i.require(helper_config_identity(config) == config_identity and
                  helper_config_identity(candidate.resolve(strict=True).parent / "config.yaml") == config_identity,
                  "HELPER_STATUS_CONFIG_MISMATCH")
        progress("[5/6] 备份旧程序并原子替换为已验证版本")
        backup = i.publish_binary(candidate, target, app)
        command_version(target, tag, runner, env)
        webui.published_digest = candidate_digest
        try:
            with stage("[6/6] 切换至新版 WebUI 并验证页面就绪；VPN 保持运行"):
                webui.restart()
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            raise ValueError("binary installed but WebUI start failed: " + str(exc) + "; inspect ~/.anytls/webui.log; VPN was not stopped/reloaded") from exc
        if activation is not None:
            info = i.strict_json((bundle / "BUILD-INFO.json").read_bytes())
            activation.finish(candidate_digest, tag, info["source_commit"])
        configure_shell_path(home, os.environ if env is None else env)
        if created:
            print("Created 0600 config.yaml EXAMPLE ONLY. Enter your actual node/password/CA; no usable credentials were generated.")
        return backup
    finally:
        candidate.unlink(missing_ok=True)


def update_only(args, transport=i.open_url, runner=subprocess.run, system=None, machine=None, euid=None, env=None):
    """Unprivileged, prebuilt-only publisher; never enter full-install lifecycle."""
    failure = 44
    downloading = False
    try:
        i.require((system or platform.system()) == "Darwin", "macOS required")
        i.require((os.geteuid() if euid is None else euid) != 0, "normal user required")
        machine = machine or platform.machine()
        arch = args.update_arch
        i.require(arch in ("arm64", "amd64") and machine in ("arm64", "x86_64", "amd64"), "unsupported architecture")
        # Go pins its OWN architecture. In particular amd64 under Rosetta stays
        # amd64; do not call full install's hardware-preference detect_arch.
        i.require(not args.check_download and args.arch is None, "incompatible update options")
        i.validate_version(args.version)
        app, target = Path(args.app_dir), Path(args.target)
        i.require(app.is_absolute() and target.is_absolute() and target.parent == app and
                  target.name in ("anytls", "anytls-macos"), "invalid update target")
        i.require(stat.S_ISDIR(app.lstat().st_mode), "app must be real directory")
        regular(target)
        if env is None:
            env = {k: os.environ[k] for k in ("HOME", "PATH", "LANG", "TMPDIR") if k in os.environ}
        failure = 45
        with installation_lock(app):
            core_reload_guard(app)
            with tempfile.TemporaryDirectory(prefix=".anytls-update-", dir=app) as temp:
                work = Path(temp)
                failure = 44
                downloading = True
                tag, bundle, digest, commit = verified_download(work, args.version, update_transport(transport), arch=arch)
                downloading = False
                failure = 45
                releases = app / "releases"
                if releases.exists() or releases.is_symlink():
                    i.require(stat.S_ISDIR(releases.lstat().st_mode), "unsafe release directory")
                releases.mkdir(mode=0o700, exist_ok=True)
                kept = releases / (tag + "-" + i.uuid.uuid4().hex)
                kept.mkdir(mode=0o700)
                # Copy all validated bundle files/licenses and the selected package.
                # Hash the sources BEFORE copying and independently reopen output.
                for src in bundle.rglob("*"):
                    dst = kept / src.relative_to(bundle)
                    if src.is_dir():
                        dst.mkdir(mode=0o700, parents=True, exist_ok=True)
                    else:
                        regular(src)
                        expected = sha256(src)
                        dst.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                        shutil.copyfile(src, dst)
                        i.require(sha256(dst) == expected, "retained material SHA mismatch")
                names = ("SHA256SUMS", "anytls-core-" + tag + "-darwin-" + arch + ".tar.gz")
                for name in names:
                    expected = sha256(work / name)
                    shutil.copyfile(work / name, kept / name)
                    i.require(sha256(kept / name) == expected, "retained archive SHA mismatch")
                candidate = work / "candidate"
                shutil.copyfile(kept / "bin/anytls-macos", candidate)
                i.require(sha256(candidate) == digest, "candidate SHA mismatch")
                candidate.chmod(0o700)
                failure = 44
                command_version(candidate, tag, runner, env)
                failure = 45
                regular(target)
                backup = i.publish_binary(candidate, target, app)
                failure = 46
                command_version(target, tag, runner, env)
                return {"version": tag, "source_commit": commit, "binary_sha256": digest,
                        "status": "UPDATED", "restartRequired": True, "installed": tag,
                        "backup": str(backup), "platform": "darwin-" + arch}
    except BinaryUnavailable as exc:
        raise UpdateFailed(42) from exc
    except DownloadFailed as exc:
        raise UpdateFailed(43) from exc
    except (gzip.BadGzipFile, EOFError) as exc:
        raise UpdateFailed(44 if downloading else failure) from exc
    except FileNotFoundError as exc:
        # Missing extracted mandatory file is invalid material, not disk-full.
        raise UpdateFailed(44 if downloading else failure) from exc
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError, subprocess.SubprocessError) as exc:
        # Download/extraction disk I/O is publication/storage, not transport.
        code = 45 if downloading and isinstance(exc, OSError) else failure
        raise UpdateFailed(code) from exc
    except Exception as exc:
        raise UpdateFailed(47) from exc


def run(args, transport=i.open_url, runner=subprocess.run, system=None, machine=None, euid=None, home=None, tty=None, env=None):
    explicit_reload = getattr(args, "reload_core", None)
    full_install = not (getattr(args, "update_only", False) or args.check_download)
    reload_core = full_install if explicit_reload is None else explicit_reload
    i.require(explicit_reload is not True or full_install,
              "--reload-core is allowed only with full installation")
    if getattr(args, "update_only", False):
        return update_only(args, transport, runner, system, machine, euid, env)
    webui_listen = getattr(args, "webui_listen", None)
    webui_listen = canonical_ipv4("0.0.0.0" if webui_listen is None else webui_listen)
    home = Path.home() if home is None else Path(home)
    app = home / ".anytls"
    requested_arch = getattr(args, "arch", None)
    i.require(args.check_download or requested_arch is None, "--arch is allowed only with --check-download; installation always uses the host architecture")
    system = system or platform.system()
    if not args.check_download:
        i.require((os.geteuid() if euid is None else euid) != 0, "run as your normal user, never root/sudo")
        arch = detect_arch(system, machine or platform.machine(), runner)
        i.require(not app.is_symlink(), "app directory cannot be a symlink")
        check_link(app / "anytls-macos", home / ".local/bin/anytls")
        app.mkdir(mode=0o700, parents=True, exist_ok=True)
    else:
        # Verification is process-free, including no sysctl probe. On translated
        # Python this checks its process architecture; --arch can select either.
        # Actual installation separately detects Apple Silicon through Rosetta.
        arch = requested_arch or ("amd64" if system == "Darwin" and (machine or platform.machine()) in ("x86_64", "amd64") else "arm64")
    # Check-only never creates app/config/link and never executes downloaded code.
    with tempfile.TemporaryDirectory(prefix="anytls-binary-", dir=None if args.check_download else app) as temp:
        work = Path(temp)
        try:
            tag, bundle, digest, commit = verified_download(work, args.version, transport, arch=arch)
        except (OSError, ValueError, KeyError, TypeError, tarfile.TarError, EOFError, http.client.HTTPException) as exc:
            # Preserve direct callers' original type/identity (including missing
            # platform packages); only the CLI needs the known phase marker.
            exc.anytls_preinstall = True
            raise
        report = {"version": tag, "source_commit": commit, "binary_sha256": digest,
                  "platform": "darwin-" + arch, "download_verified": True, "executed": False}
        if args.check_download:
            print(i.json.dumps(report, sort_keys=True))
            return report
        if env is None:
            env = {k: os.environ[k] for k in ("HOME", "PATH", "SHELL", "ZDOTDIR", "USER", "LOGNAME", "LANG", "TERM", "TMPDIR") if k in os.environ}
        with installation_lock(app) as lock_fd:
            core_reload_guard(app)
            # Retain before privileged change/publication, and under the same
            # exclusion and pending guard as the helper and detached worker.
            progress("[3/6] 保留许可证、校验和与预编译程序包；已有配置及密码不覆盖")
            kept = app / "releases" / (tag + "-" + i.uuid.uuid4().hex)
            kept.parent.mkdir(mode=0o700, exist_ok=True)
            os.replace(bundle, kept)
            for name in ("SHA256SUMS", "anytls-core-" + tag + "-darwin-" + arch + ".tar.gz"):
                shutil.copyfile(work / name, kept / name)
                i.require(sha256(work / name) == sha256(kept / name), "retained release material mismatch")
            backup = _install_verified(kept, tag, app, home, runner, env, tty, webui_listen, reload_core, lock_fd)
        print("Installed " + tag + " from verified prebuilt release; authenticated helper status succeeded.")
        if backup:
            print("Previous executable backup: " + str(backup))
        print("SHA256SUMS trusts GitHub HTTPS, NOT an independent authenticity signature.")
        print("Run now by absolute path: " + shlex.quote(str(app / "anytls-macos")))
        print("The current terminal PATH is unchanged. Open a new terminal, or for bash/zsh run: export PATH=" +
              shlex.quote(str(home / ".local/bin")) + ':"$PATH"')
        print("WebUI started using the new binary at " + webui_listen + ":18089. This installation uses --webui-listen or the default 0.0.0.0 (all IPv4 interfaces); old --listen arguments are not inherited. Open http://<real-host-or-IP>:18089/ using a reachable host/IP, not 0.0.0.0. HTTP is unencrypted; restrict access to trusted networks or protect it with a firewall/SSH tunnel/TLS reverse proxy." +
              (" Default/explicit core reload outcome and receipt are reported above; external network was not tested." if reload_core else " --no-reload-core: VPN was NOT stopped, reloaded or restarted; its running snapshot is unchanged."))
        report["executed"] = True
        return report


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    class Parser(argparse.ArgumentParser):
        def error(self, message):
            if "--update-only" in argv:
                raise UpdateFailed(44)
            super().error(message)
    parser = Parser(description=__doc__)
    parser.add_argument("--version", type=i.validate_version, help="stable tag; default is latest stable release")
    parser.add_argument("--check-download", action="store_true", help="verify only checksums and the selected binary package without executing code or changing configuration")
    parser.add_argument("--arch", choices=("arm64", "amd64"), help="only with --check-download: target archive architecture; default is native on macOS, arm64 elsewhere")
    parser.add_argument("--webui-listen", type=canonical_ipv4, default=None,
                        help="this installation's WebUI IPv4 address; default 0.0.0.0 (all interfaces), never inherited from old argv; HTTP is unencrypted; not valid with --check-download or --update-only")
    parser.add_argument("--update-only", action="store_true", help="replace only the existing app executable; no helper, configuration or restart")
    reload_options = parser.add_mutually_exclusive_group()
    reload_options.add_argument("--reload-core", dest="reload_core", action="store_true", default=None,
                                help="full install default: reload an originally running VPN once after readiness; never start a stopped VPN")
    reload_options.add_argument("--no-reload-core", dest="reload_core", action="store_false",
                                help="explicitly skip core reload; no effect in check-download/update-only")
    parser.add_argument("--app-dir")
    parser.add_argument("--target")
    parser.add_argument("--update-arch", choices=("arm64", "amd64"))
    try:
        args = parser.parse_args(argv)
    except UpdateFailed:
        print("UPDATE_VALIDATION_FAILED", file=sys.stderr)
        return 44
    if args.update_only:
        if not all((args.app_dir, args.target, args.update_arch, args.version)) or args.arch is not None or args.check_download or args.webui_listen is not None or args.reload_core:
            print("UPDATE_VALIDATION_FAILED", file=sys.stderr)
            return 44
    elif any((args.app_dir, args.target, args.update_arch)):
        parser.error("--app-dir, --target and --update-arch require --update-only")
    if args.arch is not None and not args.check_download:
        parser.error("--arch is allowed only with --check-download")
    if args.check_download and args.webui_listen is not None:
        parser.error("--webui-listen cannot be used with --check-download")
    if args.check_download and args.reload_core:
        parser.error("--reload-core cannot be used with --check-download")
    try:
        result = run(args)
        if args.update_only:
            print(i.json.dumps(result, sort_keys=True))
    except UpdateFailed as exc:
        codes = {42: "UPDATE_BINARY_UNAVAILABLE", 43: "UPDATE_DOWNLOAD_FAILED", 44: "UPDATE_VALIDATION_FAILED",
                 45: "UPDATE_PUBLISH_FAILED", 46: "UPDATE_VERIFY_FAILED", 47: "UPDATE_UNAVAILABLE"}
        print(codes.get(exc.code, "UPDATE_UNAVAILABLE"), file=sys.stderr)
        return exc.code if exc.code in codes else 47
    except (WebUIPreflightRejected, CoreReloadPreflightRejected) as exc:
        advice = 'close/inspect the existing WebUI' if isinstance(exc, WebUIPreflightRejected) else 'inspect the original core state read-only before retrying'
        print("Binary installation failed: " + str(exc) + "; " + advice + "; no automatic recovery attempted.", file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError, EOFError, http.client.HTTPException, subprocess.SubprocessError) as exc:
        if getattr(exc, 'anytls_preinstall', False):
            detail = i.transport_diagnostic(exc) if isinstance(exc, (OSError, http.client.HTTPException)) else type(exc).__name__
            print("Binary download/verification failed: " + detail +
                  "; no helper install, binary publish, WebUI signal or core reload dispatched in this attempt; "
                  "earlier UNKNOWN receipts retained and must be reconciled read-only. "
                  "No automatic source compilation, recovery reload or rollback.", file=sys.stderr)
            return 1
        detail = str(exc) if type(exc) is ValueError else type(exc).__name__
        print("Binary installation failed: " + detail + "; no automatic source compilation or recovery reload/rollback. " +
              ("Default/explicit core reload may have been dispatched: preserve its receipt; UNKNOWN must be reconciled read-only, never retried to obtain a reply. " if not args.update_only and not args.check_download and args.reload_core is not False else "VPN was not stopped/reloaded. ") +
              "Check release assets, platform, paths and local authorization. A successful helper change can precede a failed final publish; inspect `anytls helper status` before retrying.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

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
                src = stack.enter_context(transport(url, kind))
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


@contextlib.contextmanager
def installation_lock(app):
    with private_append(app / ".install.lock") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("another binary installer is running") from None
        yield


class WebUI:
    """Only manage the exact current user's default-port WebUI, never the VPN."""
    def __init__(self, target, env):
        self.target, self.env = target, env
        self.timeout = 10
        self.old = None
        self.listen = "127.0.0.1"
        self.listen_explicit = False

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
            if key not in ("--port", "--listen") or key in options:
                return None
            options[key] = value if sep else next(tokens, "")
        if options.get("--port", "18089") != "18089":
            return None
        host = options.get("--listen", "127.0.0.1")
        try:
            octets = ipaddress.IPv4Address(host).packed
        except ipaddress.AddressValueError:
            return None
        # Match Go netip's IPv4 loopback/RFC1918 policy, NOT Python is_private
        # (which also accepts reserved, link-local and documentation addresses).
        if not (octets[0] in (127, 10) or
                (octets[0] == 172 and 16 <= octets[1] <= 31) or
                (octets[0] == 192 and octets[1] == 168)):
            return None
        return host, "--listen" in options

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
            self.old = (pid, identity)
            self.listen, self.listen_explicit = listen
        # Historical webui.pid is never read: a PID is not process authority.

    def restart(self):
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
            args = [str(self.target), "webui", "--port", "18089"]
            if self.listen_explicit or self.listen != "127.0.0.1":
                args += ["--listen", self.listen]
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
                        with opener.open("http://" + self.listen + ":18089/", timeout=1) as response:
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


def install_verified(bundle, tag, app, home, runner=subprocess.run, env=None, tty=None):
    """Only called after every downloaded byte and manifest has been verified."""
    target, config, link = app / "anytls-macos", app / "config.yaml", home / ".local/bin/anytls"
    check_link(target, link)
    if target.exists() or target.is_symlink():
        regular(target)
    if config.exists() or config.is_symlink():
        regular(config)
    webui = WebUI(target, env)
    webui.preflight()
    # A unique, regular candidate in appdir matches the helper's fixed path policy.
    fd, name = tempfile.mkstemp(prefix=".anytls-bin-candidate-", dir=app)
    candidate = Path(name)
    try:
        with os.fdopen(fd, "wb") as out, (bundle / "bin/anytls-macos").open("rb") as src:
            shutil.copyfileobj(src, out, 1024 * 1024)
            out.flush()
            os.fsync(out.fileno())
        candidate.chmod(0o700)
        command_version(candidate, tag, runner, env)
        created = i.install_config(bundle, app)
        regular(config)
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
        runner([str(candidate), "helper", "status"], check=True, stdout=subprocess.PIPE,
               stderr=subprocess.PIPE, timeout=30, env=env)
        progress("[5/6] 备份旧程序并原子替换为已验证版本")
        backup = i.publish_binary(candidate, target, app)
        command_version(target, tag, runner, env)
        try:
            with stage("[6/6] 切换至新版 WebUI 并验证页面就绪；VPN 保持运行"):
                webui.restart()
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            raise ValueError("binary installed but WebUI start failed: " + str(exc) + "; inspect ~/.anytls/webui.log; VPN was not stopped/reloaded") from exc
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
    if getattr(args, "update_only", False):
        return update_only(args, transport, runner, system, machine, euid, env)
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
        tag, bundle, digest, commit = verified_download(work, args.version, transport, arch=arch)
        report = {"version": tag, "source_commit": commit, "binary_sha256": digest,
                  "platform": "darwin-" + arch, "download_verified": True, "executed": False}
        if args.check_download:
            print(i.json.dumps(report, sort_keys=True))
            return report
        if env is None:
            env = {k: os.environ[k] for k in ("HOME", "PATH", "SHELL", "ZDOTDIR", "USER", "LOGNAME", "LANG", "TERM", "TMPDIR") if k in os.environ}
        # Retain the verified package/licenses BEFORE any privileged change
        # or executable publication. Retention failure leaves the old app intact.
        progress("[3/6] 保留许可证、校验和与预编译程序包；已有配置及密码不覆盖")
        kept = app / "releases" / (tag + "-" + i.uuid.uuid4().hex)
        kept.parent.mkdir(mode=0o700, exist_ok=True)
        os.replace(bundle, kept)
        for name in ("SHA256SUMS", "anytls-core-" + tag + "-darwin-" + arch + ".tar.gz"):
            shutil.copyfile(work / name, kept / name)
            i.require(sha256(work / name) == sha256(kept / name), "retained release material mismatch")
        with installation_lock(app):
            backup = install_verified(kept, tag, app, home, runner, env, tty)
        print("Installed " + tag + " from verified prebuilt release; authenticated helper status succeeded.")
        if backup:
            print("Previous executable backup: " + str(backup))
        print("SHA256SUMS trusts GitHub HTTPS, NOT an independent authenticity signature.")
        print("Run now by absolute path: " + shlex.quote(str(app / "anytls-macos")))
        print("The current terminal PATH is unchanged. Open a new terminal, or for bash/zsh run: export PATH=" +
              shlex.quote(str(home / ".local/bin")) + ':"$PATH"')
        print("WebUI started using the new binary; existing listen address preserved (fresh installs: http://127.0.0.1:18089/). VPN was NOT stopped, reloaded or restarted; its running snapshot is unchanged.")
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
    parser.add_argument("--update-only", action="store_true", help="replace only the existing app executable; no helper, configuration or restart")
    parser.add_argument("--app-dir")
    parser.add_argument("--target")
    parser.add_argument("--update-arch", choices=("arm64", "amd64"))
    try:
        args = parser.parse_args(argv)
    except UpdateFailed:
        print("UPDATE_VALIDATION_FAILED", file=sys.stderr)
        return 44
    if args.update_only:
        if not all((args.app_dir, args.target, args.update_arch, args.version)) or args.arch is not None or args.check_download:
            print("UPDATE_VALIDATION_FAILED", file=sys.stderr)
            return 44
    elif any((args.app_dir, args.target, args.update_arch)):
        parser.error("--app-dir, --target and --update-arch require --update-only")
    if args.arch is not None and not args.check_download:
        parser.error("--arch is allowed only with --check-download")
    try:
        result = run(args)
        if args.update_only:
            print(i.json.dumps(result, sort_keys=True))
    except UpdateFailed as exc:
        codes = {42: "UPDATE_BINARY_UNAVAILABLE", 43: "UPDATE_DOWNLOAD_FAILED", 44: "UPDATE_VALIDATION_FAILED",
                 45: "UPDATE_PUBLISH_FAILED", 46: "UPDATE_VERIFY_FAILED", 47: "UPDATE_UNAVAILABLE"}
        print(codes.get(exc.code, "UPDATE_UNAVAILABLE"), file=sys.stderr)
        return exc.code if exc.code in codes else 47
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError, subprocess.SubprocessError) as exc:
        detail = str(exc) if type(exc) is ValueError else type(exc).__name__
        print("Binary installation failed: " + detail + "; no automatic source compilation or VPN stop/reload. Check release assets, platform, paths and local authorization. A successful helper change can precede a failed final publish; inspect `anytls helper status` before retrying.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

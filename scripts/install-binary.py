#!/usr/bin/env python3
"""Install the official macOS arm64/amd64 binary; never compile or run archive scripts."""
import argparse
import contextlib
import fcntl
import signal
import time
import urllib.request

import hashlib
import importlib.util
import os
from pathlib import Path
import platform
import re
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


def corresponding_source(tag, arch):
    i.require(arch in ("arm64", "amd64"), "unsupported binary architecture")
    return "anytls-core-" + tag + ("-darwin-amd64" if arch == "amd64" else "") + "-corresponding-source.tar.gz"


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


def binary_release(version=None, transport=i.open_url, arch="arm64"):
    i.require(arch in ("arm64", "amd64"), "unsupported binary architecture")
    tag, page, assets = i.release(version, transport)
    name = "anytls-core-" + tag + "-darwin-" + arch + ".tar.gz"
    # Source installer intentionally selects only its own two assets. Read the
    # same fixed release endpoint and independently validate the binary asset.
    release = i.read_json(i.API + "/releases/tags/" + tag, transport=transport)
    i.require(isinstance(release, dict) and release.get("tag_name") == tag and
              release.get("draft") is False and release.get("prerelease") is False and
              release.get("html_url") == page, "binary release identity mismatch")
    entries = release.get("assets")
    i.require(isinstance(entries, list), "invalid binary release assets")
    matches = [a for a in entries if isinstance(a, dict) and a.get("name") == name]
    i.require(len(matches) == 1, "release has no unique macOS " + arch + " binary; legacy source-only/arm64-only releases are not compiled automatically")
    url = "https://github.com/" + i.REPO + "/releases/download/" + tag + "/" + name
    i.require(matches[0].get("browser_download_url") == url, "binary asset tag/URL mismatch")
    assets[name] = i.trusted_url(url, "asset")
    ccs_name = corresponding_source(tag, arch)
    ccs = [a for a in entries if isinstance(a, dict) and a.get("name") == ccs_name]
    i.require(len(ccs) == 1, "release must provide corresponding source")
    ccs_url = "https://github.com/" + i.REPO + "/releases/download/" + tag + "/" + ccs_name
    i.require(ccs[0].get("browser_download_url") == ccs_url, "corresponding-source URL mismatch")
    assets[ccs_name] = i.trusted_url(ccs_url, "asset")
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
    progress("[1/6] 检查官方发行版本及下载附件（含对应源码，可能较大）")
    transport = progress_transport(transport)
    tag, page, assets = binary_release(version, transport, arch=arch)
    commit = i.read_json(i.API + "/commits/" + tag, transport=transport)
    i.require(isinstance(commit, dict) and re.fullmatch(r"[0-9a-f]{40}", commit.get("sha", "")), "invalid release commit")
    sums = work / "SHA256SUMS"
    i.download(assets["SHA256SUMS"], sums, transport=transport)
    text = sums.read_text(encoding="ascii")
    for name in ("anytls-core-" + tag + "-darwin-" + arch + ".tar.gz", "anytls-core-" + tag + "-source.tar.gz", corresponding_source(tag, arch)):
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


def command_version(binary, tag, runner, env):
    result = runner([str(binary), "version"], check=True, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, timeout=20, env=env)
    i.require(result.stdout.decode("utf-8").strip() == tag, "executable version mismatch; old executable preserved before publish")


def private_append(path):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
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

    def known(self, identity):
        return identity is not None and identity[0] == str(os.getuid()) and identity[2] in {
            str(self.target) + " webui", str(self.target) + " webui --port 18089",
            str(self.target) + " webui --port=18089"}

    def preflight(self):
        pids = self.listeners()
        i.require(len(pids) <= 1, "port 18089 has multiple listeners; refusing WebUI replacement")
        if pids:
            pid = next(iter(pids))
            identity = self.identity(pid)
            i.require(self.known(identity), "port 18089 is occupied by an unknown process/arguments or UID; close it yourself")
            self.old = (pid, identity)
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
            with private_append(self.target.parent / "webui.log") as log:
                child = subprocess.Popen([str(self.target), "webui", "--port", "18089"],
                                         stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                         start_new_session=True, env=self.env)
            deadline = time.monotonic() + self.timeout
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            while time.monotonic() < deadline:
                i.require(child.poll() is None, "new WebUI exited before readiness")
                if self.listeners() == {child.pid}:
                    try:
                        with opener.open("http://127.0.0.1:18089/", timeout=1) as response:
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
        if created:
            print("Created 0600 config.yaml EXAMPLE ONLY. Enter your actual node/password/CA; no usable credentials were generated.")
        return backup
    finally:
        candidate.unlink(missing_ok=True)


def run(args, transport=i.open_url, runner=subprocess.run, system=None, machine=None, euid=None, home=None, tty=None, env=None):
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
            env = {k: os.environ[k] for k in ("HOME", "PATH", "USER", "LOGNAME", "LANG", "TERM", "TMPDIR") if k in os.environ}
        # Retain required source/license materials BEFORE any privileged change
        # or executable publication. Retention failure leaves the old app intact.
        progress("[3/6] 保留许可证与对应源码；已有配置及密码不覆盖")
        kept = app / "releases" / (tag + "-" + i.uuid.uuid4().hex)
        kept.parent.mkdir(mode=0o700, exist_ok=True)
        os.replace(bundle, kept)
        for name in ("SHA256SUMS", "anytls-core-" + tag + "-source.tar.gz", corresponding_source(tag, arch)):
            shutil.copyfile(work / name, kept / name)
            i.require(sha256(work / name) == sha256(kept / name), "retained release material mismatch")
        with installation_lock(app):
            backup = install_verified(kept, tag, app, home, runner, env, tty)
        print("Installed " + tag + " from verified prebuilt release; authenticated helper status succeeded.")
        if backup:
            print("Previous executable backup: " + str(backup))
        print("SHA256SUMS trusts GitHub HTTPS, NOT an independent authenticity signature. Add ~/.local/bin to PATH.")
        print("WebUI started at http://127.0.0.1:18089/ using the new binary. VPN was NOT stopped, reloaded or restarted; its running snapshot is unchanged.")
        report["executed"] = True
        return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", type=i.validate_version, help="stable tag; default is latest stable release")
    parser.add_argument("--check-download", action="store_true", help="verify binary/source archives without executing code or changing configuration")
    parser.add_argument("--arch", choices=("arm64", "amd64"), help="only with --check-download: target archive architecture; default is native on macOS, arm64 elsewhere")
    args = parser.parse_args(argv)
    if args.arch is not None and not args.check_download:
        parser.error("--arch is allowed only with --check-download")
    try:
        run(args)
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError, subprocess.SubprocessError) as exc:
        detail = str(exc) if type(exc) is ValueError else type(exc).__name__
        print("Binary installation failed: " + detail + "; no automatic source compilation or VPN stop/reload. Check release assets, platform, paths and local authorization. A successful helper change can precede a failed final publish; inspect `anytls helper status` before retrying.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

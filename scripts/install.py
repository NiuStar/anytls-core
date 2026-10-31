#!/usr/bin/env python3
"""Source-only installer. Explicit invocation authorizes building release Go code.
SHA256SUMS shares the release's HTTPS transport trust, not a signature.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.request
import uuid

REPO = "NiuStar/anytls-core"
API = "https://api.github.com/repos/" + REPO
GO_VERSION = "go1.27.3"
TAGS = "with_gvisor,with_utls,with_upstream_cleanup_patch,embedded_core"


def require(ok, message):
    if not ok:
        raise ValueError(message)


def validate_version(value):
    require(isinstance(value, str), "invalid stable release version")
    date = re.fullmatch(r"v([0-9]{4}-[0-9]{2}-[0-9]{2})-([0-9]{2})", value)
    if date:
        datetime.date.fromisoformat(date[1])
    else:
        require(re.fullmatch(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", value), "invalid stable release version")
    return value


def trusted_url(url, kind):
    p = urllib.parse.urlsplit(url)
    require(p.scheme == "https" and not p.username and not p.password and
            not p.fragment and p.port in (None, 443), "untrusted HTTPS URL")
    if kind == "api":
        require(p.netloc == "api.github.com" and p.path.startswith("/repos/" + REPO + "/"), "untrusted API URL")
    elif kind == "asset":
        require(p.netloc == "github.com" and p.path.startswith("/" + REPO + "/releases/download/"), "untrusted release asset URL")
    elif kind == "go":
        require(p.netloc in ("go.dev", "dl.google.com") and p.path.startswith(("/dl/", "/go/")), "untrusted toolchain URL")
    else:
        raise ValueError("unknown download trust domain")
    return url


class Redirects(urllib.request.HTTPRedirectHandler):
    def __init__(self, kind):
        super().__init__()
        self.kind = kind

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        p = urllib.parse.urlsplit(newurl)
        # Keep trust domains separate across every hop, not just the first.
        require(self.kind != "api", "API redirects are not accepted")
        allowed = (("github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com")
                   if self.kind == "asset" else ("go.dev", "dl.google.com"))
        require(p.scheme == "https" and not p.username and not p.password and
                p.port in (None, 443) and not p.fragment and p.hostname in
                allowed, "untrusted download redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def open_url(url, kind):
    trusted_url(url, kind)
    request = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json" if kind == "api" else "application/octet-stream", "User-Agent": "anytls-source-installer"})
    return urllib.request.build_opener(Redirects(kind)).open(request, timeout=120)


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON field")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def read_json(url, kind="api", transport=open_url):
    with transport(url, kind) as response:
        return strict_json(response.read())


def release(version=None, transport=open_url):
    if version is not None:
        validate_version(version)
    r = read_json(API + ("/releases/tags/" + version if version else "/releases/latest"), transport=transport)
    require(isinstance(r, dict) and r.get("draft") is False and r.get("prerelease") is False, "not a stable published release")
    tag = validate_version(r.get("tag_name"))
    require(not version or tag == version, "release tag mismatch")
    require(r.get("html_url") == "https://github.com/" + REPO + "/releases/tag/" + tag, "release URL mismatch")
    names = ["anytls-core-" + tag + "-source.tar.gz", "SHA256SUMS"]
    assets = {}
    require(isinstance(r.get("assets"), list), "invalid release assets")
    for a in r["assets"]:
        require(isinstance(a, dict), "invalid release asset")
        if a.get("name") in names:
            name = a["name"]
            require(name not in assets, "duplicate release asset")
            url = "https://github.com/" + REPO + "/releases/download/" + tag + "/" + name
            require(a.get("browser_download_url") == url, "asset tag/URL mismatch")
            assets[name] = trusted_url(url, "asset")
    require(set(assets) == set(names), "release must contain source archive and SHA256SUMS (no binary assumed)")
    return tag, r["html_url"], assets


def download(url, target, expected=None, transport=open_url, kind="asset"):
    digest = hashlib.sha256()
    with transport(url, kind) as src, Path(target).open("xb") as dst:
        while True:
            block = src.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
            dst.write(block)
        dst.flush()
        os.fsync(dst.fileno())
    actual = digest.hexdigest()
    require(expected is None or actual == expected, "download SHA256 mismatch")
    return actual


def checksum(sums, name):
    matches = []
    for line in sums.splitlines():
        m = re.fullmatch(r"([0-9a-fA-F]{64}) [ *](.+)", line)
        require(m is not None, "malformed SHA256SUMS")
        if m[2] == name:
            matches.append(m[1].lower())
    require(len(matches) == 1, "missing/duplicate source checksum")
    return matches[0]


def extract(archive, destination, prefix):
    """Stream regular files/directories only; never tarfile.extract/extractall."""
    destination = Path(destination)
    destination.mkdir(mode=0o700)
    seen, files = set(), set()
    with tarfile.open(archive, "r|gz") as tar:
        for item in tar:
            name = item.name
            require(isinstance(name, str) and re.fullmatch(r"[^\x00-\x20\x7f\\\\:]+", name), "unsafe archive path")
            require(not name.startswith("/") and "\\" not in name, "unsafe archive path")
            parts = name.rstrip("/").split("/")
            require(all(p not in ("", ".", "..") for p in parts) and parts[0] == prefix, "archive tag prefix/path mismatch")
            canonical = "/".join(parts)
            require(canonical not in seen, "duplicate archive entry")
            require(item.isdir() or item.isreg(), "archive links/special files forbidden")
            require(not any("/".join(parts[:n]) in files for n in range(1, len(parts))), "file/directory collision")
            if item.isreg():
                require(not any(old.startswith(canonical + "/") for old in seen), "file/directory collision")
                files.add(canonical)
            seen.add(canonical)
            target = destination.joinpath(*parts)
            if item.isdir():
                target.mkdir(mode=0o700, parents=True, exist_ok=True)
            else:
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                with tar.extractfile(item) as src, target.open("xb") as dst:
                    shutil.copyfileobj(src, dst, 1024 * 1024)
                os.chmod(target, 0o600)  # No executable permissions copied from archive.
    return destination / prefix


def build_env(app, work):
    cache = app / "cache"
    for name in ("go-build", "mod", "gopath"):
        (cache / name).mkdir(parents=True, exist_ok=True)
    (work / "tmp").mkdir(exist_ok=True)
    # Deliberately do not inherit compiler flags, overlays, Go env or credentials.
    env = {k: os.environ[k] for k in ("HOME", "PATH", "SYSTEMROOT") if k in os.environ}
    env.update(GOMAXPROCS="2", GOMEMLIMIT="768MiB", GOTOOLCHAIN="local", GOWORK="off", GOFLAGS="", GOENV="off", GOTELEMETRY="off", GOOS="darwin", GOARCH="arm64", CGO_ENABLED="0", GOCACHE=str(cache / "go-build"), GOMODCACHE=str(cache / "mod"), GOPATH=str(cache / "gopath"), TMPDIR=str(work / "tmp"), GOPROXY="https://proxy.golang.org", GOSUMDB="sum.golang.org")
    return env


def find_go(app, env):
    candidates = [shutil.which("go"), app / "toolchains" / GO_VERSION / "go/bin/go", Path.home() / "sdk" / GO_VERSION / "bin/go", Path("/opt/homebrew/bin/go"), Path("/usr/local/go/bin/go"), Path("/usr/local/bin/go")]
    # Homebrew keeps versioned formulae in Cellar even when not linked.
    for cellar in (Path("/opt/homebrew/Cellar/go"), Path("/usr/local/Cellar/go")):
        if cellar.is_dir():
            candidates.extend(cellar.glob("*/libexec/bin/go"))
    for candidate in candidates:
        if not candidate:
            continue
        p = Path(candidate).resolve()
        if p.is_file() and os.access(p, os.X_OK):
            try:
                out = subprocess.check_output([str(p), "version"], env=env, stderr=subprocess.PIPE, timeout=20).decode().split()
                if out == ["go", "version", GO_VERSION, "darwin/arm64"]:
                    return p
            except (OSError, subprocess.SubprocessError):
                pass
    return None


def install_go(app, work, transport=open_url):
    manifest = read_json("https://go.dev/dl/?mode=json&include=all", "go", transport)
    require(isinstance(manifest, list), "invalid Go manifest")
    entries = [f for r in manifest if r.get("version") == GO_VERSION for f in r.get("files", []) if f.get("os") == "darwin" and f.get("arch") == "arm64" and f.get("kind") == "archive"]
    require(len(entries) == 1, "fixed Go toolchain not in official manifest")
    entry = entries[0]
    name = GO_VERSION + ".darwin-arm64.tar.gz"
    require(entry.get("filename") == name and re.fullmatch(r"[0-9a-f]{64}", entry.get("sha256", "")), "invalid Go manifest archive")
    archive = work / "go.tar.gz"
    download("https://go.dev/dl/" + name, archive, entry["sha256"], transport, "go")
    source = extract(archive, work / "toolchain", "go")
    # These are compiler executables from the checksum-verified official Go
    # distribution, not application archive scripts. Keep all tool names usable.
    for directory in (source / "bin", source / "pkg/tool/darwin_arm64"):
        if directory.is_dir():
            for p in directory.iterdir():
                if p.is_file():
                    p.chmod(0o700)
    dest = app / "toolchains" / GO_VERSION
    dest.parent.mkdir(parents=True, exist_ok=True)
    require(not dest.exists(), "private toolchain path already exists but is not usable; inspect it manually")
    dest.mkdir(mode=0o700)
    os.replace(source, dest / "go")
    return dest / "go/bin/go"


def publish_binary(candidate, target, app, replace=os.replace):
    """Backup actual previous executable before same-filesystem atomic rename."""
    candidate, target, app = Path(candidate), Path(target), Path(app)
    require(stat.S_ISREG(candidate.lstat().st_mode) and candidate.stat().st_size > 0, "missing built binary")
    backup = None
    if target.exists() or target.is_symlink():
        require(stat.S_ISREG(target.lstat().st_mode), "binary target must be a regular file")
        backups = app / "backups"
        backups.mkdir(mode=0o700, exist_ok=True)
        backup = backups / ("update-" + datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex + "-anytls")
        original_sha = hashlib.sha256()
        with target.open("rb") as src, backup.open("xb") as dst:
            for block in iter(lambda: src.read(1024 * 1024), b""):
                original_sha.update(block)
                dst.write(block)
            dst.flush()
            os.fsync(dst.fileno())
        # Independently reopen AFTER close; never publish an unverified backup.
        backup_sha = hashlib.sha256()
        with backup.open("rb") as src:
            for block in iter(lambda: src.read(1024 * 1024), b""):
                backup_sha.update(block)
        require(backup_sha.digest() == original_sha.digest(), "backup SHA256 mismatch")
        backup.chmod(0o700)
    candidate.chmod(0o700)
    with candidate.open("rb") as f:
        os.fsync(f.fileno())
    replace(candidate, target)
    return backup


def install_config(source, app):
    target = app / "config.yaml"
    try:
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return False
    with os.fdopen(fd, "wb") as out, (source / "config.example.yaml").open("rb") as src:
        shutil.copyfileobj(src, out)
    return True


def ensure_link(target, link):
    link = Path(link)
    link.parent.mkdir(parents=True, exist_ok=True)
    if link.exists() or link.is_symlink():
        require(link.is_symlink() and link.resolve() == target.resolve(), "~/.local/bin/anytls conflicts with another program; not overwritten")
    else:
        link.symlink_to(target)


def certified_build(stdout, wrapper, source, output):
    # Execute only the caller's trusted local wrapper, never archive Python.
    ns = {"__name__": "trusted_installer_wrapper", "__file__": str(source / "scripts/go-patched.py")}
    exec(compile(wrapper, "trusted-local-wrapper", "exec"), ns)
    ends = [json.loads(line.split(" ", 1)[1]) for line in stdout.decode().splitlines()
            if line.startswith("PATCHED_GO_END ")]
    require(len(ends) == 1, "source build missing unique certified END")
    r = ends[0]
    m, patch = ns["doh_identity"](source)
    require(r.get("doh_deadline_isolation") == ns["doh_receipt"](m, patch),
            "source build DoH identity mismatch")
    require(r.get("rc") == 0 and r.get("ephemeral_cleanup") == "ok"
            and r.get("root_inputs_unchanged") is True and r.get("original_doh_source_unchanged") is True
            and r.get("original_module_zip_unchanged") is True
            and r.get("wrapper_sha256") == hashlib.sha256(wrapper).hexdigest()
            and r.get("output_sha256") == hashlib.sha256(output.read_bytes()).hexdigest()
            and r.get("argv") == ["build", "-p", "2", "-tags", TAGS, "-trimpath", "-o", str(output), "."]
            and r.get("go_version", "").split()[2:3] == [GO_VERSION]
            and r.get("target") == {"GOOS": "darwin", "GOARCH": "arm64", "CGO_ENABLED": "0"},
            "source build certified output mismatch")
    return r


def run(args, transport=open_url):
    require(platform.system() == "Darwin" and platform.machine() == "arm64", "source installer supports macOS arm64 only")
    require(os.geteuid() != 0, "run installer as your normal user, never root/sudo")
    app = Path(args.app_dir).expanduser().absolute()
    app.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(not app.is_symlink(), "app directory cannot be a symlink")
    target = Path(args.target).expanduser().absolute() if args.target else app / "anytls-macos"
    require(target.parent == app and target.name in ("anytls-macos", "anytls"), "only appdir/anytls-macos (or legacy appdir/anytls) can be replaced")
    if target.exists() or target.is_symlink():
        require(stat.S_ISREG(target.lstat().st_mode), "binary target must be a regular file")
    if not args.update:
        # Preflight a conflicting PATH entry before downloading/building.
        link = Path.home() / ".local/bin/anytls"
        if link.exists() or link.is_symlink():
            require(link.is_symlink() and link.resolve() == target.resolve(), "~/.local/bin/anytls conflicts with another program")
    # Cleanup is scoped to this exact owned directory, never other app contents.
    with tempfile.TemporaryDirectory(prefix="update-" if args.update else "install-", dir=app) as temp:
        work = Path(temp)
        env = build_env(app, work)
        go = find_go(app, env)
        if go is None:
            require(args.install_toolchain, "Go 1.27.3 darwin/arm64 missing; rerun official install.sh --install-toolchain (private ~/.anytls/toolchains only)")
            go = install_go(app, work, transport)
            require(find_go(app, env) == go.resolve(), "downloaded toolchain version verification failed")
        tag, url, assets = release(args.version, transport)
        commit = read_json(API + "/commits/" + tag, transport=transport)
        require(isinstance(commit, dict) and re.fullmatch(r"[0-9a-f]{40}", commit.get("sha", "")), "release target commit API response invalid")
        name = "anytls-core-" + tag + "-source.tar.gz"
        sums = work / "SHA256SUMS"
        download(assets["SHA256SUMS"], sums, transport=transport)
        archive = work / name
        download(assets[name], archive, checksum(sums.read_text(), name), transport)
        source = extract(archive, work / "source", "anytls-core-" + tag)
        require((source / "VERSION").read_text().strip() == tag, "source VERSION does not match release tag")
        if not args.update and not (app / "config.yaml").exists():
            require((source / "config.example.yaml").is_file(), "release missing initial configuration example")
        # Never execute Python from the downloaded source archive. Use the local
        # trusted wrapper embedded in the current CLI / fetched with installer.
        wrapper = Path(args.wrapper).read_bytes()
        (source / "scripts/go-patched.py").write_bytes(wrapper)
        env["GO_BIN"] = str(go.resolve())
        output = work / "anytls-built"
        try:
            built = subprocess.run([sys.executable, "-I", str(source / "scripts/go-patched.py"), "build", "-p", "2", "-tags", TAGS, "-trimpath", "-o", str(output), "."], cwd=source, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=1800, check=True)
            receipt = certified_build(built.stdout, wrapper, source, output)
            reported = subprocess.check_output([str(output), "version"], env=env, stderr=subprocess.PIPE, timeout=20).decode().strip()
            require(reported == tag, "built executable version mismatch: target release must support `version` and return its exact tag; old executable preserved")
        except subprocess.SubprocessError:
            raise ValueError("source build/version command failed: target release must support `version`; old executable preserved (compiler output withheld to avoid exposing credentials)") from None
        # Retain upstream source, license, notices, sums and local module cache.
        sources = app / "sources"
        sources.mkdir(mode=0o700, exist_ok=True)
        kept = sources / (tag + "-" + uuid.uuid4().hex)
        os.replace(source, kept)
        shutil.copyfile(sums, kept / "RELEASE-SHA256SUMS")
        (kept / "CERTIFIED-BUILD.json").write_text(json.dumps(receipt, indent=2) + "\n")
        backup = publish_binary(output, target, app)
        if not args.update:
            created = install_config(kept, app)
            ensure_link(target, Path.home() / ".local/bin/anytls")
            if created:
                print("Created 0600 config.yaml EXAMPLE ONLY: enter your node/password/CA, then run anytls config to choose a node. No usable credentials were generated.")
        print("Installed " + tag + "; source-only local build. SHA256SUMS trusts GitHub HTTPS, NOT an authenticity signature. Release API target commit: " + commit["sha"])
        if backup:
            print("Previous executable backup: " + str(backup))
        print("PATH: add ~/.local/bin to PATH. No service was stopped or restarted; active VPN uses old snapshot until manual reload. Running WebUI remains OLD code: manually restart WebUI to load new code.")
        return tag


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", type=validate_version)
    parser.add_argument("--install-toolchain", action="store_true", help="explicitly install fixed Go into private app directory, not system-wide")
    parser.add_argument("--app-dir", default=str(Path.home() / ".anytls"))
    parser.add_argument("--target")
    parser.add_argument("--wrapper", default=str(Path(globals().get("__file__", "install.py")).absolute().with_name("go-patched.py")))
    parser.add_argument("--update", action="store_true")
    args = parser.parse_args(argv)
    try:
        run(args)
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as exc:
        # Do not echo exception strings containing caller paths, URLs or secrets.
        print("Install/update failed: " + (str(exc) if isinstance(exc, ValueError) else type(exc).__name__) + "; existing binary/configuration not overwritten on download/build failure.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

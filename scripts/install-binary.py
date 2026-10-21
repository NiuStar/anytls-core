#!/usr/bin/env python3
"""Install the official macOS arm64 binary; never compile or run archive scripts."""
import argparse
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

# This sibling is fetched by the trusted bootstrap, NEVER from a release archive.
sys.dont_write_bytecode = True
_spec = importlib.util.spec_from_file_location("anytls_trusted_installer", Path(__file__).resolve().with_name("install.py"))
i = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(i)


def binary_release(version=None, transport=i.open_url):
    tag, page, assets = i.release(version, transport)
    name = "anytls-core-" + tag + "-darwin-arm64.tar.gz"
    # Source installer intentionally selects only its own two assets. Read the
    # same fixed release endpoint and independently validate the binary asset.
    release = i.read_json(i.API + "/releases/tags/" + tag, transport=transport)
    i.require(isinstance(release, dict) and release.get("tag_name") == tag and
              release.get("draft") is False and release.get("prerelease") is False and
              release.get("html_url") == page, "binary release identity mismatch")
    entries = release.get("assets")
    i.require(isinstance(entries, list), "invalid binary release assets")
    matches = [a for a in entries if isinstance(a, dict) and a.get("name") == name]
    i.require(len(matches) == 1, "release has no unique macOS arm64 binary; legacy source-only releases are not compiled automatically")
    url = "https://github.com/" + i.REPO + "/releases/download/" + tag + "/" + name
    i.require(matches[0].get("browser_download_url") == url, "binary asset tag/URL mismatch")
    assets[name] = i.trusted_url(url, "asset")
    ccs_name = "anytls-core-" + tag + "-corresponding-source.tar.gz"
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


def validate_bundle(bundle, tag, commit):
    for name in ("VERSION", "BUILD-INFO.json", "bin/anytls-macos", "config.example.yaml", "LICENSE", "THIRD_PARTY_NOTICES.md"):
        regular(bundle / name)
    i.require((bundle / "VERSION").read_bytes() in (tag.encode(), (tag + "\n").encode()), "binary VERSION does not match exact release tag")
    info = i.strict_json((bundle / "BUILD-INFO.json").read_bytes())
    i.require(isinstance(info, dict) and re.fullmatch(r"[0-9a-f]{40}", info.get("source_commit", "")) and
              info["source_commit"] == commit, "binary source_commit does not match release commit")
    binary = bundle / "bin/anytls-macos"
    digest = sha256(binary)
    i.require(info.get("binary_sha256") == digest, "binary SHA256 does not match BUILD-INFO.json")
    with binary.open("rb") as src:
        header = src.read(32)
    i.require(len(header) == 32 and struct.unpack("<IIII", header[:16])[:2] == (0xfeedfacf, 0x0100000c) and
              struct.unpack("<IIII", header[:16])[3] == 2, "binary must be a thin arm64 Mach-O executable")
    return digest


def verified_download(work, version=None, transport=i.open_url):
    tag, page, assets = binary_release(version, transport)
    commit = i.read_json(i.API + "/commits/" + tag, transport=transport)
    i.require(isinstance(commit, dict) and re.fullmatch(r"[0-9a-f]{40}", commit.get("sha", "")), "invalid release commit")
    sums = work / "SHA256SUMS"
    i.download(assets["SHA256SUMS"], sums, transport=transport)
    text = sums.read_text(encoding="ascii")
    for name in ("anytls-core-" + tag + "-darwin-arm64.tar.gz", "anytls-core-" + tag + "-source.tar.gz", "anytls-core-" + tag + "-corresponding-source.tar.gz"):
        expected = i.checksum(text, name)
        i.download(assets[name], work / name, expected, transport)
    name = "anytls-core-" + tag + "-darwin-arm64"
    bundle = i.extract(work / (name + ".tar.gz"), work / "extracted", name)
    digest = validate_bundle(bundle, tag, commit["sha"])
    return tag, bundle, digest, commit["sha"]


def check_link(target, link):
    if link.exists() or link.is_symlink():
        i.require(link.is_symlink() and link.resolve() == target.resolve(), "~/.local/bin/anytls conflicts with another program; not overwritten")


def command_version(binary, tag, runner, env):
    result = runner([str(binary), "version"], check=True, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, timeout=20, env=env)
    i.require(result.stdout.decode("utf-8").strip() == tag, "executable version mismatch; old executable preserved before publish")


def install_verified(bundle, tag, app, home, runner=subprocess.run, env=None, tty=None):
    """Only called after every downloaded byte and manifest has been verified."""
    target, config, link = app / "anytls-macos", app / "config.yaml", home / ".local/bin/anytls"
    check_link(target, link)
    if target.exists() or target.is_symlink():
        regular(target)
    if config.exists() or config.is_symlink():
        regular(config)
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
        opener = tty or (lambda: open("/dev/tty", "rb", buffering=0))
        with opener() as terminal:
            runner([str(candidate), "helper", "install"], check=True, stdin=terminal, env=env)
        runner([str(candidate), "helper", "status"], check=True, stdout=subprocess.PIPE,
               stderr=subprocess.PIPE, timeout=30, env=env)
        backup = i.publish_binary(candidate, target, app)
        command_version(target, tag, runner, env)
        if created:
            print("Created 0600 config.yaml EXAMPLE ONLY. Enter your actual node/password/CA; no usable credentials were generated.")
        return backup
    finally:
        candidate.unlink(missing_ok=True)


def run(args, transport=i.open_url, runner=subprocess.run, system=None, machine=None, euid=None, home=None, tty=None, env=None):
    home = Path.home() if home is None else Path(home)
    app = home / ".anytls"
    if not args.check_download:
        i.require((system or platform.system()) == "Darwin" and (machine or platform.machine()) == "arm64", "binary installation supports macOS arm64 only")
        i.require((os.geteuid() if euid is None else euid) != 0, "run as your normal user, never root/sudo")
        i.require(not app.is_symlink(), "app directory cannot be a symlink")
        check_link(app / "anytls-macos", home / ".local/bin/anytls")
        app.mkdir(mode=0o700, parents=True, exist_ok=True)
    # Check-only never creates app/config/link and never executes downloaded code.
    with tempfile.TemporaryDirectory(prefix="anytls-binary-", dir=None if args.check_download else app) as temp:
        work = Path(temp)
        tag, bundle, digest, commit = verified_download(work, args.version, transport)
        report = {"version": tag, "source_commit": commit, "binary_sha256": digest,
                  "platform": "darwin-arm64", "download_verified": True, "executed": False}
        if args.check_download:
            print(i.json.dumps(report, sort_keys=True))
            return report
        if env is None:
            env = {k: os.environ[k] for k in ("HOME", "PATH", "USER", "LOGNAME", "LANG", "TERM", "TMPDIR") if k in os.environ}
        # Retain required source/license materials BEFORE any privileged change
        # or executable publication. Retention failure leaves the old app intact.
        kept = app / "releases" / (tag + "-" + i.uuid.uuid4().hex)
        kept.parent.mkdir(mode=0o700, exist_ok=True)
        os.replace(bundle, kept)
        for name in ("SHA256SUMS", "anytls-core-" + tag + "-source.tar.gz", "anytls-core-" + tag + "-corresponding-source.tar.gz"):
            shutil.copyfile(work / name, kept / name)
            i.require(sha256(work / name) == sha256(kept / name), "retained release material mismatch")
        backup = install_verified(kept, tag, app, home, runner, env, tty)
        print("Installed " + tag + " from verified prebuilt release; authenticated helper status succeeded.")
        if backup:
            print("Previous executable backup: " + str(backup))
        print("SHA256SUMS trusts GitHub HTTPS, NOT an independent authenticity signature. Add ~/.local/bin to PATH.")
        print("No VPN or WebUI was stopped or restarted. Running processes still use old code: manually restart WebUI; apply/reload VPN explicitly when ready.")
        report["executed"] = True
        return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", type=i.validate_version, help="stable tag; default is latest stable release")
    parser.add_argument("--check-download", action="store_true", help="verify binary/source archives without executing code or changing configuration")
    args = parser.parse_args(argv)
    try:
        run(args)
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError, subprocess.SubprocessError) as exc:
        detail = str(exc) if type(exc) is ValueError else type(exc).__name__
        print("Binary installation failed: " + detail + "; no automatic source compilation or process restart. Check release assets, platform, paths and local authorization. A successful helper change can precede a failed final publish; inspect `anytls helper status` before retrying.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

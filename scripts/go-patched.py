#!/usr/bin/env python3
"""Authenticate the pinned module ZIP, patch a private extraction, use -modfile.

Never edits cached/root source or supplies default build tags. See the patch doc.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parent.parent
IDENTITY_SHA = "9679eb6c27343cbdc0bcb3559869638a4c78c2809dca9760439f46f506636c5f"
MODULE = "github.com/sagernet/sing-box"
VERSION = "v1.14.3"
CORE_IDENTITY_SHA = "7faf6af8e873bb568f15029070f3c8051365af7ba3dd43f343488d78dcaee9e3"


def core_identity(root=ROOT):
    raw = (root / "patches/sing-box/core-slim.identity.json").read_bytes()
    require(sha(raw) == CORE_IDENTITY_SHA, "core identity SHA mismatch")
    m = json.loads(raw)
    require(m["module"] == MODULE and m["version"] == VERSION, "unsupported core revision")
    patch = (root / "patches/sing-box" / m["patch"]).read_bytes()
    require(sha(patch) == m["patch_sha256"], "core patch SHA mismatch")
    require(m["start_identity_sha256"] == IDENTITY_SHA, "Start identity mismatch")
    return m, patch


def apply_core(replacement, m, patch):
    ops = json.loads(patch)
    require(set(ops) == {"files"} and [x["file"] for x in ops["files"]] == ["box.go", "debug_http.go"], "fixed two file patch required")
    require(len(m["files"]) == 2, "fixed two file identity required")
    results = []
    for entry, pin in zip(ops["files"], m["files"]):
        require(entry["file"] == pin["file"], "core file mismatch")
        p = replacement / pin["file"]
        source = p.read_bytes()
        require(sha(source) == pin["input_sha256"], "core input SHA mismatch")
        text = source.decode()
        for op in entry["replacements"]:
            require(set(op) == {"old", "new"} and op["old"] and text.count(op["old"]) == 1, "core exact replacement mismatch")
            text = text.replace(op["old"], op["new"], 1)
        result = text.encode()
        require(sha(result) == pin["result_sha256"], "core result SHA mismatch")
        p.write_bytes(result)
        results.append(dict(pin))
    return results


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(ok, message):
    if not ok:
        raise ValueError(message)


def identity(root=ROOT):
    raw = (root / "patches/sing-box/identity.json").read_bytes()
    require(sha(raw) == IDENTITY_SHA, "identity manifest SHA mismatch")
    m = json.loads(raw)
    require(m["module"] == MODULE and m["version"] == VERSION, "unsupported revision")
    patch = (root / "patches/sing-box" / m["patch"]).read_bytes()
    require(sha(patch) == m["patch_sha256"], "patch SHA mismatch")
    return m, patch


def transform(source, m, patch):
    require(sha(source) == m["source_sha256"], "upstream source SHA mismatch")
    text = source.decode("utf-8")
    ops = json.loads(patch)
    require(set(ops) == {"replacements"} and len(ops["replacements"]) == 2, "invalid patch")
    for op in ops["replacements"]:
        require(set(op) == {"old", "new"} and op["old"] and text.count(op["old"]) == 1,
                "patch exact replacement mismatch")
        text = text.replace(op["old"], op["new"], 1)
    result = text.encode("utf-8")
    require(sha(result) == m["result_sha256"], "patched source SHA mismatch")
    return result


def arguments(argv, environ):
    args = list(argv)
    go = environ.get("GO_BIN", "")
    if args[:1] == ["--go"]:
        require(len(args) >= 3, "--go needs absolute executable and subcommand")
        go, args = args[1], args[2:]
    require(Path(go).is_absolute() and Path(go).is_file() and os.access(go, os.X_OK),
            "use --go /trusted/path/go or absolute GO_BIN")
    require(environ.get("GOTOOLCHAIN") == "local", "GOTOOLCHAIN must be local")
    require(not environ.get("GOFLAGS"), "GOFLAGS must be empty (including caller overlays)")
    require(environ.get("GOWORK", "off") == "off", "GOWORK must be off")
    require(args and args[0] in ("test", "vet", "build"), "supported: test, vet, build")
    # Intentionally small supported surface. Reject flags that can redirect the
    # module, invoke alternate tools/exec, or override the overlay after ours.
    values = {"-tags", "-o", "-p"}
    booleans = {"-trimpath", "-race"}
    if args[0] == "test":
        values |= {"-run", "-skip", "-count", "-timeout", "-parallel"}
        booleans |= {"-v", "-c", "-short", "-failfast"}
    output, packages, flags = None, 0, set()
    i = 1
    while i < len(args):
        item = args[i]
        if not item.startswith("-"):
            require(not flags.intersection({"packages"}), "invalid argument order")
            # Packages must be local; no module versions, file lists or @revision.
            require(item == "." or item.startswith("./") and "@" not in item and not item.endswith(".go"),
                    "only local package paths supported")
            packages += 1
            i += 1
            continue
        require(packages == 0, "put flags before packages")
        flag, sep, value = item.partition("=")
        require(flag not in flags, "duplicate flag")
        flags.add(flag)
        if flag in values:
            if not sep:
                i += 1
                require(i < len(args), "missing flag value")
                value = args[i]
            require(value and not value.startswith("-"), "invalid flag value")
            if flag == "-o":
                output = Path(value).absolute()
                require(not output.exists() and not output.is_symlink(), "output already exists")
                require(output.parent.is_dir(), "output parent must exist")
            elif flag in ("-p", "-count", "-parallel"):
                require(value.isdigit() and int(value) > 0, "positive numeric flag required")
        else:
            require(flag in booleans and (not sep or value in ("true", "false")), "unsupported flag")
        i += 1
    require(packages > 0, "explicit local package required")
    require(not output or args[0] == "build" or "-c" in flags, "output requires build or test -c")
    require(args[0] != "build" and "-c" not in flags or output is not None,
            "build/test -c requires explicit fresh -o path")
    return str(Path(go).resolve()), args, output


def metadata(info, m):
    require(info.get("Path", MODULE) == MODULE and info.get("Version") == VERSION
            and not info.get("Replace") and not info.get("Error"), "unsupported upstream module/replacement")
    require(info.get("Sum") == m["module_sum"] and info.get("GoModSum") == m["go_mod_sum"],
            "module checksums mismatch")
    origin = info.get("Origin", {})
    require(not origin.get("Hash") or origin["Hash"] == m["commit"], "upstream commit mismatch")


MAX_ARCHIVE_BYTES = 50 * 1024 * 1024
MAX_ARCHIVE_FILES = 10000


def stage_archive(archive, destination, expected_sum):
    """Validate all paths/bounds and Go dirhash before writing any ZIP member."""
    require(archive.stat().st_size <= MAX_ARCHIVE_BYTES, "archive size limit")
    prefix = MODULE + "@" + VERSION + "/"
    with zipfile.ZipFile(archive) as z:
        entries = z.infolist()
        require(len(entries) <= MAX_ARCHIVE_FILES, "archive entry limit")
        names, files, total = set(), [], 0
        for entry in entries:
            name = entry.filename
            require(name.startswith(prefix) and "\\" not in name and
                    all(ord(c) >= 32 and ord(c) != 127 for c in name), "unsafe archive path")
            relative = name[len(prefix):]
            parts = relative.rstrip("/").split("/")
            require(relative and all(p not in ("", ".", "..") for p in parts), "unsafe archive path")
            require(name not in names, "duplicate archive path")
            names.add(name)
            mode = stat.S_IFMT(entry.external_attr >> 16)
            require(mode in (0, stat.S_IFREG, stat.S_IFDIR) and
                    (mode != stat.S_IFDIR or entry.is_dir()) and
                    (mode != stat.S_IFREG or not entry.is_dir()), "unsafe archive file type")
            require(not entry.flag_bits & 1, "encrypted archive member")
            total += entry.file_size
            require(total <= MAX_ARCHIVE_BYTES, "archive size limit")
            if not entry.is_dir():
                files.append(entry)
        file_names = {e.filename for e in files}
        for name in names:
            parts = name.rstrip("/").split("/")
            require(not any("/".join(parts[:i]) in file_names for i in range(1, len(parts))),
                    "archive file/directory conflict")
            require(not name.endswith("/") or name[:-1] not in file_names, "archive file/directory conflict")
        # Go dirhash.Hash1: sorted *full ZIP names*, individual hex SHA256,
        # then SHA256 of 'hex  filename\n'. Directory entries are excluded.
        digest = hashlib.sha256()
        for entry in sorted(files, key=lambda e: e.filename):
            content = z.read(entry)
            require(len(content) == entry.file_size, "archive member size mismatch")
            digest.update((sha(content) + "  " + entry.filename + "\n").encode())
        actual = "h1:" + base64.b64encode(digest.digest()).decode()
        require(actual == expected_sum, "archive h1 mismatch")
        for entry in files:
            target = destination / entry.filename[len(prefix):]
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as out:
                out.write(z.read(entry))
    return {"h1": actual, "files": len(files), "bytes": total, "zip_sha256": sha(archive.read_bytes())}


def main(argv):
    go, args, output = arguments(argv, os.environ)
    m, patch = identity()
    core_m, core_patch = core_identity()
    require(core_m["commit"] == m["commit"] and core_m["start_result_sha256"] == m["result_sha256"],
            "core Start chain mismatch")
    env = dict(os.environ, GOFLAGS="-mod=readonly", GOWORK="off")

    def read(*cmd):
        return subprocess.check_output([go, *cmd], cwd=ROOT, env=env, stderr=subprocess.PIPE)

    version = read("version").decode().strip()
    require(version.split()[2] == m["toolchain"], "requires exactly go1.26.8")
    sums = (ROOT / "go.sum").read_text().splitlines()
    require(f'{MODULE} {VERSION} {m["module_sum"]}' in sums and
            f'{MODULE} {VERSION}/go.mod {m["go_mod_sum"]}' in sums, "go.sum identity mismatch")
    selected = json.loads(read("list", "-m", "-json", MODULE))
    require(selected.get("Version") == VERSION and not selected.get("Replace"), "unsupported selected revision")
    # Explicitly pinned download also supplies the original zip/go.mod h1 values;
    # on CI this materializes only this module if its Dir is not yet cached.
    info = json.loads(read("mod", "download", "-json", f"{MODULE}@{VERSION}"))
    metadata(info, m)
    directory = Path(info["Dir"]).resolve()
    if selected.get("Dir"):
        require(Path(selected["Dir"]).resolve() == directory, "selected module Dir mismatch")
    source = directory / m["file"]
    original = source.read_bytes()
    cache_debug = directory / "debug_http.go"
    original_debug = cache_debug.read_bytes()
    require(sha(original_debug) == core_m["files"][1]["original_sha256"], "cache debug SHA mismatch")
    patched = transform(original, m, patch)
    # Snapshot root inputs: only private copies are ever passed to go mod edit.
    root_inputs = {name: (ROOT / name).read_bytes() for name in ("go.mod", "go.sum")}
    base = Path(os.environ.get("TMPDIR") or Path.home() / ".hermes/cache/scratch")
    base.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="anytls-box-patched-", dir=base))
    rc, published, reservation = 1, False, None
    receipt = {"identity_sha256": IDENTITY_SHA, "wrapper_sha256": sha(Path(__file__).read_bytes()),
               "module": MODULE, "version": VERSION, "commit": m["commit"],
               "module_sum": m["module_sum"], "go_mod_sum": m["go_mod_sum"],
               "source_sha256": sha(original), "patch_sha256": sha(patch),
               "result_sha256": sha(patched), "go_version": version, "go_bin": go,
               "original_dir": str(directory), "original_zip": info["Zip"],
               "root_inputs_sha256": {k: sha(v) for k, v in root_inputs.items()},
               "argv": args, "target": {k: env.get(k, "host-default") for k in ("GOOS", "GOARCH", "CGO_ENABLED")}}
    try:
        replacement = work / "sing-box"
        replacement.mkdir()
        receipt["archive"] = stage_archive(Path(info["Zip"]), replacement, m["module_sum"])
        staged_source = replacement / m["file"]
        require(staged_source.read_bytes() == original, "archive/cache box.go mismatch")
        staged_source.write_bytes(patched)
        core_results = apply_core(replacement, core_m, core_patch)
        receipt["core_slim"] = {"identity_sha256": CORE_IDENTITY_SHA,
                                "patch_sha256": sha(core_patch), "files": core_results}
        receipt["result_sha256_scope"] = "Start cleanup intermediate, not final staged box.go; see core_slim.files"
        modfile = work / "build.mod"
        modfile.write_bytes(root_inputs["go.mod"])
        modfile.with_suffix(".sum").write_bytes(root_inputs["go.sum"])
        read("mod", "edit", "-modfile=" + str(modfile),
             "-replace=" + MODULE + "@" + VERSION + "=" + str(replacement))
        actual = json.loads(read("list", "-modfile=" + str(modfile), "-m", "-json", MODULE))
        replace = actual.get("Replace", {})
        require(actual.get("Path") == MODULE and actual.get("Version") == VERSION and
                replace.get("Path") == str(replacement) and replace.get("Dir") == str(replacement)
                and not replace.get("Version"), "temporary replacement mismatch")
        receipt.update(replace={"module": MODULE, "version": VERSION, "path": str(replacement)},
                       selected=actual, modfile=str(modfile), modfile_sha256=sha(modfile.read_bytes()))
        private_args = list(args)
        if output:
            reservation = output.open("xb")
            private_output = work / "output"
            for i, arg in enumerate(private_args):
                if arg == "-o":
                    private_args[i + 1] = str(private_output)
                    break
                if arg.startswith("-o="):
                    private_args[i] = "-o=" + str(private_output)
                    break
        command = [go, args[0], "-modfile=" + str(modfile), *private_args[1:]]
        receipt["command"] = command
        print("PATCHED_GO_BEGIN " + json.dumps(receipt, sort_keys=True), flush=True)
        rc = subprocess.call(command, cwd=ROOT, env=env)
        require(source.read_bytes() == original and cache_debug.read_bytes() == original_debug,
                "module-cache sources changed during command")
        require(all((ROOT / k).read_bytes() == v for k, v in root_inputs.items()), "root module inputs changed")
        require(all(sha((replacement / pin["file"]).read_bytes()) == pin["result_sha256"]
                    for pin in core_m["files"]), "final staged core sources changed")
        if output and rc == 0:
            require(output.lstat().st_ino == os.fstat(reservation.fileno()).st_ino,
                    "output reservation changed")
            with private_output.open("rb") as built:
                shutil.copyfileobj(built, reservation)
            reservation.flush()
            os.fchmod(reservation.fileno(), private_output.stat().st_mode & 0o777)
            receipt["output_sha256"] = sha(private_output.read_bytes())
            receipt["output"] = str(output)
            published = True
    finally:
        try:
            if reservation:
                # Only remove the output inode reserved by this invocation.
                if not published and output.exists() and output.lstat().st_ino == os.fstat(reservation.fileno()).st_ino:
                    output.unlink()
                reservation.close()
        finally:
            shutil.rmtree(work)
        require(source.read_bytes() == original and cache_debug.read_bytes() == original_debug,
                "module-cache sources changed during command")
        require(all((ROOT / k).read_bytes() == v for k, v in root_inputs.items()), "root module inputs changed")
    receipt.update(rc=rc, ephemeral_cleanup="ok", root_inputs_unchanged=True,
                   original_box_unchanged=True, original_debug_unchanged=True)
    print("PATCHED_GO_END " + json.dumps(receipt, sort_keys=True), flush=True)
    return rc


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as exc:
        print("go-patched: " + (str(exc) if not isinstance(exc, subprocess.CalledProcessError)
                              else "Go prerequisite command failed"), file=sys.stderr)
        sys.exit(2)

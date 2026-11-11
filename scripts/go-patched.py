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
CURRENT_GO = "go1.27.3"
CHROME_IDENTITY_SHA = "8752f6fc7dff8ddb1b73150603d7d5c78524f537d075ef7cf29e4228bd05b026"
LEAF_IDENTITY_SHA = "0e28b9a7e7258f2f588b49ce4820739998f610abdaf465a4f8b7b7530ce71589"
LEAF_FILES = ("option/tls.go", "common/tls/std_client.go", "common/tls/utls_client.go", "common/tls/client.go")


RETRY_IDENTITY_SHA = "0d0c382ffa625c89bc044294a2cd07b6e1c65d8b1878c56a1bc7c98ed874f70d"


DOH_IDENTITY_SHA = "7a559dc56e8677875871e0648da04a6732a5fff3eab766cde5b6442fa33cc7ff"


ACK_MODULE = "github.com/anytls/sing-anytls"
ACK_VERSION = "v0.0.11"
ACK_IDENTITY_SHA = "5e25227ce112c3c6a2f5416a284516430259eb7d16e49f41b217bc35a2987005"
HOOK_IDENTITY_SHA = "058a15eaf97e6ed92a17342b91b5995190368f25d9cc8eb8e0f907fb2654a1a1"
HOOK_FILES = ("session/client.go", "session/session.go")
BROWSER_IDENTITY_SHA = "0b536fea8c8ecc308e52bbe3625da68110affef1ccfbd43a3854fc826e1b1a48"

DNS_STREAM_IDENTITY_SHA = "b615d0ff76c4fbd5861bf645e7bd884f6d41d6c11772c23321b67d93025e9171"
DNS_STREAM_FILES = ("protocol/dns/handle.go", "route/dns.go", "route/route.go",
                    "protocol/dns/outbound.go", "service/resolved/service.go")


def dns_stream_identity(root=ROOT):
    raw = (root / "patches/sing-box/dns-stream-close.identity.json").read_bytes()
    require(sha(raw) == DNS_STREAM_IDENTITY_SHA, "DNS stream identity SHA mismatch")
    m = json.loads(raw)
    start, _ = identity(root)
    require(all(m[k] == start[k] for k in ("module", "version", "commit", "module_sum", "go_mod_sum"))
            and m["toolchain"] == CURRENT_GO and m["browser_identity_sha256"] == BROWSER_IDENTITY_SHA,
            "DNS stream upstream chain mismatch")
    require(tuple(p["file"] for p in m["files"]) == DNS_STREAM_FILES, "DNS stream file set mismatch")
    browser = browser_identity(root)
    require(m["files"][2]["source_sha256"] == browser["files"][1]["result_sha256"],
            "DNS stream browser intermediate mismatch")
    patch = (root / "patches/sing-box" / m["patch"]).read_bytes()
    require(sha(patch) == m["patch_sha256"], "DNS stream patch SHA mismatch")
    require(sha((root / "patches/sing-box" / m["upstream_diff"]).read_bytes()) == m["upstream_diff_sha256"],
            "DNS stream upstream diff SHA mismatch")
    return m, patch


def apply_dns_stream(replacement, m, patch):
    ops = json.loads(patch)
    require(set(ops) == {"files"} and tuple(p["file"] for p in ops["files"]) == DNS_STREAM_FILES,
            "DNS stream operation set mismatch")
    for entry, pin in zip(ops["files"], m["files"]):
        p = replacement / pin["file"]
        source = p.read_bytes()
        require(sha(source) == pin["source_sha256"], "DNS stream source SHA mismatch")
        text = source.decode()
        require(set(entry) == {"file", "replacements"}, "DNS stream operation mismatch")
        for op in entry["replacements"]:
            require(set(op) == {"old", "new"} and op["old"] and text.count(op["old"]) == 1,
                    "DNS stream exact replacement mismatch")
            text = text.replace(op["old"], op["new"], 1)
        result = text.encode()
        require(sha(result) == pin["result_sha256"], "DNS stream result SHA mismatch")
        p.write_bytes(result)


def dns_stream_receipt(m, patch):
    return dict(identity_sha256=DNS_STREAM_IDENTITY_SHA, module=MODULE, version=VERSION,
                module_sum=m["module_sum"], go_mod_sum=m["go_mod_sum"], patch_sha256=sha(patch),
                upstream_diff_sha256=m["upstream_diff_sha256"], files=m["files"], toolchain=CURRENT_GO)


def browser_identity(root=ROOT):
    raw = (root / "patches/sing-box/browser.identity.json").read_bytes()
    require(sha(raw) == BROWSER_IDENTITY_SHA, "browser identity SHA mismatch")
    m = json.loads(raw)
    require(m["module"] == MODULE and m["version"] == VERSION and
            tuple(p["file"] for p in m["files"]) == ("dns/router.go", "route/route.go"), "browser module/files mismatch")
    for pin in m["files"]:
        require(sha((root / "patches/sing-box" / pin["patch"]).read_bytes()) == pin["patch_sha256"], "browser patch SHA mismatch")
    return m

def apply_browser(replacement, m, root=ROOT):
    for pin in m["files"]:
        p = replacement / pin["file"]
        raw = p.read_bytes()
        require(sha(raw) == pin["source_sha256"], "browser source SHA mismatch")
        text = raw.decode()
        for op in json.loads((root / "patches/sing-box" / pin["patch"]).read_bytes())["replacements"]:
            require(set(op) == {"old", "new"} and op["old"] and text.count(op["old"]) == 1, "browser exact replacement mismatch")
            text = text.replace(op["old"], op["new"], 1)
        result = text.encode()
        require(sha(result) == pin["result_sha256"], "browser result SHA mismatch")
        p.write_bytes(result)

def browser_receipt(m):
    return dict(identity_sha256=BROWSER_IDENTITY_SHA, files=m["files"], toolchain=CURRENT_GO)

ACK_FILES = ("session/session.go", "session/stream.go", "session/connect_ack.go")


def ack_identity(root=ROOT):
    raw = (root / "patches/sing-anytls/identity.json").read_bytes()
    require(sha(raw) == ACK_IDENTITY_SHA, "ACK identity SHA mismatch")
    m = json.loads(raw)
    require(m["module"] == ACK_MODULE and m["version"] == ACK_VERSION and
            m["toolchain"] == CURRENT_GO and m["sing_box_doh_identity_sha256"] == DOH_IDENTITY_SHA,
            "unsupported ACK revision/toolchain/chain")
    require(tuple(p["file"] for p in m["files"]) == ACK_FILES, "invalid ACK file set")
    patch = (root / "patches/sing-anytls" / m["patch"]).read_bytes()
    require(sha(patch) == m["patch_sha256"], "ACK patch SHA mismatch")
    require(sha((root / "patches/sing-anytls" / m["upstream_diff"]).read_bytes()) ==
            m["upstream_diff_sha256"], "ACK upstream diff SHA mismatch")
    return m, patch


def apply_ack(replacement, m, patch):
    ops = json.loads(patch)
    require(set(ops) == {"files"} and tuple(e["file"] for e in ops["files"]) == ACK_FILES,
            "invalid ACK patch file set")
    results = []
    for entry, pin in zip(ops["files"], m["files"]):
        require(set(entry) == {"file", "old", "new"}, "invalid ACK operation")
        p = replacement / pin["file"]
        source = p.read_bytes() if p.exists() else None
        require((sha(source) if source is not None else None) == pin["source_sha256"],
                "ACK source SHA mismatch")
        require(source == (entry["old"].encode() if entry["old"] is not None else None),
                "ACK exact replacement mismatch")
        result = entry["new"].encode()
        require(sha(result) == pin["result_sha256"], "ACK result SHA mismatch")
        with p.open("xb" if source is None else "wb") as out:
            out.write(result)
        results.append(dict(pin))
    return results


def ack_receipt(m, patch):
    return dict(identity_sha256=ACK_IDENTITY_SHA, module=ACK_MODULE, version=ACK_VERSION,
                module_sum=m["module_sum"], go_mod_sum=m["go_mod_sum"],
                zip_sha256=m["zip_sha256"], patch_sha256=sha(patch),
                upstream_diff_sha256=m["upstream_diff_sha256"], files=m["files"],
                toolchain=CURRENT_GO, review_status=m["review_status"])


def hook_identity(root=ROOT):
    raw = (root / "patches/sing-anytls/die-hook-publication.identity.json").read_bytes()
    require(sha(raw) == HOOK_IDENTITY_SHA, "hook identity SHA mismatch")
    m = json.loads(raw)
    ack, _ = ack_identity(root)
    require(m["module"] == ACK_MODULE and m["version"] == ACK_VERSION and
            m["module_sum"] == ack["module_sum"] and m["zip_sha256"] == ack["zip_sha256"] and
            m["toolchain"] == CURRENT_GO and m["ack_identity_sha256"] == ACK_IDENTITY_SHA and
            tuple(p["file"] for p in m["files"]) == HOOK_FILES and
            m["files"][1]["source_sha256"] == ack["files"][0]["result_sha256"],
            "hook predecessor mismatch")
    patch = (root / "patches/sing-anytls" / m["patch"]).read_bytes()
    require(sha(patch) == m["patch_sha256"], "hook patch SHA mismatch")
    require(sha((root / "patches/sing-anytls" / m["upstream_diff"]).read_bytes()) ==
            m["upstream_diff_sha256"], "hook diff SHA mismatch")
    return m, patch


def apply_hook(replacement, m, patch):
    ops = json.loads(patch)
    require(set(ops) == {"files"} and tuple(e["file"] for e in ops["files"]) == HOOK_FILES,
            "invalid hook file set")
    for entry, pin in zip(ops["files"], m["files"]):
        require(set(entry) == {"file", "old", "new"}, "invalid hook operation")
        source = (replacement / pin["file"]).read_bytes()
        require(sha(source) == pin["source_sha256"] and source == entry["old"].encode(),
                "hook source SHA/exact mismatch")
        result = entry["new"].encode()
        require(sha(result) == pin["result_sha256"], "hook result SHA mismatch")
        (replacement / pin["file"]).write_bytes(result)
    return m["files"]


def hook_receipt(m, patch):
    return dict(identity_sha256=HOOK_IDENTITY_SHA, ack_identity_sha256=ACK_IDENTITY_SHA,
                module=ACK_MODULE, version=ACK_VERSION, module_sum=m["module_sum"],
                zip_sha256=m["zip_sha256"], patch_sha256=sha(patch),
                upstream_diff_sha256=m["upstream_diff_sha256"], files=m["files"],
                toolchain=CURRENT_GO, review_status=m["review_status"])


def doh_identity(root=ROOT):
    raw = (root / "patches/sing-box/doh-deadline-isolation.identity.json").read_bytes()
    require(sha(raw) == DOH_IDENTITY_SHA, "DoH identity SHA mismatch")
    m = json.loads(raw)
    require(m["module"] == MODULE and m["version"] == VERSION and m["toolchain"] == CURRENT_GO
            and m["file"] == "dns/transport/https.go", "unsupported DoH revision/toolchain")
    require(tuple(m[k] for k in ("start_identity_sha256", "core_identity_sha256", "chrome_identity_sha256",
                                 "leaf_identity_sha256", "retry_identity_sha256")) ==
            (IDENTITY_SHA, CORE_IDENTITY_SHA, CHROME_IDENTITY_SHA, LEAF_IDENTITY_SHA, RETRY_IDENTITY_SHA),
            "DoH historical chain mismatch")
    start, _ = identity(root)
    require(all(m[k] == start[k] for k in ("commit", "module_sum", "go_mod_sum")),
            "DoH upstream chain mismatch")
    patch = (root / "patches/sing-box" / m["patch"]).read_bytes()
    require(sha(patch) == m["patch_sha256"], "DoH patch SHA mismatch")
    return m, patch


def transform_doh(source, m, patch):
    require(sha(source) == m["source_sha256"], "DoH source SHA mismatch")
    ops = json.loads(patch)
    require(set(ops) == {"replacements"} and len(ops["replacements"]) == 6, "invalid DoH patch")
    text = source.decode("utf-8")
    for op in ops["replacements"]:
        require(set(op) == {"old", "new"} and op["old"] and text.count(op["old"]) == 1,
                "DoH exact replacement mismatch")
        text = text.replace(op["old"], op["new"], 1)
    result = text.encode("utf-8")
    require(sha(result) == m["result_sha256"], "DoH result SHA mismatch")
    return result


def doh_receipt(m, patch):
    return {"identity_sha256": DOH_IDENTITY_SHA, "patch_sha256": sha(patch),
            "file": m["file"], "source_sha256": m["source_sha256"],
            "result_sha256": m["result_sha256"], "toolchain": CURRENT_GO}


def retry_identity(root=ROOT):
    raw = (root / "patches/sing-box/retry.identity.json").read_bytes()
    require(sha(raw) == RETRY_IDENTITY_SHA, "retry identity SHA mismatch")
    m = json.loads(raw)
    require(m["module"] == MODULE and m["version"] == VERSION and m["toolchain"] == CURRENT_GO
            and m["file"] == "protocol/anytls/outbound.go", "unsupported retry revision/toolchain")
    require((m["start_identity_sha256"], m["core_identity_sha256"], m["chrome_identity_sha256"],
             m["leaf_identity_sha256"]) == (IDENTITY_SHA, CORE_IDENTITY_SHA, CHROME_IDENTITY_SHA, LEAF_IDENTITY_SHA),
            "retry historical chain mismatch")
    patch = (root / "patches/sing-box" / m["patch"]).read_bytes()
    require(sha(patch) == m["patch_sha256"], "retry patch SHA mismatch")
    return m, patch


def transform_retry(source, m, patch):
    require(sha(source) == m["source_sha256"], "retry source SHA mismatch")
    ops = json.loads(patch)
    require(set(ops) == {"replacements"} and len(ops["replacements"]) == 2, "invalid retry patch")
    text = source.decode("utf-8")
    for op in ops["replacements"]:
        require(set(op) == {"old", "new"} and op["old"] and text.count(op["old"]) == 1,
                "retry exact replacement mismatch")
        text = text.replace(op["old"], op["new"], 1)
    result = text.encode("utf-8")
    require(sha(result) == m["result_sha256"], "retry result SHA mismatch")
    return result


def retry_receipt(m, patch):
    return {"identity_sha256": RETRY_IDENTITY_SHA, "patch_sha256": sha(patch),
            "file": m["file"], "source_sha256": m["source_sha256"],
            "result_sha256": m["result_sha256"], "toolchain": CURRENT_GO}


def leaf_identity(root=ROOT):
    raw = (root / "patches/sing-box/leaf.identity.json").read_bytes()
    require(sha(raw) == LEAF_IDENTITY_SHA, "leaf identity SHA mismatch")
    m = json.loads(raw)
    require(m["module"] == MODULE and m["version"] == VERSION and m["toolchain"] == CURRENT_GO,
            "unsupported leaf revision/toolchain")
    require(m["start_identity_sha256"] == IDENTITY_SHA and m["core_identity_sha256"] == CORE_IDENTITY_SHA
            and m["chrome_identity_sha256"] == CHROME_IDENTITY_SHA, "leaf historical chain mismatch")
    require(tuple(pin["file"] for pin in m["files"]) == LEAF_FILES, "invalid leaf file set")
    patch = (root / "patches/sing-box" / m["patch"]).read_bytes()
    require(sha(patch) == m["patch_sha256"], "leaf patch SHA mismatch")
    return m, patch


def apply_leaf(replacement, m, patch):
    ops = json.loads(patch)
    require(set(ops) == {"files"} and tuple(e["file"] for e in ops["files"]) == LEAF_FILES,
            "invalid leaf patch file set")
    results = []
    for entry, pin in zip(ops["files"], m["files"]):
        require(set(entry) == {"file", "replacements"} and entry["file"] == pin["file"], "leaf file mismatch")
        p = replacement / pin["file"]
        source = p.read_bytes()
        require(sha(source) == pin["source_sha256"], "leaf source SHA mismatch")
        text = source.decode("utf-8")
        for op in entry["replacements"]:
            require(set(op) == {"old", "new"} and op["old"] and text.count(op["old"]) == 1,
                    "leaf exact replacement mismatch")
            text = text.replace(op["old"], op["new"], 1)
        result = text.encode("utf-8")
        require(sha(result) == pin["result_sha256"], "leaf result SHA mismatch")
        p.write_bytes(result)
        results.append(dict(pin))
    return results


def leaf_receipt(m, patch):
    return {"identity_sha256": LEAF_IDENTITY_SHA, "patch_sha256": sha(patch),
            "files": m["files"], "toolchain": CURRENT_GO}


def chrome_identity(root=ROOT):
    raw = (root / "patches/sing-box/chrome.identity.json").read_bytes()
    require(sha(raw) == CHROME_IDENTITY_SHA, "Chrome identity SHA mismatch")
    m = json.loads(raw)
    require(m["module"] == MODULE and m["version"] == VERSION and
            m["file"] == "protocol/anytls/outbound.go" and m["toolchain"] == CURRENT_GO,
            "unsupported Chrome revision/toolchain")
    require(m["start_identity_sha256"] == IDENTITY_SHA and
            m["core_identity_sha256"] == CORE_IDENTITY_SHA, "Chrome historical chain mismatch")
    patch = (root / "patches/sing-box" / m["patch"]).read_bytes()
    require(sha(patch) == m["patch_sha256"], "Chrome patch SHA mismatch")
    return m, patch


def transform_chrome(source, m, patch):
    require(sha(source) == m["source_sha256"], "Chrome source SHA mismatch")
    ops = json.loads(patch)
    require(set(ops) == {"replacements"} and len(ops["replacements"]) == 2, "invalid Chrome patch")
    text = source.decode("utf-8")
    for op in ops["replacements"]:
        require(set(op) == {"old", "new"} and op["old"] and text.count(op["old"]) == 1,
                "Chrome exact replacement mismatch")
        text = text.replace(op["old"], op["new"], 1)
    result = text.encode("utf-8")
    require(sha(result) == m["result_sha256"], "Chrome result SHA mismatch")
    return result


def chrome_receipt(m, patch):
    return {"identity_sha256": CHROME_IDENTITY_SHA, "patch_sha256": sha(patch),
            "file": m["file"], "source_sha256": m["source_sha256"],
            "result_sha256": m["result_sha256"], "toolchain": CURRENT_GO}


RULE_STARTUP_IDENTITY_SHA = "2ef5d65cf50a1e25e783424c62f3a5455e1b14662bcf037c9e98b3faddbd2dd5"


def rule_startup_identity(root=ROOT):
    raw = (root / "patches/sing-box/rule-startup.identity.json").read_bytes()
    require(sha(raw) == RULE_STARTUP_IDENTITY_SHA, "rule startup identity SHA mismatch")
    m = json.loads(raw)
    require(m["module"] == MODULE and m["version"] == VERSION and
            m["core_identity_sha256"] == CORE_IDENTITY_SHA, "rule startup chain mismatch")
    patch = (root / "patches/sing-box" / m["patch"]).read_bytes()
    require(sha(patch) == m["patch_sha256"], "rule startup patch SHA mismatch")
    return m, patch


def transform_rule_startup(source, m, patch):
    require(sha(source) == m["source_sha256"], "rule startup source SHA mismatch")
    ops = json.loads(patch)
    require(set(ops) == {"replacements"} and len(ops["replacements"]) == 2, "invalid rule startup patch")
    text = source.decode()
    for op in ops["replacements"]:
        require(set(op) == {"old", "new"} and op["old"] and text.count(op["old"]) == 1,
                "rule startup exact replacement mismatch")
        text = text.replace(op["old"], op["new"], 1)
    result = text.encode()
    require(sha(result) == m["result_sha256"], "rule startup result SHA mismatch")
    return result


def rule_startup_receipt(m, patch):
    return {"identity_sha256": RULE_STARTUP_IDENTITY_SHA, "patch_sha256": sha(patch),
            "source_sha256": m["source_sha256"], "result_sha256": m["result_sha256"], "file": m["file"]}


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
        booleans |= {"-v", "-c", "-short", "-failfast", "-json"}
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
    require(info.get("Path", m["module"]) == m["module"] and info.get("Version") == m["version"]
            and not info.get("Replace") and not info.get("Error"), "unsupported upstream module/replacement")
    require(info.get("Sum") == m["module_sum"] and info.get("GoModSum") == m["go_mod_sum"],
            "module checksums mismatch")
    origin = info.get("Origin", {})
    require(not m.get("commit") or not origin.get("Hash") or origin["Hash"] == m["commit"], "upstream commit mismatch")


MAX_ARCHIVE_BYTES = 50 * 1024 * 1024
MAX_ARCHIVE_FILES = 10000


def stage_archive(archive, destination, expected_sum, module=MODULE, version=VERSION):
    """Validate all paths/bounds and Go dirhash before writing any ZIP member."""
    require(archive.stat().st_size <= MAX_ARCHIVE_BYTES, "archive size limit")
    prefix = module + "@" + version + "/"
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
        # then SHA256 of 'hex  filename\n', including explicit directories.
        digest = hashlib.sha256()
        for entry in sorted(entries, key=lambda e: e.filename):
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
    rule_startup_m, rule_startup_patch = rule_startup_identity()
    chrome_m, chrome_patch = chrome_identity()
    leaf_m, leaf_patch = leaf_identity()
    retry_m, retry_patch = retry_identity()
    doh_m, doh_patch = doh_identity()
    ack_m, ack_patch = ack_identity()
    hook_m, hook_patch = hook_identity()
    browser_m = browser_identity()
    dns_stream_m, dns_stream_patch = dns_stream_identity()
    require(all(retry_m[k] == m[k] for k in ("commit", "module_sum", "go_mod_sum"))
            and retry_m["source_sha256"] == chrome_m["result_sha256"], "retry upstream chain mismatch")
    require(all(leaf_m[k] == m[k] for k in ("commit", "module_sum", "go_mod_sum")),
            "leaf upstream chain mismatch")
    require(all(chrome_m[k] == m[k] for k in ("commit", "module_sum", "go_mod_sum")),
            "Chrome upstream chain mismatch")
    require(core_m["commit"] == m["commit"] and core_m["start_result_sha256"] == m["result_sha256"],
            "core Start chain mismatch")
    env = dict(os.environ, GOFLAGS="-mod=readonly", GOWORK="off")

    def read(*cmd):
        return subprocess.check_output([go, *cmd], cwd=ROOT, env=env, stderr=subprocess.PIPE)

    version = read("version").decode().strip()
    require(version.split()[2] == CURRENT_GO, "requires exactly " + CURRENT_GO)
    sums = (ROOT / "go.sum").read_text().splitlines()
    require(f'{MODULE} {VERSION} {m["module_sum"]}' in sums and
            f'{MODULE} {VERSION}/go.mod {m["go_mod_sum"]}' in sums, "go.sum identity mismatch")
    selected = json.loads(read("list", "-m", "-json", MODULE))
    require(selected.get("Version") == VERSION and not selected.get("Replace"), "unsupported selected revision")
    # Explicitly pinned download also supplies the original zip/go.mod h1 values;
    # on CI this materializes only this module if its Dir is not yet cached.
    info = json.loads(read("mod", "download", "-json", f"{MODULE}@{VERSION}"))
    metadata(info, m)
    cache_zip = Path(info["Zip"])
    original_zip_sha = sha(cache_zip.read_bytes())
    directory = Path(info["Dir"]).resolve()
    if selected.get("Dir"):
        require(Path(selected["Dir"]).resolve() == directory, "selected module Dir mismatch")
    source = directory / m["file"]
    original = source.read_bytes()
    cache_debug = directory / "debug_http.go"
    original_debug = cache_debug.read_bytes()
    require(sha(original_debug) == core_m["files"][1]["original_sha256"], "cache debug SHA mismatch")
    patched = transform(original, m, patch)
    cache_chrome = directory / chrome_m["file"]
    original_chrome = cache_chrome.read_bytes()
    patched_chrome = transform_chrome(original_chrome, chrome_m, chrome_patch)
    patched_retry = transform_retry(patched_chrome, retry_m, retry_patch)
    cache_doh = directory / doh_m["file"]
    original_doh = cache_doh.read_bytes()
    patched_doh = transform_doh(original_doh, doh_m, doh_patch)
    original_leaf = {name: (directory / name).read_bytes() for name in LEAF_FILES}
    original_dns_stream = {name: (directory / name).read_bytes() for name in DNS_STREAM_FILES}
    require(all(sha(original_dns_stream[p["file"]]) == p["original_sha256"]
                for p in dns_stream_m["files"]), "module-cache DNS stream source SHA mismatch")
    require(all(sha(original_leaf[pin["file"]]) == pin["source_sha256"] for pin in leaf_m["files"]),
            "module-cache leaf source SHA mismatch")
    ack_selected = json.loads(read("list", "-m", "-json", ACK_MODULE))
    require(ack_selected.get("Version") == ACK_VERSION and not ack_selected.get("Replace"),
            "unsupported selected ACK revision")
    require(f'{ACK_MODULE} {ACK_VERSION} {ack_m["module_sum"]}' in sums and
            f'{ACK_MODULE} {ACK_VERSION}/go.mod {ack_m["go_mod_sum"]}' in sums, "ACK go.sum identity mismatch")
    ack_info = json.loads(read("mod", "download", "-json", ACK_MODULE + "@" + ACK_VERSION))
    metadata(ack_info, ack_m)
    ack_zip = Path(ack_info["Zip"])
    require(sha(ack_zip.read_bytes()) == ack_m["zip_sha256"], "ACK ZIP SHA mismatch")
    ack_directory = Path(ack_info["Dir"]).resolve()
    require(not ack_selected.get("Dir") or Path(ack_selected["Dir"]).resolve() == ack_directory,
            "selected ACK module Dir mismatch")
    ack_original = {pin["file"]: ((ack_directory / pin["file"]).read_bytes()
                    if (ack_directory / pin["file"]).exists() else None) for pin in ack_m["files"]}
    ack_original.update({pin["file"]: (ack_directory / pin["file"]).read_bytes()
                         for pin in hook_m["files"] if pin["file"] not in ack_original})
    require(all((sha(ack_original[pin["file"]]) if ack_original[pin["file"]] is not None else None)
                == pin["source_sha256"] for pin in ack_m["files"]), "ACK cache source SHA mismatch")
    require(sha(ack_original["session/client.go"]) == hook_m["files"][0]["source_sha256"],
            "hook cache client source SHA mismatch")
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
        require(receipt["archive"]["zip_sha256"] == original_zip_sha, "module-cache ZIP changed before staging")
        staged_source = replacement / m["file"]
        require(staged_source.read_bytes() == original, "archive/cache box.go mismatch")
        staged_source.write_bytes(patched)
        core_results = apply_core(replacement, core_m, core_patch)
        receipt["core_slim"] = {"identity_sha256": CORE_IDENTITY_SHA,
                                "patch_sha256": sha(core_patch), "files": core_results}
        receipt["result_sha256_scope"] = "Start cleanup intermediate, not final staged box.go; see core_slim.files"
        staged_source.write_bytes(transform_rule_startup(staged_source.read_bytes(), rule_startup_m, rule_startup_patch))
        receipt["rule_startup"] = rule_startup_receipt(rule_startup_m, rule_startup_patch)
        receipt["result_sha256_scope"] = "Start cleanup and core_slim are intermediates; rule_startup binds final box.go"
        staged_chrome = replacement / chrome_m["file"]
        require(staged_chrome.read_bytes() == original_chrome, "archive/cache AnyTLS outbound mismatch")
        staged_chrome.write_bytes(patched_chrome)
        receipt["chrome_backend"] = chrome_receipt(chrome_m, chrome_patch)
        require(all((replacement / name).read_bytes() == data for name, data in original_leaf.items()),
                "archive/cache leaf sources mismatch")
        apply_leaf(replacement, leaf_m, leaf_patch)
        receipt["leaf_certificate"] = leaf_receipt(leaf_m, leaf_patch)
        require(staged_chrome.read_bytes() == patched_chrome, "retry intermediate source mismatch")
        staged_chrome.write_bytes(patched_retry)
        receipt["transient_retry"] = retry_receipt(retry_m, retry_patch)
        receipt["chrome_result_sha256_scope"] = "Chrome intermediate; transient_retry binds final outbound"
        staged_doh = replacement / doh_m["file"]
        require(staged_doh.read_bytes() == original_doh, "archive/cache DoH source mismatch")
        staged_doh.write_bytes(patched_doh)
        receipt["doh_deadline_isolation"] = doh_receipt(doh_m, doh_patch)
        apply_browser(replacement, browser_m)
        receipt["browser_provenance"] = browser_receipt(browser_m)
        apply_dns_stream(replacement, dns_stream_m, dns_stream_patch)
        receipt["dns_stream_close"] = dns_stream_receipt(dns_stream_m, dns_stream_patch)
        receipt["dns_stream_staged_paths"] = {n: str(replacement / n) for n in DNS_STREAM_FILES}
        receipt["browser_result_sha256_scope"] = "intermediate route/route.go; dns_stream_close binds final"
        ack_replacement = work / "sing-anytls"
        ack_replacement.mkdir()
        receipt["ack_archive"] = stage_archive(ack_zip, ack_replacement, ack_m["module_sum"], ACK_MODULE, ACK_VERSION)
        require(receipt["ack_archive"]["zip_sha256"] == ack_m["zip_sha256"], "ACK ZIP changed before staging")
        apply_ack(ack_replacement, ack_m, ack_patch)
        receipt["stream_connect_ack"] = ack_receipt(ack_m, ack_patch)
        apply_hook(ack_replacement, hook_m, hook_patch)
        receipt["stream_die_hook_publication"] = hook_receipt(hook_m, hook_patch)
        receipt["ack_result_sha256_scope"] = "ACK session.go intermediate; hook successor binds final session.go"
        modfile = work / "build.mod"
        modfile.write_bytes(root_inputs["go.mod"])
        modfile.with_suffix(".sum").write_bytes(root_inputs["go.sum"])
        read("mod", "edit", "-modfile=" + str(modfile),
             "-replace=" + MODULE + "@" + VERSION + "=" + str(replacement))
        read("mod", "edit", "-modfile=" + str(modfile),
             "-replace=" + ACK_MODULE + "@" + ACK_VERSION + "=" + str(ack_replacement))
        ack_actual = json.loads(read("list", "-modfile=" + str(modfile), "-m", "-json", ACK_MODULE))
        ack_replace = ack_actual.get("Replace", {})
        require(ack_actual.get("Path") == ACK_MODULE and ack_actual.get("Version") == ACK_VERSION and
                ack_replace.get("Path") == str(ack_replacement) and ack_replace.get("Dir") == str(ack_replacement)
                and not ack_replace.get("Version"), "temporary ACK replacement mismatch")
        receipt.update(ack_replace={"module": ACK_MODULE, "version": ACK_VERSION, "path": str(ack_replacement)},
                       ack_selected=ack_actual, original_ack_dir=str(ack_directory), original_ack_zip=str(ack_zip))
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
        require(cache_chrome.read_bytes() == original_chrome, "module-cache AnyTLS source changed during command")
        require(all((directory / name).read_bytes() == data for name, data in original_leaf.items()),
                "module-cache leaf sources changed during command")
        require(all((ROOT / k).read_bytes() == v for k, v in root_inputs.items()), "root module inputs changed")
        require(all(sha((replacement / pin["file"]).read_bytes()) ==
                    (rule_startup_m["result_sha256"] if pin["file"] == "box.go" else pin["result_sha256"])
                    for pin in core_m["files"]), "final staged core sources changed")
        require(staged_chrome.read_bytes() == patched_retry, "final staged retry source changed")
        require(cache_doh.read_bytes() == original_doh, "module-cache DoH source changed during command")
        require(staged_doh.read_bytes() == patched_doh, "final staged DoH source changed")
        require(sha((replacement / "dns/router.go").read_bytes()) == browser_m["files"][0]["result_sha256"], "final staged browser DNS source changed")
        require(all(sha((replacement / p["file"]).read_bytes()) == p["result_sha256"]
                    for p in dns_stream_m["files"]), "final staged DNS stream sources changed")
        require(all((directory / n).read_bytes() == b for n, b in original_dns_stream.items()),
                "module-cache DNS stream sources changed")
        require(sha(cache_zip.read_bytes()) == original_zip_sha, "module-cache ZIP changed during command")
        require(all(sha((replacement / pin["file"]).read_bytes()) == pin["result_sha256"]
                    for pin in leaf_m["files"]), "final staged leaf sources changed")
        require(all(sha((ack_replacement / pin["file"]).read_bytes()) == pin["result_sha256"]
                    for pin in ack_m["files"] if pin["file"] not in HOOK_FILES) and
                all(sha((ack_replacement / pin["file"]).read_bytes()) == pin["result_sha256"]
                    for pin in hook_m["files"]), "final staged ACK/hook sources changed")
        require(sha(ack_zip.read_bytes()) == ack_m["zip_sha256"], "ACK module-cache ZIP changed before publication")
        require(all(((ack_directory / name).read_bytes() if (ack_directory / name).exists() else None) == data
                    for name, data in ack_original.items()), "ACK module-cache sources changed before publication")
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
        require(cache_doh.read_bytes() == original_doh, "module-cache DoH source changed during command")
        require(sha(cache_zip.read_bytes()) == original_zip_sha, "module-cache ZIP changed during command")
        require(source.read_bytes() == original and cache_debug.read_bytes() == original_debug,
                "module-cache sources changed during command")
        require(cache_chrome.read_bytes() == original_chrome, "module-cache AnyTLS source changed during command")
        require(all((directory / name).read_bytes() == data for name, data in original_leaf.items()),
                "module-cache leaf sources changed during command")
        require(all((ROOT / k).read_bytes() == v for k, v in root_inputs.items()), "root module inputs changed")
        require(sha(ack_zip.read_bytes()) == ack_m["zip_sha256"], "ACK module-cache ZIP changed")
        require(all((directory / n).read_bytes() == b for n, b in original_dns_stream.items()),
                "module-cache DNS stream sources changed")
        require(all(((ack_directory / name).read_bytes() if (ack_directory / name).exists() else None) == data
                    for name, data in ack_original.items()), "ACK module-cache sources changed")
    receipt.update(rc=rc, ephemeral_cleanup="ok", root_inputs_unchanged=True,
                   original_box_unchanged=True, original_debug_unchanged=True,
                   original_anytls_outbound_unchanged=True)
    receipt["original_leaf_sources_unchanged"] = True
    receipt["original_doh_source_unchanged"] = True
    receipt["original_dns_stream_sources_unchanged"] = True
    receipt["original_module_zip_unchanged"] = True
    receipt["original_ack_sources_unchanged"] = True
    receipt["original_ack_zip_unchanged"] = True
    print("PATCHED_GO_END " + json.dumps(receipt, sort_keys=True), flush=True)
    return rc


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as exc:
        print("go-patched: " + (str(exc) if not isinstance(exc, subprocess.CalledProcessError)
                              else "Go prerequisite command failed"), file=sys.stderr)
        sys.exit(2)

# CONNECT ACK dependency build candidate (not runtime auto)

Status: **PRERELEASE BLOCKED — independent ACK review and native consumption pending**.
This candidate adds no automatic address-family runtime policy and authorizes no
installation, service control, Mac execution or publication.

The second patched module is `github.com/anytls/sing-anytls@v0.0.11`.
`patches/sing-anytls/identity.json` pins the root go.sum h1/go.mod h1,
original ZIP SHA256, every original/result file, exact transformation JSON and
original reviewed-input unified diff. The diff SHA256 is
`0e660f750fb598f86b3da13c377240450bd42087bb541a9f471d71523c6147b7`.
This is the current review input, **not a claim that review passed**. A revised
payload requires an explicit successor identity/wrapper and new evidence; never
replace this frozen candidate silently.

The official `scripts/go-patched.py` continues all existing sing-box transforms
in their original order (Start cleanup, core, Chrome, leaf, retry, DoH). It
separately authenticates and extracts the complete AnyTLS ZIP, changes only the
three pinned session files, and installs a second exact-version replacement in
the same private temporary modfile. Both private module directories and modfile
share the existing invocation-owned cleanup scope. Root go.mod/go.sum and module
cache source/ZIP are not edited. No spike lab helper is included.

BEGIN and successful/failed-command END bind `stream_connect_ack`, `ack_archive`,
selected replacement/Dir, wrapper SHA and the existing target/command/output
identity. A compiler nonzero rc remains nonzero; launch exceptions keep BEGIN
and no success END, while cleanup still runs. New original ACK source/ZIP
invariants are mandatory in installer and CCS consumption.

CCS authenticates the exact linked AnyTLS archive against go.sum plus the ACK
ZIP pin, preserves its entire original ZIP and license corpus, carries all patch
materials in the application source archive and the complete certified receipt
in BUILD-IDENTITY. Nothing is trimmed from other module or Go source handling.
The installer validates the trusted local wrapper and ACK receipt before binary
publication, along with the existing DoH/toolchain/target/output checks.

Offline regression:

```
python3 -m unittest discover -s scripts -p '*test.py'
python3 scripts/tests/test-go-patched.py
python3 scripts/tests/test-doh-deadline-patched.py
```

The checked-in `scripts/tests/fixtures/sing-anytls-v0.0.11.zip` is the complete
original ZIP (SHA `5b588f1a803956f48efa5ee3b0bc7bd95df894ebb647e383e3ed4660b83589d2`,
h1 `h1:w8e9Uj1oP3m4zxkyZDewPk0EcQbvVxb7Nn+rapEx4fc=`), retained for real offline
authentication/reproduction and its original LICENSE. Wrapper integration tests
run the actual main entry with only external Go inspection/compiler simulated;
the sing-box archive there is explicitly a synthetic exact-source fixture with
its own calculated h1, not a production upstream archive. Packager tests use
unit compiler/binary fixtures and actual archive writing/ACK authentication.
These are **not native compilation, binary, real installation or release results**.

Go HashZip includes explicit directory entries in its sorted full-name digest;
staging now matches this contract for both modules. Existing real module file
pins and sing-box patch files are unchanged. Python grammar is checked against
3.9; target interpreter/native execution is still pending.

# Whole-leaf fingerprint validation

## Contract

`fingerprint` in an AnyTLS `proxies` or `nodes` entry is the SHA-256 of the complete leaf certificate DER, encoded as exactly 64 hexadecimal characters. Uppercase hex is accepted and normalized to lowercase. It is distinct from `client-fingerprint` (ClientHello profile) and `certificate-public-key-sha256` (Base64 SPKI digest).

The YAML conversion, native load, append, form editing and runtime compilation preserve this value. Explicit empty, null, non-string or malformed pins are rejected. A leaf pin cannot be combined with CA, SPKI pin or enabled skip-cert-verify. Existing CA/SPKI-only behavior remains available when no leaf pin is configured.

This is pin-only server identity authentication, not PKIX chain, hostname or expiry validation. Correct pins can authenticate self-signed IP-address nodes; leaf reissuance changes the pin even with the same public key. Unsupported native TLS engines, Reality and ECH combinations fail closed.

## Executed acceptance

Frozen source manifest: `/workspace/anytls-core-leafpin-evidence/source-v2-pins.json`; 269 files, no post-test source drift. Go 1.27.3 native macOS arm64; original sing-box v1.14.3 and six historical patch materials unchanged. The new authenticated leaf backport is applied only to the wrapper's private SDK copy.

- Published `v2026-10-24-04` CLI RED: same leaf-pin fixture exits with missing-CA error; all test-owned ports/processes recovered.
- Native targeted tests: 11 top-level and 96 subtests passed.
- Full native suite: 423 top-level and 1195 subtests passed; 4 existing environment/feature skips retained: external/embedded parity, external probe unsupported, optional reference-core parity and repeated resource observation.
- Native vet: passed.
- Native leaf/SPKI/fingerprint race subset: passed.
- Official-wrapper build: passed; macOS arm64 binary SHA256 `e46c69e5aed594353768b08c8514a4159ef09482a9c0a4754cc1a4c197b4cc0b`.
- Real engine integration: Go, Chrome and Firefox TCP/UDP correct-leaf positive and wrong-leaf/SPKI/issuer negative cases passed, including protocol rejection witnesses and zero unauthorized target payload.
- Final actual CLI against official AnyTLS server v0.0.28: 9/9 cases passed across default, Go and Chrome, each with correct leaf, wrong leaf and wrong password. Positive exact payload 114 bytes; negatives zero target connections and bytes. Same script as the published-program RED. All owned processes reaped and ports released.
- Independent source/patch/wrapper/CCS quality review: PASS, no blockers. Packaging Python tests passed; no new release archive/publication was performed.

Private execution receipts and logs remain outside Git under `/workspace/anytls-core-leafpin-evidence/`. The tested executable remains at `/Users/lihaiyan/anytls-core-leafpin-v2-20261024/anytls-leafpin`. No production configuration, VPN, helper, existing installation or service was changed. Intel native execution and a public binary release are not part of this acceptance.

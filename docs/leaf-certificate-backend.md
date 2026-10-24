# Leaf-certificate SHA-256 backend contract

This is a narrowly certified backport on **sing-box v1.14.3 / Go 1.27.3**, not an SDK upgrade. The application emits `tls.certificate_sha256` as a list of standard Base64-encoded 32-byte hashes. The SDK option type is `CertificateSHA256 badoption.Listable[[]byte]`. This differs from `certificate_public_key_sha256` (SPKI).

## Identity and rejection policy

- Hash the complete DER bytes of **only `rawCerts[0]`**, the peer's leaf certificate. A CA/chain certificate, an SPKI digest, or a renewed certificate using the same key does not match.
- Compare every supplied pin with `crypto/subtle.ConstantTimeCompare`; matching any supplied leaf pin authenticates the peer.
- This is **pin-only identity**, deliberately bypassing PKIX chain, hostname and expiry checks. A correct self-signed leaf works for a numeric server address. The expected hash must come from a separately trusted source.
- Reject pin combinations with disabled TLS, `insecure`, explicit CA material/path, SPKI pins, enabled Reality/ECH, or non-Go engines. Reject any pin not exactly 32 bytes. Do not silently fall back to a backend that ignores the field.
- Standard Go TLS, the SDK's other uTLS fingerprints, and the application's Chrome155 backend install `VerifyPeerCertificate` callbacks. They set `InsecureSkipVerify` solely to replace PKIX with the mandatory pin callback. `disable_sni`, clone and `SetServerName` do not re-enable unrelated hostname/PKIX checks for this pin-only mode.
- Authentication and application bytes may be written only after the TLS handshake succeeds.

## Certified build and corresponding source

Use the existing official `scripts/go-patched.py` entry point and the existing build tags. It authenticates the original module ZIP against the unchanged `go.sum`, creates a private extraction, applies the existing Start → core-slim → Chrome patches, then applies the new `leaf.identity.json` / `leaf.patch.json`. The historical identity files and their bytes are unchanged.

The new four-file patch touches only:

1. `option/tls.go` — typed outbound option;
2. `common/tls/std_client.go` — shared validation/leaf verifier and Go TLS callback;
3. `common/tls/utls_client.go` — callback for the SDK's other fingerprints;
4. `common/tls/client.go` — fail closed before native-engine/Reality dispatch.

The fourth file is necessary: patching only standard/uTLS constructors would let another engine silently ignore the new option. No global SDK module cache is edited. Final private source hashes and original cache bytes are checked before a successful END receipt. `leaf_certificate` binds the additional patch identity, patch hash, file input/result hashes, and toolchain in both wrapper receipts and CCS `BUILD-IDENTITY.json`. Packaging rejects missing/tampered leaf receipts or source archives missing either new patch material.

Exact upstream `.txt` fixtures allow the Python checks to run in a clean checkout before any Go/cache setup; fixtures are not compilation inputs. Original upstream licenses remain in `licenses/sing-box-LICENSE` and the source ZIP.

## Regression entry points

```sh
python3 scripts/tests/test-go-patched.py
python3 -m unittest discover -s scripts -p '*test.py'
GOTOOLCHAIN=local GO_BIN=/absolute/path/to/go python3 scripts/go-patched.py test -tags with_utls -run '^TestLeafCertificatePin' ./internal/chrometls
```

`TestLeafCertificatePinRealTLS` decodes the option through JSON so exactly the same test source compiles with the historical SDK. It tests Chrome155, standard Go and Firefox against real loopback TLS, including correct expired/no-SAN self-signed trust, wrong pin, chain-only pin, reissued/same-key certificate and SPKI-not-DER. Negative cases require a non-timeout TLS rejection and zero peer application bytes. Constructor regressions exercise conflicts and malformed pin lengths. Python tests authenticate/transform the real upstream sources and check CCS acceptance/rejection and archive inclusion; simulated packaging is explicitly separate from a real native build.

Native Go RED/GREEN, full-suite/vet, and real CLI AnyTLS authentication are separate execution gates. This document describes the implementation contract, not a claim that those platform gates or any production deployment have been completed.

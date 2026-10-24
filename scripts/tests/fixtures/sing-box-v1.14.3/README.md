# Authenticated upstream validation fixtures

Exact, unmodified `box.go`, `debug_http.go`, `protocol/anytls/outbound.go`, `option/tls.go`, `common/tls/client.go`, `common/tls/std_client.go`, and `common/tls/utls_client.go` from `github.com/sagernet/sing-box v1.14.3`, upstream commit `7054cac5124465ffdb145870d7c01885566711b1`.

The four `option-tls.go.txt` / `common-tls-*.go.txt` inputs for the leaf-certificate backport are individually SHA256-bound in `patches/sing-box/leaf.identity.json`. They were checked against the actual official proxy ZIP (2,734,188 bytes, SHA256 below); the ZIP matches the existing Go module h1 and `go.sum`.

These `.txt` copies let Python validation run in a clean checkout before Go/cache setup. They are not compiled or used as SDK build inputs. Tests hash them against the approved patch identities before transforming private disposable copies.

- `anytls-outbound.go.txt`: SHA256 `c5ed01024d6e2c04d1366432c2d65ab23b06941a19fd548d2c496e7f42f2fc1c`
- `box.go.txt`: SHA256 `35d8a84442bedb1c32ef13515d90bb356d32a1210771f709bde9c4428defb964`
- `debug_http.go.txt`: SHA256 `1234a4e10d999c9f03254ebb6b29b4d16b0076ba42f292aa20bbf902c8c5f682`
- Authenticated module ZIP SHA256: `4e4ae6c67870391933df3e1108eb27559cce890da492490b76361bc85bbed003`
- Module h1: `h1:cBg8TP5SPWoMAlWqTqbSNdHGKPUciZisjQbLtqFlMZA=`

Upstream copyright/license terms apply. Full upstream license is included at `licenses/sing-box-LICENSE`; see project `THIRD_PARTY_NOTICES.md`. The files are preserved verbatim, merely renamed with `.txt` suffixes.

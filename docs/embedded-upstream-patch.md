# sing-box Box.Start cleanup-error patch

Fixed upstream: sing-box v1.14.3, commit `7054cac5124465ffdb145870d7c01885566711b1`.

The patch adds the standard-library errors import and changes the startup failure return to `errors.Join(err, s.Close())`, preserving both causes. Its exact two replacements are in `patches/sing-box/box-start.patch.json`. Copyright and upstream terms are retained; this project is independent of SagerNet.

| Input | SHA-256 |
|---|---|
| Original box.go | 35d8a84442bedb1c32ef13515d90bb356d32a1210771f709bde9c4428defb964 |
| Patch JSON | 6cdf2954d34dd47d60c526d62aa0ed46673c06c47b6eb85f26fa2edf6d6c49e5 |
| Patched box.go | c0b76515c8efe4c0a3d474d83446c395904c08915efc9d811e4ca9fb187fcf7d |

Use `scripts/go-patched.py`, not a plain build. Current candidate requires exact Go 1.27.3 and adds a separately authenticated AnyTLS Chrome-backend hook after the existing Start/core-slim transforms. The original Start identity and its historical toolchain annotation remain unchanged; they are not the current build-toolchain selection. It verifies upstream module/ZIP checksums, safe ZIP contents and original source before applying patches in a private temporary replacement. Root module files and the original cached source remain unchanged during wrapper execution. Test/vet/build commands, each patch identity and output checksum are bound in BEGIN/END records; successful END is required. Temporary replacement is removed after completion.

The patch's native regression and latest complete tests/vet/build have run successfully. Historical interrupted experiments are not release validation and are not included in the source package. The in-code note about unpatched upstream behavior remains relevant when bypassing this wrapper.

## Rule-set startup admission ordering

The separately authenticated `rule-startup` patch consumes core-slim's historical
`box.go` result without changing either historical patch identity. It completes
the router's `PostStart` (including `RuleSetItem.Start`) before starting endpoint,
inbound or service listeners, and removes that router entry from the later
`PostStart` list so rules initialize exactly once. Previously mixed could route
while rule-set references were still being reset/populated, racing on `setList`
and incorrectly falling through to a later source rule.

`rule_startup` in BEGIN/END binds the final `box.go`; `core_slim.files` remains an
intermediate identity. CCS and the source installer require this new receipt and
the two new patch materials. Final box.go SHA-256:
`96889c402ab6b6ee9c242e2d022d243b2c4442f5b17f7eee94a0ee07a631c536`.

`TestRuleSetStartupBeforeInboundAdmission` holds the real rule startup boundary
with channels and requires no listening inbound before release, both on success
and on initialization failure. Existing actual-SDK routing tests retain their
source-index/source-ID and direct/proxy/reject assertions unchanged. This is a
startup-order fix, not a general synchronization repair for mutable upstream
local/remote rule-set reloads; it adds no locks to runtime update callbacks.

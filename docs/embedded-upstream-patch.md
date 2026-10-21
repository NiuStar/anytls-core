# sing-box Box.Start cleanup-error patch

Fixed upstream: sing-box v1.14.3, commit `7054cac5124465ffdb145870d7c01885566711b1`.

The patch adds the standard-library errors import and changes the startup failure return to `errors.Join(err, s.Close())`, preserving both causes. Its exact two replacements are in `patches/sing-box/box-start.patch.json`. Copyright and upstream terms are retained; this project is independent of SagerNet.

| Input | SHA-256 |
|---|---|
| Original box.go | 35d8a84442bedb1c32ef13515d90bb356d32a1210771f709bde9c4428defb964 |
| Patch JSON | 6cdf2954d34dd47d60c526d62aa0ed46673c06c47b6eb85f26fa2edf6d6c49e5 |
| Patched box.go | c0b76515c8efe4c0a3d474d83446c395904c08915efc9d811e4ca9fb187fcf7d |

Use `scripts/go-patched.py`, not a plain build. It verifies exact Go 1.26.8, upstream module/ZIP checksums, safe ZIP contents and original source before applying the patch in a private temporary replacement. Root module files and the original cached source remain unchanged. Test/vet/build commands and output checksum are bound in BEGIN/END records; successful END is required. Temporary replacement is removed after completion.

The patch's native regression and latest complete tests/vet/build have run successfully. Historical interrupted experiments are not release validation and are not included in the source package. The in-code note about unpatched upstream behavior remains relevant when bypassing this wrapper.

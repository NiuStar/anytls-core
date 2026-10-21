# Third-party source and build notices

anytls-core is an independent application, not an official SagerNet application and not endorsed by upstream projects.

Source archives contain the independent application and patch description. Binary Releases additionally include original license/copyright/NOTICE files under `licenses/`, and provide the exact application plus linked dependency module archives and Go source in a corresponding-source asset alongside the binary. Exact module versions and checksums are in go.mod/go.sum. Build tags are `with_gvisor,with_utls,with_upstream_cleanup_patch,embedded_core`.

- sing-box v1.14.3, commit `7054cac5124465ffdb145870d7c01885566711b1`: GPL-3.0-or-later with the additional naming/association sentence reproduced in `licenses/sing-box-LICENSE`. Source: https://github.com/SagerNet/sing-box/tree/7054cac5124465ffdb145870d7c01885566711b1
- The Box.Start patch joins startup and Close errors. See `patches/sing-box/identity.json`, `box-start.patch.json` and `docs/embedded-upstream-patch.md`. No other upstream source change is intended.
- Other important build dependencies include sing, sing-tun, sing-anytls (GPL family), SagerNet gVisor (Apache-2.0 plus file-level exceptions), MetaCubeX uTLS (BSD family) and Go runtime/standard library. Consult the exact dependency source licenses; these summaries do not override their original terms or certify binary redistribution compliance.

When redistributing a built binary, provide its exact corresponding source/build material and all applicable copyright, license and NOTICE texts. Merely linking this source release does not establish that a separately modified binary satisfies all obligations.

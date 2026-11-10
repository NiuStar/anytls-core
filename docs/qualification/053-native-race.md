# 0.5.3 candidate: clean-host native race qualification, not a release

This independent qualification branch contains the original three performance
optimizations plus CI-only qualification tooling. VERSION and App metadata remain
at the accepted 0.5.2 identity. It is not a release, installation approval, or
permission to update main, tags, latest, helpers, production apps, or VPN state.

The historical Mac Studio full-race failure remains unresolved and retained. A
passing clean GitHub-hosted run establishes only that this exact candidate passed
on those clean hosts; it neither explains nor clears the historical failure.
Independent parent acceptance is required before any later release decision.

The original Ubuntu, macOS 15 ARM, and macOS 15 Intel matrix, toolchain (Go 1.27.3),
non-race tests, vet, builds, and native Swift suites are unchanged. Each matrix
row additionally runs exactly once:

```
python3 scripts/go-patched.py test -p=2 -tags=with_gvisor,with_utls,with_upstream_cleanup_patch,embedded_core -race -count=1 -json ./...
```

CGO_ENABLED=1 is scoped to this step. There is no test filter, split, retry,
Go timeout override, child-deadline extension, race disablement, or loader/debug
bypass. The runner checks the inherited short canonical owned `$HOME/.aq-ci`
TMPDIR. Existing cache/toolchain behavior and safety guards remain intact.
Raw combined stdout/stderr and machine-readable counts/exit status stay in the
per-platform `full-race-*` Actions artifact, uploaded with `always()`. Public
failure annotations expose only fixed count keys and bounded ASCII top-level
synthetic test identifiers, never raw child output or arbitrary paths.

The offline `scripts/ci_race_test.py` contract verifies byte-for-byte retention of
the predecessor workflow after removing only the three added steps; command,
no-timeout, unchanged exit status, safe annotation, and mutation controls require
no Go compilation, network, installation, or production access.

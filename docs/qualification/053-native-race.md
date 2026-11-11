# 0.5.3 candidate: dual-Mac native race qualification, not a release

This independent qualification branch contains the original three performance
optimizations, the reviewed rules-startup repair, and CI qualification tooling.
VERSION and App metadata remain at the accepted 0.5.2 identity. It is not a
release, installation approval, or permission to update main, tags, latest,
helpers, production apps, or VPN state. Only GitHub-hosted CI is exercised;
physical Mac Studio and Intel production machines are outside this operation.

The user explicitly scoped this successor to both Macs: “ubuntu的先不管，只管两个Mac的”.
The required matrix is exactly macos-15 (ARM) and macos-15-intel, with
strategy.fail-fast: false so that one failed row cannot cancel its sibling.
Both rows must reach terminal state under the original observation deadline;
any failed, cancelled, missing, or incomplete required Mac gate remains HOLD.
Ubuntu is DEFERRED_BY_USER_NOT_PASSED, not a waived Mac check or a Linux PASS.

Historical records are immutable and unresolved: the Mac Studio 3-second
HISTORY_VERSION_TIMEOUT, and run 42935990232's Linux TestAnyTLSUDP failure with
both Mac rows cancelled by fail-fast. A later focused Linux PASS neither clears
that original failure nor qualifies this successor. No Ubuntu artifact is
required for this Mac-only operation. A clean hosted PASS establishes only that
this exact candidate passed on those hosts; independent parent acceptance is
required before any later release decision.

Except for the exact matrix and fail-fast delta, all original 20 observed steps
per Mac (including Actions housekeeping), Go 1.27.3, wrapper/cache policy,
non-race tests, vet, builds, all five native Swift suites, and safety checks are
retained. Each Mac row additionally runs exactly once:

```
python3 scripts/go-patched.py test -p=2 -tags=with_gvisor,with_utls,with_upstream_cleanup_patch,embedded_core -race -count=1 -json ./...
```

CGO_ENABLED=1 is scoped to this step. There is no test filter, split, retry,
Go timeout override (the default remains 10 minutes), 3-second child-deadline
extension, race disablement, or loader/debug bypass. The runner checks the
inherited short canonical owned `$HOME/.aq-ci` TMPDIR. Native Swift tests retain
the no-production-installation and no-WAN constraints.
Raw combined stdout/stderr and machine-readable counts/exit status stay in the
per-Mac `full-race-*` Actions artifact, uploaded with `always()`. Public failure
annotations retain the existing bounded identifier/count policy; native suite
failure categories remain fixed enums. Raw child output and arbitrary paths
are not exposed. Optional native upload still requires its producer-owned path.

The offline `scripts/ci_race_test.py` contract normalizes only the exact authorized
dual-Mac/fail-fast delta, the reviewed native-upload guard, and the three added
qualification steps back to the unchanged original BASE_WORKFLOW_SHA256. It
rejects missing Intel, either single-Mac matrix, fail-fast re-enablement, race
filtering and timeout overrides; runner command, no-timeout, original exit
status and safe annotations remain covered without compilation, network,
installation, or production access.

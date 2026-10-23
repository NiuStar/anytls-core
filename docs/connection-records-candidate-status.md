# Connection records + opt-in LAN WebUI: candidate handoff

Status: **SOURCE CANDIDATE ONLY — NOT A RELEASE / NOT READY FOR INSTALLER UPDATE.**

This handoff is intended for review and continued testing on the user-specified `172.16.51.184`. That machine's OS, architecture, privileges and existing installation have not been inspected by this task. Do not infer them from the IP address.

## Implemented candidate scope

- Same-capture runtime compilation and immutable rule/group/outbound provenance.
- Fixed-version SDK tracker route observations, not a full connection audit: ROUTED is not connected/successful; REJECT, DNS and early-error coverage remains incomplete.
- Private asynchronous append-only files, fixed on-disk index and authenticated helper paging. No history-count quota or automatic deletion.
- Connection history UI with current-page filters, desktop table and mobile cards, evidence details and cancellation ownership.
- Explicit local private IPv4 WebUI binding through `webui --listen ADDRESS --port PORT`, exact Host/Origin checks, existing login/CSRF and no CORS. Plain HTTP is not encrypted and is for trusted LAN use only.
- Shared codec cross-field consistency fix (QB-01), independently reviewed after native RED/GREEN.

## Current blocking finding — SPEC-01

A successful visible CLOSED state publication may be followed by directory Sync or writer-lock close failure. If subsequent disk writes also fail, the persisted CLOSED state cannot prove all cleanup/durability operations succeeded. The current reader can indefinitely treat that state as orderly completion.

`TestDiskRecordsTerminalFailureCannotCertifyClosed` intentionally retains the real failing regression. Four native fault-injection subcases reproduce the defect. Do not remove, skip or weaken this test to make a public release green. Ordinary successful-close and writer-lock-lifetime positive controls are also retained.

Proposed, **not yet user-approved**, contract correction: CLOSED means only the last persisted stopped-recording state, never proof of all sync/cleanup or complete history; present final-cleanup unverified / continuity UNKNOWN. The specification and implementation have not been changed to that proposal. Original failures are not reclassified as PASS.

## Verified boundaries

- Previous integrated Mac arm64 candidate (before successor UI/LAN/codec deltas): 376 top-level PASS, 701 subtests PASS, 2 SKIP; vet/build and targeted race passed. This is not the current whole-tree all-PASS result.
- Current-page UI independently reviewed and exercised in real Chromium with synthetic APIs at desktop/mobile sizes. These are not installed-helper or TUN receipts.
- QB-01 uses identical native RED/GREEN regression inputs, including private Unix exchange through authenticated ServeHTTP with a simulated peer-UID seam. Native positive/negative assertions and independent review passed.
- LAN delta: native 104 top-level / 227 subtest PASS, 1 SKIP; codec 2 / 28 PASS; vet/build passed. Known SPEC-01 was not covered by those passing subsets.
- Mac Studio ordinary-user WebUI was switched to `http://192.168.5.2:18089` with verified backup, login and asset readback. Root helper and VPN were not upgraded by that switch; records returned `UNSUPPORTED`. This is not complete connection-record feature deployment.
- Compiler descendant launch provenance and individual descendant wait/reap were not instrumented; direct wrapper waits and empty observed groups at command boundaries have narrower meaning.

## Publication gate

No new stable tag, Release, latest update, or binary install package is authorized by this candidate document. Before a Release: resolve/approve SPEC-01 semantics, implement and independently re-review the precise fix, run the complete final native suite and required branch CI (Linux, Apple Silicon and Intel), then perform clean-tag builds, packaging, corresponding-source/license checks and public attachment readback.

Existing `VERSION` remains the earlier stable version because this is an untagged source candidate; it must not be advertised as a new `v2026-10-22-06` build. Raw logs, private node/subscription configuration, credentials, generated caches and core dumps are deliberately excluded from Git.

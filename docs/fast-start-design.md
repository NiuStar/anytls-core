# Fast startup: local readiness, not internet certification

Scope: isolated feat/fast-start; offline/loopback fixtures only. No install, production configuration, VPN, SSH, release or commit.

## Contract

START/RELOAD must not query any configured node route or contact an external detection site. No selected-node exception applies; configured, warm and rule-only outbounds are preserved. Success means LOCAL_READY: staged config/TLS policy accepted, restoration baseline complete, launchd running, public route on the same TUN, nonempty DNS, final re-observation and private diagnostic persistence. It does not prove node authentication or internet reachability. No background goroutine or automatic WAN retry is introduced. Existing explicit node HTTPS checks and the separately owned macOS connectivity monitor remain the independent internet diagnostic surface; their result is not a lifecycle receipt.

The fixed 11-field invocation diagnostics retain their shape and schema 1 but success uses stage LOCAL_READY / reason INTERNET_UNVERIFIED for START/RELOAD. Legacy strict consumers reject these unknown enums rather than upgrading local readiness to old network-verified semantics. Old NONE/NONE receipts remain readable, STOP/failure/UNKNOWN semantics remain unchanged. New on-disk diagnostics for baseline v2 use schema_version 3, node_route_verification NOT_RUN, restoration_scope LOCAL_INTERFACE_DNS; server fields remain NOT_EXECUTED. START adds readiness LOCAL_READY, https NOT_EXECUTED, internet_verification NOT_RUN. Baseline v2 stores only the local public interface and original ordered DNS; it contains no server-route map. Version 0/1 STOP continues to validate its exact historical all-server restoration scope. RELOAD stops the old snapshot using its original version before starting v2. Invocation diagnostics and installer receipt_schema=2 are different protocols and unchanged. Historical before_https/after_https field names remain structural compatibility fields; they never imply an HTTPS request was performed. The fixed invocation diagnostics are authoritative for the invocation only; disk receipts remain UNTRUSTED_DIAGNOSTIC.

## Consumer inventory

- service_lifecycle.go / service_receipt.go: remove synchronous HTTPS and all per-node route observations from START, status and cleanup for v2 baselines only, retain standalone helper and all its TLS/retry negatives, rollback, restoration, snapshot and receipt gates.
- start_diagnostics.go and internal/startuptimeline/diagnostics.go: exact stage/reason/action success pairing; legacy strict NONE/NONE retained.
- control_startup.go / web_startup.go: existing lossless diagnostics projection needs no shape change.
- web_assets/app.js and startup.js: validator and visible local-ready/internet-unverified wording, never internet success.
- macos/Model.swift and KnownFailureTests.swift: accept only exact local-ready success tuple; HTTP200 alone remains insufficient when diagnostics present. Selection interfaces unchanged.
- desktop_reload_operator.go / desktop_reload_receipts.go and install-binary.py use explicit job receipt_schema=2 for new transactions. Unversioned historical receipts retain strict NONE/NONE admission; local tuples cannot fall back through legacy admission. New successful result receipts carry receipt_schema=2 as well; parent acknowledgement still binds exact result bytes. UNKNOWN/operator records remain UNKNOWN, all original identities/hashes/STOP gates remain mandatory. Historical fixture inventory is unchanged. Live helper status accepts the exact local-ready tuple independently; it never claims NETWORK_VERIFIED.

## Performance and duplicate work

The proved structural blocker is synchronous curl api.ipify.org (up to three 12-second attempts under shared 40-second budget); blocked offline fixture proves old start waits and candidate never calls it. No user-Mac latency claim. Existing Check/Run single-pass optimization is already in the baseline; do not reintroduce it or claim it anew. Final job/public-TUN/DNS observations and staged validation are safety boundaries, not blind-cache candidates. Additional deduplication requires call-count and byte-equivalence evidence first; none is assumed.

## Acceptance

Test-first identical blocked-curl fixture: old start reaches external seam, candidate finishes without reaching it and returns only local readiness. Route/job/DNS, strict TLS/config, baseline/cleanup, cancellation and receipt-write negatives remain non-ready. Legacy diagnostics decode, new tuple poisoning, HTTP200 non-success and STOP restoration regressions remain required. Native Swift/AppKit and actual TUN latency are parent-owned NOT_RUN here.

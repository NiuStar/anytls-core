# DoH request-deadline isolation (unreleased)

The pinned sing-box v1.14.3 HTTPS DNS transport force-closes every connection
when any Exchange returns context.DeadlineExceeded. On a shared HTTP/2 connection
this interrupts unrelated streams with independent remaining budgets.

The authenticated patch changes only `dns/transport/https.go`: remove the
deadline-triggered reset branch and its now-unused timestamp/imports. Keep the
existing request context, HTTP transport cancellation, error propagation,
keep-idle policy, explicit Reset and scope shutdown. Reset still replaces and
closes the current transport; there are no retired pools or new ownership paths.
No DNS retries, timeout reduction, extra upstream, TLS weakening, plaintext
fallback or TTL/cache change is introduced. Underlying connection-blackhole
recovery is a separate acceptance gate, not inferred from FIN/EOF recovery.

`doh-deadline-isolation.identity.json` pins the original SDK archive identity,
historical Start/core/Chrome/leaf/retry identities, patch bytes, original source
and resulting source. The official wrapper verifies the full module ZIP h1,
extracts privately, transforms that extraction, passes an explicit private
modfile and checks original cached/root inputs before successful END. Historical
identities remain byte-identical. BEGIN/END add `doh_deadline_isolation` and
`original_doh_source_unchanged`; prior fields retain their meanings.

The packager requires the exact new receipt and includes both patch materials in
its application-source/CCS whitelist. The source installer uses only the trusted
local wrapper, validates the new receipt, output digest, target and unchanged
inputs before version checking/publication, then retains CERTIFIED-BUILD.json.
Python packaging/installer fixtures simulate external compiler/Git boundaries;
they do not constitute a native distributable or real installation.

The frozen protocol test file must remain SHA256
`5e2a81d982446f4dcafb3f73682dca586652a3ec34b2c42a35320c2523731798`.
Original native RED evidence: protocol-baseline-r1 recovery-r2/recovery-r3,
4 PASS / 1 FAIL each. Candidate execution and any mutation must be reported
separately from full suite/vet/build, binary+CCS packaging, native installation,
WAN and public release. This change does not authorize publication or VPN changes.

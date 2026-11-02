# Default browser family coordinator: scoped integration

The production invocation is default-on; no YAML switch is added. The SDK accepted-DNS-return and selected-route transformations are now consumed by `scripts/go-patched.py` from authenticated private module extraction, together with the existing CONNECT ACK module patch. Their identity is bound into BEGIN/END, corresponding-source material validation, and source-installer output validation. No module cache source is edited.

## Runtime contract

- Only strict engine-registered HTTPS DNS transports mint client-scoped AAAA receipts. An owned refresh binds fresh AAAA and A questions to that exact transport/detour and matching original question, CNAME terminal, epoch and TTL intersection.
- Preparing route metadata does not query DNS. Original IPv6 is always attempted first; only typed remote CONNECT failure (or typed DIRECT TCP dial failure) permits the refresh. TLS/auth/transport failure, cancellation, unknown and unsupported ACK capability are not family evidence.
- At most one candidate A is tried on the same concrete immutable outbound and same actual compiled rule object/index. Original metadata and application bytes are unchanged. The original failed stream closes before the alternate. The alternate must have a successful remote TCP ACK before delivery. Target TLS remains end-to-end.
- Unsupported/unknown peers retain their original early stream and never trigger an alternate. Each ACK wait retains the SDK's three-second limit; a refresh has its own maximum two-second child budget, clamped by any inherited caller deadline. This is an additional failure-only refresh budget, not a global timeout change or a healthy-IPv6 delay.
- Admission and each attempt validate under the provenance mutex. Epoch reset/conflicting observations cancel registered contexts and close their attached streams; run close also invalidates before closing the Box. No per-connection background probing is introduced. A later connection starts IPv6 first, with no persistent node/family disable flag.

## Supported policy and deliberate UNKNOWN ceiling

Canonical compiler TUN prefixes (port53 hijack, sniff without overrides, protocol-DNS hijack), auto_detect_interface and default_domain_resolver no longer disable the whole guard. Pure matching skips sniff only when protocol is already known; it never reruns sniff/resolve. Simple immutable domain, CIDR, version, network and port rules retain their compiled identities; candidate REJECT denies launch. Domain observed in TLS sniff must agree with the trusted question.

This branch prepares captured-manifest admission for the real compiler's immutable GEOIP/CN CIDRs and SHA-verified inline RULE-SET datasets, including the exact literal-only no-op generated resolve action. See [frozen ruleset candidate contract](browser-frozen-rulesets-candidate.md). Its new Go coverage is NOT_RUN and is not inherited native acceptance. Selectors/urltest, arbitrary route options/effectful resolve, mutable datasets, unknown sniff protocol, ECS/optimistic-cache/TTL rewriting and EDNS questions remain UNKNOWN; this is not complete all-config auto-family support.

## Real execution evidence

Evidence root: `/workspace/anytls-address-family-auto-evidence/integrated-r1`.

- `attempt-2`: native Mac Go 1.27.3 official-wrapper tests first demonstrated actual compiler policy → DNS via P → browser AAAA wire response → IPv6 literal CONNECT via Q → explicit remote failure → certified refresh → IPv4 via same Q → exact HTTPS body, business request count one. Candidate CIDR REJECT launches zero IPv4 attempts.
- `attempt-3`: adds natural next-connection IPv6 recovery, zero additional DNS on the healthy connection, coordinator/ACK tests, engine vet, clean native candidate build. The controlled peer maps recovered synthetic IPv6 to the loopback HTTPS server; it is not public IPv6 egress evidence.
- `old-contract`: identical final business test/helper bytes placed on production base `3e00592` (evidence-only commit) use the old `engine.Run` interface and fail the expected HTTPS fallback assertion with Q IPv6 one, IPv4 zero and DNS one. This is business RED, not missing-API compilation failure.
- Earlier first integration failure is retained: DNS question did not equal actual TLS SNI. The fixture was corrected, not the security check.
- `final-targeted` accidentally expanded to the complete engine package under a 45-second test deadline; it timed out during an existing retry fixture after 290 test passes. `final-scoped` combined the negative DNS matrix under the same too-short 45-second deadline and timed out after the browser positive/recovery checks passed. These logs are retained and are not full-suite acceptance or diagnosed product regressions.

Tests use private authenticated AnyTLS and HTTPS DNS/target fixtures, preserving compiler DNS detour P versus business Q and the actual compiled TUN route rules. Only TUN inbound and controlled endpoint/trust material are substituted. This is unprivileged mixed-loopback validation, NOT privileged TUN/browser-site acceptance. Formal installation, VPN/helper/config/network changes and GitHub writes were not performed.

## Remaining release gates

Final full suite with adequate unchanged policy deadline, race/concurrent launch barrier cases, complete negative coordinator matrix, immutable GEOIP/RULE-SET support, full vet/package and independent final integrated review remain separate gates. No formal installation or release is authorized by this scoped result.

# Browser provenance SDK candidate (integration HOLD)

Base: `cc69b28605e933b3f534a0f8f5d9a790384a17e6`.
This is real Go implementation and SDK source transformations, **not compiled or run**. No Mac, SSH, Go process, public probe, install or release was performed. Test-first files were prepared; RED/GREEN was NOT observed.

## Implemented seam

- `decodeOptions` always creates a private per-box provenance service after the fresh service registry. No YAML mode or global state. Check constructs only, never queries.
- The existing concrete HTTPS factory registers only strict default-TLS transport identities; metrics wrapper capability preservation is unchanged. No response-supplied trust flag. Unknown/insecure/custom TLS engines do not mint authority.
- SDK `dns/router.go` hooks actual accepted response return (sync and async, including cache responses), before delivering browser bytes. Records original IN AAAA, ingress+source client scope, question, CNAME terminal, original TTL, strict transport identity and epoch. Refresh responses must pass the same SDK seam for the same owned operation and exact transport; a resolver return alone is not certification.
- 512 total leases, 32 RR limit, 8 CNAME hops, 32 trusted transports, 8 simultaneous refreshes, 2-second inherited refresh budget. No LRU: TTL claims survive negative responses; capacity overflow imposes a global finite quarantine extended over every retained/refused/newly observed lease. Reset/clear invalidates tickets and claims without shortening quarantine.
- SDK `route/route.go` invokes the guard only after actual TCP rule/outbound selection, preserving original metadata/tracker fields and all client bytes. Guard pins a private additional AAAA+A lookup to the original secure HTTPS transport/detour and current business question. Original AAAA must still occur in refreshed AAAA; IN class, question and CNAME terminal must agree, with intersected semantic TTL leases. Independent browser A responses are never combined.
- Pure shadow matching uses actual compiled immutable SDK rule objects over value-copied, reset metadata, not `Router.matchRule`, `prepareMatchMetadata`, sniff or resolve. It requires the same actual rule object/index, same concrete selected outbound leaf, fixed run policy and no action effects. Same outbound tag alone is insufficient. Candidate REJECT denies.
- The private context launch ticket is consumed via `browserAlternate(ctx, selectedOutbound)` and rechecks TTL/client ambiguity/network epoch/leaf identity. The parent coordinator still must atomically reserve launch relative to invalidation; this is NOT an atomic dial reservation.

## Deliberate UNKNOWN ceilings

Supported frozen rules: simple default DOMAIN/domain-suffix, CIDR, IP-version, ingress, network and port/source matches, route/reject with no extra effects. Unknown fields, sniff/resolve/route-options, process lookups, rule sets/GEOIP, selectors/urltest, ECS, optimistic cache config and TTL rewriting disable certification. Browser queries with EDNS additional data are conservatively unsupported. No attempt to skip effectful rules based on their current match result. Pure IPv6 literals without trusted receipt, stale/shared addresses, separate client scopes, DNS failures and UDP preserve the old path.

A static controlled GEOIP prefix fixture can be expressed using CIDR and exercised through actual compiled rules; production GEOIP rule sets are deliberately unsupported until an immutable ruleset/generation adapter exists. This narrower ceiling avoids falsely advertising pure matching of mutable remote datasets.

## Integration still required

`patches/sing-box/browser.identity.json` pins the two exact source inputs, JSON transformations and output bytes. `scripts/validate-browser-sdk.py` authenticates all 35 exported source files and applies both transformations without module cache writes. Existing `scripts/go-patched.py` is **not modified**: parent must add these two transformations to authenticated private extraction/receipt generation before native tests. Until then the SDK callbacks are absent and no browser candidate is issued.

The parent ACK-gated alternate CONNECT coordinator is not implemented here. No destination is replaced, no alternate CONNECT is launched and no health state is inferred. Ticket availability does not mean remote TCP ACK, target TLS, or browser end-to-end success. Keep strict TLS/DoH detours and original client bytes; never replay application data. This branch cannot claim browser auto-family repaired or release acceptance.

## Owner native commands (NOT RUN here)

1. Integrate the two pinned transformations into `scripts/go-patched.py` extraction+receipt chain and format new Go files with native gofmt.
2. `python3 scripts/go-patched.py test -tags with_utls ./internal/engine -run TestBrowser -count=1`
3. Repeat with `-race`, then full test/vet/build via the approved native wrapper.
4. Add real sync/async accepted-response hook fixtures, malicious custom transport rejection, concurrent invalidation/atomic reservation, actual GEOIP snapshot tests if support is expanded, and controlled browser HTTPS→literal→ACK-gated A fallback with zero pre-ACK application bytes.

Local source application output is in `/workspace/anytls-address-family-auto-evidence/browser-integration-r1/applied/report.json`; it is SOURCE_APPLICATION_ONLY_GO_NOT_RUN, never a Go/runtime PASS.

# Frozen local datasets: candidate contract

The compiler already converts each SHA-checked local v3 JSON source into SDK
`type:inline` rules, preserving the original rule-set reference and rule order.
It does **not** hand SDK a watched local path. Reuse that seam rather than adding
an SDK watcher/reload hook or rewriting RULE-SET into expanded route rules.

`loadRuleSetCaptured` returns the same read used by validation/inline compilation.
`familypolicy.Capture` verifies manifest self-digest, runtime SHA, ordered captured
source SHA/ordinal, unique label and semantic equality of every inline headless
rule. The resulting private immutable ticket retains only runtime SHA, manifest
identity and generation, not source JSON, caller-owned pointers or paths. The
embedded dispatcher carries it even when records are disabled; the engine's new
service registry cannot acquire it from SDK/user JSON tags. Each new compile/run
owns a new ticket. Failed source-SHA compile cannot replace an existing snapshot.

The shadow admission projection does not change SDK options, first-match source
index, action, outbound, no-resolve behavior, DNS/TLS or SDK nested matching.
Only default/logical headless rules built from immutable domain/IP/port/network
fields are admitted. Process/WIFI/interface, nested rulesets, unknown fields,
remote/watched local sets and runtime drift remain UNKNOWN. Selector/urltest leaf
identity remains unsupported. For the exact compiler-generated unconditional
resolve action, SDK v1.14.3 `actionResolve` is a no-op when Destination is a literal;
shadow evaluation rejects domain destinations and skips only admitted resolves.
The actual compiled rule pointer/index and concrete outbound leaf checks remain.

## Source authority

Inspected the existing local CCS archive (no download/SSH), extracted only the
pinned sing-box v1.14.3 ZIP members and recomputed Go Hash1 against this candidate's
`go.sum`: `h1:cBg8TP5SPWoMAlWqTqbSNdHGKPUciZisjQbLtqFlMZA=`.
Evidence is under `/workspace/anytls-address-family-auto-evidence/ruleset-integration-r1/sdk/`.

- `route/rule/rule_set_local.go` SHA256 `fd57200b9ba3146d421c71f079373f8471710f351f69f5e9de77ad31feb83674`: inline constructor reloads rules once; only non-inline path creates watcher; Match reads compiled headless objects.
- `route/rule/rule_item_rule_set.go` SHA256 `251f22c821462043e1782f775ca283a674430cdd95ed07f1fe36438e1e684b65`: references bind in Rule.Start; matching preserves outer match cache and nested group semantics.
- `route/route.go` SHA256 `0ceebe2b5ef5985fd8fcac3c59c8d6b3bd3bbcdbfd2c24404a7756f494c6485a`: actionResolve lines 897–923 has all effects inside Destination.IsDomain().

## Checks

Prepared Go coverage: real compiler GEOIP with/without no-resolve and RULE-SET
route/reject, exact legacy JSON equality, fixed source identity/order, deletion of
original source after compile, SHA-drift recompile failure; actual compiled SDK
rules (Rule.Start only, no Box.Start/network) for same v6/v4 rule pointer and named
ruleset REJECT; metadata/domain guard and reauthenticated unsupported policy
mutations. Snapshot ownership/runtime drift and changed inline type are covered.

Native integration evidence is retained under
`/workspace/anytls-address-family-auto-evidence/integrated-r3/`. The development
fixture's original long subtest name exceeded the Darwin temporary-path fixture
contract; the test now uses short indexed names without changing policy assertions.

A real SDK return-seam regression demonstrated same-tag unregistered DNS transport
cache laundering. The authenticated browser DNS patch now disables cache and
optimistic-cache access for caller-provided transports whose exact identity is not
the registered transport. Normal strict HTTPS sync/async initial returns and cache
hits retain receipts before delivery. Untrusted same-tag/type stubs, failed returns,
forged observation calls and cross-client/inbound scopes cannot mint authority.
The ACK patch is unchanged.

Controlled protocol tests retain actual compiler GEOIP/RULE-SET rules and prefix,
then substitute only mixed inbound and private TLS endpoints, rebind the manifest
and exact captured source, delete the original ruleset file, and use the actual
embedded dispatcher with recording disabled. Candidate rejection and distinct rule
identity despite the same Q outbound forbid alternate launch. Certificate/auth/ACK
unknown failures must not refresh DNS. Healthy IPv6 resumes without extra DNS.
This remains unprivileged synthetic protocol coverage, not production TUN/browser
acceptance; EDNS and unsupported policy families remain UNKNOWN. Final full/race/
vet/build/package outcomes belong to the exact frozen-commit evidence, not this
source document. No release, installation, helper or formal VPN changes are made.

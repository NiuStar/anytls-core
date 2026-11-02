# Frozen local datasets: candidate contract (native NOT_RUN)

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

Observed: `git diff --check`; existing offline browser SDK patch/material tests
(2 PASS). No SDK patch was changed.

**Go format/build/test/vet/race and all native/protocol execution: NOT_RUN**, per
ownership/scope. No red/green claim. This is a source candidate for the parent's
sole Go/native owner, not release acceptance or all-config support.

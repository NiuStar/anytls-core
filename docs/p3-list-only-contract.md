# P3 list-only contract (test-first checkpoint)

This checkpoint adds tests only; no implementation, deployment, build or service action is included. Parent must run the new native tests against this exact pre-implementation source before authorizing the implementation continuation.

## HTTP contract

- `GET /api/v1/rules` preserves its exact existing public projection (`rules`, `etag`, `targets`, `rule_sets`, `editable`, `edit_error`) and complete option validation.
- `GET /api/v1/rules?view=list` is the only new query form. It returns `rules`, `etag`, `editable`, `edit_error`, `view:"list"`, `options_loaded:false`. `targets` and `rule_sets` are **absent**, not empty arrays.
- Parse query strictly: a single `view=list` only. Unknown keys/values, empty `view`, duplicate `view`, malformed escaping and semicolon query syntax return HTTP 400 `INVALID_INPUT` without ETag. Previously undocumented extra query keys are deliberately rejected, not treated as legacy full mode. A URL with an empty query remains equivalent to no parameters.
- List mode shares one captured config byte snapshot and the existing layout check (including its second YAML parse). ETag, raw rule order/duplicates and editability must be identical to full mode for those bytes.
- List mode must not call node-option construction or external rule-set loading/native SDK checks. Default full GET and all mutation validation retain their old behavior; no global test hooks, caching, parser rewrite or save-chain changes.

## Frontend contract

- `loadRules(false)` requests `/rules?view=list`; `loadRules(true)` requests legacy `/rules` and requires complete option arrays.
- A list snapshot is delete-capable, not add-capable. Disabled controls **and** synthetic form submission must reject an add until full options are captured. Full-mode ETag owns add submissions; list-mode ETag owns the displayed raw/index delete action.
- Retain request/session/config invalidation, busy/operation ownership, stale row protection, full raw index mapping and all original mutation API bodies. Late list responses cannot replace a newer form; late full responses cannot reopen a form after a newer list read.
- `CONFIG_WRITE_FAILED` and `CONFIG_READBACK_FAILED` map to separate Chinese warnings. State that current disk/save status needs confirmation, ask the user to re-read and verify, and state that there is no automatic retry. Do not claim that the original file definitely remained unchanged or was not saved.

## Test commands and evidence boundaries

Native (parent-owned, approved toolchain/tags):

```sh
go test <approved-tags> -run '^TestWebRulesListOnly' -count=1 -v .
```

Also rerun the existing `TestWebSingleRule*` tests (especially native rule-set and exact public projection tests) and deletion regressions after implementation.

Frontend, no installation required:

```sh
/home/hermeswebui/.hermes/node/bin/node --test web_rules_list_only_test.mjs
# Optional immutable exported baseline; both app.js and index.html derive from WEB_ROOT:
WEB_ROOT=/absolute/export/web_assets /home/hermeswebui/.hermes/node/bin/node --test web_rules_list_only_test.mjs
```

The VM executes actual app.js with only the automatic session bootstrap excluded. DOM and HTTP are synthetic and are not a real browser, authenticated network HTTP or native persistence acceptance. The external-file deletion test proves functional independence only: default GET excludes a now-missing set while list output stays constant. It does **not** count reads/SDK constructors or prove zero I/O, because full GET also tolerates missing sets. Parent must retain a separate real workload witness before claiming reduced work/performance; source branch review alone is not an I/O count. Do not introduce production globals solely to count tests. Original delete layout/parser work remains unchanged and unoptimized in this contract.

# P3 list-only contract

The parent obtained the native business RED on the pre-implementation source before this authorized implementation. This candidate implements the contract below; it does not deploy, build or operate any service. Native GREEN and real-browser acceptance remain parent-owned and NOT_RUN by this child.

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

The VM executes actual app.js with only the automatic session bootstrap excluded. DOM and HTTP are synthetic and are not a real browser, authenticated network HTTP or native persistence acceptance. The external-file deletion test proves functional independence only: default GET excludes a now-missing set while list output stays constant. It does **not** count reads/SDK constructors or prove zero I/O, because full GET also tolerates missing sets.

`getRules` now passes a request-local `supplyOptions` closure to `webRulesProjection`. Every external-set read/native check and node-target construction remains inside that closure; list mode returns before invoking it. `TestWebRulesListOnlyOptionWork` counts this real projection collaborator (list zero, full once, malformed config zero) without production global hooks. This added test is test-after and NOT_RUN here; it is not a direct filesystem/SDK constructor counter or a measured speedup. Existing full-GET native tests still own the real semantic-validation regression. Parent must run the count test and retain a separate real workload/timing witness before claiming measured reduced work/performance. Original delete layout/parser work remains unchanged and unoptimized.

## Implementation checkpoint

- Frontend VM: observed pre-implementation RED (4 pass / 5 business failures), then candidate GREEN (9 pass / 0 fail); Node syntax and `git diff --check` pass. The additional actual delete/raw-index/ETag and list-only save-refresh assertions in the first case are test-after regressions.
- No Go tools, native execution, SSH, network calls, browser, build, publication or restart were run by this child. Parent runs the native list suite plus existing full projection/SDK rule-set/add/delete regressions and browser gates against the committed candidate.
- Full and list snapshots reuse the original raw ETag and layout work. Default GET has no new mode fields; full-option validation, mutation code and save chain remain unchanged.

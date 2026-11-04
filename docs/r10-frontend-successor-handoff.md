# R10 frontend successor handoff

## Completed

- Followed `r10-backend-r2-handoff.md`: product detail requires nonempty opaque `switch_version`, passes it unchanged as switch JSON `snapshot_version`, retains original YAML `If-Match`. Missing token fails closed; refresh/clear invalidates it. Existing backup/apply/error/owner chain retained. Synthetic tests cover cancellation, original token, unchanged YAML with snapshot conflict/no retry, and missing-token no legacy fallback.
- Added `/subscriptions/apply` to existing app.js startupMutation list. Existing `IMPORT_COMMIT` enum remains unchanged. Browser asserts startup reference associated while subscription view does not admit hidden trace reads; migrated startup suite exercises full IMPORT_COMMIT trace roundtrip for apply.
- Synthetic browser fontconfig now uses `FONTCONFIG_FILE` override or existing `/workspace/anytls-r10-product-evidence-r2/fonts.conf`. Shared old config untouched. Each product screenshot awaits fonts.ready and records CDP CSS.getPlatformFontsForNode: positive `Noto Sans CJK SC` glyphs, not fonts.check inference.
- Migrated legacy runtime fixture to debug/versions, debug/operations, debug/dns and settings/update; startup fixture enters debug/operations. Added product asset inventory / snapshot DTO, retained clipboard/redaction/old401/ownership/visibility/polling assertions. Saved test-only diff with evidence. No assertions removed.
- Migration exposed a real notice regression: product capture handler hijacked runtime-check into updateOperation, replacing APPLIED notice with 503. Removed that override so runtime.js remains sole runtime-check owner; original real-button notice-preservation assertion now passes. This is a product fix, not a weakened test.

## Verified evidence

All below are synthetic browser/VM evidence, not actual Go handler/native VPN acceptance.

Root `/workspace/anytls-r10-product-evidence-r2/frontend/`:

- `successor-final-r5/results.json`: PASS **248 checks**, **53 screenshots**, **53 positive CJK platform-font readbacks**, 1440 / 390 widths, zero pageerrors. Includes all prior traffic regressions. Screenshots, report downloads and SHA256 manifest in same new directory; no baseline/final historical evidence overwritten.
- `successor-final-r5/node-regression.log`: PASS **77/77** original five Node suites.
- `legacy-runtime-route-final-r3/results.json` + `run.log`: PASS 1280 / 390, original redaction, clipboard, old401/finally owner, visibility and real-button saved-notice assertions.
- `legacy-startup-route-r1/results.json` + `run.log`: PASS 1280 / 390, 15 parser negative cases per width, 1024 retention, 9 save-source cases including subscription apply; original clipboard/old401/oldPOST/poll/hidden/terminal assertions retained. Optional ST1_MAX_READ not configured (reported null, not claimed).
- `successor-final-r5/legacy-tests-only.diff`: isolated legacy test migration diff.
- Node syntax checks for all five owned JS/MJS files and owned-path git diff --check passed.
- Preserved preexisting historical runtime/startup failure logs and new `legacy-runtime-route-r1/run.log` which captured the actual runtime-check notice regression before correction.

## Ownership / remaining

Modified only `web_assets/app.js`, `web_assets/product.js`, `web_r10_product_browser_test.mjs`, `web_runtime_status_browser_test.mjs`, `web_startup_browser_test.mjs`, and this handoff document. Traffic rendering not overwritten. No Go, actual HTTP test, SSH, production, commit, or shared fontconfig changes.

Parent retains final pixel review and actual Go HTTP/backend integration verification. Backend schema handoff exists and snapshot_version Go DTO was observed in progress; this worker did not execute Go tests.

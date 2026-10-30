# WebUI static transfer: native implementation evidence

Implementation/test source: `329e4bc5b40134a7d938b7ba52f384b43e2ebd85` (385 tracked files). Frozen product baseline: `f683892b04b3e8a61813f59c0a10ad16f87864d4`. Planning commit: `1e47c5805347f071e1cbf4ae6db6c5f3f8f54f03` (380 tracked files). This report is documentation added after the measured source; no release, deployment, installation, production restart or VPN/helper operation was performed.

## Implementation

`web_static.go` retains only the four fixed public embedded assets, with identity and standard-library default-level gzip representations. A process-global `sync.Once` publishes the map only after every read, gzip Write and Close succeeds; failures are sticky and never expose a partial map. Requests only read the published map/slices. No request-keyed/unbounded cache, disk cache, API compression, dependency or embedded payload change.

Host, method and existing Origin gates remain before static dispatch. The API authentication/CSRF path is unchanged. Fixed GET allowlist and HEAD=405 remain. Static responses preserve security headers, no-store and MIME; add Vary: Accept-Encoding and exact representation Content-Length. Both representations refused produces uncompressed JSON 406. API/login/errors stay uncompressed.

Negotiation reads every header field, handles case-insensitive coding/q names, exact HTTP qvalue grammar (0..1, at most three decimals), explicit refusal overriding wildcard, and conservative minimum quality for duplicated codings. Invalid explicit entries count as q=0. Implicit identity has q=1 unless explicitly excluded or wildcard q=0; higher q wins, gzip wins ties. Absent/empty Accept-Encoding selects identity.

## Native gates executed

All Go compilation/tests used the unchanged official `scripts/go-patched.py` (SHA256 `835bd0bd7d742b5895edab2d1a93924e6c74cadff0aff60ab1b607f2ee46a41b`), Go 1.27.3 darwin/arm64, CGO=0, GOMAXPROCS=2 and canonical tags `with_gvisor,with_utls,with_upstream_cleanup_patch,embedded_core`, GOPROXY/GOSUMDB=off. Native ordinary UID=501, isolated root `/Users/lihaiyan/.ais2/wst01`. The trusted read-only production collector was reused byte-for-byte, SHA256 `f57dd1081a64cc98af024f6385159171f1ac089387b1c95f5cf9930969b97ca5`.

- Test-first gzip slice: test commit `4e507b1`, exact baseline source plus identical new HTTP-test bytes: compiled business RED (`red02-red`, rc=1; missing gzip Content-Encoding and transfer headers), then `c5e678f` GREEN. The test file SHA remains `883f706c104cc12a4aaeb5f6bda577f6891646aaa345a808ce3767cdb992e2b1` in candidate.
- Test-first negotiation slice: test commit `bcbb6ed` failed 15 negotiation subcases against the first implementation; `83a8bae` passed the same test bytes (SHA256 `f7820c8b8f1b4ea0d247a836e7c97a9019f86c05e003ee853d5a91461cb97c0f`). The archived attempt is named `negred-green` because the runner used its green command to observe the expected RED; its actual status is FAIL, not relabeled PASS.
- Final focused static gate: 6 top-level tests and 56 subtests PASS. Includes all four decompressed bytes/SHA, real loopback HTTP framing with automatic client decompression disabled, independent concurrent once-store reads (32 callers x 10 loads), sticky initialization failure, and security/API negative gates. The latter mechanism/wire checks were added after implementation, not claimed as test-first.
- Affected existing/new `^TestWeb` gate: 169 top-level PASS, 1 existing SKIP, 784 subtests PASS, no failures.
- Both benchmark binaries built by unchanged wrapper `test -c` to the private app directory outside source; output SHA checked against END receipts. Baseline binary SHA256 `f5b37277bfc646a30aac538cf607404e20085bed74c6d952f71797aa3911d9ef`, candidate `4c3dbd90e69169e9caf8be03fc09e2eaf74b1733d907888730d8cb39a3107705`. These are test binaries, not product/release size measurements.
- Per-run complete tracked manifests and source/production snapshots remained unchanged. Toolchain/module inventories were protected (only the exact current-commit .info addition is allowed by the reused closure helper; paired measurements had exact equality). Build cache is mutable and is not claimed unchanged.

One initial runner setup failed before Go execution due to a missing `hashlib` namespace import in a reused scoped helper; original report/input snapshots are retained as `red01-red`. It is not business RED. Local Git author config was absent; commits used explicit per-command identity matching the preceding commit, without global config changes.

## Actual wire representation sizes

| Asset | Identity B | Go default gzip B |
|---|---:|---:|
| index.html | 26,161 | 9,109 |
| app.js | 97,045 | 31,266 |
| startup.js | 20,220 | 7,388 |
| style.css | 26,237 | 6,630 |
| Total | 169,663 | 54,393 |

Four-asset gzip response bodies shrink 67.94%. This supersedes the planning-only Python gzip estimate (different compressor/default). Complete embedded payload bytes/SHA are preserved, including warnings/functional content; no minification or feature removal.

## Paired hot-handler benchmarks

Five fresh-process **baseline → candidate** pairs, alternating for ten processes total; each process measures four assets x identity/gzip at exactly 10,000 calls per case. Identical benchmark test bytes on both trees: SHA256 `4526fd08cb71a141480db75ce7af3d7e93a79a5e885c2914658099aa922a3a8d`. Eight cases x ten processes = 80 validated raw samples. Median below, no synthetic output.

Measurement boundary: direct real ServeHTTP calls with a reused immutable request and a discard ResponseWriter that retains headers/status/body byte count (no recorder body allocation in the loop). Actual handler output/body SHA and optional gzip decompression are validated before each timed segment. These numbers are handler CPU/allocation microbenchmarks, **not network throughput, browser load latency or startup speedup**. The old implementation ignores Accept-Encoding:gzip and returns identity; its gzip-request row is explicitly an identity-response baseline, not a passing old gzip contract.

| Case | Old ns/op | New ns/op | Old B/op | New B/op | Old allocs/op | New allocs/op |
|---|---:|---:|---:|---:|---:|---:|
| index identity | 3,048 | 452.8 | 27,453 | 202 | 11 | 12 |
| app identity | 8,857 | 456.9 | 98,493 | 202 | 11 | 12 |
| startup identity | 2,782 | 477.9 | 20,669 | 202 | 11 | 12 |
| style identity | 3,047 | 453.4 | 27,453 | 202 | 11 | 12 |
| index gzip request | 2,932 | 481.1 | 27,453 | 224 | 11 | 13 |
| app gzip request | 8,777 | 487.0 | 98,493 | 218 | 11 | 13 |
| startup gzip request | 2,381 | 490.4 | 20,669 | 224 | 11 | 13 |
| style gzip request | 2,918 | 508.4 | 27,453 | 224 | 11 | 13 |

The payload-sized per-request copy is eliminated. Allocation **count increases** by one identity/two gzip (extra representation headers/length), despite much lower allocated bytes. Do not claim allocation-free or all-metric improvement.

## One-time cost and limits

An independent local store instrumented through an fs.ReadFileFS wrapper saw exactly four embedded reads across all concurrent loads and stable identity/gzip backing addresses. Retained logical bytes: identity 169,663 + gzip 54,393; total backing-slice capacities 238,848 B, excluding map/string/header overhead. This is not measured RSS or an exact retained heap profile.

Cold **representation construction**, measured separately for five repetitions x 100 fresh stores: median 2,102,941 ns/op, 4,608,804 allocated B/op, 106 allocs/op. This is one-off lazy first-static-request work, not OS-page-cache cold, binary startup or retained memory. Compressor construction transient allocations are larger than retained payloads; no sync.Pool/new tuning was added to hide the cost.

Remaining parent gates: independent review, browser acceptance, clean final whole-repository Mac test/vet/product build. No race-detector gate was executed (concurrent functional test passed); no TUN/native GUI, production transfer, WAN throughput, RSS, release/packaging or deployment claims.

## Evidence locations

Local: `/workspace/anytls-webui-transfer-evidence/` (`red02-red`, `green01-green`, `negred-green`, `green02-green`, `candidate-green`, `candidate-web`, `baseline-compile`, `candidate-compile`, `paired`, `benchmark-summary.json`, `readback-validation.json`). Native originals under `/Users/lihaiyan/.ais2/wst01/evidence/`; binary/source roots remain private. Raw command logs were read back and independently rehashed against their receipts; enumerated sample/test counts were parsed programmatically.

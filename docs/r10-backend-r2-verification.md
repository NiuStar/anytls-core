# Backend R2 repair verification

Backend repair STOP-WRITE; parent owns combined freeze/full/vet/build/native/browser acceptance. Frozen original review is unchanged at /workspace/anytls-r10-product-review/backend-r2/review.md (SHA256 ebe586cf87ee7bf1e3494b40cb9c80152ecb4becfc8f6d7a9e8018ce081ad804).

## Implemented

- Detail switch_version / POST snapshot_version binds stable active ID plus exact existence+bytes of config, selected and subscription. New product must use it; independent quoted If-Match token also works. Legacy YAML-only callers remain compatible and are not full-snapshot protected. Explicit empty/incorrect snapshot_version cannot fall back to valid YAML If-Match.
- Manual check/preview completion validates live original cookie session, CSRF, expiry and password digest while holding actionMu; authMu and password-rotation mutex fence writes against logout/reset. All success/failure metadata writes and secret preview publication are behind this gate. Worker uses separate service-owned context authority; logout and password rotation do not stop scheduled checks.
- Marker publication readback failure restores and verifies all four targets, including originally absent active-profile. Unsafe marker replacement yields PROFILE_STATE_UNCERTAIN rather than false rollback success. Per-console post-rename seam creates actual filesystem private-mode/symlink faults in real ServeHTTP regression.
- subscriptions/apply is a startup mutation using existing IMPORT_COMMIT enum. Active changed receipt traverses real private Unix IPC fixture; stopped/noop/inactive and stale target/candidate/conversion/selection errors return explicit startup_operation:null without replacing previous operation or invoking service action. Inactive apply does not activate.

## Execution

Exact invocation: `python3 scripts/go-patched.py --go /home/hermeswebui/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.27.3.linux-amd64/bin/go test -p 1 -tags with_gvisor,with_utls,with_upstream_cleanup_patch,embedded_core -run 'TestR10|TestWebProfiles|TestWebStartup' -count=1 -v .`
Environment retained GOTOOLCHAIN=local GOWORK=off GOPROXY=off GOSUMDB=off GOMAXPROCS=2; no caches deleted.

Final /workspace/anytls-r10-product-review/backend-r2/router-final2.log: 43 top-level PASS + 248 subtest PASS, rc=0, PATCHED_GO_END ephemeral_cleanup=ok, root_inputs_unchanged=true. Six added R2 top-level regressions. This is targeted real root-package execution, not the whole repository/full native acceptance.

RED evidence: router-red-wrapper.log demonstrates revoked manual commits and missing startup envelope against pre-repair code. Initial raw go invocation failed compilation because it bypassed required patch wrapper; retained router-red.log is NOT behavioral RED. router-green1.log exposed an invalid test route (subscription PUT 405), corrected to real subscriptions/unlink stimulus in final test. router-green2.log caught inactive apply missing explicit null and was repaired.

Sensitivity: mutation-final-red.log uses identical final tests on isolated marker-mutation-tree, changing only complete snapshot token to YAML-only and rollback to three targets. It rejects selection-only, subscription-only and identical-YAML active-ID stale switches plus all three marker failure cases. Wrapper rc=1 and cleanup=ok are the expected negative result. mutation-inputs.json pins exact candidate/mutation bytes. Earlier failed overlay attempt is retained: wrapper correctly disallows caller overlays. No wrapper policy was bypassed or changed.

## Final source pins

repair-manifest.json in evidence directory is authoritative exact file SHA map:
- web_profiles.go 7e107764a30dd84af9d97937255234bb830927f5b795a6368ede824df64c662d
- web_subscriptions.go 7e7de43d46b9dff0f874fe5c8d9758a5be1f91d1b38bfb35debdfa5722e54e3d
- web_startup.go e68d40d1099b54bc3cb7860c0ea952fcac6f9d3a7d84dd919a510d69e0e84e51
- webui.go 43a0667c2c200b843adc29a414dee84d613812668f44a0c734cfbfc04ec3e076 (includes concurrent parent metrics/traffic changes; preserved STOP_TIMEOUT)
- web_r10_backend_r2_test.go 8107701c27f81f9e9f8a0adde5330bd09b6fab8d263c0eff96133e38a94ebda7
- docs/r10-backend-contract.md b9124e132f235f528b2397ab80caf0e450f4ef1e88ae3e6f971e09961b48198d

## Remaining gates / explicit limits

Parent must freeze combined frontend/backend inputs and run full root suite, vet, build, native and unified real HTTP browser. No production/SSH/commit/service actions performed. Existing webAtomicWrite file fsync without parent-directory fsync is unchanged: power-loss/crash durability is NOT established. Transaction readback/rollback tests establish live-process behavior only; hostile same-UID ancestor replacement remains excluded by existing storage contract. Auth mutex holds over final bounded local file writes/response, not network fetch/conversion.

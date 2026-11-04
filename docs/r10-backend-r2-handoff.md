# Backend R2 implementation handoff (in progress)

Frontend switch contract: GET /api/v1/profiles?detail=1 adds `switch_version` (opaque `switch-v1-<hex>` string). New product MUST submit JSON `snapshot_version: detail.switch_version` on POST /api/v1/profiles/switch; may retain legacy YAML If-Match header but snapshot_version takes precedence and never falls back on mismatch. Alternatively If-Match: "switch-v1-<hex>" is accepted. Keep config etag separate. Existing YAML-only If-Match callers remain compatible but are legacy, not full-snapshot protected. Token binds active ID plus existence and exact bytes of config/selection/subscription under actionMu.

Parent/UI: add /api/v1/subscriptions/apply to app.js startupMutation. Backend uses existing IMPORT_COMMIT source enum for subscription apply (whole imported snapshot application); no schema enum addition.

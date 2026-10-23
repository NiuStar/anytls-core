# Connection Records disk v1 — minimal implementation contract

Status: **SPECIFICATION ONLY; implementation and native acceptance NOT_RUN.**
Only this contract and its approval artifacts are revised. No build, SSH,
helper installation/update, production change, VPN stop/start/reload, or SDK
modification is authorized here. Parent SPEC review, then independent QUALITY
review of this document's exact SHA, must precede implementation.

## 1. Decision, evidence, and non-goals

Current source inspection baseline: tracked application commit
`42db62a9bc9b9ff95ef6a2b5a9f2c84884c846ca`. The earlier feasibility report,
`artifacts/baidu-routing-diagnostics-v1/connection-record-feasibility.md`, was
written at `50ede36d45eb36a71ba061cd3f6812754a18b04b`. It authenticates sing-box
**v1.14.3** against root go.sum:
`h1:cBg8TP5SPWoMAlWqTqbSNdHGKPUciZisjQbLtqFlMZA=`
(ZIP SHA256 `4e4ae6c67870391933df3e1108eb27559cce890da492490b76361bc85bbed003`).
SDK references below use that report's authenticated `SDK/` directory.

User consent `同意，请继续` approves the preceding proposal: **private local
files, asynchronous append, authenticated WebUI paging; no history-count quota,
no automatic deletion; no passwords, bodies or full URLs; recording failure
stops recording with a visible gap while VPN forwarding continues**. Consent
changes the former no-disk privacy agreement, not the route-only coverage or
production authorization boundaries. Exact proposal, consent provenance and
source digests are bound in `artifacts/connection-records-disk-v1/approval.json`.

The exact former 577-line memory contract is preserved as
`artifacts/connection-records-disk-v1/frozen-memory-spec.md`, SHA256
`a8b799ba4d5f0680db3adc857085dc1bdf376fcb3282ef9d5a815a0648225d52`.
The old `native-pressure-proof/report.json` remains **NOTPASS**, unchanged.
Its ENOTSUP and unproven real-pressure delivery are historical evidence, not
new acceptance prerequisites. Disk v1 requires no mmap, native memory-pressure
listener, libdispatch/CGO bridge or new native allocator. Do not rebuild or
rerun that probe to implement this contract.

Existing isolated Baidu diagnostics establish business DIRECT routes and a
separate DNS proxy dial, not formal TUN traffic or the cause of slowness.
Historical installed versions/PIDs and unreadable root snapshots are not proof
of this feature or its compiled generation. Do not touch that service here.

Deliver an authenticated table answering observed destination, top-level source
rule/set or MATCH/default, DIRECT or selected group chain and actual compiled
node/outbound **in the originating Run**. This is routing history, not a full
connection audit, connectivity test, DNS tracer, traffic meter or diagnosis.
Mandatory persistent banner, including an empty result:

> Only normal tracker-visible TCP/UDP/flow route observations are shown.
> ROUTED does not mean connected or successful. REJECT, DNS hijack/internal DNS,
> and failures before the tracker are unobserved. This is NOT a full audit.
> No records does NOT mean no traffic. DNS status: UNKNOWN.
> Destination history is stored privately on this Mac across VPN/console restarts;
> there is no automatic deletion. Gaps and unavailable recording are shown.

## 2. Fixed SDK integration: route-only, no wrappers

Use these public APIs (SDK/adapter/router.go:18–30,108–112;
SDK/box.go:664–666):

```go
instance.Router().Rules() []adapter.Rule
instance.Router().AppendTracker(adapter.ConnectionTracker)
// ConnectionTracker methods:
RoutedConnection(context.Context, net.Conn, adapter.InboundContext,
    adapter.Rule, adapter.Outbound) net.Conn
RoutedPacketConnection(context.Context, N.PacketConn, adapter.InboundContext,
    adapter.Rule, adapter.Outbound) N.PacketConn
RoutedFlow(context.Context, adapter.InboundContext,
    adapter.Rule, adapter.Outbound) tun.FlowTracker
```

These are signature references, not additional declarations. N is the SDK's
sing common/network alias; tun is its sing-tun alias. Install one tracker after
box.New and binding validation, **before Start**; AppendTracker is not concurrent
registration. Add optional typed telemetry input to internal/engine Run with a
delegating entry preserving existing callers. Check remains construct/Close-only:
no store creation, file append, running collector registration or listener.

Append one ROUTED observation per callback; return the **exact original** TCP/
packet object and **nil** from RoutedFlow. SDK/route/route.go:526–540 ignores nil
flow trackers. No Close/Read/Write wrappers, byte counters, optional-interface
emulation or active registry. `active,duration,ended_at,connected,error` are
UNKNOWN/null, never false/zero. IDs identify observations, not unique sockets;
never deduplicate TCP/UDP/flow by destination.

Normal TCP/UDP trackers run after matching but before dialing
(SDK/route/route.go:108–176,243–311); flow runs through NewTracker in preMatchFlow,
not every pre-match call (:451–540). REJECT, hijack and early errors bypass them.
A refused dial can still be ROUTED. There is no public full onClose/error chain.
No SDK patch, Rule.String()/log parsing, PlatformLogWriter, Clash API or SDK
trafficcontrol registration. Keep internal/engine/options.go logging disabled.

DNS remains a separate `{status:UNKNOWN,evidence:null}` panel. Do not infer DNS
success/route from ports, detour configuration, caches or business rows. Any
tracker-visible DNS-related transport is an unclassified route observation,
not DNS-transaction evidence. Typed DNS support needs a separate review.

## 3. Compiler provenance with unchanged runtime JSON

Current anchors: runtime_config.go prepareRuntime; routing.go applyRoutingBytes;
groups.go resolveGroup; service_lifecycle.go serviceConfigBytes.compile;
engine_dispatch_embedded.go dispatchEngine; internal/engine/engine.go Run.

Produce an **in-memory parallel result**, not new SDK JSON fields or a second
compiler. Existing APIs may delegate and discard provenance. Use the same
captured private config/selection/rule-set/CA inputs that produce the actual
Box runtime bytes. Extend the existing group resolver to return its exact
selected path without changing validation or behavior. Do not reread current
YAML on callbacks or reconstruct old history from today's config. Pass immutable
manifest and runtime bytes together. No persistent raw manifest/config sidecar:
only safe record projections and the identity/digest header below are stored.

Manifest contains:

- Version; random 128-bit lowercase hex `instance_id` and `generation`, both new
  for every compiled Run, even identical configuration. `selection_generation`
  equals generation. IDs are not authentication secrets.
- SHA256 of actual runtime JSON and captured staged config/selection (ABSENT
  distinct from empty), referenced rule-set/CA content, and canonical manifest
  digest (`manifest_id`). Paths/content remain private; HTTP exposes only opaque
  identities/digests, never root paths or runtime/config bytes.
- Every emitted SDK rule slot in final order, including synthetic sniff/resolve/
  hijack: expected rule Type/action Type/tag, synthetic kind, source ordinal
  (zero-based; UI +1), ID `generation:rule:ordinal`, typed safe condition,
  configured target, ordered `{group,selected}` edges, terminal node ID/tag.
  Duplicate rules keep distinct IDs; node ID is generation-scoped source ordinal,
  not credentials or a globally unique label.
- Separate `final_origin` for source MATCH. No source rules means
  `DEFAULT_SELECTED` with actual selected terminal, not a fabricated MATCH.
  RULE-SET identifies the top-level source/set label/digest only, never an
  unobservable matching member.

After box.New validate Rules() count/order and public Type()/Action().Type()
against final emitted slots. For route actions require the exported concrete
`*rule.RuleActionRoute.Outbound` (SDK/route/rule/rule_action.go:190–197), not
String(). Validate actual outbound registry tags/types/final. Current default
rule objects are pointers (SDK/route/rule/rule_default.go:46–55); validate their
pointer type/comparability before identity lookup, reject rather than panic.
Bind actual object identity only for its originating Box. Never re-run Match(),
map source ordinal directly to SDK slot, or reverse shared tags into groups.

Each callback cross-checks rule identity and actual outbound Tag()/Type(). nil
rule binds only verified final_origin and actual default outbound. VERIFIED
requires all relevant checks. Mismatch fails closed **for attribution only**:
keep destination and actual callback tag/type, set `provenance_status=MISMATCH`,
and make source/group/node claims UNKNOWN/null. Initial binding failure makes
the generation's attribution UNKNOWN, not its traffic failed. Never infer a
DIRECT node from an unknown tag or repair evidence with disk YAML.

## 4. Record, queue, and failure contract

Schema version 1 record, explicit nullable fields:

- `instance_id,generation,manifest_id,seq,observation_id,observed_at`.
  seq is committed append order starting at 1 per Run; observation_id is an
  atomic callback ticket, not socket ID. Both are canonical decimal uint64
  strings for JavaScript precision. observed_at is UTC receipt time, not socket
  creation time; concurrent callback times may be out of order.
- `event=ROUTED,hook=tcp|udp|flow,network=tcp|udp|UNKNOWN`.
- `destination={host,ip,port,host_source}`: valid Destination.Fqdn first, otherwise
  metadata.Domain (`METADATA_DOMAIN`). IP only from valid Destination.Addr.
  Domain source does not prove SNI versus DNS origin. Nullable separate typed
  `origin_destination` and `route_original_destination` preserve their own
  metadata fields. Actual dial-peer IP is UNKNOWN; no DestinationAddresses.
- `route={evidence,source_id,source_index,kind,condition,rule_set,
  configured_target,group_path,terminal_kind,final_node_id,final_node_label,
  outbound_tag,outbound_type,selection_generation}`. Terminal kind
  DIRECT|NODE|UNKNOWN; attribution null on mismatch except actual tag/type.
  condition only typed DOMAIN/DOMAIN-SUFFIX/IP-CIDR scalar or RULE-SET label;
  never raw YAML/rule text. MATCH/default condition is null.
- `state=ROUTED,connected=null,active=null,duration=null,ended_at=null,error=null`.

Callback: small typed projection/string references, fixed atomics, one
nonblocking select into a preallocated **256-slot channel**. No I/O, wait on
reader/writer locks, full-string copying/serialization, history allocation or
per-event goroutine. Do not queue the metadata/context/connection/SDK objects.
One worker owns bounded encoding buffers and disk appends. Queue capacity is
backpressure protection, **not** a history retention limit. Memory is bounded
by queue, current compiler manifest, fixed status and bounded pages/worker
buffers, not lifetime observation count. The compiler manifest may scale with
the already accepted configuration; do not turn it into a lifetime index.

Queue full/busy drops explicitly. Record >256 KiB encoded is rejected whole,
without truncation. Use streaming encoding with a bounded writer/buffer, not
unbounded Marshal then checking size. No effect on VPN compilation/forwarding.
Unexpected worker/encoding failure stops collection; disk open/write/short
write/Sync/rename/permission/I/O failure latches `collection=IO_FAILED`.
Collection values are RECORDING|CLOSING|CLOSED|IO_FAILED|INIT_FAILED|
WORKER_FAILED|ID_EXHAUSTED; helper may project UNKNOWN for stale/unreadable status.
Failures remain latched; in-process normal shutdown returns CLOSED with verified
cleanup only without recording/cleanup failure. Persisted CLOSED may precede a
final directory Sync or lock Close failure: it is only the last saved stopped-
recording observation, never a completion certificate. **No retry/resume within this Run**, eviction,
automatic deletion, fallback to growing memory, or VPN restart. A separately
requested later Run may initialize a fresh history; it never rewrites old files.

All rejected/discarded observations increase fixed `lost_total` and reason
counters when known. `gap=true` is permanent once any loss/uncertainty occurs;
`loss_epoch` changes on loss. Counters saturate with `counter_saturated=true`;
seq/observation_id **stop before wrap**, latch ID_EXHAUSTED/gap and never reuse
IDs. Missing seq ranges are UNKNOWN because seq counts commits, not attempts.
`pending` is queued/uncommitted observations; empty poll is not inactivity.
Unknown crash remainder/counters stay UNKNOWN, not invented zeros.

Status is separate from data so a full queue need not append a gap row. Publish
failure status best effort, with no raw errors/paths. A completely unwritable
store cannot promise to persist its own error: stop refreshing the status;
helper reports UNKNOWN + visible GAP after **5 seconds without a fresh active
status** (including negative/future clock age), never keeps an old RECORDING
badge. Publish active status at least once per second, even without rows.
This is bounded failure visibility, not immediate cross-process notification or
proof of a live VPN. HTTP/helper failure is immediately shown as unavailable.

## 5. Minimal private file store and ownership

**Chosen route: root VPN writes private files; existing root helper pages those
files for the registered ordinary UID.** No VPN telemetry socket, launch ticket,
nonce/attach protocol, native allocation or new database is needed. Protected
file ownership and immutable Run headers provide the read boundary; page status
is recorded history, not runtime liveness/readiness authority. Reusing helper
transport avoids the old two-hop socket ownership/recovery framework while not
giving an ordinary WebUI direct root file access.

Fixed base is
`/Library/PrivilegedHelperTools/com.nousresearch.anytls-control/records/`.
Helper root ancestors must be real root-owned directories, no symlink or group/
world write. records, each registration namespace and each Run directory are
root-owned **0700**; every file is root-owned **0600**, regular, one hard link.
Reject unsafe components/type/mode/owner; do not repair/chown an existing unsafe
path. Open files no-follow/nonblocking before fstat to reject FIFO/device races;
check same handle and captured inode/size as appropriate. Do not claim resistance
to root compromise. Existing user-writable service staging/path digests are not
upgraded to root authenticity by this feature.

Namespace is SHA256 of canonical `{schema_version:1,uid,config_identity}` using
the existing root-private registration; config_identity remains canonical-path
identity, **not loaded configuration contents**. No HTTP/IPC path, UID, filename,
namespace or offset selects a root file. Helper derives namespace from its
registration; WebUI verifies returned config_identity against its local existing
configuration identity. Rebinding/reinstalling for a different UID/config leaves
the old namespace untouched and inaccessible via the new registration. No
migration/adoption/clear/export endpoint is included.

Only an eligible root embedded Run for that registration's exact staged
`<registered config parent>/service/config.yaml` may initialize this fixed store.
Thread an internal typed telemetry option through the existing authorized service
launch/Run path; verify root registration and expected staged-path association.
Do not accept an arbitrary storage path over public CLI/IPC, infer eligibility
from a filename alone, or turn a standalone/foreign Run into the registered VPN.
Nonroot/foreign/external-core runs expose TELEMETRY_UNAVAILABLE. Isolated tests
may inject a private store root in package-private seams only. This association
retains existing staging trust limitations; it is not new executable attestation.

### Files and commit algorithm

Per namespace: a fixed `writer.lock`, atomic `latest.json`, and one exclusively
created `<instance_id>/` per eligible Run. Use the existing OS file-lock facility
(nonblocking exclusive flock) on the validated lock handle for the **writer's
entire actual lifetime**, not a new locking framework. Lock busy/init failure
only disables this collector; never steals/deletes another writer's resources.
Helper readers do not acquire this lock. No root directory provisioning/installed
helper change is performed by an HTTP read; eventual provisioning/update is a
separately authorized install, or an eligible root Run creates missing safe
children under the already validated protected helper root.

Each Run directory contains exactly the required store files:

- Immutable `header.json` (<=8 KiB): schema, registration config_identity,
  instance_id/generation/manifest_id/runtime_sha256, created_at, and nullable
  `previous_binding={instance_id,generation,manifest_id}` captured from the
  prior valid latest pointer/header (null if none). This complete binding lets
  the next page request select a prior Run without another discovery protocol.
  No config, credential, raw manifest or filesystem path.
- `records.bin`: consecutive `uint32 big-endian JSON_length` + UTF-8 JSON record;
  record schema above, length 1..256 KiB.
- `index.bin`: fixed **16-byte** entries, `uint64 big-endian offset` into
  records.bin and `uint64 big-endian framed_length` (includes 4-byte prefix).
  Entry for seq s is at `(s-1)*16`; use checked signed-file-offset arithmetic.
  This is a disk index only: no growing Go slice/map or full-history scan.
- Atomic `state.json` (<=8 KiB): schema and complete header identity, monotonically
  increasing status revision, high_water_seq, committed_data_bytes,
  committed_index_bytes, collection, provenance_status, pending/loss counters,
  gap, timestamp and `closed` (the last saved stopped-recording state, not proof
  of successful final publication Sync, lock Close, cleanup or complete history).
  No raw errors. All wire/file counters use canonical decimal strings.

Create files exclusively; validate any prior latest/header before linking it;
never append to/adopt a previous Run's data. Initialize an empty state and safe
header, then atomically publish latest `{schema_version:1,instance_id}`. Failed
initialization does not replace a valid latest pointer. Incomplete/orphan files
are retained, not automatically deleted/adopted; report initialization failure.
No automatic directory scan/recovery/reindex is required. The previous-header
chain gives history navigation without a growing catalog or repeated scans.

Single worker batches at most **100 records or 1 second**, with bounded memory;
seqs are tentative until commit. Write complete framed records then complete
index entries, Sync both data and index, then publish state by exclusive 0600
same-directory temporary file -> write -> Sync -> Close -> rename. Sync the
containing directory where required for durable publication, using the target
platform's verified supported operation; failure is IO_FAILED, not silent
success. Initial header/latest publication follows the same durable ordering.
These are standard file operations, not a new journal/storage engine.
State commits index_bytes=16*high_water and the exact data prefix length; all
length/offset arithmetic is checked before file access. Each state revision
publishes only a complete prefix. Existing records/index prefix is immutable.
No per-record sidecar, unlimited index cache or scan from byte zero per page.

Failure after data but before index/state leaves an **uncommitted tail**, never
visible rows. Keep the last valid state/prefix; never truncate/delete/reindex
that tail automatically. If an atomic publication may have taken effect despite
an error, report commit outcome UNKNOWN; helper accepts only a fully validated
state/prefix and never claims missing writes committed. On host/process crash,
some queued/batched events can be lost; recent Sync is not a universal disk/power
loss guarantee. Every public page has continuity UNKNOWN, including ordinary
successful CLOSED. No durable marker or best-effort failure rewrite can certify
all later I/O when the store may become completely unwritable.

### Lifetime and bounded shutdown

History persists across Run/VPN/helper/WebUI/browser restart, Stop, reload and
ordinary executable updates; it is outside the deletable service snapshot.
Each new Run gets a new identity/directory and links the previous published Run;
never relabel old records with new selection. Helper restart can read this safe
persisted history without an old secret or live-Run attach. It must label it
HISTORICAL/LAST_RECORDED, **not current live VPN**. latest means most recently
published history, not ready/running. A new generation does not erase older files
or rows; UI clears the displayed old page before switching, with explicit prior
history navigation. Manual file deletion requires separate explicit user scope;
no age/count/byte quota, rotation, pruning, clear API or silent uninstall cleanup.

Shutdown has one **5-second total telemetry budget**: stop admission, do not
close a channel under callbacks, stop new worker work, attempt one bounded final
batch/status, account known discarded pending events, cancel page operations
owned by the process and wait for known users. No unlimited drain. Box.Close and
its existing errors remain independent and are never skipped, replaced or fed
telemetry errors into lifecycle rollback. Ordinary regular-file I/O/Sync/Close
is not guaranteed context-interruptible: on budget expiry mark cleanup UNKNOWN,
stop waiting and retain worker-owned handles/buffers/lock until it really exits
or process end; never close/reuse a handle still used by a worker, release its
writer lock early, or claim quiescence. No additional VPN stop/restart. This is
not a hard deadline on upstream Box.Close or kernel filesystem calls.

## 6. Authenticated helper paging, not arbitrary file reads

Boundary: `browser -> ordinary-user authenticated HTTP -> existing root helper
control.sock -> fixed registered store`. WebUI remains nonroot loopback HTTP.
No root HTTP, extra VPN listener, file download, arbitrary command/path/read,
full SDK control plane or installation fallback. Existing start/stop/reload/
status request and response schemas/4096-byte limits remain unchanged.

Reuse **existing control.sock** ancestry/socket validation and Darwin
LOCAL_PEERCRED/XUCRED checks: server requires exact registered nonzero UID,
rejecting root/other UIDs; client requires server peer UID 0. Add one explicitly
read-only versioned action handled **before** execute's `action != status`
mutation branch. Never acquire lifecycle mutation/action locks or call state,
preflight/start/stop/reload, config compilation or repair from records.read.
A registration binding read is not a service status/liveness query.

One connection: one JSON request followed by client CloseWrite, one JSON response
followed by server close, matching current EOF transport. No added length frame
or attach exchange. Distinct strict request schema:
`{action:"records.read",schema_version:1,instance_id,generation,manifest_id,after,limit}`.
All identity fields null means discovery only (no rows); otherwise all required.
Use canonical 128-bit hex instance/generation and 256-bit hex manifest. after is
exclusive committed seq, default decimal string `"0"`; limit integer default
100, accepted 1..500. Client never provides file offsets. Discovery returns
latest complete header identity and previous_binding, or typed unavailable
if there is no valid history. A bound request may read an old Run in this
namespace; its previous_binding is returned for backwards Run navigation.
Unknown/mismatched identity gives STALE_GENERATION with no rows, never fallback
to latest. Current disk-config bytes are not a condition for reading old history.

Keep control decoder budgets unchanged; add telemetry-specific strict decoding:
request **8 KiB**, response **1 MiB**, reject at most budget+1 bytes via bounded
read **before decoding**, not io.ReadAll then checking. Current EOF protocol needs
no length-prefix allocation. Both directions reject invalid UTF-8, NUL, recursive
duplicate/unknown keys, null/wrong types except explicit nullable fields, wrong
version, trailing JSON/frames, noncanonical/overflow decimal counters/hex IDs.
Use the same strict rules on bounded header/latest/state/record JSON. Telemetry
errors are fixed enums, not raw errors/paths. Old helper rejects the unknown
action/schema: new WebUI maps this to TELEMETRY_UNAVAILABLE/UNSUPPORTED, never []
or an instruction to auto-update/reload. Old control clients keep working.

Total **5-second** telemetry deadline covers connect, credentials, request read,
file paging and response write; HTTP cancellation closes its owned IPC request.
Only **one active telemetry operation per helper**; overlaps get immediate BUSY,
no queued readers/unbounded goroutines. Retain that slot until actual file work
finishes even after caller timeout. A blocked disk operation may leave telemetry
busy/unavailable but must not consume the lifecycle mutation lock or block VPN.
Network deadline does not magically interrupt regular-file I/O; report this
boundary instead of unsafe handle close from another goroutine.

Page algorithm: capture one valid state + header from bounded same-handle reads;
validate complete identity and high-water/index/data prefix against fstat sizes.
Open the two root-private regular files with nofollow; keep those read handles
for the operation. Reject checked-offset overflow/future after. Seek/read at
most limit index entries from after*16; validate contiguous offsets, framed
lengths and each row's seq/identity against the committed prefix. Copy only whole
records fitting the 1 MiB response including envelope; if next whole record
would exceed it, stop before that record and set has_more. Record budget ensures
one valid record and the bounded envelope can fit. Never iterate all preceding
records or load/rebuild an index. Corrupt/missing files or short committed reads
return STORE_INVALID/UNAVAILABLE with no partial page, no repair/truncation.
A later valid state may advance while paging: this page uses only captured
high-water. Recheck registration and file/header identity before return; reject
replacement/mismatch, do not require unchanged data size while appending.

All response bytes are independently owned bounded memory; release handles and
page work before socket write. No borrowed SDK buffers/storage locks. Counters
may update during a read; return one captured consistent state, freshness and
coverage uncertainty, not mixed revisions. Helper never writes history/status.
Root trust plus validated persisted identities is the chosen history boundary,
not a claim of real-time executable/VPN attestation.

## 7. HTTP and browser ownership

`GET /api/v1/connections?after=<decimal>&limit=<1..500>` with optional complete
instance_id,generation,manifest_id binding. Omitted binding is discovery only.
Reject duplicate/unknown query keys. Existing ServeHTTP session/password-reset
revocation, exact loopback Host+port, no CORS, no-store, nosniff and CSP remain.
Explicitly enforce same-origin even for this GET: `X-AnyTLS-Origin` must equal
`http://` + validated Host and browser `Sec-Fetch-Site` must be `same-origin`.
When Origin exists also apply exact originOK. Browser sets the application
header, not forbidden Origin; no CORS/OPTIONS preflight grant. Native clients
supply the same headers. These headers do not defeat a malicious authenticated
local client inside the UID boundary. No CSRF in URLs; POST/PUT and clear are 405;
existing mutations retain session CSRF.

200 envelope contains schema/config_identity, full binding/runtime digest,
previous_binding, history_kind=LAST_RECORDED|HISTORICAL (never LIVE),
provenance_status, collection/freshness/closed, history_start_seq (`"1"` or null
for empty), high_water_seq, next_after, has_more, records, pending, and coverage
`{complete:false,unobserved:[REJECT,DNS,EARLY_ERROR],gap,lost_total,
loss_epoch,loss_reasons,counter_saturated,continuity}` plus DNS UNKNOWN.
Unknown counters are null, never zero. has_more refers only to the captured
high-water; next_after is last returned seq or requested after if empty.
Status/counter freshness failure or unclosed stale history forces visible GAP/
UNKNOWN even if the last stored state had gap=false. All pages project
`coverage.continuity=UNKNOWN`. Persisted closed history preserves exact committed
rows, binding, provenance/source attribution, `collection=CLOSED` and
`closed=true` as history only, but projects `freshness=UNKNOWN`, `gap=true`, and
`pending`, `lost_total`, `loss_epoch` and every loss reason as null. This applies
immediately and indefinitely, including ordinary successful shutdown; no loss
quantity is invented. `counter_saturated` remains a stored observation, not a
completion claim. Shared public-page validation rejects continuity CLOSED,
closed freshness other than UNKNOWN, closed gap=false, or known closed
pending/loss counters/reasons. Disk State validation remains compatible with
previously valid stored CLOSED/known-zero states. In-process Shutdown still
reports actual IO_FAILED/cleanup UNKNOWN after errors; writer-lock lifetime,
once-close, committed prefixes and no-auto-delete behavior are unchanged.
Explicit errors: 400 invalid query, 401 AUTH_REQUIRED, 403 origin/peer rejection,
409 STALE_GENERATION/BUSY, 503 TELEMETRY_UNAVAILABLE/STORE_INVALID. No record
bodies in error replies. Authentication precedes helper contact.

Tab displays time, TCP/UDP/flow, host/IP/port, source rule/set or MATCH/default,
group edge chain, DIRECT or terminal node, actual outbound and ROUTED. Use
textContent, not HTML; UNKNOWN/mismatch/gap/failure remain visible. Show stored
Run identity, last update and persistence warning; never green connected or a
current-VPN claim. Always visibly state `完整收尾未验证／连续性 UNKNOWN`;
when displaying CLOSED explain it is only the last saved stopped-recording state,
not full cleanup or success. DNS remains separately UNKNOWN.

Exactly one fetch active, private AbortController and **5-second client timeout**,
next timer **1 second after completion**, including has_more (no tight catch-up
loop). Discovery on opening/visibility return; then bound paging. Keep **one
displayed page and fixed-size cursor anchors only**; no growing array of prior
pages/cursors. Forward pages use next_after; Back may jump at most limit seqs
using decimal-string/BigInt arithmetic, then refetch (byte-budget-short pages
need not reproduce old page boundaries). Provide Start/latest-history and prior
Run controls using header previous_binding, not a growing Run cache. Do not
poll/switch a manually selected historical Run into latest silently. No
localStorage/IndexedDB/service-worker cache/automatic export.

Tab hidden/panel closed/logout/401/reset: cancel owned timer/fetch, increment
panel/auth epochs and clear rows/binding/cursors as appropriate. Old finally
cannot clear/rearm a newer poll after same-turn cancel/reopen. Every response
must match auth/panel/request epochs, identity and requested cursor before
render; late responses cannot repopulate cleared DOM. A changed latest identity
is announced and clears the old display before opt-in/latest navigation; explicit
historical browsing remains separate, never merged/retagged. Stale requested
identity clears claims and rediscovery notice, not silent fallback. Unavailable
is not “no traffic”. Logout cleanup is best effort, not erasure of delivered
bytes, disk history or OS/browser memory.

## 8. Privacy and staged acceptance

Store only the approved projections. Never serialize InboundContext,
ProcessInfo/User/DNSResponse/SniffContext, password, subscription URL, TLS
material, payload, full HTTP URL/path/query/fragment, headers/cookies or raw
errors. Validate host/domain/CIDR forms; labels are untrusted authenticated
text, never ordinary logs. Secret sentinels in excluded fields must be absent
from exact disk/IPC/HTTP bytes. No telemetry debug logs or intentional crash
dumps. Permissions are not encryption/secure erasure: root, backups and OS crash
policy can expose local history. Explain persistent sensitive destination
history and no automatic deletion; do not promise disk capacity or OOM survival.
No historical disk byte/free-space gates are reintroduced: counts/bytes/free
space are diagnostics only. Real I/O errors, timeouts, ownership, integrity,
privacy and production boundaries remain mandatory.

All implementation/native gates below are **NOT_RUN**. TDD uses the same test
inputs/assertions on exact old/new source: old-side behavioral RED, not missing
new symbol/compile failure; existing-compatible seams or independent harnesses.
Pin source/SDK h1/harness SHA/platform/tags/raw commands/results and protected
state. Do not fabricate data/PASS or treat static review as native acceptance.

1. **Review first:** parent SPEC -> independent QUALITY on this exact document
   SHA. Preserve old valid unchanged coverage/attribution findings but re-review
   disk retention/privacy/ownership/IPC/shutdown changes. No native-pressure
   rebuild, new pressure bridge or pressure stress acceptance step.
2. **First implementation slice — real files:** private temporary store with
   standard file APIs, framed records + fixed disk index + atomic state. Prove
   direct seeks with increasing histories and instrumented read counts: page
   work/memory independent of preceding rows, no index rebuild/full scan. Inject
   open/permission/short write/data/index/Sync/rename/Close failures, data-complete
   index-incomplete, state-publication uncertainty and cancellation; previous
   committed prefix remains readable, incomplete tails invisible/retained,
   IO_FAILED/gap and stale-status notice visible, VPN result unchanged. Test
   queue-full/oversize/worker failure/counter saturation and IDs near uint64 max.
   No eviction/deletion/wrap. Block worker I/O across 5-second shutdown: no unsafe
   handle close/early lock release/unbounded wait; cleanup UNKNOWN, Box.Close
   still called with original error chain. Record native filesystem Sync
   semantics honestly; local failure injection is not power-loss proof.
3. **Persistence/ownership:** Run A -> normal Stop -> B, Run/helper/browser crash
   and restart, unchanged config/new generation, header previous navigation,
   empty history, orphan init and stale latest, stale heartbeat/future clock,
   manual missing/replaced/corrupt file and namespace re-registration. Old rows
   remain A with A attribution; B never appends A. Helper restart reads safe
   history without adoption of a live collector. Test competing writer locks,
   unsafe ancestors/symlink/FIFO/device/hardlink/mode/owner/replacement, offset
   overflow and index beyond committed prefix. Ordinary UID cannot directly
   read files; authorized helper paging succeeds; no user-supplied root path.
4. **Compiler/SDK real routing:** actual prepareRuntime/applyRoutingBytes (not
   hand-written SDK JSON) -> isolated mixed TCP/UDP echo + authenticated local
   AnyTLS peer. DIRECT payload arrives with zero proxy business bytes/flows;
   proxy positive payload/counters. Nested groups, two groups sharing one reused
   outbound, duplicate rules, MATCH/nil fallback, no-rules DEFAULT_SELECTED,
   RULE-SET top-level and sniff/resolve/hijack insertions. Real returned Rule
   identity maps to exact path; altered identity/slot/action/outbound/manifest
   makes attribution UNKNOWN without changing forwarding. Runtime JSON semantics/
   bytes unchanged under same encoder. Refused dial remains ROUTED, no connected;
   REJECT/early errors/DNS do not invent records or DNS DIRECT. Original connection
   identity/interfaces preserved, flow nil accepted by pinned real path; native
   flow needing TUN stays pending until separately authorized, not unit-PASS.
5. **Real helper transport/auth:** one EOF request/response through actual socket,
   registered UID positive and root/other UID negative, server root peer check,
   legacy four actions still compatible; old-helper unavailable without update.
   >4096-byte valid page, 8 KiB/1 MiB/256 KiB boundaries, empty page/gap, partial/
   trailing JSON, recursive duplicate/unknown keys, invalid UTF-8/NUL/types/hex/
   uint64 and >2^53 cursors, future cursor, all identity mutations, prior Run
   pages, wrong namespace/config identity and replaced store. Auth failures have
   no reads; every read/failure has zero lifecycle/state/preflight/repair calls
   and no mutation-lock acquisition. Slow socket writer cannot hold page handles
   or storage locks; blocked file reader retains its one slot, not service lock.
6. **Full HTTP and real browser:** successful login/read through ServeHTTP before
   rejection matrix; exact Host/Origin/application header/fetch metadata/session
   reset, existing mutation CSRF, no CORS. Desktop/mobile table, ROUTED/UNKNOWN/
   DNS banner, persistent retention disclosure, gap after writer fault/status
   timeout with no rows, previous Run/Back/Start, fixed-size DOM/cache, one fetch,
   hidden/show/logout and late replies across panel/auth/generation changes.
   Same-turn cancel/reopen proves old finally cannot own new timer/controller.
7. **Native isolated acceptance then release boundary:** freeze exact candidate,
   run native targeted RED/GREEN and full relevant tests/vet/build only after
   their separate execution scope is approved; report callback/load timing and
   bounded resident state, no universal latency/disk/OOM claims. Protect config/
   selection/CA/rules, installed executable, incumbent PID/service/route/DNS/
   proxy identity before/after. Intel and Apple Silicon native receipts remain
   separate; Linux/cross-build do not substitute. Independent code review next;
   helper install/update and live TUN/production acceptance require their own
   authorization. No documentation approval automatically reloads a VPN.

This contract does not deliver implemented Connection Records, complete traffic
coverage, a successful native-pressure mechanism, or a fix for Baidu slowness.

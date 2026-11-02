# DNS stream CachedConn ownership patch (local candidate)

This successor preserves sing-box v1.14.3 and all existing patch identities. Its
new authenticated patch is applied after browser provenance; `route/route.go`
therefore has an explicitly pinned intermediate and final digest.

The stream entry constructor synchronously takes the buffers from contiguous
concrete `*bufio.CachedConn` layers before starting asynchronous exchanges. Their
original owners have `taken=true` and no longer participate in buffer reads or
release. Only finite replay-buffer reads/releases share a per-stream mutex;
network reads never hold it. Close first wakes the underlying connection and then
releases remaining replay buffers under that mutex. `sync.Once` preserves the
first Close result and prevents callback/loop cleanup from closing twice. The
outer connection still forwards Write, addresses, deadlines and handshake
traversal. Replay order, EOF and per-request async exchange behavior are unchanged.

The constructor is installed in route hijack, deprecated DNS outbound and Linux
resolved stream loops. Route cleanup retains the identical idempotent wrapper.
No UDP, retry, timeout, TLS, DNS error/cancel mapping or non-DNS forwarding changes.
This does not repair generic sing CachedConn globally; opaque caller-supplied
wrappers hiding another CachedConn are outside this concrete ownership boundary.
Linux resolved receives a source patch but is not runtime-tested by Darwin gates.

`dns_stream_close` is mandatory in wrapper receipts, corresponding-source
packaging and source installer acceptance, with the original-source invariant.
Patch JSON, review diff and identity are required package materials. Private
replacement paths are provenance, not an upstream unmodified module claim.

Tests: `python3 scripts/tests/test-go-patched.py`; packaging and installer tests;
`TestDNSStreamCachedOwnershipBeforeAsyncClose` (identical private native RED/GREEN),
replay/EOF/close-error identity, split-frame pipelining, concurrent cached reads
and Close. The unchanged blackhole test remains in the expanded native race gate.

Any produced package uses the unchanged repository VERSION **only for local
package validation**. This is not a new release, approval to install, or permission
to publish, restart a service, alter production DNS or run a privileged TUN probe.

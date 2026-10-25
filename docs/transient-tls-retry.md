# Bounded pre-auth TLS-dial reset mitigation (candidate only)

This is **not a root-cause cure** for the public connection resets. It retries
only failure returned by the original AnyTLS outbound TLS dialer, before that
connection is returned to sing-anytls for authentication. TLS certificate
verification may already have run before a later reset; this hook does not claim
to locate resets before the certificate phase.

## Contract

* At most three invocations of the **same** SDK `tls.Dialer.DialTLSContext`,
  separated by cancellable 150 ms and 300 ms waits.
* One aggregate context covers TCP dial, TLS handshake and waits. Its duration is
  the TLS config's original handshake timeout (15 seconds by default), bounded by
  any earlier caller deadline. It does not refresh on retries.
* Retry requires `errors.Is(ECONNRESET)`, a real `*net.OpError`, and a single
  unwrap chain ending in that exact syscall sentinel. Multi-error trees, timeout
  wrappers, EOF, cancellation, permissions, TLS/security/protocol errors and
  same-text lookalikes are not retryable. Error classification is bounded to 32
  unwrap steps and never matches strings.
  Explicit standard TLS/x509 security error types are rejected even if a verifier
  wraps a transport reset; a separate native RED/GREEN regression binds this case.
* Each attempt uses the original dialer, destination and multiplex-session
  context: interface binding, detour, SNI, Chrome/Go TLS and strict leaf pin are
  unchanged. There is no raw TCP redial or peer-address shortcut.
* The retry seam does not enclose `CreateStream`, password authentication,
  destination writes, reads or business operations. Wrong pin/password do not
  trigger replay. Failed returned connections are closed once; cleanup failure
  stops retries. The pinned SDK already closes its raw connection on handshake
  error and normally returns nil. All failed-attempt/cleanup/cancellation errors
  remain inspectable via `errors.Is/As`.
* Factory registration is in the embedded engine registry only, using the exact
  anonymous interface key. Missing registration preserves upstream single-dial
  behavior. The new authenticated patch only adds this hook at `dialOut`.

## Build/source chain

Historical Start, core-slim, Chrome and leaf identities and patches are unchanged.
`retry.identity.json` authenticates a new transform **after** the Chrome
intermediate. Wrapper BEGIN/END and CCS certification require `transient_retry`;
Chrome's result remains explicitly intermediate, and the retry receipt binds the
final outbound bytes. CCS/source materials include both new patch files.

## Evidence scope

`TestAnyTLSTransientResetThenPinnedBusiness` uses real TCP RST injection on the
first ClientHello and a real strict pinned TLS + AnyTLS server and echo target on
the second connection. It proves recovery within one application operation and
exactly one business payload; its identical bytes compile against baseline and
candidate. Initial fixture compile/encoding failures are retained separately,
not counted as behavioral RED. Native security tests require actual peer
certificate/auth rejection, one accepted connection and zero target business.
Counted original-dialer tests exercise cap, aggregate budget, shorter caller,
backoff cancellation, context/destination preservation and error/close ownership;
they are injected witnesses, not observations of public root cause.

Public acceptance uses six fresh ordinary-user actual CLI instances against the
existing configured public endpoint, strict trusted pin, no skip/fallback, and a
single bounded run. Results, including all failures, must be reported honestly.
No production installation, helper/VPN control, system routing changes, push,
tag or release is authorized by this candidate.

# Explicit SNI suppression

AnyTLS nodes accept optional YAML **`disable-sni: true`**. The default is unchanged:
omitted or `false` keeps the existing TLS backend behavior, including sending an
explicit DNS `sni`. No configuration migration removes or rewrites a user's SNI.
Explicit null, strings (including `'true'`), numbers, collections and other
non-boolean values are rejected, including inherited/aliased nulls. Conversion
removes an invalid whole node with its usual skip report, never just the field.

```yaml
nodes:
  - name: pinned-ip
    type: anytls
    server: 203.0.113.7
    port: 443
    password: '<your-password>'
    fingerprint: '<trusted-64-hex-leaf-DER-SHA256>'
    # Optional for an existing config that already contains a DNS sni:
    disable-sni: true
```

The placeholders are not runnable credentials or pins. A numeric IP plus a
trusted whole-leaf pin does not require SNI: when no `sni` is configured, the TLS
backend does not send a numeric IP as a server-name extension. This pin-only
identity still verifies the entire leaf DER, not PKIX/hostname/expiry; SNI
suppression does not weaken or replace that mandatory pin check. Servers that
select a certificate or virtual service by SNI may still require it.

For an **existing configuration**, `disable-sni: true` can coexist with its
explicit `sni`. The compiler retains that string as `tls.server_name` and emits
`tls.disable_sni: true`; the backend suppresses the ClientHello SNI extension.
With `ca`, the retained name is still the hostname verification reference and
the chain must still be trusted. A wrong hostname or untrusted CA remains a
certificate failure before AnyTLS authentication. This switch does not set
`skip-cert-verify` or change either leaf/SPKI pin type.

Native YAML load/save, the existing node-form edit (which preserves advanced
fields), Clash/native conversion, add-only imports and YAML exports retain the
field. There is no AnyTLS URI import/export implementation here; URI responses
remain explicitly unsupported. No URI dialect or automatic migration is added.
The raw YAML editor is the existing advanced-field editing path.

This explicit client option is **independent** of a panel choosing to omit SNI
in newly generated IP/pin subscriptions. Such a panel default does not alter
existing client configs and is not implemented by this change.

A prior investigation observed SNI-sensitive resets on one path, with successful
controls; the original SNI is not guaranteed to fail. This option is an explicit
workaround candidate, **not proof of the reset source, a complete root-cause fix,
or a promise of long-term stability**. The separately inherited bounded TLS-dial
retry remains described in [transient-tls-retry.md](transient-tls-retry.md); it is
not business replay and does not bypass certificate rejection.

## Regression gates

`TestDisableSNIBuildNode` checks actual runtime JSON and unchanged defaults.
`TestDisableSNIRejectNonBool` covers explicit malformed values and scalar
aliases/merges. `TestDisableSNIConversionEditExport` covers conversion, native
no-op bytes, form edit, typed save and export. `TestDisableSNIEngineConstruction`
requires Chrome/default to fail closed without `with_utls`, while Go remains
constructible.

`TestDisableSNILocalTLS` runs the real YAML compiler and embedded engine against
an ephemeral loopback TLS/AnyTLS service (Chrome default, Go, Firefox). It checks
actual ClientHello names, strict pin/CA authenticated binary echo, wrong leaf,
wrong hostname and untrusted CA rejection with zero service admissions,
authentication plaintext reads, streams and business bytes. Omitted/false and
IP-with-pin/no-SNI cases are separate controls. It is not public-path or TUN
acceptance. RED/GREEN logs and final native full-suite/build identity are separate
execution evidence, not claims implied by this document.

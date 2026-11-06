# Browser qualification gates

Automatic update checks run only in an authenticated, visible, online browser document: initial login/session bootstrap, then hourly after success or 15 minutes after failure. Route changes do not trigger checks. Closing the page stops checks. No installation, download, helper operation or VPN/restart action is automatic.

Normal Go tests execute the background-update VM regression through `TestWebBackgroundUpdateFrontend` when Node is installed (or `ANYTLS_R10_NODE` points to it). Missing Node is an explicit skip, not a frontend pass.

Release qualification must enable both browser gates on the final frozen source:

```
ANYTLS_R10_HTTP_BROWSER=1
ANYTLS_TRAFFIC_TREND_BROWSER=1
ANYTLS_R10_NODE=<absolute installed Node path>
ANYTLS_R10_HTTP_EVIDENCE=<new exclusive evidence directory>
```

Run the repository's authenticated `scripts/go-patched.py --go <trusted Go 1.27.3> test` wrapper with `-p=2 -tags with_gvisor,with_utls,with_upstream_cleanup_patch,embedded_core -count=1 -timeout=8m -json ./...` and offline module configuration. Browser dependencies/CJK fonts must already be installed; these tests do not download them.

`TestR10RealHTTPBrowser` uses actual authenticated Go HTTP routing and embedded assets, with private fixture files. Privileged lifecycle, provider and release lookup are synthetic seams. No route fulfillment substitutes product assets or handler responses. `TestTrafficTrendLineBrowser` is explicitly a synthetic-API frontend geometry suite, not native traffic acquisition or real-handler evidence. Its ordinary default skip must not be counted as release qualification.

Any asset/test edit after the freeze invalidates exact-final compiled browser evidence; freeze and run again after integration. Native macOS/helper/VPN acceptance remains a separately authorized gate.

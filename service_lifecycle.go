package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// Concrete per-invocation dependencies; fixtures only use their own TempDir.
// The privileged entry points and fixed launchd label cannot be overridden.
type serviceLifecycle struct {
	root           string
	tool           func(context.Context, string, ...string) (string, error)
	state          func() (bool, bool, error)
	route          func(string) (string, error)
	dns            func() ([]string, error)
	proxy          func() error
	stage          func(string, string, string, string) error
	remove         func(string) error
	pause          func()
	owned          *snapshotRootIdentity
	receipt        *serviceDiagnostic
	diagnostic     *startDiagnostics
	startupCtx     context.Context
	startupServer  *controlHelperServer
	startupSegment string
	startupRound   int
	startupRoutes  string
}

func newServiceLifecycle(root string) serviceLifecycle {
	return newServiceLifecycleContext(root, context.Background())
}
func newServiceLifecycleContext(root string, ctx context.Context) serviceLifecycle {
	owned := &snapshotRootIdentity{}
	return serviceLifecycle{root: root, tool: runTool, state: serviceState, route: routeInterface, owned: owned,
		dns: dnsServers, proxy: checkProxyInactive, stage: func(binary, config, core, root string) error {
			return stagePrivateRunOwnedContext(ctx, binary, config, core, root, owned)
		}, remove: os.RemoveAll, pause: func() { time.Sleep(time.Second) }}
}

// Do not print tool output, config values or upstream errors; preserve causes
// for errors.Is/As (explicit unwrapping is not a sanitized display API).
type lifecycleError struct {
	message string
	cause   error
}

func (e *lifecycleError) Error() string                  { return e.message }
func (e *lifecycleError) Unwrap() error                  { return e.cause }
func lifecycleFailure(message string, cause error) error { return &lifecycleError{message, cause} }

// Use the existing compiler's exact IP strings, never DNS or a second resolver.
func serviceOutbounds(config string, allowInsecure bool) ([]string, bool, error) {
	captured, err := captureServiceConfig(config)
	if err != nil {
		return nil, false, lifecycleFailure("service config unavailable", err)
	}
	return captured.outbounds(allowInsecure)
}

func (captured serviceConfigBytes) compile(allowInsecure bool) (map[string]any, error) {
	n, err := captured.selected()
	if err != nil {
		return nil, lifecycleFailure("service selection unavailable", err)
	}
	nodes, err := loadNodesBytes(captured.config)
	if err != nil {
		return nil, lifecycleFailure("service config unavailable", err)
	}
	cfg, err := buildNode(n, "tun", 0, allowInsecure)
	if err != nil {
		return nil, lifecycleFailure("service config rejected", err)
	}
	if err := applyRoutingBytes(captured.path, captured.config, nodes, n, cfg, allowInsecure); err != nil {
		return nil, lifecycleFailure("service routing rejected", err)
	}
	return cfg, nil
}

func (captured serviceConfigBytes) outbounds(allowInsecure bool) ([]string, bool, error) {
	cfg, err := captured.compile(allowInsecure)
	if err != nil {
		return nil, false, err
	}
	var servers []string
	insecure := false
	for _, entry := range cfg["outbounds"].([]any) {
		out := entry.(map[string]any)
		if out["type"] != "anytls" {
			continue
		}
		server := out["server"].(string)
		if !slices.Contains(servers, server) {
			servers = append(servers, server)
		}
		insecure = insecure || out["tls"].(map[string]any)["insecure"] == true
	}
	if len(servers) == 0 {
		return nil, false, errors.New("service has no outbound servers")
	}
	return servers, insecure, nil
}
func physicalInterface(iface string) bool {
	return iface != "" && strings.TrimSpace(iface) == iface && !strings.ContainsAny(iface, " \t\n\r") && !strings.HasPrefix(iface, "utun")
}
func validBaseline(b networkBaseline) error {
	if !physicalInterface(b.PublicInterface) || len(b.DNS) == 0 {
		return errors.New("restoration baseline incomplete")
	}
	for _, entry := range b.DNS {
		parts := strings.Split(entry, " : ")
		if len(parts) != 2 || !strings.HasPrefix(parts[0], "nameserver[") || !strings.HasSuffix(parts[0], "]") {
			return errors.New("restoration DNS baseline invalid")
		}
		// Validate scoped IPv6 without normalizing or dropping its zone. The
		// original strings and order remain authoritative for restoration.
		if _, err := netip.ParseAddr(parts[1]); err != nil {
			return errors.New("restoration DNS baseline invalid")
		}
	}
	if b.Version != 0 && b.Version != 1 {
		return errors.New("restoration baseline version unsupported")
	}
	if net.ParseIP(b.Server) == nil || !physicalInterface(b.ServerInterface) {
		return errors.New("legacy server baseline invalid")
	}
	if b.Version == 1 {
		if len(b.Servers) == 0 || b.Servers[b.Server] != b.ServerInterface {
			return errors.New("server baseline incomplete")
		}
		for server, iface := range b.Servers {
			if net.ParseIP(server) == nil || !physicalInterface(iface) {
				return errors.New("server baseline invalid")
			}
		}
	} else if len(b.Servers) != 0 {
		return errors.New("legacy baseline inconsistent")
	}
	return nil
}
func (d serviceLifecycle) baseline() (networkBaseline, []string, error) {
	var b networkBaseline
	raw, err := os.ReadFile(filepath.Join(d.root, serviceBaselineName))
	if err != nil {
		return b, nil, lifecycleFailure("restoration baseline unavailable", err)
	}
	if err := json.Unmarshal(raw, &b); err != nil {
		return b, nil, lifecycleFailure("restoration baseline invalid", err)
	}
	if err := validBaseline(b); err != nil {
		return b, nil, err
	}
	servers, _, err := d.traceOutbounds(filepath.Join(d.root, "config.yaml"), true)
	if err != nil {
		return b, nil, d.failure("CONFIG", "CONFIG_COMPILE_FAILED", lifecycleFailure("restoration scope not verified", err))
	}
	if b.Version == 0 {
		if len(servers) != 1 || servers[0] != b.Server {
			return b, nil, errors.New("legacy baseline does not prove all server routes")
		}
		b.Servers = map[string]string{b.Server: b.ServerInterface}
	}
	if len(servers) != len(b.Servers) {
		return b, nil, errors.New("restoration server scope mismatch")
	}
	for _, server := range servers {
		if _, ok := b.Servers[server]; !ok {
			return b, nil, errors.New("restoration server scope mismatch")
		}
	}
	return b, servers, nil
}
func (d serviceLifecycle) serverRoutes(b networkBaseline, servers []string) (result error) {
	stage := d.startupRoutes
	if stage == "" {
		stage = "READINESS_SERVER_ROUTES"
	}
	span := d.traceBegin(stage)
	completed := 0
	defer func() { d.traceRouteAggregateEnd(span, completed, result) }()
	for i, server := range servers {
		iface, err := d.route(server)
		if d.receipt != nil {
			d.receipt.server(i, "FAILED")
			d.receipt.active.Servers = "FAILED"
		}
		if err != nil {
			return d.failure("SERVER_ROUTE", "SERVER_ROUTE_UNAVAILABLE", lifecycleFailure("server route probe failed", err))
		}
		if !physicalInterface(iface) || iface != b.Servers[server] {
			if d.receipt != nil && d.receipt.active == &d.receipt.Restore && d.receipt.diagnostic != nil {
				d.receipt.diagnostic.Restoration = "FAILED"
			}
			return d.failure("SERVER_ROUTE", "SERVER_ROUTE_CHANGED", errors.New("server route differs from original physical interface"))
		}
		if d.receipt != nil {
			d.receipt.server(i, "VERIFIED")
		}
		completed++
	}
	if d.receipt != nil {
		d.receipt.active.Servers = "VERIFIED"
	}
	return nil
}
type restorationJobError struct{ error }

func (e *restorationJobError) Unwrap() error { return e.error }

func (d serviceLifecycle) restored(b networkBaseline, servers []string) error {
	var diagnostic *startDiagnostics
	if d.receipt != nil {
		diagnostic = d.receipt.diagnostic
	}
	if diagnostic != nil {
		diagnostic.Restoration = "UNKNOWN"
	}
	if d.receipt != nil {
		d.receipt.Restore = diagnosticUnknown()
		d.receipt.active = &d.receipt.Restore
		for i := range d.receipt.Servers {
			d.receipt.Servers[i].Restoration = "NOT_EXECUTED"
		}
	}
	loaded, running, err := d.traceState("RESTORE_JOB")
	if d.receipt != nil {
		d.receipt.Restore.Job = "FAILED"
	}
	if err != nil {
		return &restorationJobError{lifecycleFailure("job state probe failed", err)}
	}
	if loaded || running {
		if diagnostic != nil {
			diagnostic.Restoration = "FAILED"
		}
		return &restorationJobError{errors.New("job still loaded")}
	}
	if d.receipt != nil {
		d.receipt.Restore.Job = "UNLOADED"
		d.receipt.Restore.Public = "FAILED"
	}
	iface, err := d.traceRoute("RESTORE_PUBLIC_ROUTE", "1.1.1.1")
	if err != nil {
		return lifecycleFailure("public route probe failed", err)
	}
	if !physicalInterface(iface) || iface != b.PublicInterface {
		if diagnostic != nil {
			diagnostic.Restoration = "FAILED"
		}
		return errors.New("public route not restored")
	}
	if d.receipt != nil {
		d.receipt.Restore.Public = "VERIFIED"
	}
	d.startupRoutes = "RESTORE_SERVER_ROUTES"
	if err := d.serverRoutes(b, servers); err != nil {
		return err
	}
	if d.receipt != nil {
		d.receipt.Restore.DNS = "FAILED"
	}
	dns, err := d.traceDNS("RESTORE_DNS")
	if err != nil {
		return lifecycleFailure("DNS probe failed", err)
	}
	if len(dns) == 0 || !slices.Equal(dns, b.DNS) {
		if diagnostic != nil {
			diagnostic.Restoration = "FAILED"
		}
		return errors.New("DNS not restored")
	}
	if d.receipt != nil {
		d.receipt.Restore.DNS = "VERIFIED"
	}
	if diagnostic != nil {
		diagnostic.Restoration = "VERIFIED"
	}
	return nil
}
func (d serviceLifecycle) start(binary, config, core string, allowInsecure bool) (result error) {
	d.startupSegment = "START"
	r := newDiagnostic("START")
	d.diagnostic = newStartDiagnostics("START")
	r.diagnostic = d.diagnostic
	d.receipt = r
	defer d.finishReceipt(r, &result)
	r.Baseline.Job = "FAILED"
	d.diagnostic.Job = "UNKNOWN"
	loaded, running, err := d.traceState("JOB_INITIAL")
	if err != nil {
		return d.failure("JOB", "JOB_STATE_UNAVAILABLE", lifecycleFailure("job state probe failed", err))
	}
	r.Baseline.Job = "UNLOADED"
	d.diagnostic.Job = "UNLOADED"
	if loaded || running {
		r.Baseline.Job = "LOADED"
		d.diagnostic.Job = "NOT_RUNNING"
		if running {
			d.diagnostic.Job = "RUNNING"
		}
		return d.failure("JOB", "JOB_ALREADY_LOADED", errors.New("AnyTLS job already loaded; run 'anytls stop' before starting"))
	}
	// A confirmed-unloaded legacy snapshot is evidence, not an active job.
	span := d.traceBegin("SNAPSHOT_EXISTENCE")
	_, existErr := os.Lstat(d.root)
	d.traceEnd(span, nil)
	if existErr == nil {
		old := newDiagnostic("STOP")
		d.owned, err = snapshotRootAt(d.root)
		if err == nil {
			old.capture(d.root)
			old.Stopped, old.Restoration = "VERIFIED", "NOT_VERIFIED"
			err = d.archiveSnapshot(old)
		}
		if err != nil {
			return d.failure("SNAPSHOT", "SNAPSHOT_IDENTITY_FAILED", lifecycleFailure("legacy snapshot archival failed; retained", err))
		}
		d.owned = nil
		d.diagnostic.Restoration = "UNKNOWN"
		fmt.Println("Warning: previous snapshot archived; previous network restoration is not verified")
	} else if !errors.Is(existErr, os.ErrNotExist) {
		return d.failure("SNAPSHOT", "SNAPSHOT_UNAVAILABLE", lifecycleFailure("private snapshot unavailable", existErr))
	}
	r.phase = "STAGING_FAILED"
	attempted := false
	preserveExisting := false
	defer func() {
		if result == nil || preserveExisting {
			return
		}
		d.traceCapture()
		if d.diagnostic.Reason == "NONE" {
			d.diagnostic.fail("UNKNOWN", "UNKNOWN", result)
		}
		if attempted {
			r.Rollback = "FAILED"
			if err := d.stopObserved(r); err != nil {
				result = errors.Join(result, lifecycleFailure("rollback/restoration failed; diagnostic snapshot retained", err))
			} else {
				r.Rollback = "SUCCEEDED"
			}
			return
		}
		loaded, running, err := d.traceState("JOB_INITIAL")
		if err != nil {
			d.diagnostic.Cleanup = "UNKNOWN"
			result = errors.Join(result, lifecycleFailure("cleanup job state unavailable; snapshot retained", err))
			return
		}
		if loaded || running {
			d.diagnostic.Cleanup = "UNKNOWN"
			result = errors.Join(result, errors.New("cleanup job may be loaded; snapshot retained"))
			return
		}
		if d.owned == nil {
			d.diagnostic.Cleanup = "UNKNOWN"
			result = errors.Join(result, errors.New("snapshot ownership unavailable; retained"))
			return
		}
		if err := d.traceRemove(); err != nil {
			d.diagnostic.Cleanup = "FAILED"
			result = errors.Join(result, lifecycleFailure("private snapshot cleanup failed", err))
		} else {
			r.Snapshot = "REMOVED"
			d.diagnostic.Cleanup = "VERIFIED"
		}
	}()
	span = d.traceBegin("SNAPSHOT_STAGE")
	stageErr := d.stage(binary, config, core, d.root)
	d.traceEnd(span, stageErr)
	if err := stageErr; err != nil {
		var stageErr *snapshotStageError
		if errors.As(err, &stageErr) {
			d.owned = stageErr.owned
		} else if !errors.Is(err, os.ErrExist) {
			// Concrete fixture staging hooks retain their existing cleanup seam.
			d.owned, _ = snapshotRootAt(d.root)
		}
		if !errors.Is(err, os.ErrExist) {
			d.traceReceiptCapture(r, "RECEIPT_CAPTURE")
			r.Snapshot = "STAGING_INCOMPLETE"
		}
		preserveExisting = errors.Is(err, os.ErrExist)
		return d.failure("SNAPSHOT", "SNAPSHOT_STAGE_FAILED", lifecycleFailure("private snapshot staging failed", err))
	}
	span = d.traceBegin("SNAPSHOT_IDENTITY")
	if d.owned == nil || d.owned.info == nil {
		d.owned, err = snapshotRootAt(d.root)
	}
	if err != nil {
		d.traceEnd(span, err)
		return d.failure("SNAPSHOT", "SNAPSHOT_IDENTITY_FAILED", err)
	}
	if err := d.owned.check(); err != nil {
		d.traceEnd(span, err)
		return d.failure("SNAPSHOT", "SNAPSHOT_IDENTITY_FAILED", err)
	}
	d.traceEnd(span, nil)
	d.traceReceiptCapture(r, "RECEIPT_CAPTURE")
	r.Snapshot = "STAGED"
	// Stage first: compile the actual private inputs before baseline or control.
	servers, insecure, err := d.traceOutbounds(filepath.Join(d.root, "config.yaml"), allowInsecure)
	if err != nil {
		return d.failure("CONFIG", "CONFIG_COMPILE_FAILED", err)
	}
	span = d.traceBegin("PROXY_CHECK")
	proxyErr := d.proxy()
	d.traceEnd(span, proxyErr)
	if err := proxyErr; err != nil {
		reason := "PROXY_STATE_UNAVAILABLE"
		var active *systemProxyActiveError
		if errors.As(err, &active) {
			reason = "SYSTEM_PROXY_ACTIVE"
		}
		return d.failure("PROXY", reason, lifecycleFailure("system proxy preflight failed", err))
	}
	baseline := networkBaseline{Version: 1, Servers: map[string]string{}, Server: servers[0]}
	r.serverScope(len(servers), "NOT_EXECUTED")
	r.Baseline.Servers = "FAILED"
	span = d.traceBegin("BASELINE_SERVER_ROUTES")
	for i, server := range servers {
		r.server(i, "FAILED")
		iface, err := d.route(server)
		if err != nil {
			d.traceRouteAggregateEnd(span, i, err)
			return d.failure("SERVER_ROUTE", "SERVER_ROUTE_UNAVAILABLE", lifecycleFailure("server route preflight failed", err))
		}
		if !physicalInterface(iface) {
			d.traceRouteAggregateEnd(span, i, errors.New("not physical"))
			return d.failure("SERVER_ROUTE", "SERVER_ROUTE_NOT_PHYSICAL", errors.New("server route is not on physical interface"))
		}
		baseline.Servers[server] = iface
		r.server(i, "CAPTURED_PHYSICAL")
	}
	d.traceRouteAggregateEnd(span, len(servers), nil)
	r.Baseline.Servers = "CAPTURED_PHYSICAL"
	r.Baseline.Public = "FAILED"
	baseline.ServerInterface = baseline.Servers[baseline.Server]
	baseline.PublicInterface, err = d.traceRoute("BASELINE_PUBLIC_ROUTE", "1.1.1.1")
	if err != nil {
		return d.failure("PUBLIC_ROUTE", "PUBLIC_ROUTE_UNAVAILABLE", lifecycleFailure("public route preflight failed", err))
	}
	r.Baseline.Public = "CAPTURED"
	r.Baseline.DNS = "FAILED"
	baseline.DNS, err = d.traceDNS("BASELINE_DNS")
	if err != nil {
		return d.failure("DNS", "DNS_STATE_UNAVAILABLE", lifecycleFailure("DNS preflight failed", err))
	}
	if err := validBaseline(baseline); err != nil {
		if len(baseline.DNS) == 0 {
			return d.failure("DNS", "DNS_EVIDENCE_EMPTY", err)
		}
		return d.failure("BASELINE", "BASELINE_INVALID", err)
	}
	r.Baseline.DNS = "CAPTURED"
	raw, err := json.Marshal(baseline)
	if err != nil {
		return d.failure("BASELINE", "BASELINE_WRITE_FAILED", lifecycleFailure("baseline encoding failed", err))
	}
	span = d.traceBegin("BASELINE_WRITE")
	baselineWriteErr := os.WriteFile(filepath.Join(d.root, serviceBaselineName), raw, 0600)
	d.traceEnd(span, baselineWriteErr)
	if err := baselineWriteErr; err != nil {
		return d.failure("BASELINE", "BASELINE_WRITE_FAILED", lifecycleFailure("baseline write failed", err))
	}
	// Recompile the staged bytes, not user config: confirm actual launch scope.
	span = d.traceBegin("BASELINE_REVALIDATE")
	_, _, baselineErr := d.baseline()
	d.traceEnd(span, baselineErr)
	if err := baselineErr; err != nil {
		return d.failure("BASELINE", "BASELINE_INVALID", err)
	}
	span = d.traceBegin("PLIST_CREATE_WRITE_CLOSE")
	plist, err := d.startupPlist(insecure)
	if err != nil {
		d.traceEnd(span, err)
		return d.failure("PLIST", "PLIST_CREATE_FAILED", err)
	}
	servicePath := filepath.Join(d.root, "anytls.plist")
	f, err := os.OpenFile(servicePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		d.traceEnd(span, err)
		return d.failure("PLIST", "PLIST_CREATE_FAILED", lifecycleFailure("plist create failed", err))
	}
	_, writeErr := f.WriteString(plist)
	closeErr := f.Close()
	d.traceEnd(span, errors.Join(writeErr, closeErr))
	if err := errors.Join(writeErr, closeErr); err != nil {
		return d.failure("PLIST", "PLIST_WRITE_FAILED", lifecycleFailure("plist write/close failed", err))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	span = d.traceBegin("PLIST_LINT")
	_, err = d.tool(ctx, "/usr/bin/plutil", "-lint", servicePath)
	d.traceEnd(span, err)
	cancel()
	if err != nil {
		return d.failure("PLIST", "PLIST_INVALID", lifecycleFailure("invalid launchd plist", err))
	}
	r.phase = "BOOTSTRAP_FAILED"
	ctx, cancel = context.WithTimeout(context.Background(), 8*time.Second)
	attempted = true // A failed bootstrap may still have loaded a job.
	span = d.traceBegin("BOOTSTRAP")
	_, err = d.tool(ctx, "/bin/launchctl", "bootstrap", "system", servicePath)
	d.traceEnd(span, err)
	cancel()
	if err != nil {
		return d.failure("BOOTSTRAP", "LAUNCHD_BOOTSTRAP_FAILED", lifecycleFailure("launchd bootstrap failed", err))
	}
	r.phase = "READINESS_FAILED"
	r.active = &r.BeforeHTTPS
	for i := 0; i < 16; i++ {
		d.startupRound = i + 1
		roundSpan := d.traceBegin("READINESS_ROUND")
		roundDone, roundErr := func() (bool, error) {
			r.BeforeHTTPS = diagnosticUnknown()
			for j := range r.Servers {
				r.Servers[j].Readiness = "NOT_EXECUTED"
			}
			r.BeforeHTTPS.Job = "FAILED"
			d.diagnostic.Job = "UNKNOWN"
			loaded, running, err := d.traceState("READINESS_JOB")
			if err != nil {
				return true, d.failure("READINESS", "READINESS_JOB_UNAVAILABLE", lifecycleFailure("readiness job probe failed", err))
			}
			r.BeforeHTTPS.Job = "NOT_RUNNING"
			d.diagnostic.Job = "NOT_RUNNING"
			if loaded && running {
				r.BeforeHTTPS.Job = "RUNNING"
				d.diagnostic.Job = "RUNNING"
			}
			r.BeforeHTTPS.Public = "FAILED"
			d.diagnostic.Tun = "UNKNOWN"
			target, err := d.traceRoute("READINESS_PUBLIC_ROUTE", "1.1.1.1")
			if err != nil {
				return true, d.failure("READINESS", "READINESS_ROUTE_UNAVAILABLE", lifecycleFailure("readiness public route probe failed", err))
			}
			r.BeforeHTTPS.Public = "NOT_TUN"
			d.diagnostic.Tun = "NOT_TUN"
			if strings.HasPrefix(target, "utun") {
				r.BeforeHTTPS.Public = "TUN"
				d.diagnostic.Tun = "TUN"
			}
			d.startupRoutes = "READINESS_SERVER_ROUTES"
			if err := d.serverRoutes(baseline, servers); err != nil {
				return true, err
			}
			if loaded && running && strings.HasPrefix(target, "utun") {
				r.HTTPS = "FAILED"
				if err := d.httpsExitProbe(context.Background(), target, baseline, servers); err != nil {
					if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
						r.HTTPS = "CANCELLED"
					}
					return true, err
				}
				r.HTTPS = "SUCCEEDED_SAME_INVOCATION"
				r.active = &r.AfterHTTPS
				r.AfterHTTPS.Job = "FAILED"
				d.diagnostic.Job = "UNKNOWN"
				// Re-read after the blocking HTTPS probe; PID alone never establishes ready.
				l, runningFinal, err := d.traceState("FINAL_JOB")
				if err != nil {
					return true, d.failure("READINESS", "READINESS_JOB_UNAVAILABLE", lifecycleFailure("readiness final job probe failed", err))
				}
				r.AfterHTTPS.Job = "NOT_RUNNING"
				d.diagnostic.Job = "NOT_RUNNING"
				if l && runningFinal {
					d.receipt.AfterHTTPS.Job = "RUNNING"
					d.diagnostic.Job = "RUNNING"
				}
				d.receipt.AfterHTTPS.Public = "FAILED"
				d.diagnostic.Tun = "UNKNOWN"
				finalTarget, routeErr := d.traceRoute("FINAL_PUBLIC_ROUTE", "1.1.1.1")
				if routeErr != nil {
					return true, d.failure("READINESS", "READINESS_ROUTE_UNAVAILABLE", lifecycleFailure("readiness final public route probe failed", routeErr))
				}
				d.diagnostic.Tun = "NOT_TUN"
				if strings.HasPrefix(finalTarget, "utun") {
					d.diagnostic.Tun = "TUN"
				}
				if !l || !runningFinal || finalTarget != target {
					return true, d.failure("READINESS", "READINESS_CHANGED", errors.New("readiness changed during HTTPS probe"))
				}
				r.AfterHTTPS.Public = "VERIFIED_SAME_TUN"
				d.startupRoutes = "FINAL_SERVER_ROUTES"
				if err := d.serverRoutes(baseline, servers); err != nil {
					return true, err
				}
				r.AfterHTTPS.DNS = "FAILED"
				dns, err := d.traceDNS("FINAL_DNS")
				if err != nil {
					return true, d.failure("DNS", "DNS_STATE_UNAVAILABLE", lifecycleFailure("readiness DNS probe failed", err))
				}
				if len(dns) == 0 {
					return true, d.failure("DNS", "DNS_EVIDENCE_EMPTY", errors.New("readiness DNS evidence unavailable"))
				}
				r.AfterHTTPS.DNS = "OBSERVED_NONEMPTY"
				r.Readiness = "NETWORK_VERIFIED"
				fmt.Printf("AnyTLS TUN ready; all server routes preserved; HTTPS exit probe passed; TLS identity %s\n", map[bool]string{true: "unverified (one or more routed outbounds)", false: "verified by configured CA"}[insecure])
				return true, nil
			}
			return false, nil
		}()
		d.traceCapture()
		d.traceEnd(roundSpan, roundErr)
		if roundDone {
			return roundErr
		}
		if i < 15 {
			d.tracePause()
		}
	}
	d.startupRound = 0
	d.traceCapture()
	reason := "READINESS_UNKNOWN"
	switch {
	case d.diagnostic.Job == "NOT_RUNNING" && d.diagnostic.Tun == "NOT_TUN":
		reason = "PROCESS_AND_TUN_NOT_READY"
	case d.diagnostic.Job == "NOT_RUNNING":
		reason = "PROCESS_NOT_RUNNING"
	case d.diagnostic.Tun == "NOT_TUN":
		reason = "TUN_NOT_READY"
	}
	return d.failure("READINESS", reason, errors.New("TUN did not become ready"))
}

// Retry only curl's transient transport failures, never TLS verification,
// invalid content or unknown execution errors. No retry delay is needed: curl
// already has bounded connect/transfer waits, and identity is rechecked first.
func (d serviceLifecycle) httpsExitProbe(parent context.Context, target string, baseline networkBaseline, servers []string) error {
	ctx, cancel := context.WithTimeout(parent, 40*time.Second)
	defer cancel()
	var last error
	// state/route retain their existing four-second native tool bound. Reserve
	// that bound before each read, since those seams do not accept a context.
	checkRead := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		deadline, _ := ctx.Deadline()
		if time.Until(deadline) <= 4*time.Second {
			return context.DeadlineExceeded
		}
		return nil
	}
	for attempt := 0; attempt < 3; attempt++ {
		d.startupRound = attempt + 1
		if err := ctx.Err(); err != nil {
			return errors.Join(last, d.failure("HTTPS", "CANCELLED", lifecycleFailure("HTTPS exit probe cancelled", err)))
		}
		if attempt > 0 {
			if err := checkRead(); err != nil {
				return errors.Join(last, d.failure("READINESS", "CANCELLED", lifecycleFailure("HTTPS retry deadline unavailable", err)))
			}
			if d.diagnostic != nil {
				d.diagnostic.Job = "UNKNOWN"
			}
			loaded, running, err := d.traceState("HTTPS_RETRY_JOB")
			if err != nil {
				return errors.Join(last, d.failure("READINESS", "READINESS_JOB_UNAVAILABLE", lifecycleFailure("readiness retry job probe failed", err)))
			}
			if d.diagnostic != nil {
				d.diagnostic.Job = "UNLOADED"
				if loaded {
					d.diagnostic.Job = "NOT_RUNNING"
				}
				if loaded && running {
					d.diagnostic.Job = "RUNNING"
				}
			}
			if !loaded || !running {
				return errors.Join(last, d.failure("READINESS", "READINESS_CHANGED", errors.New("readiness changed before HTTPS retry")))
			}
			if err := checkRead(); err != nil {
				return errors.Join(last, d.failure("READINESS", "CANCELLED", lifecycleFailure("HTTPS retry deadline unavailable", err)))
			}
			if d.diagnostic != nil {
				d.diagnostic.Tun = "UNKNOWN"
			}
			current, err := d.traceRoute("HTTPS_RETRY_PUBLIC_ROUTE", "1.1.1.1")
			if err != nil {
				return errors.Join(last, d.failure("READINESS", "READINESS_ROUTE_UNAVAILABLE", lifecycleFailure("readiness retry public route probe failed", err)))
			}
			if d.diagnostic != nil {
				d.diagnostic.Tun = "NOT_TUN"
				if strings.HasPrefix(current, "utun") {
					d.diagnostic.Tun = "TUN"
				}
			}
			if current != target {
				return errors.Join(last, d.failure("READINESS", "READINESS_CHANGED", errors.New("readiness changed before HTTPS retry")))
			}
			if err := ctx.Err(); err != nil {
				return errors.Join(last, d.failure("HTTPS", "CANCELLED", lifecycleFailure("HTTPS exit probe cancelled", err)))
			}
			// Check cancellation between individual server route reads too.
			route := d.route
			retry := d
			retry.startupRoutes = "HTTPS_RETRY_SERVER_ROUTES"
			retry.route = func(server string) (string, error) {
				if err := checkRead(); err != nil {
					return "", err
				}
				return route(server)
			}
			if err := retry.serverRoutes(baseline, servers); err != nil {
				return errors.Join(last, err)
			}
			if err := ctx.Err(); err != nil {
				return errors.Join(last, d.failure("HTTPS", "CANCELLED", lifecycleFailure("HTTPS exit probe cancelled", err)))
			}
		}
		probeCtx, probeCancel := context.WithTimeout(ctx, 15*time.Second)
		span := d.traceBegin("HTTPS_ATTEMPT")
		probe, err := d.tool(probeCtx, "/usr/bin/curl", "--noproxy", "*", "-4", "-fsS", "--connect-timeout", "5", "--max-time", "12", "https://api.ipify.org")
		d.traceEnd(span, err)
		probeCancel()
		if ctx.Err() != nil {
			return errors.Join(lifecycleFailure("HTTPS exit probe failed", err), d.failure("HTTPS", "CANCELLED", lifecycleFailure("HTTPS exit probe cancelled", ctx.Err())))
		}
		if err == nil {
			if net.ParseIP(strings.TrimSpace(probe)) == nil {
				return d.failure("HTTPS", "HTTPS_RESPONSE_INVALID", errors.New("HTTPS exit probe returned invalid address"))
			}
			return nil
		}
		last = lifecycleFailure("HTTPS exit probe failed", err)
		var exit interface{ ExitCode() int }
		if !errors.As(err, &exit) {
			return d.failure("HTTPS", httpsFailureReason(last), last)
		}
		code := exit.ExitCode()
		category := "non-retryable"
		switch code {
		case 6:
			category = "DNS resolution"
		case 7:
			category = "connect"
		case 28:
			category = "timeout"
		case 35:
			category = "TLS handshake"
		case 52:
			category = "empty response"
		case 56:
			category = "receive"
		}
		last = lifecycleFailure(fmt.Sprintf("HTTPS exit probe failed (curl exit %d: %s; attempt %d/3)", code, category, attempt+1), err)
		if category == "non-retryable" || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return d.failure("HTTPS", httpsFailureReason(last), last)
		}
	}
	return d.failure("HTTPS", httpsFailureReason(last), last)
}

func (d serviceLifecycle) stop() (result error) {
	d.startupSegment = "STOP"
	d.startupRound = 0
	r := newDiagnostic("STOP")
	r.diagnostic = newStartDiagnostics("STOP")
	d.diagnostic = nil
	d.receipt = r
	defer d.finishReceipt(r, &result)
	return d.stopObserved(r)
}

func (d serviceLifecycle) stopObserved(r *serviceDiagnostic) error {
	if r.Operation != "STOP" {
		d.startupSegment = "ROLLBACK"
	}
	d.startupRound = 0
	if d.owned == nil || d.owned.info == nil {
		d.owned, _ = snapshotRootAt(d.root)
	}
	d.traceReceiptCapture(r, "STOP_CAPTURE") // Before deletion; never read a previous diagnostic receipt.
	if r.Operation == "STOP" {
		r.phase = "STOP_FAILED"
	}
	r.Restoration = "NOT_VERIFIED"
	r.Snapshot = "RETAINED"
	loaded, running, err := d.traceState("JOB_INITIAL")
	if err != nil {
		return lifecycleFailure("job state probe failed; stop not attempted", err)
	}
	if r.diagnostic != nil {
		r.diagnostic.Restoration = "UNKNOWN"
		r.diagnostic.Cleanup = "UNKNOWN"
	}
	if !loaded && !running {
		span := d.traceBegin("SNAPSHOT_EXISTENCE")
		_, existErr := os.Lstat(d.root)
		d.traceEnd(span, nil)
		if err := existErr; errors.Is(err, os.ErrNotExist) {
			r.Stopped = "VERIFIED"
			r.Snapshot = "ABSENT"
			if r.diagnostic != nil {
				r.diagnostic.Cleanup = "VERIFIED"
				r.diagnostic.Job = "UNLOADED"
			}
			r.Restoration = "UNAVAILABLE_NO_BASELINE"
			fmt.Println("AnyTLS TUN stopped")
			return nil
		} else if err != nil {
			return lifecycleFailure("snapshot unavailable; restoration not verified", err)
		}
	}
	span := d.traceBegin("STOP_BASELINE")
	var baseline networkBaseline
	var servers []string
	readErr := d.owned.check()
	if readErr == nil {
		baseline, servers, readErr = d.baseline()
	}
	d.traceEnd(span, readErr)
	if r.Operation == "STOP" && readErr == nil {
		r.serverScope(len(servers), "STORED_NOT_OBSERVED")
		r.Baseline = diagnosticEvidence{"UNKNOWN", "STORED_NOT_OBSERVED", "STORED_NOT_OBSERVED", "STORED_NOT_OBSERVED"}
	}
	if loaded || running {
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		d.traceCapture()
		span = d.traceBegin("BOOTOUT")
		_, bootErr := d.tool(ctx, "/bin/launchctl", "bootout", "system/"+serviceLabel)
		d.traceEnd(span, bootErr)
		cancel()
		if bootErr != nil {
			return errors.Join(lifecycleFailure("launchd bootout failed", bootErr), readErr)
		}
	}
	// Even without a baseline, confirm unload; never infer restoration from it.
	var last error
	for i := 0; i < 12; i++ {
		d.startupRound = i + 1
		roundSpan := d.traceBegin("STOP_ROUND")
		roundDone, roundErr := func() (bool, error) {
			loaded, running, err := d.traceState("JOB_INITIAL")
			if err != nil {
				return true, errors.Join(readErr, lifecycleFailure("stop job state probe failed", err))
			}
			if !loaded && !running {
				r.Restore.Job = "UNLOADED"
				r.Stopped = "VERIFIED"
				if r.diagnostic != nil && r.Operation == "STOP" {
					r.diagnostic.Job = "UNLOADED"
				}
				if readErr != nil {
					return true, d.stopRecoveryWarning(r, readErr)
				}
				last = d.restored(baseline, servers)
				var jobErr *restorationJobError
				if errors.As(last, &jobErr) {
					r.Stopped = "UNKNOWN"
					return true, last
				}
				var probeErr *lifecycleError
				if errors.As(last, &probeErr) {
					return true, d.stopRecoveryWarning(r, last)
				}
				if last == nil {
					r.Restoration = "VERIFIED"
					r.Stopped = "VERIFIED"
					if d.owned == nil {
						return true, errors.New("snapshot ownership unavailable; retained")
					}
					if err := d.traceRemove(); err != nil {
						if r.diagnostic != nil {
							r.diagnostic.Cleanup = "FAILED"
						}
						return true, lifecycleFailure("restoration verified but snapshot cleanup failed", err)
					}
					r.Snapshot = "REMOVED"
					if r.diagnostic != nil {
						r.diagnostic.Cleanup = "VERIFIED"
					}
					fmt.Println("AnyTLS TUN stopped; all server/public routes and DNS restoration verified")
					return true, nil
				}
			} else {
				last = errors.New("job remains loaded")
			}
			return false, nil
		}()
		d.traceEnd(roundSpan, roundErr)
		if roundDone {
			return roundErr
		}
		if i < 11 {
			d.tracePause()
		}
	}
	if r.Stopped == "VERIFIED" {
		return d.stopRecoveryWarning(r, errors.Join(readErr, last))
	}
	return errors.Join(readErr, lifecycleFailure("job remains loaded; snapshot retained", last))
}

func (d serviceLifecycle) stopRecoveryWarning(r *serviceDiagnostic, cause error) error {
	if r.diagnostic != nil {
		r.Restoration = r.diagnostic.Restoration
	}
	if err := d.archiveSnapshot(r); err != nil {
		if r.diagnostic != nil {
			r.diagnostic.Cleanup = "FAILED"
		}
		return errors.Join(cause, lifecycleFailure("recovery snapshot archival failed", err))
	}
	if r.diagnostic != nil {
		r.diagnostic.Cleanup = "VERIFIED"
	}
	fmt.Println("AnyTLS TUN stopped; warning: network restoration not verified; diagnostic snapshot archived")
	// Independent STOP succeeds after unload; failed START retains both causes.
	if r.Operation != "STOP" {
		return lifecycleFailure("rollback network restoration not verified; snapshot archived", cause)
	}
	return nil
}

// Read-only status, deliberately no network exit request or sudo.
func (d serviceLifecycle) status() (string, error) {
	loaded, running, err := d.state()
	if err != nil {
		return "AnyTLS TUN not_verified; job state unavailable", lifecycleFailure("job state probe failed", err)
	}
	state := "stopped"
	if loaded {
		state = "loaded"
	}
	if running {
		state = "running"
	}
	baseline, servers, err := d.baseline()
	if err != nil {
		if !loaded && !running {
			if _, e := os.Lstat(d.root); errors.Is(e, os.ErrNotExist) {
				archives, _ := filepath.Glob(filepath.Join(filepath.Dir(d.root), ".service-recovery-*"))
				if len(archives) > 0 {
					return "AnyTLS TUN stopped; previous recovery diagnostics archived; network restoration not_verified", nil
				}
				return "AnyTLS TUN stopped", nil
			}
		}
		return "AnyTLS TUN " + state + "; readiness not_verified; restoration not_verified (snapshot proof unavailable)", nil
	}
	if !loaded && !running {
		if err := d.restored(baseline, servers); err != nil {
			return "AnyTLS TUN stopped; restoration_failed; snapshot retained (will be archived on next start)", err
		}
		return "AnyTLS TUN stopped; restoration verified; snapshot retained", nil
	}
	if !running {
		return "AnyTLS TUN loaded; readiness not_verified", nil
	}
	iface, err := d.route("1.1.1.1")
	if err != nil {
		return "AnyTLS TUN running; readiness not_verified", lifecycleFailure("public route probe failed", err)
	}
	if err := d.serverRoutes(baseline, servers); err != nil {
		return "AnyTLS TUN running; readiness not_verified", err
	}
	dns, err := d.dns()
	if err != nil {
		return "AnyTLS TUN running; readiness not_verified", lifecycleFailure("DNS probe failed", err)
	}
	if len(dns) == 0 {
		return "AnyTLS TUN running; readiness not_verified (DNS unavailable)", nil
	}
	if !strings.HasPrefix(iface, "utun") {
		return "AnyTLS TUN running; network not ready; HTTPS not_verified", nil
	}
	// No unauthenticated on-disk ready receipt: only start's in-memory HTTPS
	// evidence can establish full ready. A later status proves network scope only.
	return "AnyTLS TUN running; network ready; HTTPS not_verified (no retained authoritative evidence)", nil
}

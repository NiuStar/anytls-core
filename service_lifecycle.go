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
	root       string
	tool       func(context.Context, string, ...string) (string, error)
	state      func() (bool, bool, error)
	route      func(string) (string, error)
	dns        func() ([]string, error)
	proxy      func() error
	stage      func(string, string, string, string) error
	remove     func(string) error
	pause      func()
	owned      *snapshotRootIdentity
	receipt    *serviceDiagnostic
	diagnostic *startDiagnostics
}

func newServiceLifecycle(root string) serviceLifecycle {
	owned := &snapshotRootIdentity{}
	return serviceLifecycle{root: root, tool: runTool, state: serviceState, route: routeInterface, owned: owned,
		dns: dnsServers, proxy: checkProxyInactive, stage: func(binary, config, core, root string) error {
			return stagePrivateRunOwned(binary, config, core, root, owned)
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
	servers, _, err := serviceOutbounds(filepath.Join(d.root, "config.yaml"), true)
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
func (d serviceLifecycle) serverRoutes(b networkBaseline, servers []string) error {
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
	}
	if d.receipt != nil {
		d.receipt.active.Servers = "VERIFIED"
	}
	return nil
}
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
	loaded, running, err := d.state()
	if d.receipt != nil {
		d.receipt.Restore.Job = "FAILED"
	}
	if err != nil {
		return lifecycleFailure("job state probe failed", err)
	}
	if loaded || running {
		if diagnostic != nil {
			diagnostic.Restoration = "FAILED"
		}
		return errors.New("job still loaded")
	}
	if d.receipt != nil {
		d.receipt.Restore.Job = "UNLOADED"
		d.receipt.Restore.Public = "FAILED"
	}
	iface, err := d.route("1.1.1.1")
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
	if err := d.serverRoutes(b, servers); err != nil {
		return err
	}
	if d.receipt != nil {
		d.receipt.Restore.DNS = "FAILED"
	}
	dns, err := d.dns()
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
	r := newDiagnostic("START")
	d.diagnostic = newStartDiagnostics("START")
	r.diagnostic = d.diagnostic
	d.receipt = r
	defer r.finish(d.root, &result)
	r.Baseline.Job = "FAILED"
	d.diagnostic.Job = "UNKNOWN"
	loaded, running, err := d.state()
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
	// Do not claim an existing directory or delete its diagnostic evidence.
	if _, err := os.Lstat(d.root); !errors.Is(err, os.ErrNotExist) {
		reason := "SNAPSHOT_UNAVAILABLE"
		if err == nil {
			reason = "SNAPSHOT_EXISTS"
		}
		return d.failure("SNAPSHOT", reason, lifecycleFailure("private snapshot already exists or is unavailable", err))
	}
	r.phase = "STAGING_FAILED"
	attempted := false
	preserveExisting := false
	defer func() {
		if result == nil || preserveExisting {
			return
		}
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
		loaded, running, err := d.state()
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
		if err := d.owned.remove(d.remove); err != nil {
			d.diagnostic.Cleanup = "FAILED"
			result = errors.Join(result, lifecycleFailure("private snapshot cleanup failed", err))
		} else {
			r.Snapshot = "REMOVED"
			d.diagnostic.Cleanup = "VERIFIED"
		}
	}()
	if err := d.stage(binary, config, core, d.root); err != nil {
		var stageErr *snapshotStageError
		if errors.As(err, &stageErr) {
			d.owned = stageErr.owned
		} else if !errors.Is(err, os.ErrExist) {
			// Concrete fixture staging hooks retain their existing cleanup seam.
			d.owned, _ = snapshotRootAt(d.root)
		}
		if !errors.Is(err, os.ErrExist) {
			r.capture(d.root)
			r.Snapshot = "STAGING_INCOMPLETE"
		}
		preserveExisting = errors.Is(err, os.ErrExist)
		return d.failure("SNAPSHOT", "SNAPSHOT_STAGE_FAILED", lifecycleFailure("private snapshot staging failed", err))
	}
	if d.owned == nil || d.owned.info == nil {
		d.owned, err = snapshotRootAt(d.root)
	}
	if err != nil {
		return d.failure("SNAPSHOT", "SNAPSHOT_IDENTITY_FAILED", err)
	}
	if err := d.owned.check(); err != nil {
		return d.failure("SNAPSHOT", "SNAPSHOT_IDENTITY_FAILED", err)
	}
	r.capture(d.root)
	r.Snapshot = "STAGED"
	// Stage first: compile the actual private inputs before baseline or control.
	servers, insecure, err := serviceOutbounds(filepath.Join(d.root, "config.yaml"), allowInsecure)
	if err != nil {
		return d.failure("CONFIG", "CONFIG_COMPILE_FAILED", err)
	}
	if err := d.proxy(); err != nil {
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
	for i, server := range servers {
		r.server(i, "FAILED")
		iface, err := d.route(server)
		if err != nil {
			return d.failure("SERVER_ROUTE", "SERVER_ROUTE_UNAVAILABLE", lifecycleFailure("server route preflight failed", err))
		}
		if !physicalInterface(iface) {
			return d.failure("SERVER_ROUTE", "SERVER_ROUTE_NOT_PHYSICAL", errors.New("server route is not on physical interface"))
		}
		baseline.Servers[server] = iface
		r.server(i, "CAPTURED_PHYSICAL")
	}
	r.Baseline.Servers = "CAPTURED_PHYSICAL"
	r.Baseline.Public = "FAILED"
	baseline.ServerInterface = baseline.Servers[baseline.Server]
	baseline.PublicInterface, err = d.route("1.1.1.1")
	if err != nil {
		return d.failure("PUBLIC_ROUTE", "PUBLIC_ROUTE_UNAVAILABLE", lifecycleFailure("public route preflight failed", err))
	}
	r.Baseline.Public = "CAPTURED"
	r.Baseline.DNS = "FAILED"
	baseline.DNS, err = d.dns()
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
	if err := os.WriteFile(filepath.Join(d.root, serviceBaselineName), raw, 0600); err != nil {
		return d.failure("BASELINE", "BASELINE_WRITE_FAILED", lifecycleFailure("baseline write failed", err))
	}
	// Recompile the staged bytes, not user config: confirm actual launch scope.
	if _, _, err := d.baseline(); err != nil {
		return d.failure("BASELINE", "BASELINE_INVALID", err)
	}
	plist, err := servicePlist(filepath.Join(d.root, "anytls-macos"), filepath.Join(d.root, "config.yaml"), filepath.Join(d.root, "sing-box"), filepath.Join(d.root, serviceLogName), insecure)
	if err != nil {
		return d.failure("PLIST", "PLIST_CREATE_FAILED", err)
	}
	servicePath := filepath.Join(d.root, "anytls.plist")
	f, err := os.OpenFile(servicePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return d.failure("PLIST", "PLIST_CREATE_FAILED", lifecycleFailure("plist create failed", err))
	}
	_, writeErr := f.WriteString(plist)
	closeErr := f.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		return d.failure("PLIST", "PLIST_WRITE_FAILED", lifecycleFailure("plist write/close failed", err))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	_, err = d.tool(ctx, "/usr/bin/plutil", "-lint", servicePath)
	cancel()
	if err != nil {
		return d.failure("PLIST", "PLIST_INVALID", lifecycleFailure("invalid launchd plist", err))
	}
	r.phase = "BOOTSTRAP_FAILED"
	ctx, cancel = context.WithTimeout(context.Background(), 8*time.Second)
	attempted = true // A failed bootstrap may still have loaded a job.
	_, err = d.tool(ctx, "/bin/launchctl", "bootstrap", "system", servicePath)
	cancel()
	if err != nil {
		return d.failure("BOOTSTRAP", "LAUNCHD_BOOTSTRAP_FAILED", lifecycleFailure("launchd bootstrap failed", err))
	}
	r.phase = "READINESS_FAILED"
	r.active = &r.BeforeHTTPS
	for i := 0; i < 16; i++ {
		r.BeforeHTTPS = diagnosticUnknown()
		for j := range r.Servers {
			r.Servers[j].Readiness = "NOT_EXECUTED"
		}
		r.BeforeHTTPS.Job = "FAILED"
		d.diagnostic.Job = "UNKNOWN"
		loaded, running, err := d.state()
		if err != nil {
			return d.failure("READINESS", "READINESS_JOB_UNAVAILABLE", lifecycleFailure("readiness job probe failed", err))
		}
		r.BeforeHTTPS.Job = "NOT_RUNNING"
		d.diagnostic.Job = "NOT_RUNNING"
		if loaded && running {
			r.BeforeHTTPS.Job = "RUNNING"
			d.diagnostic.Job = "RUNNING"
		}
		r.BeforeHTTPS.Public = "FAILED"
		d.diagnostic.Tun = "UNKNOWN"
		target, err := d.route("1.1.1.1")
		if err != nil {
			return d.failure("READINESS", "READINESS_ROUTE_UNAVAILABLE", lifecycleFailure("readiness public route probe failed", err))
		}
		r.BeforeHTTPS.Public = "NOT_TUN"
		d.diagnostic.Tun = "NOT_TUN"
		if strings.HasPrefix(target, "utun") {
			r.BeforeHTTPS.Public = "TUN"
			d.diagnostic.Tun = "TUN"
		}
		if err := d.serverRoutes(baseline, servers); err != nil {
			return err
		}
		if loaded && running && strings.HasPrefix(target, "utun") {
			r.HTTPS = "FAILED"
			if err := d.httpsExitProbe(context.Background(), target, baseline, servers); err != nil {
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					r.HTTPS = "CANCELLED"
				}
				return err
			}
			r.HTTPS = "SUCCEEDED_SAME_INVOCATION"
			r.active = &r.AfterHTTPS
			r.AfterHTTPS.Job = "FAILED"
			d.diagnostic.Job = "UNKNOWN"
			// Re-read after the blocking HTTPS probe; PID alone never establishes ready.
			l, runningFinal, err := d.state()
			if err != nil {
				return d.failure("READINESS", "READINESS_JOB_UNAVAILABLE", lifecycleFailure("readiness final job probe failed", err))
			}
			r.AfterHTTPS.Job = "NOT_RUNNING"
			d.diagnostic.Job = "NOT_RUNNING"
			if l && runningFinal {
				d.receipt.AfterHTTPS.Job = "RUNNING"
				d.diagnostic.Job = "RUNNING"
			}
			d.receipt.AfterHTTPS.Public = "FAILED"
			d.diagnostic.Tun = "UNKNOWN"
			finalTarget, routeErr := d.route("1.1.1.1")
			if routeErr != nil {
				return d.failure("READINESS", "READINESS_ROUTE_UNAVAILABLE", lifecycleFailure("readiness final public route probe failed", routeErr))
			}
			d.diagnostic.Tun = "NOT_TUN"
			if strings.HasPrefix(finalTarget, "utun") {
				d.diagnostic.Tun = "TUN"
			}
			if !l || !runningFinal || finalTarget != target {
				return d.failure("READINESS", "READINESS_CHANGED", errors.New("readiness changed during HTTPS probe"))
			}
			r.AfterHTTPS.Public = "VERIFIED_SAME_TUN"
			if err := d.serverRoutes(baseline, servers); err != nil {
				return err
			}
			r.AfterHTTPS.DNS = "FAILED"
			dns, err := d.dns()
			if err != nil {
				return d.failure("DNS", "DNS_STATE_UNAVAILABLE", lifecycleFailure("readiness DNS probe failed", err))
			}
			if len(dns) == 0 {
				return d.failure("DNS", "DNS_EVIDENCE_EMPTY", errors.New("readiness DNS evidence unavailable"))
			}
			r.AfterHTTPS.DNS = "OBSERVED_NONEMPTY"
			r.Readiness = "NETWORK_VERIFIED"
			fmt.Printf("AnyTLS TUN ready; all server routes preserved; HTTPS exit probe passed; TLS identity %s\n", map[bool]string{true: "unverified (one or more routed outbounds)", false: "verified by configured CA"}[insecure])
			return nil
		}
		if i < 15 {
			d.pause()
		}
	}
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
			loaded, running, err := d.state()
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
			current, err := d.route("1.1.1.1")
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
		probe, err := d.tool(probeCtx, "/usr/bin/curl", "--noproxy", "*", "-4", "-fsS", "--connect-timeout", "5", "--max-time", "12", "https://api.ipify.org")
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
	r := newDiagnostic("STOP")
	r.diagnostic = newStartDiagnostics("STOP")
	d.diagnostic = nil
	d.receipt = r
	defer r.finish(d.root, &result)
	return d.stopObserved(r)
}

func (d serviceLifecycle) stopObserved(r *serviceDiagnostic) error {
	if d.owned == nil || d.owned.info == nil {
		d.owned, _ = snapshotRootAt(d.root)
	}
	r.capture(d.root) // Before deletion; never read a previous diagnostic receipt.
	if r.Operation == "STOP" {
		r.phase = "STOP_FAILED"
	}
	r.Restoration = "NOT_VERIFIED"
	r.Snapshot = "RETAINED"
	loaded, running, err := d.state()
	if err != nil {
		return lifecycleFailure("job state probe failed; stop not attempted", err)
	}
	if r.diagnostic != nil {
		r.diagnostic.Restoration = "UNKNOWN"
		r.diagnostic.Cleanup = "UNKNOWN"
	}
	if !loaded && !running {
		if _, err := os.Lstat(d.root); errors.Is(err, os.ErrNotExist) {
			r.Stopped = "VERIFIED"
			r.Snapshot = "ABSENT"
			if r.diagnostic != nil {
				r.diagnostic.Cleanup = "VERIFIED"
			}
			r.Restoration = "UNAVAILABLE_NO_BASELINE"
			fmt.Println("AnyTLS TUN stopped")
			return nil
		} else if err != nil {
			return lifecycleFailure("snapshot unavailable; restoration not verified", err)
		}
	}
	baseline, servers, readErr := d.baseline()
	if r.Operation == "STOP" && readErr == nil {
		r.serverScope(len(servers), "STORED_NOT_OBSERVED")
		r.Baseline = diagnosticEvidence{"UNKNOWN", "STORED_NOT_OBSERVED", "STORED_NOT_OBSERVED", "STORED_NOT_OBSERVED"}
	}
	if loaded || running {
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		_, bootErr := d.tool(ctx, "/bin/launchctl", "bootout", "system/"+serviceLabel)
		cancel()
		if bootErr != nil {
			return errors.Join(lifecycleFailure("launchd bootout failed", bootErr), readErr)
		}
	}
	// Even without a baseline, confirm unload; never infer restoration from it.
	var last error
	for i := 0; i < 12; i++ {
		loaded, running, err := d.state()
		if err != nil {
			return errors.Join(readErr, lifecycleFailure("stop job state probe failed", err))
		}
		if !loaded && !running {
			r.Restore.Job = "UNLOADED"
			if readErr != nil {
				return lifecycleFailure("job unloaded; restoration not verified; snapshot retained", readErr)
			}
			last = d.restored(baseline, servers)
			var probeErr *lifecycleError
			if errors.As(last, &probeErr) {
				return lifecycleFailure("restoration_failed; snapshot retained", last)
			}
			if last == nil {
				r.Restoration = "VERIFIED"
				r.Stopped = "VERIFIED"
				if d.owned == nil {
					return errors.New("snapshot ownership unavailable; retained")
				}
				if err := d.owned.remove(d.remove); err != nil {
					if r.diagnostic != nil {
						r.diagnostic.Cleanup = "FAILED"
					}
					return lifecycleFailure("restoration verified but snapshot cleanup failed", err)
				}
				r.Snapshot = "REMOVED"
				if r.diagnostic != nil {
					r.diagnostic.Cleanup = "VERIFIED"
				}
				fmt.Println("AnyTLS TUN stopped; all server/public routes and DNS restoration verified")
				return nil
			}
		} else {
			last = errors.New("job remains loaded")
		}
		if i < 11 {
			d.pause()
		}
	}
	return errors.Join(readErr, lifecycleFailure("restoration_failed; snapshot retained", last))
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
				return "AnyTLS TUN stopped", nil
			}
		}
		return "AnyTLS TUN " + state + "; readiness not_verified; restoration not_verified (snapshot proof unavailable)", nil
	}
	if !loaded && !running {
		if err := d.restored(baseline, servers); err != nil {
			return "AnyTLS TUN restoration_failed; snapshot retained", err
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

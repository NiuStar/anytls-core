package main

import (
	"context"
	"errors"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const webNodeProbeTimeout = 8 * time.Second

var errNodeProbeUnsupported = errors.New("node probe unsupported")

type webNodeProbeResult struct {
	Name         string   `json:"name"`
	Mode         string   `json:"mode"`
	Status       string   `json:"status"`
	LatencyMS    *float64 `json:"latency_ms"`
	Error        string   `json:"error"`
	CheckedAt    string   `json:"checked_at"`
	RiskInsecure bool     `json:"risk_insecure"`
	ConfigETag   string   `json:"config_etag"`
}

// Called by the authenticated, CSRF-protected dispatcher. Probes never save,
// select, reload or start the VPN. Both short actionMu phases are shared reads.
func (w *webConsole) probeNodeHandler(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		webError(rw, 405, "METHOD_NOT_ALLOWED")
		return
	}
	if !w.actionMu.TryRLock() {
		webError(rw, 409, "ACTION_BUSY")
		return
	}
	locked := true
	defer func() {
		if locked {
			w.actionMu.RUnlock()
		}
	}()
	var in struct {
		Name            string `json:"name"`
		Mode            string `json:"mode"`
		ConfirmInsecure bool   `json:"confirm_insecure"`
	}
	if webDecode(rw, r, &in) != nil || in.Name == "" || (in.Mode != "tcp" && in.Mode != "https") {
		webError(rw, 400, "INVALID_INPUT")
		return
	}
	if r.Header.Get("If-Match") == "" {
		webError(rw, 428, "IF_MATCH_REQUIRED")
		return
	}
	b, err := readSnapshotSource(w.configPath, snapshotConfigLimit, false)
	if err != nil {
		webError(rw, 503, "CONFIG_UNAVAILABLE")
		return
	}
	etag := `"` + shaHex(b) + `"`
	if r.Header.Get("If-Match") != etag {
		webError(rw, 412, "CONFIG_CONFLICT")
		return
	}
	nodes, err := loadNodesBytes(b)
	if err != nil {
		webError(rw, 422, "CONFIG_VALIDATION_FAILED")
		return
	}
	var selected node
	found := false
	for _, n := range nodes {
		if n.Name == in.Name {
			selected, found = n, true
			break
		}
	}
	if !found {
		webError(rw, 404, "NODE_NOT_FOUND")
		return
	}
	risk := selected.SkipVerify && selected.CA == ""
	if in.Mode == "https" && risk && !in.ConfirmInsecure {
		webError(rw, 400, "INSECURE_CONFIRMATION_REQUIRED")
		return
	}
	w.probeSlotsOnce.Do(func() {
		w.probeSlots = make(chan struct{}, 8)
	})
	slots := w.probeSlots
	select {
	case slots <- struct{}{}:
		defer func() { <-slots }()
	default:
		webError(rw, 429, "PROBE_BUSY")
		return
	}
	result := webNodeProbeResult{Name: in.Name, Mode: in.Mode, Status: "FAILED", RiskInsecure: risk, ConfigETag: etag}
	ctx, cancel := context.WithTimeout(r.Context(), webNodeProbeTimeout)
	defer cancel()
	probe := w.nodeProbe
	if probe == nil {
		probe = webNodeProbe
	}
	w.actionMu.RUnlock()
	locked = false
	var ms float64
	if selected.Type != "anytls" {
		err = errNodeProbeUnsupported
	} else {
		ms, err = probe(ctx, selected, in.Mode)
	}
	// Synchronous probe cleanup has completed before finalization or slot release.
	if !w.actionMu.TryRLock() {
		webError(rw, 409, "ACTION_BUSY")
		return
	}
	locked = true
	latest, readErr := readSnapshotSource(w.configPath, snapshotConfigLimit, false)
	if readErr != nil || `"`+shaHex(latest)+`"` != etag {
		webError(rw, 412, "CONFIG_CONFLICT")
		return
	}
	// A canceled/deadline-expired request cannot publish a successful sample,
	// even if a transport raced with cancellation.
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	switch {
	case errors.Is(err, errNodeProbeUnsupported):
		result.Status, result.Error = "UNSUPPORTED", "PROBE_UNSUPPORTED"
	case errors.Is(err, context.DeadlineExceeded):
		result.Status, result.Error = "TIMEOUT", "PROBE_TIMEOUT"
	case errors.Is(err, context.Canceled):
		result.Error = "PROBE_CANCELED"
	case err != nil:
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			result.Status, result.Error = "TIMEOUT", "PROBE_TIMEOUT"
		} else {
			result.Error = "PROBE_FAILED"
		}
	case math.IsNaN(ms) || math.IsInf(ms, 0) || ms < 0:
		result.Error = "PROBE_FAILED"
	default:
		result.Status, result.LatencyMS = "OK", &ms
	}
	result.CheckedAt = w.now().UTC().Format(time.RFC3339Nano)
	rw.Header().Set("ETag", etag)
	webJSON(rw, 200, result)
}

// TCP is only a direct connect time to the configured server, NOT AnyTLS
// authentication, proxy readiness, throughput or an automatic selection signal.
// Configured private/loopback servers are allowed; there is no request URL.
func webNodeProbe(ctx context.Context, n node, mode string) (float64, error) {
	if mode != "tcp" && mode != "https" {
		return 0, errNodeProbeUnsupported
	}
	ctx, cancel := context.WithTimeout(ctx, webNodeProbeTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if n.Type != "anytls" || n.Port < 1 || n.Port > 65535 || strings.TrimSpace(n.Server) == "" || strings.ContainsAny(n.Server, " /\t\r\n%") {
		return 0, errors.New("invalid node probe configuration")
	}
	if mode == "https" {
		return webEmbeddedNodeProbe(ctx, n)
	}
	start := time.Now()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(n.Server, strconv.Itoa(n.Port)))
	if err != nil {
		return 0, err
	}
	elapsed := float64(time.Since(start)) / float64(time.Millisecond)
	if err := conn.Close(); err != nil {
		return 0, errors.New("node probe close failed")
	}
	return elapsed, ctx.Err()
}

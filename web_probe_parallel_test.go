package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

const parallelProbeWait = 2 * time.Second

type parallelProbeRequest struct {
	done   chan struct{}
	cancel context.CancelFunc
	rec    *httptest.ResponseRecorder
}

type parallelProbeFixture struct {
	w          *webConsole
	cookie     *http.Cookie
	csrf, etag string
	release    chan struct{}
	entered    chan string
	once       sync.Once
	requests   []*parallelProbeRequest
}

func newParallelProbeFixture(t *testing.T) *parallelProbeFixture {
	t.Helper()
	w, cookie, csrf, etag := probeWebFixture(t)
	f := &parallelProbeFixture{w: w, cookie: cookie, csrf: csrf, etag: etag, release: make(chan struct{}), entered: make(chan string, 32)}
	w.nodeProbe = func(ctx context.Context, n node, mode string) (float64, error) {
		f.entered <- mode
		select {
		case <-f.release:
		case <-ctx.Done():
		}
		// Deliberately return a nominal sample even after cancellation.
		return 17, nil
	}
	t.Cleanup(func() {
		f.unblock()
		for _, r := range f.requests {
			r.cancel()
		}
		for _, r := range f.requests {
			select {
			case <-r.done:
			case <-time.After(parallelProbeWait):
				t.Error("request goroutine did not join")
			}
		}
	})
	return f
}

func (f *parallelProbeFixture) unblock() { f.once.Do(func() { close(f.release) }) }

func (f *parallelProbeFixture) start(mode string) *parallelProbeRequest {
	ctx, cancel := context.WithCancel(context.Background())
	p := &parallelProbeRequest{done: make(chan struct{}), cancel: cancel}
	f.requests = append(f.requests, p)
	go func() {
		defer close(p.done)
		r := httptest.NewRequest("POST", "http://127.0.0.1:18089/api/v1/nodes/probe", strings.NewReader(`{"name":"first","mode":"`+mode+`","confirm_insecure":true}`)).WithContext(ctx)
		r.Host = "127.0.0.1:18089"
		r.Header.Set("Origin", "http://"+r.Host)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", f.csrf)
		r.Header.Set("If-Match", f.etag)
		r.AddCookie(f.cookie)
		p.rec = httptest.NewRecorder()
		f.w.ServeHTTP(p.rec, r)
	}()
	return p
}

func (f *parallelProbeFixture) awaitEntry(t *testing.T, p *parallelProbeRequest) bool {
	t.Helper()
	select {
	case <-f.entered:
		return true
	case <-p.done:
		t.Errorf("network entry required before first response; HTTP=%d body=%s", p.rec.Code, p.rec.Body.String())
	case <-time.After(parallelProbeWait):
		t.Error("network entry timeout")
	}
	return false
}

func awaitParallelProbe(t *testing.T, p *parallelProbeRequest) *httptest.ResponseRecorder {
	t.Helper()
	select {
	case <-p.done:
		return p.rec
	case <-time.After(parallelProbeWait):
		t.Error("response timeout")
		return nil
	}
}

func requireParallelError(t *testing.T, r *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if r == nil {
		return
	}
	var body map[string]any
	if json.Unmarshal(r.Body.Bytes(), &body) != nil || r.Code != status || body["error"] != code || len(body) != 1 {
		t.Errorf("expected HTTP=%d error-only %s, got HTTP=%d %s", status, code, r.Code, r.Body.String())
	}
}

func fillParallelProbes(t *testing.T, f *parallelProbeFixture) []*parallelProbeRequest {
	t.Helper()
	var active []*parallelProbeRequest
	for i := 0; i < 8; i++ {
		mode := "tcp"
		if i%2 != 0 {
			mode = "https"
		}
		p := f.start(mode)
		active = append(active, p)
		if !f.awaitEntry(t, p) {
			return nil
		}
	}
	return active
}

func TestWebNodeProbeParallelCapacity(t *testing.T) {
	f := newParallelProbeFixture(t)
	active := fillParallelProbes(t, f)
	if active == nil {
		return
	}
	ninth := f.start("tcp")
	requireParallelError(t, awaitParallelProbe(t, ninth), 429, "PROBE_BUSY")
	select {
	case mode := <-f.entered:
		t.Errorf("ninth reached network: %s", mode)
	default:
	}
	for _, p := range active {
		select {
		case <-p.done:
			t.Error("held probe returned before release")
		default:
		}
	}
	t.Log("business witness: active=8 rejected=1 network admissions=8 TCP+HTTPS shared")
	f.unblock()
	for _, p := range active {
		awaitParallelProbe(t, p)
	}
	if r := awaitParallelProbe(t, f.start("tcp")); r != nil && r.Code != 200 {
		t.Errorf("capacity recovery HTTP=%d", r.Code)
	}
}

func TestWebNodeProbeParallelMutationLockAvailable(t *testing.T) {
	f := newParallelProbeFixture(t)
	p := f.start("tcp")
	if !f.awaitEntry(t, p) {
		return
	}
	if !f.w.actionMu.TryLock() {
		t.Error("mutation TryLock unavailable during held network")
		return
	}
	f.w.actionMu.Unlock()
	f.unblock()
	awaitParallelProbe(t, p)
}

func TestWebNodeProbeParallelFinalBusy(t *testing.T) {
	f := newParallelProbeFixture(t)
	p := f.start("tcp")
	if !f.awaitEntry(t, p) {
		return
	}
	if !f.w.actionMu.TryLock() {
		t.Error("cannot arrange final contention: network owns actionMu")
		return
	}
	func() {
		// Unlock before fixture cleanup even on an assertion failure.
		defer f.w.actionMu.Unlock()
		f.unblock()
		requireParallelError(t, awaitParallelProbe(t, p), 409, "ACTION_BUSY")
	}()
	select {
	case <-p.done:
	default:
		return
	}
	// Refill all eight held slots, not merely a single sequential slot.
	f.release = make(chan struct{})
	f.once = sync.Once{}
	active := fillParallelProbes(t, f)
	if active == nil {
		return
	}
	requireParallelError(t, awaitParallelProbe(t, f.start("tcp")), 429, "PROBE_BUSY")
	f.unblock()
	for _, p := range active {
		awaitParallelProbe(t, p)
	}
}

// Control: final ETag rejection is already accepted behavior in the old backend.
func TestWebNodeProbeParallelFinalConfigControl(t *testing.T) {
	f := newParallelProbeFixture(t)
	p := f.start("tcp")
	if !f.awaitEntry(t, p) {
		return
	}
	if err := os.WriteFile(f.w.configPath, []byte("nodes: []\n"), 0600); err != nil {
		t.Fatal(err)
	}
	f.unblock()
	requireParallelError(t, awaitParallelProbe(t, p), 412, "CONFIG_CONFLICT")
}

// Control: cancellation must override a seam's nominal successful sample.
func TestWebNodeProbeParallelCanceledSuccessControl(t *testing.T) {
	f := newParallelProbeFixture(t)
	p := f.start("tcp")
	if !f.awaitEntry(t, p) {
		return
	}
	p.cancel()
	r := awaitParallelProbe(t, p)
	if r == nil {
		return
	}
	var body webNodeProbeResult
	if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &body) != nil || body.Status != "FAILED" || body.Error != "PROBE_CANCELED" || body.LatencyMS != nil {
		t.Errorf("canceled request published fake success: HTTP=%d %s", r.Code, r.Body.String())
	}
	// Fresh request must enter while the original shared release stays closed.
	next := f.start("https")
	if !f.awaitEntry(t, next) {
		return
	}
	f.unblock()
	awaitParallelProbe(t, next)
}

func TestWebNodeProbeParallelCancellationReleasesCapacity(t *testing.T) {
	f := newParallelProbeFixture(t)
	active := fillParallelProbes(t, f)
	if active == nil {
		return
	}
	active[0].cancel()
	r := awaitParallelProbe(t, active[0])
	if r != nil && (strings.Contains(r.Body.String(), `"status":"OK"`) || !strings.Contains(r.Body.String(), `"latency_ms":null`)) {
		t.Errorf("cancellation fake sample: %s", r.Body.String())
	}
	replacement := f.start("https")
	if !f.awaitEntry(t, replacement) {
		return
	}
	requireParallelError(t, awaitParallelProbe(t, f.start("tcp")), 429, "PROBE_BUSY")
	f.unblock()
	for _, p := range append(active[1:], replacement) {
		awaitParallelProbe(t, p)
	}
}

// Control: mutation lock contention must reject without network entry.
func TestWebNodeProbeParallelInitialBusyControl(t *testing.T) {
	f := newParallelProbeFixture(t)
	f.w.actionMu.Lock()
	p := f.start("tcp")
	r := awaitParallelProbe(t, p)
	f.w.actionMu.Unlock()
	requireParallelError(t, r, 409, "ACTION_BUSY")
	select {
	case <-f.entered:
		t.Error("initial-busy performed network")
	default:
	}
}

func TestWebNodeProbeParallelConcurrency(t *testing.T) {
	f := newParallelProbeFixture(t)
	first := f.start("tcp")
	if !f.awaitEntry(t, first) {
		return
	}
	second := f.start("https")
	if !f.awaitEntry(t, second) {
		return
	}
	select {
	case <-first.done:
		t.Error("first response escaped held network")
	default:
	}
	t.Log("business witness: entered=2 before first response")
	f.unblock()
	for _, p := range []*parallelProbeRequest{first, second} {
		if r := awaitParallelProbe(t, p); r != nil && r.Code != 200 {
			// Concurrent finalization may legitimately lose the final TryLock.
			requireParallelError(t, r, 409, "ACTION_BUSY")
		}
	}
}

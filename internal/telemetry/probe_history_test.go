package telemetry

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestHistoryPrivateBoundedRestartAndRejectUnsafeLeaf(t *testing.T) {
	path := filepath.Join(t.TempDir(), "webui-metrics.json")
	now := time.Now().UTC()
	s := New(path)
	s.Record(now.Add(-time.Second), now, nil)
	flushStore(t, s)
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("private file %v %v", st, err)
	}
	reopened := New(path)
	if g := reopened.Snapshot(now); g.Network.Attempts != 1 || g.Network.HistoryStatus != "OK" {
		t.Fatalf("restart lost actual sample: %+v", g.Network)
	}
	// A restart gap does not become observations or a fabricated full-day SLA.
	if g := reopened.Snapshot(now.Add(2 * time.Hour)); g.Network.Attempts != 1 || g.Network.State != "STALE" || g.Network.Availability24h != nil {
		t.Fatal(g.Network)
	}
	bad := filepath.Join(t.TempDir(), "link.json")
	if err = os.Symlink(path, bad); err != nil {
		t.Fatal(err)
	}
	unsafe := New(bad)
	unsafe.Record(now.Add(time.Second), now.Add(2*time.Second), nil)
	flushStore(t, unsafe)
	if g := unsafe.Snapshot(now.Add(2 * time.Second)); g.Network.HistoryStatus != "UNAVAILABLE" {
		t.Fatal(g.Network)
	}
	if g := New(path).Snapshot(now); g.Network.Attempts != 1 {
		t.Fatal("symlink write touched target")
	}
	if err = os.WriteFile(path, []byte(`{"schema_version":1,"target":"https://evil.invalid","samples":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if g := New(path).Snapshot(now); g.Network.Attempts != 0 || g.Network.HistoryStatus != "UNAVAILABLE" {
		t.Fatal("untrusted history accepted")
	}
	memory := New("")
	start := now.Add(-time.Hour)
	for i := 0; i < MaxSamples+20; i++ {
		p := start.Add(time.Duration(i) * time.Second)
		memory.Record(p, p.Add(time.Millisecond), nil)
	}
	if len(memory.rows) != MaxSamples {
		t.Fatal("history count unbounded", len(memory.rows))
	}
}

func TestHTTPSProbeStrictTLSNoProxyNoRedirect(t *testing.T) {
	var hits atomic.Int32
	var status atomic.Int32
	status.Store(204)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Method != "GET" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Error("unexpected request")
		}
		if status.Load() == 302 {
			w.Header().Set("Location", "https://forbidden.invalid/")
		}
		w.WriteHeader(int(status.Load()))
	}))
	defer server.Close()
	trust := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	if trust.InsecureSkipVerify {
		t.Fatal("fixture disables verification")
	}
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("NO_PROXY", "")
	if err := probeHTTPS(context.Background(), server.URL, trust); err != nil {
		t.Fatal("positive strict TLS loopback", err)
	}
	if hits.Load() != 1 {
		t.Fatal(hits.Load())
	}
	if err := probeHTTPS(context.Background(), server.URL, nil); err == nil {
		t.Fatal("untrusted certificate accepted")
	}
	if hits.Load() != 1 {
		t.Fatal("invalid TLS reached HTTP")
	}
	status.Store(302)
	if err := probeHTTPS(context.Background(), server.URL, trust); err == nil {
		t.Fatal("redirect accepted")
	}
	if hits.Load() != 2 {
		t.Fatal("redirect retried")
	}
	c, cancel := context.WithCancel(context.Background())
	cancel()
	if err := probeHTTPS(c, server.URL, trust); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation %v", err)
	}
	if err := probeHTTPS(context.Background(), "http://127.0.0.1", &tls.Config{}); err == nil {
		t.Fatal("HTTP accepted")
	}
}

func TestResidentSamplerCompletesWithoutAnyHTTPReadAndStops(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(204) }))
	defer server.Close()
	trust := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	path := filepath.Join(t.TempDir(), "history.json")
	s := New(path)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.run(ctx, 20*time.Millisecond, func(c context.Context) error { return probeHTTPS(c, server.URL, trust) })
	}()
	deadline := time.Now().Add(3 * time.Second)
	for hits.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stop did not join sampler")
	}
	flushStore(t, s)
	n := hits.Load()
	time.Sleep(40 * time.Millisecond)
	if hits.Load() != n || n < 3 {
		t.Fatalf("resident/stop failed %d -> %d", n, hits.Load())
	}
	g := New(path).Snapshot(time.Now())
	if g.Network.Attempts < 2 || g.Network.Succeeded != g.Network.Attempts || g.Traffic.Quality != "NOT_OBSERVED" {
		t.Fatal(g.Network)
	}
}

func TestSamplerCanceledProbeDoesNotPublishFailure(t *testing.T) {
	s := New("")
	ctx, cancel := context.WithCancel(context.Background())
	entered := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.run(ctx, time.Hour, func(c context.Context) error { close(entered); <-c.Done(); return c.Err() })
	}()
	<-entered
	cancel()
	<-done
	if g := s.Snapshot(time.Now()); g.Network.Attempts != 0 {
		t.Fatal("shutdown counted as failure")
	}
}

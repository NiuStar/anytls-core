package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// Real authenticated HTTP requests call the production TCP dial/Close path.
// A test-only post-dial barrier holds completed network work before publication;
// it does not claim eight TCP connects remain in flight after Dial returns.
func TestWebNodeProbeHTTPParallelTCP(t *testing.T) {
	w, cookie, csrf, _ := probeWebFixture(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan struct{}, 64)
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
			accepted <- struct{}{}
		}
	}()
	defer func() { listener.Close(); <-acceptDone }()
	b := []byte(fmt.Sprintf("nodes:\n  - {name: first, type: anytls, server: 127.0.0.1, port: %d, password: fixture}\n", listener.Addr().(*net.TCPAddr).Port))
	if err := os.WriteFile(w.configPath, b, 0600); err != nil {
		t.Fatal(err)
	}
	etag := `"` + shaHex(b) + `"`
	server := httptest.NewServer(w)
	defer server.Close()
	client := &http.Client{Timeout: 5 * time.Second}
	defer client.CloseIdleConnections()
	totalOK, totalBusy := 0, 0
	for round := 0; round < 5; round++ {
		func() {
			gate := make(chan struct{})
			var release sync.Once
			defer release.Do(func() { close(gate) })
			entered := make(chan struct{}, 8)
			w.nodeProbe = func(ctx context.Context, n node, mode string) (float64, error) {
				ms, err := webNodeProbe(ctx, n, mode)
				entered <- struct{}{}
				select {
				case <-gate:
				case <-ctx.Done():
				}
				return ms, err
			}
			type reply struct {
				status int
				body   []byte
				err    error
			}
			done := make(chan reply, 8)
			request := func() reply {
				r, _ := http.NewRequest("POST", server.URL+"/api/v1/nodes/probe", strings.NewReader(`{"name":"first","mode":"tcp"}`))
				r.Host = "127.0.0.1:18089"
				r.Header.Set("Origin", "http://"+r.Host)
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("X-CSRF-Token", csrf)
				r.Header.Set("If-Match", etag)
				r.AddCookie(cookie)
				resp, err := client.Do(r)
				if err != nil {
					return reply{err: err}
				}
				defer resp.Body.Close()
				body, err := io.ReadAll(resp.Body)
				return reply{resp.StatusCode, body, err}
			}
			for i := 0; i < 8; i++ {
				go func() { done <- request() }()
				select {
				case <-entered:
				case <-time.After(2 * time.Second):
					t.Fatal("HTTP request did not enter real TCP probe")
				}
				select {
				case <-accepted:
				case <-time.After(2 * time.Second):
					t.Fatal("target did not accept real TCP connection")
				}
			}
			ninth := request()
			if ninth.err != nil || ninth.status != 429 || string(ninth.body) != "{\"error\":\"PROBE_BUSY\"}\n" {
				t.Fatalf("ninth reply: %+v", ninth)
			}
			if !w.actionMu.TryLock() {
				t.Fatal("network held action lock")
			}
			w.actionMu.Unlock()
			// Broadcast all eight completions together, not staggered to hide contention.
			release.Do(func() { close(gate) })
			ok, busy := 0, 0
			for i := 0; i < 8; i++ {
				reply := <-done
				if reply.err != nil {
					t.Fatal(reply.err)
				}
				switch reply.status {
				case 200:
					var result webNodeProbeResult
					if json.Unmarshal(reply.body, &result) != nil || result.Status != "OK" || result.LatencyMS == nil || *result.LatencyMS < 0 {
						t.Fatalf("bad TCP result %s", reply.body)
					}
					ok++
				case 409:
					if string(reply.body) != "{\"error\":\"ACTION_BUSY\"}\n" {
						t.Fatalf("busy leaked sample %s", reply.body)
					}
					busy++
				default:
					t.Fatalf("unexpected reply %d %s", reply.status, reply.body)
				}
			}
			if ok == 0 {
				t.Fatal("no completed probe published")
			}
			totalOK += ok
			totalBusy += busy
			t.Logf("completion round=%d real_tcp=8 HTTP200=%d HTTP409=%d rejected429=1", round, ok, busy)
		}()
	}
	t.Logf("completion totals real_tcp=40 HTTP200=%d HTTP409=%d rejected429=5", totalOK, totalBusy)
}

func TestWebNodeProbeCanceledCleanupKeepsSlot(t *testing.T) {
	f := newParallelProbeFixture(t)
	cleanup := make(chan struct{})
	defer close(cleanup)
	f.w.nodeProbe = func(ctx context.Context, n node, mode string) (float64, error) {
		f.entered <- mode
		<-ctx.Done()
		<-cleanup // Model synchronous Close that has not actually completed.
		return 1, nil
	}
	active := fillParallelProbes(t, f)
	if active == nil {
		return
	}
	active[0].cancel()
	requireParallelError(t, awaitParallelProbe(t, f.start("tcp")), 429, "PROBE_BUSY")
	select {
	case <-active[0].done:
		t.Fatal("cancellation released slot before synchronous cleanup")
	default:
	}
	for _, p := range active {
		p.cancel()
	}
}

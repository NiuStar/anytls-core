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
func TestWebNodeProbeSharedHTTPBroadcastTCP(t *testing.T) {
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
			if ok != 8 || busy != 0 {
				t.Errorf("shared completion requires 8 OK / 0 busy: got OK=%d busy=%d", ok, busy)
			}
			totalOK += ok
			totalBusy += busy
			t.Logf("completion round=%d real_tcp=8 HTTP200=%d HTTP409=%d rejected429=1", round, ok, busy)
		}()
	}
	t.Logf("completion totals real_tcp=40 peer_accept=40 HTTP200=%d HTTP409=%d rejected429=5", totalOK, totalBusy)
	if totalOK != 40 || totalBusy != 0 {
		t.Errorf("shared publication requires 40 OK / 0 busy")
	}
}

// sharedEntryBody holds the real decode phase, not an external writer.
// It is compatible with the old Mutex source; no proposed fields/helpers used.
type sharedEntryBody struct {
	io.Reader
	entered chan<- struct{}
	gate    <-chan struct{}
	once    sync.Once
}

func (b *sharedEntryBody) Read(p []byte) (int, error) {
	b.once.Do(func() { b.entered <- struct{}{}; <-b.gate })
	return b.Reader.Read(p)
}
func (b *sharedEntryBody) Close() error { return nil }

func TestWebNodeProbeSharedSimultaneousCapture(t *testing.T) {
	w, cookie, csrf, etag := probeWebFixture(t)
	gate, start := make(chan struct{}), make(chan struct{})
	var release sync.Once
	defer release.Do(func() { close(gate) })
	entered := make(chan struct{}, 8)
	done := make(chan *httptest.ResponseRecorder, 8)
	w.nodeProbe = func(context.Context, node, string) (float64, error) { return 1, nil }
	for i := 0; i < 8; i++ {
		go func() {
			<-start
			r := httptest.NewRequest("POST", "http://127.0.0.1:18089/api/v1/nodes/probe", nil)
			r.Host = "127.0.0.1:18089"
			r.Body = &sharedEntryBody{Reader: strings.NewReader(`{"name":"first","mode":"tcp"}`), entered: entered, gate: gate}
			r.Header.Set("Origin", "http://"+r.Host)
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("X-CSRF-Token", csrf)
			r.Header.Set("If-Match", etag)
			r.AddCookie(cookie)
			rw := httptest.NewRecorder()
			w.ServeHTTP(rw, r)
			done <- rw
		}()
	}
	close(start)
	// Every reader must reach decode while every other reader is held there.
	// A Mutex cannot pass this barrier even if scheduling otherwise hides busy.
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	n := 0
capture:
	for n < 8 {
		select {
		case <-entered:
			n++
		case <-timer.C:
			break capture
		}
	}
	release.Do(func() { close(gate) })
	ok, busy := 0, 0
	for i := 0; i < 8; i++ {
		select {
		case r := <-done:
			if r.Code == 200 {
				var result webNodeProbeResult
				if json.Unmarshal(r.Body.Bytes(), &result) != nil || result.Status != "OK" {
					t.Errorf("bad result %s", r.Body)
				}
				ok++
			} else if r.Code == 409 && r.Body.String() == "{\"error\":\"ACTION_BUSY\"}\n" {
				busy++
			} else {
				t.Errorf("unexpected response %d %s", r.Code, r.Body)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("entry request did not finish")
		}
	}
	t.Logf("simultaneous capture entered=%d HTTP200=%d HTTP409=%d external_writer=0", n, ok, busy)
	if n != 8 || ok != 8 || busy != 0 {
		t.Errorf("shared capture requires all 8 decode entries and 8 OK, no busy")
	}
}

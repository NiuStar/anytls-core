package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/NiuStar/anytls-core/internal/telemetry"
)

func metricsHTTPRequest(w *webConsole, c *http.Cookie, query string, change func(*http.Request)) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "http://127.0.0.1:18089/api/v1/metrics"+query, nil)
	r.Header.Set("X-AnyTLS-Origin", "http://"+r.Host)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	if c != nil {
		r.AddCookie(c)
	}
	if change != nil {
		change(r)
	}
	out := httptest.NewRecorder()
	w.ServeHTTP(out, r)
	return out
}

func TestR10MetricsAuthenticatedSnapshotAndRejectMatrix(t *testing.T) {
	w, password := webFixture(t)
	cookie, _ := webLogin(t, w, password)
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	w.now = func() time.Time { return now }
	s := telemetry.New("")
	s.Record(now.Add(-time.Second), now, nil)
	w.metrics = &webMetricsController{store: s}
	w.state = func() (bool, bool, error) { t.Fatal("metrics must not probe/start service"); return false, false, nil }
	w.serviceAction = func(context.Context, string, bool) error { t.Fatal("metrics changed service"); return nil }
	// Must not acquire lifecycle lock or let a page read trigger collection.
	w.actionMu.Lock()
	got := metricsHTTPRequest(w, cookie, "", nil)
	w.actionMu.Unlock()
	want, _ := json.Marshal(s.Snapshot(now))
	var a, b any
	if got.Code != 200 || json.Unmarshal(got.Body.Bytes(), &a) != nil || json.Unmarshal(want, &b) != nil || !reflect.DeepEqual(a, b) {
		t.Fatalf("positive full path %d %s", got.Code, got.Body.String())
	}
	if got.Header().Get("Cache-Control") != "no-store" || got.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("headers")
	}
	for _, tc := range []struct {
		name, query string
		status      int
		change      func(*http.Request)
	}{
		{"unauthenticated", "", 401, func(r *http.Request) { r.Header.Del("Cookie") }},
		{"foreign Host", "", 403, func(r *http.Request) { r.Host = "evil:18089" }},
		{"app origin absent", "", 403, func(r *http.Request) { r.Header.Del("X-AnyTLS-Origin") }},
		{"app origin duplicate", "", 403, func(r *http.Request) { r.Header.Add("X-AnyTLS-Origin", "http://"+r.Host) }},
		{"app origin foreign", "", 403, func(r *http.Request) { r.Header.Set("X-AnyTLS-Origin", "http://localhost:18089") }},
		{"fetch absent", "", 403, func(r *http.Request) { r.Header.Del("Sec-Fetch-Site") }},
		{"fetch cross-site", "", 403, func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }},
		{"Origin foreign", "", 403, func(r *http.Request) { r.Header.Set("Origin", "http://localhost:18089") }},
		{"Origin duplicate", "", 403, func(r *http.Request) {
			r.Header.Add("Origin", "http://"+r.Host)
			r.Header.Add("Origin", "http://"+r.Host)
		}},
		{"caller target", "?url=https://evil.invalid", 400, nil},
		{"caller path", "?path=/secret", 400, nil},
		{"empty query", "?", 400, nil},
		{"post", "", 405, func(r *http.Request) { r.Method = "POST"; r.Header.Set("Origin", "http://"+r.Host) }},
		{"put", "", 405, func(r *http.Request) { r.Method = "PUT"; r.Header.Set("Origin", "http://"+r.Host) }},
		{"options", "", 405, func(r *http.Request) { r.Method = "OPTIONS" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if r := metricsHTTPRequest(w, cookie, tc.query, tc.change); r.Code != tc.status {
				t.Fatalf("got %d want %d %s", r.Code, tc.status, r.Body.String())
			}
		})
	}
	w.metrics = nil
	if r := metricsHTTPRequest(w, cookie, "", nil); r.Code != 200 {
		t.Fatal("absent collector should return NOT_OBSERVED", r.Code)
	}
	if _, err := webPassword(w.passwordPath, true); err != nil {
		t.Fatal(err)
	}
	if r := metricsHTTPRequest(w, cookie, "", nil); r.Code != 401 {
		t.Fatal("reset did not revoke telemetry")
	}
}

func TestR10MetricsControllerStopBoundedAndReportsUnjoinedWorker(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	c := &webMetricsController{store: telemetry.New(""), cancel: cancel, done: make(chan struct{})}
	started := time.Now()
	if err := c.Stop(); err != context.DeadlineExceeded {
		t.Fatalf("unjoined worker must report timeout: %v", err)
	}
	if time.Since(started) > 1500*time.Millisecond {
		t.Fatal("unbounded controller Stop")
	}
	if ctx.Err() != context.Canceled {
		t.Fatal("worker was not canceled")
	}
	close(c.done)
	if err := c.Stop(); err != context.DeadlineExceeded {
		t.Fatal("idempotent Stop lost original timeout", err)
	}
}

func TestR10MetricsRealHTTPListener(t *testing.T) {
	w, password := webFixture(t)
	cookie, _ := webLogin(t, w, password)
	server := httptest.NewServer(w)
	defer server.Close()
	u, _ := url.Parse(server.URL)
	port, _ := strconv.Atoi(u.Port())
	w.port = port
	r, _ := http.NewRequest("GET", server.URL+"/api/v1/metrics", nil)
	r.AddCookie(cookie)
	r.Header.Set("X-AnyTLS-Origin", server.URL)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	response, err := server.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var result telemetry.Snapshot
	if response.StatusCode != 200 || json.NewDecoder(response.Body).Decode(&result) != nil || result.Traffic.Quality != "NOT_OBSERVED" || len(result.Bins) != 288 {
		t.Fatalf("real HTTP %d %+v", response.StatusCode, result)
	}
}

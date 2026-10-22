package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestWebNodeProbeTCP(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	n := node{Name: "loopback", Type: "anytls", Server: "127.0.0.1", Port: l.Addr().(*net.TCPAddr).Port}
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, e := l.Accept()
		if e == nil {
			c.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if ms, err := webNodeProbe(ctx, n, "tcp"); err != nil || ms < 0 {
		t.Fatalf("TCP probe ms=%v err=%v", ms, err)
	}
	l.Close()
	<-done
	if _, err := webNodeProbe(ctx, n, "tcp"); err == nil {
		t.Fatal("closed server accepted")
	}
	canceled, stop := context.WithCancel(context.Background())
	stop()
	if _, err := webNodeProbe(canceled, n, "tcp"); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost")
	}
	if _, err := webNodeProbe(ctx, n, "speed"); !errors.Is(err, errNodeProbeUnsupported) {
		t.Fatal("invalid mode accepted")
	}
}

func probeWebFixture(t *testing.T) (*webConsole, *http.Cookie, string, string) {
	t.Helper()
	w, password := webFixture(t)
	b := []byte("nodes:\n  - {name: first, type: anytls, server: 127.0.0.1, port: 443, password: private-first, skip-cert-verify: true}\n  - {name: second, type: anytls, server: 127.0.0.2, port: 8443, password: private-second, skip-cert-verify: true, ca: /not-read-by-seam}\n")
	if err := os.WriteFile(w.configPath, b, 0600); err != nil {
		t.Fatal(err)
	}
	cookie, csrf := webLogin(t, w, password)
	return w, cookie, csrf, `"` + shaHex(b) + `"`
}

func probeWebRequest(w *webConsole, cookie *http.Cookie, csrf, etag, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "http://127.0.0.1:18089/api/v1/nodes/probe", strings.NewReader(body))
	r.Host = "127.0.0.1:18089"
	r.Header.Set("Origin", "http://"+r.Host)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", csrf)
	r.Header.Set("If-Match", etag)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, r)
	return rec
}

func TestWebNodeProbeAuthenticatedIdentity(t *testing.T) {
	w, cookie, csrf, etag := probeWebFixture(t)
	calls := 0
	w.nodeProbe = func(ctx context.Context, n node, mode string) (float64, error) {
		calls++
		if n.Name != "second" || n.Server != "127.0.0.2" || n.Port != 8443 || n.Password != "private-second" || mode != "https" {
			t.Fatal("wrong configured identity")
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > webNodeProbeTimeout {
			t.Fatal("probe missing deadline")
		}
		return 12.5, nil
	}
	body := `{"name":"second","mode":"https","confirm_insecure":true}`
	for _, tc := range []struct {
		cookie     *http.Cookie
		csrf, etag string
		status     int
	}{
		{nil, csrf, etag, 401}, {cookie, "wrong", etag, 403}, {cookie, csrf, "", 428}, {cookie, csrf, `"stale"`, 412},
	} {
		if r := probeWebRequest(w, tc.cookie, tc.csrf, tc.etag, body); r.Code != tc.status {
			t.Fatalf("got %d want %d", r.Code, tc.status)
		}
	}
	if calls != 0 {
		t.Fatal("network before auth/config gates")
	}
	r := probeWebRequest(w, cookie, csrf, etag, body)
	var result webNodeProbeResult
	if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &result) != nil || result.Name != "second" || result.Status != "OK" || result.LatencyMS == nil || *result.LatencyMS != 12.5 || result.ConfigETag != etag || result.CheckedAt == "" || result.RiskInsecure {
		t.Fatalf("bad result %d %s", r.Code, r.Body.String())
	}
	if calls != 1 || strings.Contains(r.Body.String(), "private-") {
		t.Fatal("bad call count or secret leak")
	}
}

func TestWebNodeProbeValidationAndStale(t *testing.T) {
	w, cookie, csrf, etag := probeWebFixture(t)
	calls := 0
	w.nodeProbe = func(context.Context, node, string) (float64, error) { calls++; return 1, nil }
	for _, tc := range []struct {
		body   string
		status int
	}{
		{`{"name":"first","mode":"speed"}`, 400},
		{`{"name":"missing","mode":"tcp"}`, 404},
		{`{"name":"first","mode":"https"}`, 400},
		{`{"name":"first","mode":"tcp","url":"https://private/"}`, 400},
	} {
		if r := probeWebRequest(w, cookie, csrf, etag, tc.body); r.Code != tc.status {
			t.Fatalf("got %d want %d", r.Code, tc.status)
		}
	}
	if calls != 0 {
		t.Fatal("invalid request performed network")
	}
	w.nodeProbe = func(context.Context, node, string) (float64, error) {
		if err := os.WriteFile(w.configPath, []byte("nodes: []\n"), 0600); err != nil {
			t.Fatal(err)
		}
		return 1, nil
	}
	r := probeWebRequest(w, cookie, csrf, etag, `{"name":"first","mode":"tcp"}`)
	if r.Code != 412 || strings.Contains(r.Body.String(), "latency_ms") {
		t.Fatalf("stale sample published: %s", r.Body.String())
	}
}

func TestWebNodeProbeCanceledSuccessIsNotOK(t *testing.T) {
	w, _, _, etag := probeWebFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.nodeProbe = func(context.Context, node, string) (float64, error) {
		cancel() // Simulate a transport returning a sample despite cancellation.
		return 1, nil
	}
	r := httptest.NewRequest("POST", "http://127.0.0.1:18089/api/v1/nodes/probe", strings.NewReader(`{"name":"first","mode":"tcp"}`)).WithContext(ctx)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("If-Match", etag)
	rec := httptest.NewRecorder()
	w.probeNodeHandler(rec, r)
	var result webNodeProbeResult
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &result) != nil || result.Status != "FAILED" || result.Error != "PROBE_CANCELED" || result.LatencyMS != nil {
		t.Fatalf("canceled success published: %s", rec.Body.String())
	}
}

func TestWebNodeProbeExternalHTTPSUnsupported(t *testing.T) {
	if !externalCoreRequired() {
		t.Skip("external-only no-child contract")
	}
	n := node{Type: "anytls", Server: "127.0.0.1", Port: 443}
	if _, err := webNodeProbe(context.Background(), n, "https"); !errors.Is(err, errNodeProbeUnsupported) {
		t.Fatal("external build HTTPS probe must be unsupported")
	}
}

func TestWebNodeProbeControlledFailures(t *testing.T) {
	for i, tc := range []struct {
		err          error
		status, code string
	}{
		{errors.New("secret credential remote host"), "FAILED", "PROBE_FAILED"},
		{context.DeadlineExceeded, "TIMEOUT", "PROBE_TIMEOUT"},
		{context.Canceled, "FAILED", "PROBE_CANCELED"},
		{errNodeProbeUnsupported, "UNSUPPORTED", "PROBE_UNSUPPORTED"},
	} {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			w, cookie, csrf, etag := probeWebFixture(t)
			w.nodeProbe = func(context.Context, node, string) (float64, error) { return 999, tc.err }
			r := probeWebRequest(w, cookie, csrf, etag, `{"name":"first","mode":"tcp"}`)
			var result webNodeProbeResult
			if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &result) != nil || result.Status != tc.status || result.Error != tc.code || result.LatencyMS != nil || !result.RiskInsecure || strings.Contains(r.Body.String(), "secret") {
				t.Fatalf("bad result %d %s", r.Code, r.Body.String())
			}
		})
	}
}

package main

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	cr "github.com/NiuStar/anytls-core/internal/connectionrecords"
)

func recordsHTTPRequest(w *webConsole, cookie *http.Cookie, query string, change func(*http.Request)) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "http://127.0.0.1:18089/api/v1/connections"+query, nil)
	r.Header.Set("X-AnyTLS-Origin", "http://"+r.Host)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	if cookie != nil {
		r.AddCookie(cookie)
	}
	if change != nil {
		change(r)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, r)
	return rec
}
func TestWebRecordsServeHTTPPositiveThenReject(t *testing.T) {
	w, password := webFixture(t)
	cookie, _ := webLogin(t, w, password)
	identity, err := controlHelperConfigIdentity(w.configPath)
	if err != nil {
		t.Fatal(err)
	}
	page := recordsTestPage(identity)
	calls := 0
	w.state = func() (bool, bool, error) { t.Error("records called service state"); return false, false, nil }
	w.serviceAction = func(context.Context, string, bool) error { t.Error("records mutated service"); return nil }
	w.recordsRequest = func(ctx context.Context, q cr.PageRequest) (cr.PageResponse, error) {
		calls++
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > cr.TelemetryTimeout {
			t.Error("missing total deadline")
		}
		if q.Binding != nil || q.After != "0" || q.Limit != 100 {
			t.Error("wrong defaults")
		}
		return page, nil
	}
	// Prove the positive full authentication/router/handler path first, including
	// complete frozen public DTO bytes. Holding the lifecycle lock cannot block it.
	w.actionMu.Lock()
	rec := recordsHTTPRequest(w, cookie, "", nil)
	w.actionMu.Unlock()
	want, err := cr.EncodeBounded(page, cr.MaxResponseBytes)
	if err != nil || rec.Code != 200 || !bytes.Equal(rec.Body.Bytes(), want) || calls != 1 {
		t.Fatalf("positive route %d %s %v", rec.Code, rec.Body.String(), err)
	}
	if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Content-Type-Options") != "nosniff" || rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("response security headers")
	}
	for _, tc := range []struct {
		name, query string
		status      int
		change      func(*http.Request)
	}{
		{"no cookie", "", 401, func(r *http.Request) { r.Header.Del("Cookie") }},
		{"host", "", 403, func(r *http.Request) { r.Host = "evil:18089" }},
		{"no application origin", "", 403, func(r *http.Request) { r.Header.Del("X-AnyTLS-Origin") }},
		{"foreign application origin", "", 403, func(r *http.Request) { r.Header.Set("X-AnyTLS-Origin", "http://localhost:18089") }},
		{"duplicate application origin", "", 403, func(r *http.Request) { r.Header.Add("X-AnyTLS-Origin", "http://"+r.Host) }},
		{"fetch absent", "", 403, func(r *http.Request) { r.Header.Del("Sec-Fetch-Site") }},
		{"cross site", "", 403, func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }},
		{"foreign Origin", "", 403, func(r *http.Request) { r.Header.Set("Origin", "http://localhost:18089") }},
		{"duplicate Origin", "", 403, func(r *http.Request) {
			r.Header.Add("Origin", "http://"+r.Host)
			r.Header.Add("Origin", "http://"+r.Host)
		}},
		{"unknown key", "?path=/secret", 400, nil}, {"uid", "?uid=501", 400, nil},
		{"duplicate after", "?after=0&after=1", 400, nil}, {"empty after", "?after=", 400, nil},
		{"leading zero", "?after=00", 400, nil}, {"overflow", "?after=18446744073709551616", 400, nil},
		{"limit zero", "?limit=0", 400, nil}, {"limit over", "?limit=501", 400, nil}, {"limit exponent", "?limit=1e2", 400, nil},
		{"partial binding", "?instance_id=" + strings.Repeat("a", 32), 400, nil}, {"invalid escape", "?after=%GG", 400, nil},
		{"post", "", 405, func(r *http.Request) { r.Method = "POST"; r.Header.Set("Origin", "http://"+r.Host) }},
		{"put", "", 405, func(r *http.Request) { r.Method = "PUT"; r.Header.Set("Origin", "http://"+r.Host) }},
		{"options", "", 405, func(r *http.Request) { r.Method = "OPTIONS" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := recordsHTTPRequest(w, cookie, tc.query, tc.change)
			if r.Code != tc.status {
				t.Fatalf("%d %s", r.Code, r.Body.String())
			}
		})
	}
	if calls != 1 {
		t.Fatal("rejection contacted helper")
	}
	// Password reset revocation is the existing live on-disk hash contract.
	if _, err := webPassword(w.passwordPath, true); err != nil {
		t.Fatal(err)
	}
	if r := recordsHTTPRequest(w, cookie, "", nil); r.Code != 401 || calls != 1 {
		t.Fatal("reset did not revoke history")
	}
}
func TestWebRecordsErrorMappingAndConfigBinding(t *testing.T) {
	w, password := webFixture(t)
	cookie, _ := webLogin(t, w, password)
	for _, code := range []cr.ErrorCode{cr.InvalidRequest, cr.Forbidden, cr.Busy, cr.StaleGeneration, cr.TelemetryUnavailable, cr.StoreInvalid, cr.Unsupported} {
		w.recordsRequest = func(context.Context, cr.PageRequest) (cr.PageResponse, error) { return cr.PageResponse{}, code }
		r := recordsHTTPRequest(w, cookie, "", nil)
		var e cr.ErrorResponse
		if r.Code != recordsHTTPStatus(code) || cr.DecodeStrict(r.Body.Bytes(), &e, cr.MaxResponseBytes) != nil || e.ErrorCode != code {
			t.Fatalf("bad mapping %s %d %s", code, r.Code, r.Body.String())
		}
	}
	w.recordsRequest = func(context.Context, cr.PageRequest) (cr.PageResponse, error) {
		return recordsTestPage(strings.Repeat("f", 64)), nil
	}
	r := recordsHTTPRequest(w, cookie, "", nil)
	if r.Code != 503 || strings.Contains(r.Body.String(), "records") {
		t.Fatal("accepted wrong registration config identity")
	}
}
func TestWebRecordsQueryCanonicalBinding(t *testing.T) {
	binding := cr.Binding{InstanceID: strings.Repeat("a", 32), Generation: strings.Repeat("b", 32), ManifestID: strings.Repeat("c", 64)}
	q, err := webRecordsQuery("instance_id=" + binding.InstanceID + "&generation=" + binding.Generation + "&manifest_id=" + binding.ManifestID + "&after=9007199254740993&limit=500")
	if err != nil || q.Binding == nil || *q.Binding != binding || q.After != "9007199254740993" || q.Limit != 500 {
		t.Fatal(q, err)
	}
}
func TestWebRecordsAuthenticatedThroughHelperEOF(t *testing.T) {
	w, password := webFixture(t)
	cookie, _ := webLogin(t, w, password)
	s := recordsTestServer(t)
	s.registration.Config = w.configPath
	identity, _ := controlHelperConfigIdentity(w.configPath)
	page := recordsTestPage(identity)
	w.recordsRequest = func(ctx context.Context, q cr.PageRequest) (cr.PageResponse, error) {
		c, _ := unitControlPair(t, s)
		defer c.Close()
		return controlHelperRecordsExchange(ctx, c, q, func(net.Conn) (uint32, error) { return 0, nil })
	}
	// A real loopback HTTP server exercises browser-shaped authenticated GET and
	// EOF helper exchange; UID/file reader remain explicitly UNIT seams here.
	server := httptest.NewServer(w)
	defer server.Close()
	u, _ := url.Parse(server.URL)
	_, port, _ := net.SplitHostPort(u.Host)
	w.port, _ = strconv.Atoi(port)
	req, _ := http.NewRequest("GET", server.URL+"/api/v1/connections", nil)
	req.AddCookie(cookie)
	req.Header.Set("X-AnyTLS-Origin", server.URL)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	client := &http.Client{Timeout: 2 * time.Second}
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var got cr.PageResponse
	if response.StatusCode != 200 || cr.ReadStrict(response.Body, &got, cr.MaxResponseBytes) != nil || !reflect.DeepEqual(got, page) {
		t.Fatal("HTTP→helper page mismatch", response.StatusCode)
	}
}
func TestWebRecordsRevokedDuringHelperRead(t *testing.T) {
	w, password := webFixture(t)
	cookie, _ := webLogin(t, w, password)
	identity, _ := controlHelperConfigIdentity(w.configPath)
	w.recordsRequest = func(context.Context, cr.PageRequest) (cr.PageResponse, error) {
		w.authMu.Lock()
		delete(w.sessions, cookie.Value)
		w.authMu.Unlock()
		return recordsTestPage(identity), nil
	}
	if r := recordsHTTPRequest(w, cookie, "", nil); r.Code != 401 {
		t.Fatal("late history exposed after logout", r.Code)
	}
}

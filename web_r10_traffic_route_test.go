package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	ts "github.com/NiuStar/anytls-core/internal/trafficstats"
)

// Exercise the published router, not a direct method call or a static server.
func TestR10TrafficRouteIsAuthenticatedReadOnly(t *testing.T) {
	w, password := webFixture(t)
	cookie, _ := webLogin(t, w, password)
	w.state = func() (bool, bool, error) {
		t.Fatal("traffic read queried service lifecycle")
		return false, false, nil
	}
	w.serviceAction = func(context.Context, string, bool) error { t.Fatal("traffic read controlled service"); return nil }
	call := func(cookie *http.Cookie, method string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://127.0.0.1:18089/api/v1/traffic", nil)
		r.Header.Set("X-AnyTLS-Origin", "http://"+r.Host)
		r.Header.Set("Origin", "http://"+r.Host)
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		if cookie != nil {
			r.AddCookie(cookie)
		}
		out := httptest.NewRecorder()
		w.ServeHTTP(out, r)
		return out
	}
	if r := call(nil, "GET"); r.Code != 401 {
		t.Fatalf("anonymous: %d", r.Code)
	}
	if r := call(cookie, "POST"); r.Code != 405 {
		t.Fatalf("wrong method: %d", r.Code)
	}
	// Nil metrics and an unsupported/absent helper must not create a collector.
	w.actionMu.Lock()
	r := call(cookie, "GET")
	w.actionMu.Unlock()
	var got ts.Response
	if r.Code != 503 || json.Unmarshal(r.Body.Bytes(), &got) != nil || got.Availability != "UNAVAILABLE" || got.Snapshot != nil {
		t.Fatalf("unavailable route: %d %s", r.Code, r.Body.String())
	}
	if r.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("missing no-store")
	}
}

func TestR10TrafficRealHTTPRoute(t *testing.T) {
	w, password := webFixture(t)
	cookie, _ := webLogin(t, w, password)
	s := httptest.NewServer(w)
	defer s.Close()
	u, _ := url.Parse(s.URL)
	w.port, _ = strconv.Atoi(u.Port())
	r, _ := http.NewRequest("GET", s.URL+"/api/v1/traffic", nil)
	r.AddCookie(cookie)
	r.Header.Set("X-AnyTLS-Origin", s.URL)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	response, err := s.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var got ts.Response
	if response.StatusCode != 503 || json.NewDecoder(response.Body).Decode(&got) != nil || ts.Validate(got) != nil || got.Availability != "UNAVAILABLE" {
		t.Fatalf("real route: %d %+v", response.StatusCode, got)
	}
}

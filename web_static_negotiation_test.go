package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWebStaticNegotiation(t *testing.T) {
	w, _ := webFixture(t)
	for _, tc := range []struct {
		name     string
		values   []string
		status   int
		encoding string
	}{
		{"absent", nil, 200, ""},
		{"empty", []string{""}, 200, ""},
		{"unknown", []string{"br, deflate"}, 200, ""},
		{"case-OWS", []string{"  GZip ; Q=1.000 , BR  "}, 200, "gzip"},
		{"fields", []string{"br", "gzip"}, 200, "gzip"},
		{"wildcard", []string{"*"}, 200, "gzip"},
		{"explicit-zero", []string{"*;q=1, gzip;q=0"}, 200, ""},
		{"explicit-zero-fields", []string{"*;q=1", "GZIP;q=0"}, 200, ""},
		{"gzip-lower-than-default-identity", []string{"gzip;q=0.5"}, 200, ""},
		{"identity-higher", []string{"gzip;q=0.5, identity;q=0.8"}, 200, ""},
		{"gzip-higher", []string{"gzip;q=0.8, identity;q=0.5"}, 200, "gzip"},
		{"tie", []string{"gzip;q=0.5, identity;q=0.5"}, 200, "gzip"},
		{"wildcard-lower", []string{"*;q=0.5"}, 200, ""},
		{"identity-refused", []string{"gzip;q=0.001, identity;q=0"}, 200, "gzip"},
		{"wildcard-refused-explicit-gzip", []string{"*;q=0, gzip;q=1"}, 200, "gzip"},
		{"wildcard-refused-explicit-identity", []string{"*;q=0, identity;q=1"}, 200, ""},
		{"all-refused", []string{"gzip;q=0, identity;q=0"}, 406, ""},
		{"wildcard-refused", []string{"*;q=0"}, 406, ""},
		{"only-unknown-identity-refused", []string{"br, identity;q=0"}, 406, ""},
		{"malformed", []string{"gzip;q=wat"}, 200, ""},
		{"missing-q", []string{"gzip;q="}, 200, ""},
		{"overprecision", []string{"gzip;q=1.0000"}, 200, ""},
		{"out-of-range", []string{"gzip;q=1.001"}, 200, ""},
		{"negative", []string{"gzip;q=-0.1"}, 200, ""},
		{"no-leading-zero", []string{"gzip;q=.5, identity;q=0"}, 406, ""},
		{"exponent", []string{"gzip;q=1e0"}, 200, ""},
		{"NaN", []string{"gzip;q=NaN"}, 200, ""},
		{"duplicate-q", []string{"gzip;q=1;q=0"}, 200, ""},
		{"unknown-parameter", []string{"gzip;level=1"}, 200, ""},
		{"trailing-dot", []string{"gzip;q=1."}, 200, "gzip"},
		{"zero-dot", []string{"gzip;q=0., identity;q=0"}, 406, ""},
		{"duplicate-conservative-zero", []string{"gzip;q=1, gzip;q=0"}, 200, ""},
		{"invalid-explicit-overrides-wildcard", []string{"*;q=1, gzip;q=bad"}, 200, ""},
		{"invalid-explicit-identity", []string{"identity;q=bad"}, 406, ""},
		{"empty-members", []string{", ,gzip,,"}, 200, "gzip"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "http://127.0.0.1:18089/app.js", nil)
			for _, value := range tc.values {
				r.Header.Add("Accept-Encoding", value)
			}
			rec := httptest.NewRecorder()
			w.ServeHTTP(rec, r)
			if rec.Code != tc.status || rec.Header().Get("Content-Encoding") != tc.encoding {
				t.Fatalf("negotiation status=%d encoding=%q, want status=%d encoding=%q", rec.Code, rec.Header().Get("Content-Encoding"), tc.status, tc.encoding)
			}
			if rec.Header().Get("Vary") != "Accept-Encoding" || rec.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("missing negotiation/cache headers")
			}
			if tc.status == 406 && rec.Header().Get("Content-Type") != "application/json; charset=utf-8" {
				t.Fatal("negotiation error is not uncompressed JSON")
			}
		})
	}
}

func TestWebStaticSecurityBoundaries(t *testing.T) {
	w, p := webFixture(t)
	cookie, _ := webLogin(t, w, p)
	for _, tc := range []struct {
		name, method, path, host, origin string
		cookie                           bool
		status                           int
	}{
		{"host", "GET", "/app.js", "evil.example:18089", "", false, 403},
		{"HEAD", "HEAD", "/app.js", "127.0.0.1:18089", "", false, 405},
		{"POST-origin", "POST", "/app.js", "127.0.0.1:18089", "", false, 403},
		{"POST", "POST", "/app.js", "127.0.0.1:18089", "http://127.0.0.1:18089", false, 405},
		{"unknown", "GET", "/private.js", "127.0.0.1:18089", "", false, 404},
		{"allowlist", "GET", "/index.html", "127.0.0.1:18089", "", false, 404},
		{"api-unauthenticated", "GET", "/api/v1/status", "127.0.0.1:18089", "", false, 401},
		{"api-authenticated", "GET", "/api/v1/status", "127.0.0.1:18089", "", true, 200},
		{"csrf", "POST", "/api/v1/logout", "127.0.0.1:18089", "http://127.0.0.1:18089", true, 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, "http://"+tc.host+tc.path, nil)
			r.Header.Set("Accept-Encoding", "gzip, identity;q=0")
			if tc.origin != "" {
				r.Header.Set("Origin", tc.origin)
			}
			if tc.cookie {
				r.AddCookie(cookie)
			}
			rec := httptest.NewRecorder()
			w.ServeHTTP(rec, r)
			if rec.Code != tc.status || rec.Header().Get("Content-Encoding") != "" {
				t.Fatalf("security/API status=%d encoding=%q", rec.Code, rec.Header().Get("Content-Encoding"))
			}
			if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Content-Type-Options") != "nosniff" || rec.Header().Get("X-Frame-Options") != "DENY" || rec.Header().Get("Referrer-Policy") != "no-referrer" || rec.Header().Get("Content-Security-Policy") == "" {
				t.Fatal("security headers changed")
			}
		})
	}
	// Login remains ordinary uncompressed JSON, even when static identity is refused.
	body := `{"username":"admin","password":"wrong"}`
	r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:18089/api/v1/login", strings.NewReader(body))
	r.Header.Set("Origin", "http://127.0.0.1:18089")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept-Encoding", "gzip, identity;q=0")
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, r)
	if rec.Code != 401 || rec.Header().Get("Content-Encoding") != "" {
		t.Fatal("login error compressed or status changed")
	}
}

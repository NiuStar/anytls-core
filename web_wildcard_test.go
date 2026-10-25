package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	cr "github.com/NiuStar/anytls-core/internal/connectionrecords"
)

// Exercise the real authenticated dispatcher, not just the Host predicate.
func TestWebWildcardServeHTTP(t *testing.T) {
	for _, host := range []string{"console.example:18089", "my-server:18089", "192.168.5.2:18089", "8.8.8.8:18089", "127.0.0.1:18089", "localhost:18089"} {
		t.Run(host, func(t *testing.T) {
			w, password := webFixture(t)
			w.listenHost = "0.0.0.0"
			request := func(method, path string, cookie *http.Cookie, csrf string, change func(*http.Request)) *httptest.ResponseRecorder {
				body, _ := json.Marshal(map[string]string{"username": "admin", "password": password})
				r := httptest.NewRequest(method, "http://"+host+path, bytes.NewReader(body))
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Origin", "http://"+host)
				if cookie != nil {
					r.AddCookie(cookie)
				}
				if csrf != "" {
					r.Header.Set("X-CSRF-Token", csrf)
				}
				if change != nil {
					change(r)
				}
				rec := httptest.NewRecorder()
				w.ServeHTTP(rec, r)
				if rec.Header().Get("Access-Control-Allow-Origin") != "" {
					t.Fatal("CORS enabled")
				}
				return rec
			}
			if r := request("GET", "/", nil, "", nil); r.Code != 200 || !bytes.Contains(r.Body.Bytes(), []byte("<title>AnyTLS")) {
				t.Fatal("page", r.Code, r.Body.String())
			}
			if r := request("GET", "/api/v1/status", nil, "", nil); r.Code != 401 {
				t.Fatal("anonymous status", r.Code)
			}
			login := request("POST", "/api/v1/login", nil, "", nil)
			if login.Code != 200 {
				t.Fatal("login", login.Code, login.Body.String())
			}
			cookie := login.Result().Cookies()[0]
			var result struct {
				CSRF string `json:"csrf"`
			}
			if err := json.Unmarshal(login.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Domain != "" || result.CSRF == "" {
				t.Fatal("session flags")
			}
			if r := request("GET", "/api/v1/status", cookie, "", nil); r.Code != 200 || !bytes.Contains(r.Body.Bytes(), []byte(`"transport":"network-http"`)) {
				t.Fatal("status", r.Code, r.Body.String())
			}
			for _, change := range []func(*http.Request){
				func(r *http.Request) { r.Header.Del("Origin") },
				func(r *http.Request) { r.Header.Set("Origin", "http://other.example:18089") },
				func(r *http.Request) { r.Header.Add("Origin", "http://"+host) },
			} {
				if r := request("POST", "/api/v1/login", nil, "", change); r.Code != 403 {
					t.Fatal("login Origin", r.Code)
				}
				if r := request("POST", "/api/v1/logout", cookie, result.CSRF, change); r.Code != 403 {
					t.Fatal("logout Origin", r.Code)
				}
			}
			if r := request("POST", "/api/v1/login", nil, "", func(r *http.Request) { r.Body = http.NoBody }); r.Code != 400 {
				t.Fatal("bad login", r.Code)
			}
			for _, csrf := range []string{"", "wrong"} {
				if r := request("POST", "/api/v1/logout", cookie, csrf, nil); r.Code != 403 {
					t.Fatal("CSRF", r.Code)
				}
			}
			identity, err := controlHelperConfigIdentity(w.configPath)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			w.recordsRequest = func(context.Context, cr.PageRequest) (cr.PageResponse, error) {
				calls++
				return recordsTestPage(identity), nil
			}
			for _, site := range []string{"", "same-origin"} {
				r := request("GET", "/api/v1/connections", cookie, "", func(r *http.Request) {
					r.Header.Del("Origin") // Network HTTP browsers may omit both headers.
					r.Header.Set("X-AnyTLS-Origin", "http://"+host)
					if site != "" {
						r.Header.Set("Sec-Fetch-Site", site)
					}
				})
				if r.Code != 200 {
					t.Fatal("records", site, r.Code, r.Body.String())
				}
			}
			for _, change := range []func(*http.Request){
				func(r *http.Request) { r.Header.Del("X-AnyTLS-Origin") },
				func(r *http.Request) { r.Header.Set("X-AnyTLS-Origin", "http://other.example:18089") },
				func(r *http.Request) { r.Header.Add("X-AnyTLS-Origin", "http://"+host) },
				func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") },
				func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "same-site") },
				func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "") },
				func(r *http.Request) {
					r.Header.Add("Sec-Fetch-Site", "same-origin")
					r.Header.Add("Sec-Fetch-Site", "same-origin")
				},
				func(r *http.Request) { r.Header.Set("Origin", "http://other.example:18089") },
			} {
				r := request("GET", "/api/v1/connections", cookie, "", func(r *http.Request) { r.Header.Set("X-AnyTLS-Origin", "http://"+host); change(r) })
				if r.Code != 403 {
					t.Fatal("records source", r.Code)
				}
			}
			if calls != 2 {
				t.Fatal("rejections reached backend", calls)
			}
			if r := request("POST", "/api/v1/logout", cookie, result.CSRF, nil); r.Code != 200 {
				t.Fatal("logout", r.Code)
			}
			if r := request("GET", "/api/v1/status", cookie, "", nil); r.Code != 401 {
				t.Fatal("revocation", r.Code)
			}
		})
	}
}

package main

import (
	"context"
	de "github.com/NiuStar/anytls-core/internal/dnsevidence"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDNSRuntimeAssetsAndRevocation(t *testing.T) {
	w, password := webFixture(t)
	cookie, _ := webLogin(t, w, password)
	for _, path := range []string{"/", "/dns.js"} {
		r := httptest.NewRequest("GET", "http://127.0.0.1:18089"+path, nil)
		rec := httptest.NewRecorder()
		w.ServeHTTP(rec, r)
		if rec.Code != 200 {
			t.Fatal("asset", path, rec.Code)
		}
		if path == "/" && !strings.Contains(rec.Body.String(), "缓存来源、合并查询") {
			t.Fatal("coverage missing from actual served HTML")
		}
	}
	identity, _ := controlHelperConfigIdentity(w.configPath)
	w.dnsRequest = func(context.Context, de.Read) (de.Response, error) {
		w.authMu.Lock()
		delete(w.sessions, cookie.Value)
		w.authMu.Unlock()
		return de.Response{DNSSchema: 1, Code: "UNAVAILABLE", Availability: "UNAVAILABLE", ConfigIdentity: &identity}, nil
	}
	r := httptest.NewRequest("GET", "http://127.0.0.1:18089/api/v1/dns-runtime", nil)
	r.AddCookie(cookie)
	r.Header.Set("X-AnyTLS-Origin", "http://"+r.Host)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, r)
	if rec.Code != 401 {
		t.Fatal("session revocation not honored", rec.Code)
	}
}

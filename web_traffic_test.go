package main

import (
	"context"
	"errors"
	ts "github.com/NiuStar/anytls-core/internal/trafficstats"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTrafficHandlerReadOnlyAndRejects(t *testing.T) {
	w, password := webFixture(t)
	cookie, _ := webLogin(t, w, password)
	identity, e := controlHelperConfigIdentity(w.configPath)
	if e != nil {
		t.Fatal(e)
	}
	c := new(ts.Counter)
	c.Upload(9007199254740993)
	snap := ts.New(c, recordsTestPage(identity).Header).Sample(time.Now(), "RUNNING")
	calls := 0
	w.trafficRequest = func(ctx context.Context) (ts.Response, error) {
		calls++
		if _, ok := ctx.Deadline(); !ok {
			t.Error("no deadline")
		}
		return ts.Response{TrafficSchema: 1, Availability: "OBSERVED", Snapshot: &snap}, nil
	}
	w.state = func() (bool, bool, error) { t.Error("state read"); return false, false, nil }
	w.serviceAction = func(context.Context, string, bool) error { t.Error("mutation"); return nil }
	request := func(change func(*http.Request)) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "http://127.0.0.1:18089/api/v1/traffic", nil)
		r.AddCookie(cookie)
		r.Header.Set("X-AnyTLS-Origin", "http://"+r.Host)
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		if change != nil {
			change(r)
		}
		rec := httptest.NewRecorder()
		w.getTraffic(rec, r)
		return rec
	}
	rec := request(nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"9007199254740993"`) || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal(rec.Code, rec.Body.String())
	}
	for _, tc := range []struct {
		name   string
		status int
		change func(*http.Request)
	}{
		{"auth", 401, func(r *http.Request) { r.Header.Del("Cookie") }},
		{"method", 405, func(r *http.Request) { r.Method = "POST" }},
		{"origin", 403, func(r *http.Request) { r.Header.Del("X-AnyTLS-Origin") }},
		{"duplicate", 403, func(r *http.Request) { r.Header.Add("X-AnyTLS-Origin", "http://"+r.Host) }},
		{"crosssite", 403, func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }},
		{"query", 400, func(r *http.Request) { r.URL.RawQuery = "uid=0" }},
		{"emptyquery", 400, func(r *http.Request) { r.URL.ForceQuery = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := calls
			rec := request(tc.change)
			if rec.Code != tc.status || calls != before {
				t.Fatal(rec.Code, rec.Body.String(), calls)
			}
		})
	}
	for _, kind := range []string{"stale", "binding", "source", "closed", "saturated", "error"} {
		t.Run(kind, func(t *testing.T) {
			bad := snap
			w.trafficRequest = func(context.Context) (ts.Response, error) {
				switch kind {
				case "stale":
					bad.SampledAt = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)
				case "binding":
					bad.Header.ConfigIdentity = strings.Repeat("f", 64)
				case "source":
					bad.Source = "NIC"
				case "closed":
					bad.State = "CLOSED"
				case "saturated":
					bad.Saturated = true
				case "error":
					return ts.Unavailable(), errors.New("old helper")
				}
				return ts.Response{TrafficSchema: 1, Availability: "OBSERVED", Snapshot: &bad}, nil
			}
			rec := request(nil)
			if rec.Code != 503 || !strings.Contains(rec.Body.String(), `"snapshot":null`) {
				t.Fatal(rec.Code, rec.Body.String())
			}
		})
	}
}

func TestTrafficHandlerRevokedSessionAfterRead(t *testing.T) {
	w, password := webFixture(t)
	cookie, _ := webLogin(t, w, password)
	r := httptest.NewRequest("GET", "http://127.0.0.1:18089/api/v1/traffic", nil)
	r.AddCookie(cookie)
	r.Header.Set("X-AnyTLS-Origin", "http://"+r.Host)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()
	w.getTrafficWith(rec, r, func(context.Context) (ts.Response, error) { r.Header.Del("Cookie"); return ts.Unavailable(), nil })
	if rec.Code != 401 {
		t.Fatal(rec.Code)
	}
}

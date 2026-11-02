package main

import (
	"context"
	de "github.com/NiuStar/anytls-core/internal/dnsevidence"
	"net/http"
	"net/url"
	"time"
)

func (w *webConsole) getDNSRuntime(rw http.ResponseWriter, r *http.Request) {
	fail := func(status int, code string) {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(status)
		b, _ := de.Encode(de.Response{DNSSchema: 1, Code: code, Availability: "UNAVAILABLE"})
		_, _ = rw.Write(b)
	}
	app, site := r.Header.Values("X-AnyTLS-Origin"), r.Header.Values("Sec-Fetch-Site")
	siteOK := len(site) == 1 && site[0] == "same-origin" || len(site) == 0 && w.networkListen()
	if len(app) != 1 || app[0] != "http://"+r.Host || !siteOK || (len(r.Header.Values("Origin")) > 0 && !w.originOK(r)) {
		fail(403, "FORBIDDEN")
		return
	}
	q := de.Read{DNSSchema: 1, Action: "dns.read"}
	v, e := url.ParseQuery(r.URL.RawQuery)
	if e != nil || len(r.URL.RawQuery) > de.ReadBytes {
		fail(400, "INVALID_REQUEST")
		return
	}
	for k, vs := range v {
		if len(vs) != 1 {
			fail(400, "INVALID_REQUEST")
			return
		}
		s := vs[0]
		switch k {
		case "instance_id":
			q.InstanceID = &s
		case "generation":
			q.Generation = &s
		case "manifest_id":
			q.ManifestID = &s
		default:
			fail(400, "INVALID_REQUEST")
			return
		}
	}
	if de.Validate(q) != nil {
		fail(400, "INVALID_REQUEST")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	request := w.dnsRequest
	if request == nil {
		request = controlHelperDNSRequest
	}
	p, e := request(ctx, q)
	if e != nil || de.Validate(p) != nil {
		fail(503, "UNAVAILABLE")
		return
	}
	id, e := controlHelperConfigIdentity(w.configPath)
	if e != nil || p.ConfigIdentity == nil || *p.ConfigIdentity != id || q.InstanceID == nil && p.Snapshot != nil || q.InstanceID != nil && p.Code == "OK" && (p.Binding == nil || !de.Matches(q, *p.Binding)) {
		fail(503, "UNAVAILABLE")
		return
	}
	b, e := de.Encode(p)
	if e != nil || ctx.Err() != nil {
		fail(503, "UNAVAILABLE")
		return
	}
	if _, ok := w.authenticated(r); !ok {
		webError(rw, 401, "AUTH_REQUIRED")
		return
	}
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(200)
	_, _ = rw.Write(b)
}

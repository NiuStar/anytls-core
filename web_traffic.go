package main

import (
	"context"
	"net/http"
	"time"

	cr "github.com/NiuStar/anytls-core/internal/connectionrecords"
	ts "github.com/NiuStar/anytls-core/internal/trafficstats"
)

// getTraffic is routed by the WebUI owner after normal Host/session validation.
// The second auth check fences password resets while privileged IO is pending.
func (w *webConsole) getTraffic(rw http.ResponseWriter, r *http.Request) {
	request := w.trafficRequest
	if request == nil {
		request = controlHelperTrafficRequest
	}
	w.getTrafficWith(rw, r, request)
}
func (w *webConsole) getTrafficWith(rw http.ResponseWriter, r *http.Request, request func(context.Context) (ts.Response, error)) {
	if r.Method != http.MethodGet {
		webError(rw, 405, "METHOD_NOT_ALLOWED")
		return
	}
	if _, ok := w.authenticated(r); !ok {
		webError(rw, 401, "AUTH_REQUIRED")
		return
	}
	app, site := r.Header.Values("X-AnyTLS-Origin"), r.Header.Values("Sec-Fetch-Site")
	siteOK := len(site) == 1 && site[0] == "same-origin" || len(site) == 0 && w.networkListen()
	if len(app) != 1 || app[0] != "http://"+r.Host || !siteOK || len(r.Header.Values("Origin")) > 0 && !w.originOK(r) {
		webError(rw, 403, "INVALID_ORIGIN")
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		webError(rw, 400, "INVALID_INPUT")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), cr.TelemetryTimeout)
	defer cancel()
	response, e := request(ctx)
	if e != nil || ts.Validate(response) != nil {
		response = ts.Unavailable()
	}
	if response.Snapshot != nil {
		identity, e := controlHelperConfigIdentity(w.configPath)
		at, ae := time.Parse(time.RFC3339Nano, response.Snapshot.SampledAt)
		if e != nil || identity != response.Snapshot.Header.ConfigIdentity || ae != nil || time.Since(at) < 0 || time.Since(at) > ts.FreshFor {
			response = ts.Unavailable()
		}
	}
	if ctx.Err() != nil {
		response = ts.Unavailable()
	}
	if _, ok := w.authenticated(r); !ok {
		webError(rw, 401, "AUTH_REQUIRED")
		return
	}
	b, e := ts.Encode(response)
	if e != nil {
		webError(rw, 503, "TELEMETRY_UNAVAILABLE")
		return
	}
	rw.Header().Set("Cache-Control", "no-store")
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	status := 200
	if response.Availability != "OBSERVED" {
		status = 503
	}
	rw.WriteHeader(status)
	_, _ = rw.Write(b)
}

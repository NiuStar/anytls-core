package main

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	cr "github.com/NiuStar/anytls-core/internal/connectionrecords"
)

func recordsHTTPStatus(code cr.ErrorCode) int {
	switch code {
	case cr.InvalidRequest:
		return 400
	case cr.Forbidden:
		return 403
	case cr.Busy, cr.StaleGeneration:
		return 409
	default:
		return 503
	}
}
func webRecordsError(rw http.ResponseWriter, code cr.ErrorCode) {
	b := recordsErrorBytes(code)
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	rw.WriteHeader(recordsHTTPStatus(code))
	_, _ = rw.Write(b)
}
func webRecordsQuery(raw string) (cr.PageRequest, error) {
	q := cr.PageRequest{SchemaVersion: 1, After: "0", Limit: cr.DefaultPageLimit}
	if len(raw) > cr.MaxRequestBytes {
		return q, cr.InvalidRequest
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return q, cr.InvalidRequest
	}
	for k, v := range values {
		if len(v) != 1 {
			return q, cr.InvalidRequest
		}
		switch k {
		case "after", "limit", "instance_id", "generation", "manifest_id":
		default:
			return q, cr.InvalidRequest
		}
	}
	if v, ok := values["after"]; ok {
		q.After = cr.Decimal(v[0])
	}
	if v, ok := values["limit"]; ok {
		// No +1, exponent, whitespace or leading zero spellings.
		if v[0] == "" || strings.Trim(v[0], "0123456789") != "" || v[0][0] == '0' {
			return q, cr.InvalidRequest
		}
		n, e := strconv.Atoi(v[0])
		if e != nil {
			return q, cr.InvalidRequest
		}
		q.Limit = n
	}
	_, a := values["instance_id"]
	_, b := values["generation"]
	_, c := values["manifest_id"]
	if a || b || c {
		if !a || !b || !c {
			return q, cr.InvalidRequest
		}
		q.Binding = &cr.Binding{InstanceID: values.Get("instance_id"), Generation: values.Get("generation"), ManifestID: values.Get("manifest_id")}
	}
	if cr.ValidatePageRequest(q) != nil {
		return q, cr.InvalidRequest
	}
	return q, nil
}
func (w *webConsole) getConnections(rw http.ResponseWriter, r *http.Request) {
	app, site := r.Header.Values("X-AnyTLS-Origin"), r.Header.Values("Sec-Fetch-Site")
	// Insecure LAN HTTP may omit Fetch Metadata. Only explicit LAN listeners
	// accept absence, still requiring the exact custom origin (and no CORS).
	siteOK := len(site) == 1 && site[0] == "same-origin" || len(site) == 0 && w.lanListen()
	if len(app) != 1 || app[0] != "http://"+r.Host || !siteOK || (len(r.Header.Values("Origin")) > 0 && !w.originOK(r)) {
		webRecordsError(rw, cr.Forbidden)
		return
	}
	q, err := webRecordsQuery(r.URL.RawQuery)
	if err != nil {
		webRecordsError(rw, cr.InvalidRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), cr.TelemetryTimeout)
	defer cancel()
	request := w.recordsRequest
	if request == nil {
		request = controlHelperRecordsRequest
	}
	p, err := request(ctx, q)
	if err != nil {
		webRecordsError(rw, recordsErrorCode(err))
		return
	}
	identity, err := controlHelperConfigIdentity(w.configPath)
	if err != nil || identity != p.ConfigIdentity || !recordsPageMatches(p, q) {
		webRecordsError(rw, cr.StoreInvalid)
		return
	}
	b, err := cr.EncodeBounded(p, cr.MaxResponseBytes)
	if err != nil {
		webRecordsError(rw, cr.StoreInvalid)
		return
	}
	if ctx.Err() != nil {
		webRecordsError(rw, cr.TelemetryUnavailable)
		return
	}
	// Revoke a login/reset that happened while the helper read was outstanding.
	if _, ok := w.authenticated(r); !ok {
		webError(rw, 401, "AUTH_REQUIRED")
		return
	}
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	rw.WriteHeader(200)
	_, _ = rw.Write(b)
}

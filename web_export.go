package main

import (
	"context"
	"net/http"
	"time"
)

// Export is explicit authenticated access to node credentials, never a save or
// runtime action. Subscription addresses and private metadata are not included.
func webExportJSON(rw http.ResponseWriter, b []byte, report webConversionReport) {
	rw.Header().Set("Cache-Control", "no-store")
	webJSON(rw, http.StatusOK, map[string]any{"yaml": string(b), "filename": "anytls-config.yaml", "format": "anytls-native", "conversion": report})
}

func (w *webConsole) exportConverted(rw http.ResponseWriter, r *http.Request) {
	var in struct {
		Token string `json:"token"`
	}
	if webDecode(rw, r, &in) != nil {
		webError(rw, 400, "INVALID_INPUT")
		return
	}
	p := w.importPending
	if p == nil || !w.now().Before(p.expires) || !webEqual(in.Token, p.token) || !webEqual(r.Header.Get("X-CSRF-Token"), p.csrf) {
		webError(rw, 409, "IMPORT_PREVIEW_EXPIRED")
		return
	}
	if r.Header.Get("If-Match") != p.etag {
		webError(rw, 412, "CONFIG_CONFLICT")
		return
	}
	for _, f := range []webImportFile{p.oldConfig, p.oldSelected, p.oldSubscription} {
		if !webImportSame(f) {
			webError(rw, 412, "CONFIG_CONFLICT")
			return
		}
	}
	webExportJSON(rw, p.data, p.conversion)
}

func (w *webConsole) exportCurrent(rw http.ResponseWriter, r *http.Request) {
	// Avoid observing an in-process import's individually atomic write sequence.
	if !w.actionMu.TryLock() {
		webError(rw, 409, "ACTION_BUSY")
		return
	}
	defer w.actionMu.Unlock()
	b, err := readSnapshotSource(w.configPath, snapshotConfigLimit, false)
	if err != nil {
		webError(rw, 503, "CONFIG_UNAVAILABLE")
		return
	}
	// Current native bytes stay exact. Legacy Clash-shaped configuration is
	// normalized without fetching providers or executing any service action.
	noFetch := func(context.Context, string) ([]byte, error) { return nil, context.Canceled }
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	converted, report, err := webConvertConfiguration(ctx, b, false, noFetch)
	if err != nil {
		webError(rw, 422, webConversionErrorCode(err))
		return
	}
	if len(report.Issues) > 0 {
		webJSON(rw, 422, map[string]any{"error": "CONFIG_CONVERSION_UNSUPPORTED", "conversion": report})
		return
	}
	webExportJSON(rw, converted, report)
}

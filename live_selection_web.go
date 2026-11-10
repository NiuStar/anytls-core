package main

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

type liveWebRecovery struct {
	request     webControlRequestFunc // transport seam only, never result synthesis
	operation   *liveSelectionOperation
	fingerprint string
	unknown     bool
	changed     bool
}

// Call only while actionMu is held, after an explicitly requested service
// start/reload has been authenticated and completed LOCAL_READY. Never call
// from ordinary status/refresh, NO_CHANGE, or a failed/unknown reinitialization.
func (w *webConsole) selectionReinitialized() {
	w.metaMu.Lock()
	w.selectionRecovery.operation = nil
	w.selectionRecovery.fingerprint = ""
	w.selectionRecovery.unknown = false
	w.selectionRecovery.changed = false
	w.metaMu.Unlock()
}

// Called by the authenticated mutation router before committing selection files.
func (w *webConsole) selectionMutationBlocked(rw http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/api/v1/nodes/selection" && r.URL.Path != "/api/v1/groups/selection" {
		return false
	}
	w.metaMu.Lock()
	unknown := w.selectionRecovery.unknown
	w.metaMu.Unlock()
	if unknown {
		webJSON(rw, 409, map[string]any{"error": "SWITCH_UNKNOWN", "readback_requires_owned_lease": true})
		return true
	}
	return false
}
func (w *webConsole) selectionRequest(ctx context.Context, action string) (controlHelperResponse, error) {
	request := w.selectionRecovery.request
	if request == nil {
		request = controlHelperRequest
	}
	status, e := webControlBoundStatus(ctx, w.configPath, request)
	if e != nil {
		return controlHelperResponse{}, e
	}
	if !status.OK || !status.Loaded || !status.Running || status.Code != "" || ctx.Err() != nil {
		return controlHelperResponse{}, &webControlError{Code: "SWITCH_UNKNOWN"}
	}
	result, e := request(ctx, action, false)
	expected, identityErr := controlHelperConfigIdentity(w.configPath)
	if identityErr != nil || expected != status.ConfigIdentity || result.ConfigIdentity != status.ConfigIdentity {
		return controlHelperResponse{}, &webControlError{Code: "HELPER_CONFIG_MISMATCH"}
	}
	if e != nil || ctx.Err() != nil {
		if ctx.Err() == nil && !result.OK && result.Code == "RELOAD_REQUIRED" {
			return result, &webControlError{Code: "RELOAD_REQUIRED"}
		}
		return result, &webControlError{Code: "SWITCH_UNKNOWN"}
	}
	if !result.OK || !result.Loaded || !result.Running || result.Code != "HOT_APPLIED" || !result.SelectionOperation.valid() {
		if result.Code == "RELOAD_REQUIRED" && !result.OK {
			return result, &webControlError{Code: "RELOAD_REQUIRED"}
		}
		return result, &webControlError{Code: "SWITCH_UNKNOWN"}
	}
	return result, nil
}
func (w *webConsole) selectionSavedName() string {
	saved, e := captureServiceConfig(w.configPath)
	if e != nil {
		return ""
	}
	nodes, e := loadNodesBytes(saved.config)
	if e != nil {
		return ""
	}
	name, e := selectedBytes(saved.selection, nodes)
	if e != nil {
		return ""
	}
	return name
}
func (w *webConsole) finishSelectionSave(rw http.ResponseWriter, r *http.Request, changed bool, etag string, _ bool) {
	if e := w.syncActiveProfile(); e != nil {
		w.saved()
		webJSON(rw, 500, map[string]any{"error": "PROFILE_SYNC_FAILED", "saved": true, "applied": false})
		return
	}
	status, applied := "NO_CHANGE", false
	pending, known := w.pendingState()
	w.metaMu.Lock()
	locked := w.selectionRecovery.unknown
	w.metaMu.Unlock()
	if locked {
		status = "SWITCH_UNKNOWN"
	} else if changed || pending || !known {
		w.saved()
		loaded, running, e := w.state()
		switch {
		case e != nil || running && !loaded:
			status = "STATE_UNAVAILABLE"
		case !running:
			status = "SAVED_STOPPED"
		default:
			before := w.fingerprint()
			name := w.selectionSavedName()
			w.metaMu.Lock()
			w.selectionRecovery.operation = nil
			w.selectionRecovery.fingerprint = ""
			w.metaMu.Unlock()
			ctx, cancel := context.WithTimeout(r.Context(), 7*time.Second)
			result, e := w.selectionRequest(ctx, "select")
			cancel()
			valid := before != "" && name != "" && w.fingerprint() == before && result.SelectionOperation.valid() && result.SelectionOperation.Node == name
			w.metaMu.Lock()
			if valid {
				op := *result.SelectionOperation
				w.selectionRecovery.operation = &op
				w.selectionRecovery.fingerprint = before
				w.selectionRecovery.changed = changed
			}
			if e == nil && valid {
				w.baseline, w.pending, w.pendingKnown = before, false, true
				w.selectionRecovery.unknown = false
				status, applied = "HOT_APPLIED", true
			} else {
				var ce *webControlError
				if errors.As(e, &ce) && ce.Code == "RELOAD_REQUIRED" {
					status = "RELOAD_REQUIRED"
				} else {
					status = "SWITCH_UNKNOWN"
					w.selectionRecovery.unknown = true
					w.pending, w.pendingKnown = true, false
				}
			}
			w.metaMu.Unlock()
		}
	}
	w.selectionReply(rw, changed, etag, status, applied)
}
func (w *webConsole) selectionReply(rw http.ResponseWriter, changed bool, etag, status string, applied bool) {
	pending, known := w.pendingState()
	w.metaMu.Lock()
	var op *liveSelectionOperation
	if w.selectionRecovery.operation != nil {
		copyOp := *w.selectionRecovery.operation
		op = &copyOp
	}
	unknown := w.selectionRecovery.unknown
	w.metaMu.Unlock()
	rw.Header().Set("ETag", etag)
	webJSON(rw, 200, map[string]any{"ok": true, "saved": true, "changed": changed, "applied": applied, "apply_status": status, "pendingReload": pending, "pendingKnown": known, "etag": etag, "startup_operation": nil, "connection_policy": "EXISTING_CONNECTIONS_RETAIN_OLD_EXIT", "selection_operation": op, "readback_requires_owned_lease": unknown && op == nil})
}
func (w *webConsole) getSelectionReadback(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		webError(rw, 405, "METHOD_NOT_ALLOWED")
		return
	}
	if !w.actionMu.TryLock() {
		webError(rw, 409, "ACTION_BUSY")
		return
	}
	defer w.actionMu.Unlock()
	w.metaMu.Lock()
	var expected *liveSelectionOperation
	if w.selectionRecovery.operation != nil {
		copyOp := *w.selectionRecovery.operation
		expected = &copyOp
	}
	fingerprint := w.selectionRecovery.fingerprint
	changed := w.selectionRecovery.changed
	w.metaMu.Unlock()
	reject := func() {
		w.metaMu.Lock()
		w.selectionRecovery.unknown = true
		w.pending, w.pendingKnown = true, false
		w.metaMu.Unlock()
		webJSON(rw, 409, map[string]any{"error": "SWITCH_UNKNOWN", "applied": false, "readback_requires_owned_lease": true})
	}
	if !expected.valid() {
		reject()
		return
	}
	q, queryErr := url.ParseQuery(r.URL.RawQuery)
	if queryErr != nil || len(q) != 4 {
		reject()
		return
	}
	for _, key := range []string{"operation", "generation", "revision", "node"} {
		if len(q[key]) != 1 {
			reject()
			return
		}
	}
	if q.Get("operation") != expected.Operation || q.Get("generation") != expected.Generation || q.Get("revision") != strconv.FormatUint(expected.Revision, 10) || q.Get("node") != expected.Node || w.fingerprint() != fingerprint {
		reject()
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 7*time.Second)
	defer cancel()
	result, e := w.selectionRequest(ctx, "select-read")
	saved, captureErr := captureServiceConfig(w.configPath)
	etag := ""
	if captureErr == nil {
		etag = `"` + shaHex(saved.config) + `"`
	}
	applied := e == nil && captureErr == nil && result.SelectionOperation.valid() && *result.SelectionOperation == *expected && w.fingerprint() == fingerprint
	w.metaMu.Lock()
	w.selectionRecovery.unknown = !applied
	var controlErr *webControlError
	if !applied && errors.As(e, &controlErr) && controlErr.Code == "SWITCH_UNKNOWN" && !result.SelectionOperation.valid() {
		// Helper no longer owns this operation (e.g. restart). Keep UNKNOWN but
		// explicitly require a fresh owned lease via reinitialization.
		w.selectionRecovery.operation = nil
		w.selectionRecovery.fingerprint = ""
	}
	if applied {
		w.baseline, w.pending, w.pendingKnown = fingerprint, false, true
	} else {
		w.pending, w.pendingKnown = true, false
	}
	w.metaMu.Unlock()
	status := "SWITCH_UNKNOWN"
	if applied {
		status = "HOT_APPLIED"
	}
	w.selectionReply(rw, changed, etag, status, applied)
}

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	st "github.com/NiuStar/anytls-core/internal/startuptimeline"
)

// Only diagnostic memory is protected by startupMu; never hold it over IPC,
// authentication, config reads, encoding, or the service action lock.
type webStartupOperation struct {
	id                              string
	legacy                          bool
	source, action, started, result string
	finished                        *string
	recorder                        *st.Recorder
	wait                            uint64
	reference                       st.OperationReference
	helperEpoch                     *string
	helperObserved                  bool
	configIdentity                  string
	helperResult                    *st.MutationResponse
	diagnostics                     *startDiagnostics
}
type webStartupReadFunc func(context.Context, *string) (st.ReadResponse, error)
type webStartupControlFunc func(context.Context, string, bool, string) (st.MutationResponse, error)
type webStartupResponseWriter struct{ http.ResponseWriter }

func webStartupMutationPath(r *http.Request) bool {
	switch r.URL.Path {
	case "/api/v1/config", "/api/v1/nodes", "/api/v1/groups/selection", "/api/v1/nodes/selection", "/api/v1/rules", "/api/v1/profiles/switch", "/api/v1/import/commit":
		return r.Method != "GET"
	}
	return strings.HasPrefix(r.URL.Path, "/api/v1/service/")
}

func webStartupID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

type webStartupSourceKey struct{}

func webStartupSource(r *http.Request) string {
	if source, ok := r.Context().Value(webStartupSourceKey{}).(string); ok && source == "IMPORT_APPEND" {
		return source
	}
	switch r.URL.Path {
	case "/api/v1/config":
		return "SAVE_YAML"
	case "/api/v1/nodes":
		return "SAVE_NODE"
	case "/api/v1/groups/selection":
		return "SAVE_GROUP"
	case "/api/v1/nodes/selection":
		return "SAVE_SELECTION"
	case "/api/v1/rules":
		return "SAVE_RULE"
	case "/api/v1/profiles/switch":
		return "PROFILE_SWITCH"
	case "/api/v1/import/commit":
		return "IMPORT_COMMIT"

	}
	return "LEGACY_CONTROL"
}
func (w *webConsole) beginStartup(action, source string) *webStartupOperation {
	op := &webStartupOperation{source: source, action: strings.ToUpper(action), started: time.Now().UTC().Format(time.RFC3339Nano), result: "IN_PROGRESS", reference: st.OperationReference{TimelineSchema: 1, Availability: "UNAVAILABLE"}}
	op.configIdentity, _ = controlHelperConfigIdentity(w.configPath)
	random := w.startupRandom
	if random == nil {
		random = rand.Reader
	}
	var bytes [16]byte
	if _, err := io.ReadFull(random, bytes[:]); err == nil {
		op.id = hex.EncodeToString(bytes[:])
		op.reference.OperationID = &op.id
		op.recorder, _ = st.NewRecorder("WEB", st.Provenance{SHAKind: "UNKNOWN", ExecutionMapping: "NOT_ATTESTED"})
		if op.recorder == nil {
			op.id = ""
			op.reference.OperationID = nil
		}
		if op.recorder != nil {
			op.recorder.Observe("PREFLIGHT", "WEB_ACCEPT", "OK", st.Fields{})
			op.wait = op.recorder.Begin("PREFLIGHT", "WEB_WAIT_HELPER", st.Fields{})
		}
	}
	op.legacy = w.serviceAction != nil
	w.startupMu.Lock()
	w.startupLatest = op
	w.startupMu.Unlock()
	return op
}
func (w *webConsole) finishStartup(op *webStartupOperation, err error) {
	if op == nil {
		return
	}
	result := "SUCCEEDED"
	code := "OK"
	if err != nil {
		result = "FAILED"
		code = "FAILED"
		var uncertain *webControlError
		if errors.As(err, &uncertain) && uncertain.StartupUnknown {
			result = "UNKNOWN"
			code = "UNKNOWN"
		}
	}
	op.recorder.End(op.wait, code, st.Fields{})
	op.recorder.Observe("FINALIZE", "WEB_FINISH", code, st.Fields{})
	op.recorder.Finish(result)
	finished := time.Now().UTC().Format(time.RFC3339Nano)
	w.startupMu.Lock()
	op.result = result
	op.finished = &finished
	w.startupMu.Unlock()
}
func (w *webConsole) startupReference(op *webStartupOperation) *st.OperationReference {
	w.startupMu.Lock()
	defer w.startupMu.Unlock()
	ref := op.reference
	return &ref
}

// Result-bearing variant preserves successful as well as failed helper DTOs.
// A mutation is sent at most once: only capability discovery may fall back.
type webControlActionResultValue struct {
	Reference   st.OperationReference
	Helper      *st.MutationResponse
	Diagnostics *startDiagnostics
}

func webControlActionResult(ctx context.Context, config, action string, allow bool, id string, legacy webControlRequestFunc, read webStartupReadFunc, mutate webStartupControlFunc, unsupported func(error) bool) (webControlActionResultValue, error) {
	var helper *st.MutationResponse
	var diagnostic *startDiagnostics
	legacyRequest := func(ctx context.Context, verb string, allow bool) (controlHelperResponse, error) {
		r, err := legacy(ctx, verb, allow)
		if verb == action && err == nil && r.OK && r.Diagnostics != nil && r.Diagnostics.valid(true) {
			copy := *r.Diagnostics
			diagnostic = &copy
		}
		return r, err
	}
	request := func(ctx context.Context, action string, allow bool, id string) (st.MutationResponse, error) {
		result, err := mutate(ctx, action, allow, id)
		if err == nil && st.Validate(result) == nil {
			copy := result
			helper = &copy
		}
		return result, err
	}
	ref, err := webControlActionReference(ctx, config, action, allow, id, legacyRequest, read, request, unsupported)
	if err == nil && helper != nil && helper.Diagnostics != nil {
		d := helper.Diagnostics
		diagnostic = &startDiagnostics{Schema: d.Schema, Operation: d.Operation, Outcome: d.Outcome, Stage: d.Stage, Reason: d.Reason, Rollback: d.Rollback, Restoration: d.Restoration, Cleanup: d.Cleanup, Receipt: d.Receipt, Job: d.Job, Tun: d.Tun}
	}
	return webControlActionResultValue{Reference: ref, Helper: helper, Diagnostics: diagnostic}, err
}
func webControlActionReference(ctx context.Context, config, action string, allow bool, id string, legacy webControlRequestFunc, read webStartupReadFunc, mutate webStartupControlFunc, unsupported func(error) bool) (st.OperationReference, error) {
	ref := st.OperationReference{TimelineSchema: 1, Availability: "UNAVAILABLE"}
	if id != "" {
		ref.OperationID = &id
	}
	if action == "status" || !controlHelperValidRequest(controlHelperWireRequest{action, allow}) {
		return ref, &webControlError{Code: "INVALID_REQUEST"}
	}
	recorder := st.FromContext(ctx)
	boundSpan := recorder.Begin("PREFLIGHT", "WEB_BOUND_STATUS", st.Fields{})
	status, err := webControlBoundStatus(ctx, config, legacy)
	boundCode := "OK"
	if err != nil {
		boundCode = "FAILED"
	}
	recorder.End(boundSpan, boundCode, st.Fields{})
	if err != nil {
		return ref, err
	}
	if id == "" {
		return ref, webControlActionBound(ctx, config, action, allow, legacy, status)
	}
	capctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	capability, err := read(capctx, nil)
	cancel()
	if err != nil {
		if unsupported(err) || errors.Is(err, context.DeadlineExceeded) {
			ref.Availability = "UNSUPPORTED"
			if !unsupported(err) {
				ref.Availability = "UNAVAILABLE"
			}
			return ref, webControlActionBound(ctx, config, action, allow, legacy, status)
		}
		return ref, &webControlError{Code: "HELPER_UNAVAILABLE"}
	}
	if st.Validate(capability) != nil || capability.ConfigIdentity == nil || *capability.ConfigIdentity != status.ConfigIdentity {
		return ref, &webControlError{Code: "HELPER_CONFIG_MISMATCH"}
	}
	if capability.Code != "OK" && capability.Code != "NO_OPERATION" {
		return ref, &webControlError{Code: "HELPER_UNAVAILABLE"}
	}
	if capability.HelperEpoch == nil {
		return ref, &webControlError{Code: "HELPER_UNAVAILABLE"}
	}
	// Capability proves the ID can be queried even when the mutation reply is lost.
	ref.Availability = "AVAILABLE"
	result, err := mutate(ctx, action, allow, id) // alreadySent: never resend after this line.
	if err != nil {
		return ref, &webControlError{Code: "HELPER_UNAVAILABLE", StartupUnknown: true}
	}
	if st.Validate(result) != nil {
		return ref, &webControlError{Code: "HELPER_UNAVAILABLE", StartupUnknown: true}
	}
	expected, e := controlHelperConfigIdentity(config)
	if e != nil || expected != status.ConfigIdentity || result.ConfigIdentity != expected {
		return ref, &webControlError{Code: "HELPER_CONFIG_MISMATCH"}
	}
	if result.TimelineAvailability == "AVAILABLE" {
		if result.OperationID == nil || *result.OperationID != id || capability.HelperEpoch == nil || result.HelperEpoch == nil || *result.HelperEpoch != *capability.HelperEpoch {
			return ref, &webControlError{Code: "HELPER_UNAVAILABLE"}
		}
		ref.Availability = "AVAILABLE"
	} else {
		ref.Availability = "UNAVAILABLE"
		ref.OperationID = nil
	}
	if !result.OK {
		failure := &webControlError{Code: result.Code}
		if result.Diagnostics != nil {
			d := result.Diagnostics
			failure.Diagnostics = &startDiagnostics{Schema: d.Schema, Operation: d.Operation, Outcome: d.Outcome, Stage: d.Stage, Reason: d.Reason, Rollback: d.Rollback, Restoration: d.Restoration, Cleanup: d.Cleanup, Receipt: d.Receipt, Job: d.Job, Tun: d.Tun}
		}
		return ref, failure
	}
	return ref, nil
}
func (w *webConsole) startupAction(ctx context.Context, action string, allow bool, op *webStartupOperation) error {
	// Existing injected error-only service seam remains isolated from real IPC.
	if w.serviceAction != nil {
		return w.serviceAction(ctx, action, allow)
	}
	read := w.startupReadRequest
	if read == nil {
		read = startupRead
	}
	request := read
	read = func(ctx context.Context, id *string) (st.ReadResponse, error) {
		response, err := request(ctx, id)
		if id == nil && err == nil && st.Validate(response) == nil {
			w.startupMu.Lock()
			op.helperEpoch = response.HelperEpoch
			w.startupMu.Unlock()
		}
		return response, err
	}
	mutate := w.startupControlRequest
	if mutate == nil {
		mutate = startupControl
	}
	legacy := w.startupLegacyRequest
	if legacy == nil {
		legacy = controlHelperRequest
	}
	result, err := webControlActionResult(st.WithRecorder(ctx, op.recorder), w.configPath, action, allow, op.id, legacy, read, mutate, startupUnsupported)
	w.startupMu.Lock()
	op.reference = result.Reference
	op.helperResult = result.Helper
	op.diagnostics = result.Diagnostics
	w.startupMu.Unlock()
	return err
}
func (w *webConsole) getStartupTrace(rw http.ResponseWriter, r *http.Request) {
	app, site := r.Header.Values("X-AnyTLS-Origin"), r.Header.Values("Sec-Fetch-Site")
	siteOK := len(site) == 1 && site[0] == "same-origin" || len(site) == 0 && w.networkListen()
	if len(app) != 1 || app[0] != "http://"+r.Host || !siteOK || len(r.Header.Values("Origin")) > 0 && !w.originOK(r) {
		webError(rw, 403, "FORBIDDEN")
		return
	}
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(r.URL.RawQuery) > 128 {
		webError(rw, 400, "INVALID_REQUEST")
		return
	}
	var requested *string
	for key, v := range values {
		if key != "operation_id" || len(v) != 1 || !webStartupID(v[0]) {
			webError(rw, 400, "INVALID_REQUEST")
			return
		}
		id := v[0]
		requested = &id
	}
	identity, err := controlHelperConfigIdentity(w.configPath)
	if err != nil {
		webError(rw, 503, "HELPER_UNAVAILABLE")
		return
	}
	w.startupMu.Lock()
	op := w.startupLatest
	var id string
	if op != nil {
		id = op.id
	}
	w.startupMu.Unlock()
	if requested != nil && (op == nil || *requested != id) {
		webError(rw, 409, "OPERATION_MISMATCH")
		return
	}
	if op != nil && op.configIdentity != identity {
		webError(rw, 503, "HELPER_CONFIG_MISMATCH")
		return
	}
	response := st.ReadResponse{TimelineSchema: 1, Code: "NO_OPERATION"}
	if op != nil && id != "" {
		request := w.startupReadRequest
		if request == nil {
			request = startupRead
		}
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		if op.legacy && w.startupReadRequest == nil {
			response = st.ReadResponse{TimelineSchema: 1, Code: "UNAVAILABLE", OperationID: &id}
		} else {
			response, err = request(ctx, &id)
		}
		cancel()
		if err != nil {
			response = st.ReadResponse{TimelineSchema: 1, Code: "UNAVAILABLE", OperationID: &id}
			if startupUnsupported(err) {
				response.Code = "UNSUPPORTED"
			}
		} else if st.Validate(response) != nil {
			webError(rw, 503, "INVALID_TRACE")
			return
		}
		if r.Context().Err() != nil {
			return
		}
		if response.ConfigIdentity != nil && *response.ConfigIdentity != identity {
			webError(rw, 503, "HELPER_CONFIG_MISMATCH")
			return
		}
		if response.OperationID != nil && *response.OperationID != id {
			webError(rw, 409, "OPERATION_MISMATCH")
			return
		}
		if response.Code == "OK" && response.ConfigIdentity == nil {
			webError(rw, 503, "HELPER_CONFIG_MISMATCH")
			return
		}
		w.startupMu.Lock()
		source, action, started, finished, result, helperEpoch, observed := op.source, op.action, op.started, op.finished, op.result, op.helperEpoch, op.helperObserved
		w.startupMu.Unlock()
		if response.Code == "OK" {
			if response.Trace.Operation != action || helperEpoch != nil && (response.HelperEpoch == nil || *response.HelperEpoch != *helperEpoch) {
				webError(rw, 409, "OPERATION_MISMATCH")
				return
			}
			// Do not mutate the helper/request seam's retained snapshot or its slices.
			encoded, e := st.Encode(response)
			if e != nil || st.Decode(strings.NewReader(string(encoded)), &response) != nil {
				webError(rw, 503, "INVALID_TRACE")
				return
			}
			for _, stream := range response.Trace.Streams {
				if stream.Role == "WEB" {
					webError(rw, 503, "INVALID_TRACE")
					return
				}
			}
			response.Trace.Source = source
			w.startupMu.Lock()
			op.helperObserved = true
			w.startupMu.Unlock()
			response.Trace.WebReturn = result
			if finished == nil {
				response.Trace.State = "IN_PROGRESS"
				response.Trace.FinishedAt = nil
			} else if response.Trace.State == "FINISHED" {
				response.Trace.FinishedAt = finished
			}
		} else if response.Code == "NO_OPERATION" || response.Code == "OPERATION_MISMATCH" && !observed && finished == nil {
			response = st.ReadResponse{TimelineSchema: 1, Code: "OK", OperationID: &id, ConfigIdentity: &identity, Trace: &st.Trace{Authority: st.Authority, OperationID: id, ConfigIdentity: &identity, Operation: action, Source: source, StartedAt: started, FinishedAt: finished, State: "IN_PROGRESS", LifecycleResult: "UNKNOWN", HelperReturn: "UNKNOWN", WebReturn: result, ReceiptResult: "UNKNOWN", Streams: []st.ProcessStream{}, CoreObservation: st.CoreObservation{Availability: "NOT_OBSERVED", Gap: true}, Gap: true}}
			if finished != nil {
				response.Trace.State = "FINISHED"
			}
		}
		if response.Trace != nil && op.recorder != nil {
			response.Trace.Streams = append(response.Trace.Streams, op.recorder.Snapshot())
		}
	} else if op != nil {
		response.Code = "UNAVAILABLE"
	}
	b, err := st.Encode(response)
	if err != nil {
		webError(rw, 503, "INVALID_TRACE")
		return
	}
	// All three bindings are checked again immediately before publishing bytes.
	if _, ok := w.authenticated(r); !ok {
		webError(rw, 401, "AUTH_REQUIRED")
		return
	}
	currentIdentity, err := controlHelperConfigIdentity(w.configPath)
	if err != nil || identity != currentIdentity {
		webError(rw, 503, "HELPER_CONFIG_MISMATCH")
		return
	}
	w.startupMu.Lock()
	same := w.startupLatest == op
	w.startupMu.Unlock()
	if !same {
		webError(rw, 409, "OPERATION_MISMATCH")
		return
	}
	status := 200
	switch response.Code {
	case "OPERATION_MISMATCH", "BUSY":
		status = 409
	case "FORBIDDEN":
		status = 403
	case "INVALID_REQUEST":
		status = 400
	case "OK", "NO_OPERATION":
	default:
		status = 503
	}
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	rw.WriteHeader(status)
	_, _ = rw.Write(b)
}

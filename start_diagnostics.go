package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

// Invocation-local evidence, never reconstructed from a file or error text.
type startDiagnostics struct {
	Schema      int    `json:"schema"`
	Operation   string `json:"operation"`
	Outcome     string `json:"outcome"`
	Stage       string `json:"stage"`
	Reason      string `json:"reason"`
	Rollback    string `json:"rollback"`
	Restoration string `json:"restoration"`
	Cleanup     string `json:"cleanup"`
	Receipt     string `json:"receipt"`
	Job         string `json:"job"`
	Tun         string `json:"tun"`
}
type startDiagnosticError struct {
	diagnostic startDiagnostics
	cause      error
}

func (e *startDiagnosticError) Error() string { return e.cause.Error() }
func (e *startDiagnosticError) Unwrap() error { return e.cause }
func newStartDiagnostics(op string) *startDiagnostics {
	return &startDiagnostics{1, op, "SUCCEEDED", "NONE", "NONE", "NOT_ATTEMPTED", "NOT_ATTEMPTED", "NOT_ATTEMPTED", "NOT_ATTEMPTED", "NOT_OBSERVED", "NOT_OBSERVED"}
}
func (d *startDiagnostics) fail(stage, reason string, err error) error {
	if d != nil && d.Reason == "NONE" {
		d.Stage, d.Reason, d.Outcome = stage, reason, "FAILED"
		if stage == "UNKNOWN" && reason == "UNKNOWN" {
			d.Outcome = "UNKNOWN"
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			d.Reason, d.Outcome = "CANCELLED", "CANCELLED"
		}
	}
	return err
}
func (d serviceLifecycle) failure(stage, reason string, err error) error {
	return d.diagnostic.fail(stage, reason, err)
}

type systemProxyActiveError struct{}

func (*systemProxyActiveError) Error() string {
	return "system proxy active; turn it off before starting TUN"
}
func httpsFailureReason(err error) string {
	var exit interface{ ExitCode() int }
	if !errors.As(err, &exit) {
		return "HTTPS_FAILED"
	}
	switch exit.ExitCode() {
	case 6:
		return "HTTPS_DNS_FAILED"
	case 7:
		return "HTTPS_CONNECT_FAILED"
	case 28:
		return "HTTPS_TIMEOUT"
	case 35:
		return "HTTPS_TLS_HANDSHAKE_FAILED"
	case 60:
		return "HTTPS_CERTIFICATE_FAILED"
	case 22:
		return "HTTPS_HTTP_FAILED"
	case 52:
		return "HTTPS_EMPTY_RESPONSE"
	case 56:
		return "HTTPS_RECEIVE_FAILED"
	}
	return "HTTPS_FAILED"
}

var diagnosticReasons = map[string]string{
	"HELPER_PREFLIGHT": "PREFLIGHT_REJECTED", "JOB": "JOB_STATE_UNAVAILABLE JOB_ALREADY_LOADED JOB_NOT_LOADED", "SNAPSHOT": "SNAPSHOT_EXISTS SNAPSHOT_UNAVAILABLE SNAPSHOT_STAGE_FAILED SNAPSHOT_IDENTITY_FAILED", "CONFIG": "CONFIG_COMPILE_FAILED", "PROXY": "SYSTEM_PROXY_ACTIVE PROXY_STATE_UNAVAILABLE", "SERVER_ROUTE": "SERVER_ROUTE_UNAVAILABLE SERVER_ROUTE_NOT_PHYSICAL SERVER_ROUTE_CHANGED", "PUBLIC_ROUTE": "PUBLIC_ROUTE_UNAVAILABLE", "DNS": "DNS_STATE_UNAVAILABLE DNS_EVIDENCE_EMPTY", "BASELINE": "BASELINE_INVALID BASELINE_WRITE_FAILED", "PLIST": "PLIST_CREATE_FAILED PLIST_WRITE_FAILED PLIST_INVALID", "BOOTSTRAP": "LAUNCHD_BOOTSTRAP_FAILED", "READINESS": "READINESS_JOB_UNAVAILABLE READINESS_ROUTE_UNAVAILABLE READINESS_CHANGED PROCESS_NOT_RUNNING TUN_NOT_READY PROCESS_AND_TUN_NOT_READY READINESS_UNKNOWN", "HTTPS": "HTTPS_DNS_FAILED HTTPS_CONNECT_FAILED HTTPS_TIMEOUT HTTPS_TLS_HANDSHAKE_FAILED HTTPS_CERTIFICATE_FAILED HTTPS_HTTP_FAILED HTTPS_EMPTY_RESPONSE HTTPS_RECEIVE_FAILED HTTPS_RESPONSE_INVALID HTTPS_FAILED", "STOP": "STOP_FAILED", "DIAGNOSTIC": "RECEIPT_WRITE_FAILED", "UNKNOWN": "UNKNOWN", "NONE": "NONE",
}

func inDiagnosticSet(s, values string) bool {
	for _, v := range strings.Fields(values) {
		if s == v {
			return true
		}
	}
	return false
}
func (d *startDiagnostics) valid(ok bool) bool {
	if d == nil {
		return true
	}
	if d.Schema != 1 || !inDiagnosticSet(d.Operation, "START RELOAD STOP") || !inDiagnosticSet(d.Outcome, "SUCCEEDED FAILED CANCELLED UNKNOWN") || !inDiagnosticSet(d.Job, "NOT_OBSERVED RUNNING NOT_RUNNING UNLOADED UNKNOWN") || !inDiagnosticSet(d.Tun, "NOT_OBSERVED TUN NOT_TUN UNKNOWN") || !inDiagnosticSet(d.Receipt, "NOT_ATTEMPTED WRITTEN FAILED UNKNOWN") {
		return false
	}
	for _, v := range []string{d.Rollback, d.Restoration, d.Cleanup} {
		if !inDiagnosticSet(v, "NOT_ATTEMPTED VERIFIED FAILED UNKNOWN") {
			return false
		}
	}
	reasons, known := diagnosticReasons[d.Stage]
	if !known {
		return false
	}
	if d.Outcome == "CANCELLED" {
		return !ok && d.Stage != "NONE" && d.Reason == "CANCELLED"
	}
	if !inDiagnosticSet(d.Reason, reasons) {
		return false
	}
	if ok {
		return d.Outcome == "SUCCEEDED" && d.Stage == "NONE" && d.Reason == "NONE"
	}
	switch d.Outcome {
	case "SUCCEEDED":
		return d.Stage == "DIAGNOSTIC" && d.Reason == "RECEIPT_WRITE_FAILED"
	case "UNKNOWN":
		return d.Stage == "UNKNOWN" && d.Reason == "UNKNOWN"
	case "FAILED":
		return d.Reason != "NONE" && d.Stage != "UNKNOWN" && d.Stage != "DIAGNOSTIC"
	}
	return false
}
func (d *startDiagnostics) UnmarshalJSON(b []byte) error {
	type plain startDiagnostics
	var p plain
	err := controlHelperDecode(strings.NewReader(string(b)), map[string]any{"schema": &p.Schema, "operation": &p.Operation, "outcome": &p.Outcome, "stage": &p.Stage, "reason": &p.Reason, "rollback": &p.Rollback, "restoration": &p.Restoration, "cleanup": &p.Cleanup, "receipt": &p.Receipt, "job": &p.Job, "tun": &p.Tun})
	if err != nil {
		return err
	}
	*d = startDiagnostics(p)
	if !d.valid(false) && !d.valid(true) {
		return errors.New("invalid diagnostics")
	}
	return nil
}

// Only the response extension is optional. Request/registration decoding stays strict.
func controlHelperReadResponse(r io.Reader, p *controlHelperResponse) error {
	return controlHelperDecodeOptional(r, map[string]any{"ok": &p.OK, "code": &p.Code, "message": &p.Message, "loaded": &p.Loaded, "running": &p.Running, "helper_version": &p.HelperVersion, "helper_sha256": &p.HelperSHA256, "config_identity": &p.ConfigIdentity, "diagnostics": &p.Diagnostics}, "diagnostics")
}
func diagnosticFromError(err error, op, stage, reason string) *startDiagnostics {
	var e *startDiagnosticError
	if errors.As(err, &e) {
		d := e.diagnostic
		d.Operation = op
		return &d
	}
	d := newStartDiagnostics(op)
	d.fail(stage, reason, err)
	return d
}
func webControlDiagnostics(err error) *startDiagnostics {
	var e *webControlError
	if errors.As(err, &e) && e.Diagnostics != nil && e.Diagnostics.valid(false) {
		d := *e.Diagnostics
		return &d
	}
	return nil
}
func webControlErrorBody(err error) map[string]any {
	b := map[string]any{"error": webControlFailureCode(err)}
	if d := webControlDiagnostics(err); d != nil {
		b["diagnostics"] = d
	}
	return b
}

var _ json.Unmarshaler = (*startDiagnostics)(nil)

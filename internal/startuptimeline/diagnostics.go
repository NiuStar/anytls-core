package startuptimeline

var diagnosticReasons = map[string]string{
	"HELPER_PREFLIGHT": "PREFLIGHT_REJECTED", "JOB": "JOB_STATE_UNAVAILABLE JOB_ALREADY_LOADED JOB_NOT_LOADED", "SNAPSHOT": "SNAPSHOT_EXISTS SNAPSHOT_UNAVAILABLE SNAPSHOT_STAGE_FAILED SNAPSHOT_IDENTITY_FAILED", "CONFIG": "CONFIG_COMPILE_FAILED", "PROXY": "SYSTEM_PROXY_ACTIVE PROXY_STATE_UNAVAILABLE", "SERVER_ROUTE": "SERVER_ROUTE_UNAVAILABLE SERVER_ROUTE_NOT_PHYSICAL SERVER_ROUTE_CHANGED", "PUBLIC_ROUTE": "PUBLIC_ROUTE_UNAVAILABLE", "DNS": "DNS_STATE_UNAVAILABLE DNS_EVIDENCE_EMPTY", "BASELINE": "BASELINE_INVALID BASELINE_WRITE_FAILED", "PLIST": "PLIST_CREATE_FAILED PLIST_WRITE_FAILED PLIST_INVALID", "BOOTSTRAP": "LAUNCHD_BOOTSTRAP_FAILED", "READINESS": "READINESS_JOB_UNAVAILABLE READINESS_ROUTE_UNAVAILABLE READINESS_CHANGED PROCESS_NOT_RUNNING TUN_NOT_READY PROCESS_AND_TUN_NOT_READY READINESS_UNKNOWN", "HTTPS": "HTTPS_DNS_FAILED HTTPS_CONNECT_FAILED HTTPS_TIMEOUT HTTPS_TLS_HANDSHAKE_FAILED HTTPS_CERTIFICATE_FAILED HTTPS_HTTP_FAILED HTTPS_EMPTY_RESPONSE HTTPS_RECEIVE_FAILED HTTPS_RESPONSE_INVALID HTTPS_FAILED", "STOP": "STOP_FAILED", "DIAGNOSTIC": "RECEIPT_WRITE_FAILED", "UNKNOWN": "UNKNOWN", "NONE": "NONE",
}

func validDiagnostics(d *Diagnostics, ok bool) bool {
	if d == nil {
		return true
	}
	if d.Schema != 1 || !in(d.Operation, "START RELOAD STOP") || !in(d.Outcome, "SUCCEEDED FAILED CANCELLED UNKNOWN") || !in(d.Job, "NOT_OBSERVED RUNNING NOT_RUNNING UNLOADED UNKNOWN") || !in(d.Tun, "NOT_OBSERVED TUN NOT_TUN UNKNOWN") || !in(d.Receipt, "NOT_ATTEMPTED WRITTEN FAILED UNKNOWN") {
		return false
	}
	for _, v := range []string{d.Rollback, d.Restoration, d.Cleanup} {
		if !in(v, "NOT_ATTEMPTED VERIFIED FAILED UNKNOWN") {
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
	if !in(d.Reason, reasons) {
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

func validDiagnosticsEither(d *Diagnostics) bool {
	return validDiagnostics(d, true) || validDiagnostics(d, false)
}

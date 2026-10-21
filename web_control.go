package main

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// Only allowlisted stage codes cross the HTTP boundary. Never forward helper
// messages or wrapped tool output, which may contain private configuration.
type webControlError struct{ Code string }

func (e *webControlError) Error() string { return e.Code }
func webControlFailureCode(err error) string {
	var e *webControlError
	if errors.As(err, &e) {
		switch e.Code {
		case "HELPER_UNAVAILABLE", "HELPER_CONFIG_MISMATCH", "FORBIDDEN", "INVALID_REQUEST", "BUSY", "PREFLIGHT_FAILED", "STOP_FAILED", "START_FAILED", "STATE_FAILED":
			return e.Code
		}
	}
	return "SERVICE_ACTION_FAILED"
}

type webControlRequestFunc func(context.Context, string, bool) (controlHelperResponse, error)

func webControlBoundStatus(ctx context.Context, config string, request webControlRequestFunc) (controlHelperResponse, error) {
	expected, err := controlHelperConfigIdentity(config)
	if err != nil {
		return controlHelperResponse{}, &webControlError{Code: "HELPER_UNAVAILABLE"}
	}
	result, err := request(ctx, "status", false)
	if err != nil {
		return result, &webControlError{Code: "HELPER_UNAVAILABLE"}
	}
	if result.ConfigIdentity == "" {
		return result, &webControlError{Code: "HELPER_UNAVAILABLE"}
	}
	if result.ConfigIdentity != expected {
		return result, &webControlError{Code: "HELPER_CONFIG_MISMATCH"}
	}
	return result, nil
}

// Per-call transport seam: authenticate/read status before every mutation,
// including stop. No path or identity is accepted in the wire request.
func webControlAction(ctx context.Context, config, action string, allow bool, request webControlRequestFunc) error {
	if action == "status" || !controlHelperValidRequest(controlHelperWireRequest{action, allow}) {
		return &webControlError{Code: "INVALID_REQUEST"}
	}
	status, err := webControlBoundStatus(ctx, config, request)
	if err != nil {
		return err
	}
	result, err := request(ctx, action, allow)
	if result.ConfigIdentity != "" && result.ConfigIdentity != status.ConfigIdentity {
		return &webControlError{Code: "HELPER_CONFIG_MISMATCH"}
	}
	if err != nil {
		code := result.Code
		if code == "" {
			code = "HELPER_UNAVAILABLE"
		}
		return &webControlError{Code: code}
	}
	if result.ConfigIdentity == "" {
		return &webControlError{Code: "HELPER_UNAVAILABLE"}
	}
	// Also reject local symlink relocation during this call. This is path
	// identity, not a configuration-content fingerprint or same-UID defense.
	expected, err := controlHelperConfigIdentity(config)
	if err != nil || expected != status.ConfigIdentity {
		return &webControlError{Code: "HELPER_CONFIG_MISMATCH"}
	}
	return nil
}

func webControlStatus(rw http.ResponseWriter, r *http.Request) {
	_, config, _, err := servicePaths()
	if err != nil {
		webJSON(rw, 200, map[string]any{"available": false, "code": "HELPER_UNAVAILABLE", "installCommand": "anytls helper install"})
		return
	}
	webControlStatusForConfig(rw, r, config, controlHelperRequest)
}
func webControlStatusForConfig(rw http.ResponseWriter, r *http.Request, config string, request webControlRequestFunc) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	result, err := webControlBoundStatus(ctx, config, request)
	if err != nil {
		webJSON(rw, 200, map[string]any{"available": false, "code": webControlFailureCode(err), "installCommand": "anytls helper install"})
		return
	}
	webJSON(rw, 200, map[string]any{"available": true, "status": result})
}

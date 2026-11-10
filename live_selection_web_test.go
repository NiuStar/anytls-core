package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestWebSelectionDoesNotReload(t *testing.T) {
	w, cookie, csrf := linkFixture(t, selectionLinkConfig, "a")
	w.state = func() (bool, bool, error) { return true, true, nil }
	actions := []string{}
	identity, _ := controlHelperConfigIdentity(w.configPath)
	w.selectionRecovery.request = func(_ context.Context, action string, _ bool) (controlHelperResponse, error) {
		r := controlHelperResponse{OK: true, Loaded: true, Running: true, ConfigIdentity: identity}
		if action == "status" {
			return r, nil
		}
		actions = append(actions, action)
		r.Code = "HOT_APPLIED"
		r.SelectionOperation = &liveSelectionOperation{Operation: strings.Repeat("a", 32), Generation: strings.Repeat("b", 32), Revision: 1, Node: "b"}
		return r, nil
	}
	w.serviceAction = func(_ context.Context, action string, _ bool) error { actions = append(actions, action); return nil }
	out := groupETagRequest(w, cookie, csrf, "/api/v1/nodes/selection", `{"name":"b","confirm_insecure":true}`, "")
	var result map[string]any
	json.Unmarshal(out.Body.Bytes(), &result)
	if out.Code != 200 || result["apply_status"] != "HOT_APPLIED" || len(actions) != 1 || actions[0] != "select" {
		t.Fatalf("status=%d body=%s actions=%v", out.Code, out.Body.String(), actions)
	}
}

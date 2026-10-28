package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestWebRuleDeleteApplyStateAndConsent(t *testing.T) {
	for _, mode := range []string{"state-error", "inconsistent-state", "loaded-stopped", "no-consent"} {
		t.Run(mode, func(t *testing.T) {
			w, p := webFixture(t)
			c, csrf := webLogin(t, w, p)
			raw := []byte(singleRuleConfig)
			if err := os.WriteFile(w.configPath, raw, 0600); err != nil {
				t.Fatal(err)
			}
			old := w.beginStartup("start", "MANUAL_START")
			w.state = func() (bool, bool, error) {
				switch mode {
				case "state-error":
					return false, false, errors.New("SECRET_STATE_ERROR")
				case "inconsistent-state":
					return false, true, nil
				case "loaded-stopped":
					return true, false, nil
				default:
					return true, true, nil
				}
			}
			calls := 0
			w.serviceAction = func(_ context.Context, action string, consent bool) error {
				calls++
				if mode != "no-consent" || action != "reload" || consent {
					t.Error("unexpected action/consent")
				}
				return nil
			}
			// Absence is explicitly false, never implicit authorization.
			out := groupETagRequest(w, c, csrf, deleteRulePath, `{"index":0,"rule":"DOMAIN,old.example,DIRECT"}`, `"`+shaHex(raw)+`"`)
			var result struct {
				Saved, Changed, Applied bool
				Status                  string `json:"apply_status"`
			}
			wantStatus, wantCalls := "STATE_UNAVAILABLE", 0
			if mode == "loaded-stopped" {
				wantStatus = "SAVED_STOPPED"
			}
			if mode == "no-consent" {
				wantStatus, wantCalls = "APPLIED", 1
			}
			if out.Code != 200 || json.Unmarshal(out.Body.Bytes(), &result) != nil || !result.Saved || !result.Changed || result.Status != wantStatus || result.Applied != (mode == "no-consent") || calls != wantCalls || strings.Contains(out.Body.String(), "SECRET") {
				t.Fatal(out.Code, out.Body.String(), calls)
			}
			if mode != "no-consent" && (w.startupLatest != old || !strings.Contains(out.Body.String(), `"startup_operation":null`)) {
				t.Fatal("nonapply replaced startup operation")
			}
		})
	}
}

func TestWebRuleDeleteReplayCannotDeleteNextRow(t *testing.T) {
	w, p := webFixture(t)
	c, csrf := webLogin(t, w, p)
	raw := []byte("nodes: []\nrules:\n - DOMAIN,dup.example,DIRECT\n - DOMAIN,dup.example,DIRECT\n - MATCH,DIRECT\n")
	if err := os.WriteFile(w.configPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	body, etag := deleteRuleBody(0, "DOMAIN,dup.example,DIRECT"), `"`+shaHex(raw)+`"`
	first := groupETagRequest(w, c, csrf, deleteRulePath, body, etag)
	after, err := os.ReadFile(w.configPath)
	if err != nil || first.Code != 200 {
		t.Fatal(first.Code, first.Body.String(), err)
	}
	second := groupETagRequest(w, c, csrf, deleteRulePath, body, etag)
	got, err := os.ReadFile(w.configPath)
	if err != nil || second.Code != 412 || !strings.Contains(second.Body.String(), "CONFIG_CONFLICT") || !bytes.Equal(got, after) || bytes.Count(got, []byte("DOMAIN,dup.example,DIRECT")) != 1 {
		t.Fatal(second.Code, second.Body.String(), err)
	}
}

func TestWebRuleDeleteRepairMissingSet(t *testing.T) {
	w, p := webFixture(t)
	c, csrf := webLogin(t, w, p)
	raw := []byte("nodes: []\nrules:\n - RULE-SET,missing,DIRECT\n - MATCH,DIRECT\n")
	if err := os.WriteFile(w.configPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	out := groupETagRequest(w, c, csrf, deleteRulePath, deleteRuleBody(0, "RULE-SET,missing,DIRECT"), `"`+shaHex(raw)+`"`)
	got, err := os.ReadFile(w.configPath)
	if err != nil || out.Code != 200 || string(got) != "nodes: []\nrules:\n - MATCH,DIRECT\n" {
		t.Fatal(out.Code, out.Body.String(), err)
	}
}

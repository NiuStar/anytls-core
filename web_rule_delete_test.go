package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"
)

func TestWebSingleRuleDeleteStopped(t *testing.T) {
	w, password := webFixture(t)
	cookie, csrf := webLogin(t, w, password)
	raw := []byte(singleRuleConfig)
	if err := os.WriteFile(w.configPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	w.state = func() (bool, bool, error) { return false, false, nil }
	serviceCalls := 0
	w.serviceAction = func(context.Context, string, bool) error {
		serviceCalls++
		return nil
	}

	out := groupETagRequest(w, cookie, csrf, "/api/v1/rules/delete", `{"index":0,"rule":"DOMAIN,old.example,DIRECT"}`, `"`+shaHex(raw)+`"`)
	if out.Code != http.StatusOK {
		t.Fatalf("authenticated single-rule delete should save: %d %s", out.Code, out.Body.String())
	}
	got, err := os.ReadFile(w.configPath)
	if err != nil {
		t.Fatal(err)
	}
	want := bytes.Replace(raw, []byte("  - 'DOMAIN,old.example,DIRECT' # keep\n"), nil, 1)
	if !bytes.Equal(got, want) {
		t.Fatalf("delete must remove only the selected physical rule row, preserving all other bytes:\ngot:  %q\nwant: %q", got, want)
	}
	var result struct {
		Saved       bool   `json:"saved"`
		Changed     bool   `json:"changed"`
		Applied     bool   `json:"applied"`
		ApplyStatus string `json:"apply_status"`
		ETag        string `json:"etag"`
	}
	if err := json.Unmarshal(out.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.Saved || !result.Changed || result.Applied || result.ApplyStatus != "SAVED_STOPPED" || result.ETag != `"`+shaHex(want)+`"` || out.Header().Get("ETag") != result.ETag {
		t.Fatalf("delete must report the saved stopped config and its readback ETag: %s", out.Body.String())
	}
	if serviceCalls != 0 {
		t.Fatalf("deleting a rule while stopped must not invoke service actions: %d", serviceCalls)
	}
}

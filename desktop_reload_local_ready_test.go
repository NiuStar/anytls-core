package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestDesktopReloadLocalReadyOperatorVersioned(t *testing.T) {
	m, _, calls := migrationFixture(t)
	dir := operatorFixture(t, m)
	for _, name := range []string{"response.json", "timeline.json"} {
		p := "diagnostics"
		if name == "timeline.json" {
			p = "trace.diagnostics"
		}
		reloadMutate(t, dir, name, p+".stage", "LOCAL_READY")
		reloadMutate(t, dir, name, p+".reason", "INTERNET_UNVERIFIED")
	}
	operatorRehash(t, dir)
	operatorBlocked(t, m, dir, calls) // no version: legacy stays strict
	reloadMutate(t, dir, "job.json", "receipt_schema", 2)
	operatorRehash(t, dir)
	before := reloadManifest(t, dir)
	if e := m.pending(""); e != nil {
		t.Fatal("versioned local readiness", e)
	}
	if *calls != 0 {
		t.Fatal("dispatched lifecycle")
	}
	after := reloadManifest(t, dir)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("history changed")
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "result.json"))
	var result map[string]any
	json.Unmarshal(raw, &result)
	if result["state"] != "UNKNOWN" {
		t.Fatal("unknown promoted")
	}
	reloadMutate(t, dir, "job.json", "receipt_schema", true)
	operatorRehash(t, dir)
	operatorBlocked(t, m, dir, calls)
}

func TestDesktopReloadLocalReadyDiagnosticsPoison(t *testing.T) {
	d := map[string]any{"schema": json.Number("1"), "operation": "RELOAD", "outcome": "SUCCEEDED", "stage": "LOCAL_READY", "reason": "INTERNET_UNVERIFIED", "rollback": "NOT_ATTEMPTED", "restoration": "NOT_ATTEMPTED", "cleanup": "NOT_ATTEMPTED", "receipt": "WRITTEN", "job": "RUNNING", "tun": "TUN"}
	if !reloadSuccessDiagnostics(d, true) || reloadSuccessDiagnostics(d) || reloadDiagnostics(d, true, true) {
		t.Fatal("contract discrimination")
	}
	for k, v := range map[string]any{"schema": true, "operation": "STOP", "outcome": "UNKNOWN", "stage": "NONE", "reason": "NONE", "receipt": "FAILED", "job": "UNKNOWN", "tun": "UNKNOWN", "cleanup": "POISON"} {
		t.Run(k, func(t *testing.T) {
			old := d[k]
			d[k] = v
			defer func() { d[k] = old }()
			if reloadSuccessDiagnostics(d, true) {
				t.Fatal("poison admitted")
			}
		})
	}
}

func TestDesktopReloadLocalReadyAcceptedVersioned(t *testing.T) {
	m, _, calls := migrationFixture(t)
	op := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	dir := reloadFixture(t, m, "accepted", op)
	reloadMutate(t, dir, "result.json", "receipt_schema", 2)
	app := filepath.Join(m.home, ".anytls")
	job := map[string]any{"receipt_schema": 2, "app": app, "operation_id": op, "digest": strings.Repeat("d", 64), "tag": "v1.2.3", "revision": strings.Repeat("b", 40), "before": map[string]any{}}
	raw, _ := json.Marshal(job)
	os.WriteFile(filepath.Join(dir, "job.json"), raw, 0600)
	r, _ := os.ReadFile(filepath.Join(dir, "result.json"))
	ack, _ := json.Marshal(map[string]any{"operation_id": op, "result_sha256": desktopSum(r)})
	os.WriteFile(filepath.Join(dir, "accepted.json"), ack, 0600)
	if e := m.pending(""); e != nil {
		t.Fatal(e)
	}
	reloadMutate(t, dir, "job.json", "receipt_schema", true)
	operatorBlocked(t, m, dir, calls)
}

func TestDesktopReloadLocalReadyPreflightVersioned(t *testing.T) {
	m, _, calls := migrationFixture(t)
	dir := reloadFixture(t, m, "reconciled", strings.Repeat("a", 32))
	raw, err := os.ReadFile(filepath.Join(dir, "job.json"))
	if err != nil {
		t.Fatal(err)
	}
	var job map[string]any
	if err = json.Unmarshal(raw, &job); err != nil {
		t.Fatal(err)
	}
	before := job["before"].(map[string]any)
	identity := before["config"].(map[string]any)["identity"]
	before["status"] = map[string]any{"ok": true, "code": "", "message": "fixture", "loaded": true, "running": true, "helper_version": job["tag"], "helper_sha256": job["digest"], "config_identity": identity, "diagnostics": map[string]any{"schema": 1, "operation": "START", "outcome": "SUCCEEDED", "stage": "LOCAL_READY", "reason": "INTERNET_UNVERIFIED", "rollback": "NOT_ATTEMPTED", "restoration": "NOT_ATTEMPTED", "cleanup": "NOT_ATTEMPTED", "receipt": "WRITTEN", "job": "RUNNING", "tun": "TUN"}}
	raw, _ = json.Marshal(job)
	if err = os.WriteFile(filepath.Join(dir, "job.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	reloadRehash(t, dir)
	operatorBlocked(t, m, dir, calls)
	reloadMutate(t, dir, "job.json", "receipt_schema", 2)
	manifest := reloadManifest(t, dir)
	if err = m.pending(""); err != nil {
		t.Fatal("versioned prior local status", err)
	}
	if *calls != 0 || !reflect.DeepEqual(manifest, reloadManifest(t, dir)) {
		t.Fatal("not read-only")
	}
}

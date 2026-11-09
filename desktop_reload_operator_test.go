package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const operatorFixtureID = "887e3586e7684e7b8ead5b5a12a7af67"

// Same unchanged Python fixture-producer bytes, with explicit local identity
// rebinding; no private capture or helper/STOP execution is used here.
func operatorFixture(t *testing.T, m desktopMigration) string {
	t.Helper()
	raw, e := os.ReadFile("testdata/desktop-reload/operator.json")
	if e != nil {
		t.Fatal(e)
	}
	app := filepath.Join(m.home, ".anytls")
	raw = []byte(strings.ReplaceAll(strings.ReplaceAll(string(raw), "/fixture/.anytls", app), desktopSum([]byte("/fixture/.anytls/config.yaml")), desktopSum([]byte(filepath.Join(app, "config.yaml")))))
	var files map[string]string
	if e = json.Unmarshal(raw, &files); e != nil {
		t.Fatal(e)
	}
	var marker map[string]any
	json.Unmarshal([]byte(files["operator-reconciled.json"]), &marker)
	for n := range marker["receipt_sha256"].(map[string]any) {
		marker["receipt_sha256"].(map[string]any)[n] = desktopSum([]byte(files[n]))
	}
	b, _ := json.Marshal(marker)
	files["operator-reconciled.json"] = string(b)
	dir := filepath.Join(app, ".core-reload-"+operatorFixtureID)
	if e = os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	for n, b := range files {
		if e = os.WriteFile(filepath.Join(dir, n), []byte(b), 0600); e != nil {
			t.Fatal(e)
		}
	}
	return dir
}
func TestDesktopReloadOperatorGolden(t *testing.T) {
	m, _, calls := migrationFixture(t)
	dir := operatorFixture(t, m)
	before := reloadManifest(t, dir)
	if e := m.pending(""); e != nil {
		t.Fatal("strict historical operator admission", e)
	}
	if _, e := m.inspect(); e != nil {
		t.Fatal(e)
	}
	if *calls != 0 || !reflect.DeepEqual(before, reloadManifest(t, dir)) {
		t.Fatal("admission mutated history or dispatched STOP")
	}
}
func operatorRehash(t *testing.T, dir string) {
	t.Helper()
	p := filepath.Join(dir, "operator-reconciled.json")
	b, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		t.Fatal("marker")
	}
	for n := range m["receipt_sha256"].(map[string]any) {
		raw, e := os.ReadFile(filepath.Join(dir, n))
		if e == nil {
			m["receipt_sha256"].(map[string]any)[n] = desktopSum(raw)
		}
	}
	b, _ = json.Marshal(m)
	if e = os.WriteFile(p, b, 0600); e != nil {
		t.Fatal(e)
	}
}
func operatorBlocked(t *testing.T, m desktopMigration, dir string, calls *int) {
	t.Helper()
	before := reloadManifest(t, dir)
	if e := m.pending(""); e == nil || e.Error() != "CORE_RELOAD_PENDING" {
		t.Fatal("unsafe history admitted", e)
	}
	if *calls != 0 || !reflect.DeepEqual(before, reloadManifest(t, dir)) {
		t.Fatal("not read only")
	}
}
func TestDesktopReloadOperatorSemanticMatrix(t *testing.T) {
	cases := []struct {
		file, path string
		v          any
	}{
		{"operator-reconciled.json", "schema", true}, {"operator-reconciled.json", "authorization", "AUTOMATIC"},
		{"operator-reconciled.json", "status", "SUCCEEDED"}, {"operator-reconciled.json", "historical_process_identity", "VERIFIED"},
		{"operator-reconciled.json", "action", "RELOAD"}, {"operator-reconciled.json", "helper_epoch", strings.Repeat("f", 32)},
		{"operator-reconciled.json", "operation_id", strings.Repeat("f", 32)}, {"operator-reconciled.json", "extra", true},
		{"operator-reconciled.json", "pending_sha256", strings.Repeat("f", 64)}, {"operator-reconciled.json", "pending_raw_base64", "%%%"},
		{"operator-reconciled.json", "current.state", "RUNNING"}, {"operator-reconciled.json", "current.core", map[string]any{}},
		{"operator-reconciled.json", "current.config.identity", strings.Repeat("f", 64)},
		{"operator-reconciled.json", "current.status.ok", 1}, {"operator-reconciled.json", "current.status.loaded", true},
		{"operator-reconciled.json", "current.status.running", true}, {"operator-reconciled.json", "current.status.helper_sha256", strings.Repeat("f", 64)},
		{"operator-reconciled.json", "stop_read.operation_id", operatorFixtureID},
		{"operator-reconciled.json", "stop_read.helper_epoch", strings.Repeat("f", 32)},
		{"operator-reconciled.json", "stop_read.trace.source", "MANUAL_RELOAD"},
		{"operator-reconciled.json", "stop_read.trace.started_at", "2026-11-06T01:00:00Z"},
		{"operator-reconciled.json", "stop_read.trace.streams.0.provenance.sha256", strings.Repeat("f", 64)},
		{"operator-reconciled.json", "stop_read.trace.streams.0.events.0.span_id", "99"},
		{"operator-reconciled.json", "stop_read.trace.streams.0.terminal.result", "FAILED"},
		{"job.json", "operation_id", strings.Repeat("f", 32)}, {"job.json", "app", "/foreign"},
		{"job.json", "revision", strings.Repeat("F", 40)}, {"job.json", "before.state", "STOPPED"},
		{"job.json", "before.core.uid", 1}, {"job.json", "before.config.selection", false},
		{"claim.json", "pid", true}, {"intent.json", "single_dispatch", 1}, {"intent.json", "allow_insecure", 1},
		{"intent.json", "helper_epoch", strings.Repeat("f", 32)}, {"result.json", "code", "CORE_RELOAD_INVALID"},
		{"result.json", "state", "SUCCEEDED"}, {"response.json", "timeline_schema", true},
		{"response.json", "ok", 1}, {"response.json", "loaded", false},
		{"response.json", "helper_sha256", strings.Repeat("f", 64)}, {"response.json", "helper_version", "v0"},
		{"response.json", "diagnostics.job", "UNLOADED"}, {"response.json", "diagnostics.tun", "NOT_TUN"},
		{"timeline.json", "trace.lifecycle_result", "FAILED"}, {"timeline.json", "trace.receipt_result", "NOT_ATTEMPTED"},
		{"timeline.json", "trace.streams.1.provenance.sha256", strings.Repeat("f", 64)},
		{"timeline.json", "trace.streams.1.provenance.dirty", 0}, {"timeline.json", "trace.streams.0.provenance.version", "v0"},
	}
	for x, c := range cases {
		t.Run(fmt.Sprintf("%02d/%s/%s", x, c.file, c.path), func(t *testing.T) {
			m, _, calls := migrationFixture(t)
			dir := operatorFixture(t, m)
			if e := m.pending(""); e != nil {
				t.Fatal("positive", e)
			}
			reloadMutate(t, dir, c.file, c.path, c.v)
			operatorRehash(t, dir)
			operatorBlocked(t, m, dir, calls)
		})
	}
}
func TestDesktopReloadOperatorClosedShapes(t *testing.T) {
	for _, name := range []string{"job.json", "intent.json", "response.json", "result.json", "claim.json", "timeline.json", "operator-reconciled.json"} {
		for _, mode := range []string{"missing", "extra", "null", "duplicate", "case-alias", "trailing"} {
			t.Run(name+"/"+mode, func(t *testing.T) {
				m, _, calls := migrationFixture(t)
				dir := operatorFixture(t, m)
				p := filepath.Join(dir, name)
				raw, _ := os.ReadFile(p)
				switch mode {
				case "missing":
					var v map[string]any
					json.Unmarshal(raw, &v)
					for k := range v {
						delete(v, k)
						break
					}
					raw, _ = json.Marshal(v)
				case "extra":
					raw = append([]byte(`{"foreign":1,`), raw[1:]...)
				case "null":
					raw = []byte("null")
				case "duplicate":
					raw = append([]byte(`{"schema":1,"schema":1,`), raw[1:]...)
				case "case-alias":
					raw = append([]byte(`{"schema":1,"Schema":1,`), raw[1:]...)
				case "trailing":
					raw = append(raw, []byte("{}")...)
				}
				os.WriteFile(p, raw, 0600)
				if name != "operator-reconciled.json" {
					operatorRehash(t, dir)
				}
				operatorBlocked(t, m, dir, calls)
			})
		}
	}
}
func TestDesktopReloadOperatorPendingPayload(t *testing.T) {
	for _, raw := range []string{`{"operation_id":"ffffffffffffffffffffffffffffffff"}`, `{"operation_id":true}`, `{"operation_id":"` + operatorFixtureID + `","operation_id":"` + operatorFixtureID + `"}`, `{"operation_id":"` + operatorFixtureID + `","extra":1}`} {
		t.Run(desktopSum([]byte(raw))[:8], func(t *testing.T) {
			m, _, calls := migrationFixture(t)
			dir := operatorFixture(t, m)
			reloadMutate(t, dir, "operator-reconciled.json", "pending_raw_base64", base64.StdEncoding.EncodeToString([]byte(raw)))
			reloadMutate(t, dir, "operator-reconciled.json", "pending_sha256", desktopSum([]byte(raw)))
			operatorBlocked(t, m, dir, calls)
		})
	}
}
func TestDesktopReloadOperatorFilesystem(t *testing.T) {
	names := []string{"operator-reconciled.json", "job.json", "intent.json", "response.json", "result.json", "claim.json", "timeline.json", "worker.log"}
	for _, name := range names {
		for _, mode := range []string{"missing", "permissions", "hardlink", "symlink", "oversize", "hash", "alias"} {
			t.Run(name+"/"+mode, func(t *testing.T) {
				m, _, calls := migrationFixture(t)
				dir := operatorFixture(t, m)
				p := filepath.Join(dir, name)
				switch mode {
				case "missing":
					os.Remove(p)
				case "permissions":
					os.Chmod(p, 0644)
				case "hardlink":
					if e := os.Link(p, filepath.Join(m.home, "link")); e != nil {
						t.Fatal(e)
					}
				case "symlink":
					dst := filepath.Join(m.home, "target")
					os.Rename(p, dst)
					os.Symlink(dst, p)
				case "oversize":
					os.WriteFile(p, bytes.Repeat([]byte(" "), reloadReceiptLimit+1), 0600)
				case "hash":
					raw, _ := os.ReadFile(p)
					os.WriteFile(p, append(raw, ' '), 0600)
					if name == "operator-reconciled.json" {
						os.WriteFile(p, []byte("{}"), 0600)
					}
				case "alias":
					os.Rename(p, filepath.Join(dir, strings.ToUpper(name)))
				}
				operatorBlocked(t, m, dir, calls)
			})
		}
	}
	for _, name := range []string{"pending.json", "Pending.json", "accepted.json", "reconciled.json", "Stop-read.json"} {
		t.Run("conflict/"+name, func(t *testing.T) {
			m, _, calls := migrationFixture(t)
			dir := operatorFixture(t, m)
			os.WriteFile(filepath.Join(dir, name), []byte("{}"), 0600)
			operatorBlocked(t, m, dir, calls)
		})
	}
	t.Run("dangling-pending", func(t *testing.T) {
		m, _, calls := migrationFixture(t)
		dir := operatorFixture(t, m)
		os.Symlink("missing", filepath.Join(dir, "pending.json"))
		operatorBlocked(t, m, dir, calls)
	})
	t.Run("directory-mode", func(t *testing.T) {
		m, _, calls := migrationFixture(t)
		dir := operatorFixture(t, m)
		os.Chmod(dir, 0755)
		operatorBlocked(t, m, dir, calls)
	})
	t.Run("entry-limit", func(t *testing.T) {
		m, _, calls := migrationFixture(t)
		dir := operatorFixture(t, m)
		for x := 0; x < 65; x++ {
			os.WriteFile(filepath.Join(dir, fmt.Sprint(x)), nil, 0600)
		}
		operatorBlocked(t, m, dir, calls)
	})
	t.Run("aggregate-limit", func(t *testing.T) {
		m, _, calls := migrationFixture(t)
		dir := operatorFixture(t, m)
		for x := 0; x < 13; x++ {
			os.WriteFile(filepath.Join(dir, fmt.Sprint(x)), bytes.Repeat([]byte("x"), reloadReceiptLimit), 0600)
		}
		operatorBlocked(t, m, dir, calls)
	})
}
func TestDesktopReloadOperatorMixedHistory(t *testing.T) {
	m, _, calls := migrationFixture(t)
	dir := operatorFixture(t, m)
	reloadFixture(t, m, "accepted", strings.Repeat("a", 32))
	reloadFixture(t, m, "stop-response", strings.Repeat("b", 32))
	if e := m.pending(""); e != nil {
		t.Fatal(e)
	}
	root := filepath.Join(m.home, ".anytls", ".core-reload-"+strings.Repeat("f", 32))
	os.Mkdir(root, 0700)
	os.WriteFile(filepath.Join(root, "pending.json"), []byte("{}"), 0600)
	operatorBlocked(t, m, dir, calls)
}
func TestDesktopReloadOperatorHistoricalNotCurrent(t *testing.T) {
	m, _, calls := migrationFixture(t)
	dir := operatorFixture(t, m)
	os.WriteFile(filepath.Join(m.home, ".anytls", "config.yaml"), []byte("future config"), 0600)
	reloadMutate(t, dir, "claim.json", "pid", os.Getpid())
	operatorRehash(t, dir)
	before := reloadManifest(t, dir)
	if e := m.pending(""); e != nil {
		t.Fatal(e)
	}
	if *calls != 0 || !reflect.DeepEqual(before, reloadManifest(t, dir)) {
		t.Fatal("not read only")
	}
}

func TestDesktopReloadOperatorCommitRevalidates(t *testing.T) {
	for _, kind := range []string{"busy", "pending-resurrection", "marker-replacement"} {
		t.Run(kind, func(t *testing.T) {
			m, _, calls := migrationFixture(t)
			dir := operatorFixture(t, m)
			preview, e := m.inspect()
			if e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "busy":
				lock, e := m.lock()
				if e != nil {
					t.Fatal(e)
				}
				defer lock.Close()
			case "pending-resurrection":
				if e = os.WriteFile(filepath.Join(dir, "pending.json"), []byte("{}"), 0600); e != nil {
					t.Fatal(e)
				}
			case "marker-replacement":
				if e = os.WriteFile(filepath.Join(dir, "operator-reconciled.json"), []byte("{}"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			before := reloadManifest(t, dir)
			_, e = m.commit(preview.Plan)
			if e == nil || *calls != 0 {
				t.Fatal("commit used stale preview", e, *calls)
			}
			stages, _ := filepath.Glob(filepath.Join(m.home, ".anytls/.desktop-candidate-*"))
			if len(stages) != 0 || !reflect.DeepEqual(before, reloadManifest(t, dir)) {
				t.Fatal("mutated before admission")
			}
			if kind == "busy" && e.Error() != "INSTALL_BUSY" {
				t.Fatal(e)
			}
		})
	}
}
func TestDesktopReloadOperatorHashInventory(t *testing.T) {
	for _, mode := range []string{"missing", "extra", "wrong-type"} {
		t.Run(mode, func(t *testing.T) {
			m, _, calls := migrationFixture(t)
			dir := operatorFixture(t, m)
			p := filepath.Join(dir, "operator-reconciled.json")
			raw, _ := os.ReadFile(p)
			var v map[string]any
			json.Unmarshal(raw, &v)
			hashes := v["receipt_sha256"].(map[string]any)
			switch mode {
			case "missing":
				delete(hashes, "worker.log")
			case "extra":
				hashes["extra"] = desktopSum(nil)
			case "wrong-type":
				hashes["worker.log"] = true
			}
			raw, _ = json.Marshal(v)
			os.WriteFile(p, raw, 0600)
			operatorBlocked(t, m, dir, calls)
		})
	}
}
func TestDesktopReloadOperatorStopSemanticMatrix(t *testing.T) {
	cases := []struct {
		path string
		v    any
	}{
		{"trace.streams.0.events.1.duration_ns", "0"},
		{"trace.streams.0.events.2.duration_ns", "0"},
		{"trace.streams.0.events.2.at", "2026-11-05T00:00:00Z"},
		{"trace.streams.0.terminal.at", "2026-11-05T00:00:00Z"},
		{"trace.streams.0.terminal.elapsed_ns", "0"},
		{"trace.streams.0.dropped_events", "1"},
		{"trace.streams.0.provenance.dirty", 0},
		{"trace.diagnostics.schema", true},
		{"trace.diagnostics.job", "RUNNING"},
		{"trace.diagnostics.tun", "TUN"},
		{"trace.lifecycle_result", "FAILED"},
		{"timeline_schema", true},
	}
	for x, c := range cases {
		t.Run(fmt.Sprint(x), func(t *testing.T) {
			m, _, calls := migrationFixture(t)
			dir := operatorFixture(t, m)
			reloadMutate(t, dir, "operator-reconciled.json", "stop_read."+c.path, c.v)
			operatorBlocked(t, m, dir, calls)
		})
	}
}

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Golden bytes are produced and independently consumed by the unchanged Python
// installer fixtures. Only canonical app-path/hash rebinding is fixture-local.
func reloadFixture(t *testing.T, m desktopMigration, kind, op string) string {
	t.Helper()
	b, e := os.ReadFile("testdata/desktop-reload/receipts.json")
	if e != nil {
		t.Fatal(e)
	}
	var variants map[string]map[string]string
	if e = json.Unmarshal(b, &variants); e != nil {
		t.Fatal(e)
	}
	files := variants[kind]
	if files == nil {
		t.Fatal(kind)
	}
	root := filepath.Join(m.home, ".anytls")
	dir := filepath.Join(root, ".core-reload-"+op)
	if e = os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	for n, v := range files {
		v = strings.ReplaceAll(v, "/fixture/home/.anytls", root)
		v = strings.ReplaceAll(v, desktopSum([]byte("/fixture/home/.anytls/config.yaml")), desktopSum([]byte(filepath.Join(root, "config.yaml"))))
		v = strings.ReplaceAll(v, strings.Repeat("a", 32), op)
		files[n] = v
	}
	if v, ok := files["accepted.json"]; ok {
		var a map[string]string
		json.Unmarshal([]byte(v), &a)
		a["result_sha256"] = desktopSum([]byte(files["result.json"]))
		b, _ = json.Marshal(a)
		files["accepted.json"] = string(b)
	}
	if v, ok := files["reconciled.json"]; ok {
		var a map[string]any
		json.Unmarshal([]byte(v), &a)
		for _, field := range []string{"receipt_sha256", "stop_sha256"} {
			for n := range a[field].(map[string]any) {
				a[field].(map[string]any)[n] = desktopSum([]byte(files[n]))
			}
		}
		b, _ = json.Marshal(a)
		files["reconciled.json"] = string(b)
	}
	for n, v := range files {
		if e = os.WriteFile(filepath.Join(dir, n), []byte(v), 0600); e != nil {
			t.Fatal(e)
		}
	}
	return dir
}

// Reserved receipt spellings are canonical even on case-sensitive filesystems.
// Rename existing proofs (rather than overwrite aliases on APFS).
func TestDesktopReloadReservedCaseAliases(t *testing.T) {
	reserved := []string{"pending.json", "operator-reconciled.json", "accepted.json", "reconciled.json", "timeline.json", "stop-intent.json", "stop-read.json", "stop-response.json", "job.json", "intent.json", "response.json", "result.json", "claim.json"}
	for _, kind := range []string{"accepted", "stop-response"} {
		for _, name := range reserved {
			for _, alias := range []string{strings.ToUpper(name[:1]) + name[1:], strings.ToUpper(name)} {
				t.Run(kind+"/"+alias, func(t *testing.T) {
					m, _, calls := migrationFixture(t)
					dir := reloadFixture(t, m, kind, strings.Repeat("a", 32))
					if e := m.pending(""); e != nil {
						t.Fatal("positive baseline", e)
					}
					p := filepath.Join(dir, name)
					if _, e := os.Lstat(p); e == nil {
						if e = os.Rename(p, filepath.Join(dir, alias)); e != nil {
							t.Fatal(e)
						}
					} else if os.IsNotExist(e) {
						if e = os.WriteFile(filepath.Join(dir, alias), []byte("{}"), 0600); e != nil {
							t.Fatal(e)
						}
					} else {
						t.Fatal(e)
					}
					before := reloadManifest(t, dir)
					if e := m.pending(""); e == nil || e.Error() != "CORE_RELOAD_PENDING" {
						t.Fatal("reserved alias admitted", e)
					}
					if !reflect.DeepEqual(before, reloadManifest(t, dir)) || *calls != 0 {
						t.Fatal("not read only")
					}
				})
			}
		}
	}
	for _, name := range []string{"Worker.LOG", "pending.json.old", "accepted.json.backup", "pending-json", "notes.json"} {
		t.Run("ancillary/"+name, func(t *testing.T) {
			m, _, _ := migrationFixture(t)
			dir := reloadFixture(t, m, "accepted", strings.Repeat("a", 32))
			if e := os.WriteFile(filepath.Join(dir, name), []byte("retained"), 0600); e != nil {
				t.Fatal(e)
			}
			if e := m.pending(""); e != nil {
				t.Fatal("unrelated ancillary rejected", e)
			}
		})
	}
}

func TestDesktopReloadGoldenVariants(t *testing.T) {
	for _, kind := range []string{"accepted", "reconciled", "stop", "stop-response", "mismatch"} {
		t.Run(kind, func(t *testing.T) {
			m, _, calls := migrationFixture(t)
			dir := reloadFixture(t, m, kind, strings.Repeat("a", 32))
			before := reloadManifest(t, dir)
			if e := m.pending(""); e != nil {
				t.Fatal(e)
			}
			if _, e := m.inspect(); e != nil {
				t.Fatal(e)
			}
			if !reflect.DeepEqual(before, reloadManifest(t, dir)) || *calls != 0 {
				t.Fatal("not read only")
			}
		})
	}
}
func reloadManifest(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	filepath.Walk(dir, func(p string, i os.FileInfo, e error) error {
		if e != nil {
			t.Fatal(e)
		}
		v := i.Mode().String()
		if i.Mode().IsRegular() {
			b, e := os.ReadFile(p)
			if e != nil {
				t.Fatal(e)
			}
			v += desktopSum(b)
		}
		out[p] = v
		return nil
	})
	return out
}
func reloadMutate(t *testing.T, dir, name, path string, value any) {
	t.Helper()
	p := filepath.Join(dir, name)
	b, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		t.Fatal("fixture")
	}
	parts := strings.Split(path, ".")
	var parent any = m
	for _, part := range parts[:len(parts)-1] {
		if a, ok := parent.([]any); ok {
			n, _ := strconv.Atoi(part)
			parent = a[n]
		} else {
			parent = parent.(map[string]any)[part]
		}
	}
	last := strings.ReplaceAll(parts[len(parts)-1], "/", ".")
	if value == "DELETE" {
		delete(parent.(map[string]any), last)
	} else {
		parent.(map[string]any)[last] = value
	}
	b, _ = json.Marshal(m)
	if e = os.WriteFile(p, b, 0600); e != nil {
		t.Fatal(e)
	}
	reloadRehash(t, dir)
}
func reloadRehash(t *testing.T, dir string) {
	t.Helper()
	if b, e := os.ReadFile(filepath.Join(dir, "reconciled.json")); e == nil {
		var m map[string]any
		json.Unmarshal(b, &m)
		for _, field := range []string{"receipt_sha256", "stop_sha256"} {
			if hashes, ok := m[field].(map[string]any); ok {
				for n := range hashes {
					if raw, e := os.ReadFile(filepath.Join(dir, n)); e == nil {
						hashes[n] = desktopSum(raw)
					}
				}
			}
		}
		b, _ = json.Marshal(m)
		os.WriteFile(filepath.Join(dir, "reconciled.json"), b, 0600)
	}
	if b, e := os.ReadFile(filepath.Join(dir, "accepted.json")); e == nil {
		var m map[string]any
		json.Unmarshal(b, &m)
		raw, _ := os.ReadFile(filepath.Join(dir, "result.json"))
		m["result_sha256"] = desktopSum(raw)
		b, _ = json.Marshal(m)
		os.WriteFile(filepath.Join(dir, "accepted.json"), b, 0600)
	}
}
func TestDesktopReloadRehashedSemanticMatrix(t *testing.T) {
	cases := []struct {
		name, file, path string
		value            any
	}{
		{"result-code", "result.json", "code", "CORE_RELOAD_NEW_PROCESS"}, {"result-class", "result.json", "error_class", "RuntimeError"}, {"claim-bool", "claim.json", "pid", true}, {"job-app", "job.json", "app", "/wrong"}, {"job-extra", "job.json", "unknown", true}, {"job-revision", "job.json", "revision", "B"}, {"job-tag", "job.json", "tag", "bad"}, {"before-state", "job.json", "before.state", "STOPPED"}, {"before-core-uid", "job.json", "before.core.uid", 1}, {"config-identity", "job.json", "before.config.identity", strings.Repeat("0", 64)}, {"config-selection", "job.json", "before.config.selection", false}, {"intent-epoch", "intent.json", "helper_epoch", strings.Repeat("f", 32)}, {"intent-bool", "intent.json", "allow_insecure", 0}, {"intent-dispatch", "intent.json", "single_dispatch", false}, {"response-code", "response.json", "code", ""}, {"response-ok", "response.json", "ok", true}, {"response-digest", "response.json", "helper_sha256", strings.Repeat("0", 64)}, {"response-schema-bool", "response.json", "timeline_schema", true}, {"diag-reason", "response.json", "diagnostics.reason", "NONE"}, {"marker-schema", "reconciled.json", "schema", true}, {"marker-epoch", "reconciled.json", "helper_epoch", strings.Repeat("f", 32)}, {"current-state", "reconciled.json", "current.state", "RUNNING"}, {"current-core", "reconciled.json", "current.core", map[string]any{}}, {"current-status", "reconciled.json", "current.status.running", true}, {"read-epoch", "reconciled.json", "helper_read.helper_epoch", strings.Repeat("f", 32)}, {"trace-state", "reconciled.json", "helper_read.trace.state", "UNKNOWN"}, {"trace-provenance", "reconciled.json", "helper_read.trace.streams.0.provenance.dirty", true}, {"trace-drop", "reconciled.json", "helper_read.trace.streams.0.dropped_events", "1"}, {"trace-gap", "reconciled.json", "helper_read.trace.streams.0.gap", true}, {"trace-count", "reconciled.json", "helper_read.trace.streams.0.generated_events", "5"}, {"trace-stage", "reconciled.json", "helper_read.trace.streams.0.events.4.stage", "HELPER_FINAL_STATE"}, {"trace-time", "reconciled.json", "helper_read.trace.streams.0.events.4.at", "2026-11-04T01:02:05.0Z"}, {"trace-duration", "reconciled.json", "helper_read.trace.streams.0.events.4.duration_ns", "2"}, {"trace-terminal", "reconciled.json", "helper_read.trace.streams.0.terminal.result", "SUCCEEDED"}, {"trace-observation", "reconciled.json", "helper_read.trace.core_observation.age_ns", "0"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, _, calls := migrationFixture(t)
			dir := reloadFixture(t, m, "reconciled", strings.Repeat("a", 32))
			reloadMutate(t, dir, c.file, c.path, c.value)
			if e := m.pending(""); e == nil || e.Error() != "CORE_RELOAD_PENDING" {
				t.Fatal("unsafe accepted", e)
			}
			if *calls != 0 {
				t.Fatal("STOP")
			}
		})
	}
}
func TestDesktopReloadFilesystemAndAckGuards(t *testing.T) {
	for _, kind := range []string{"missing-ack", "raw-drift", "wrong-ack-op", "extra-ack", "pending", "dangling-pending", "result-mode", "root-mode", "hardlink", "symlink", "fifo", "oversize", "duplicate", "case-alias", "nested-duplicate", "trailing", "null", "unsupported", "mixed", "short-id", "upper-id", "ancillary"} {
		t.Run(kind, func(t *testing.T) {
			m, _, calls := migrationFixture(t)
			dir := reloadFixture(t, m, "accepted", strings.Repeat("a", 32))
			p := filepath.Join(dir, "result.json")
			b, _ := os.ReadFile(p)
			switch kind {
			case "missing-ack":
				os.Remove(filepath.Join(dir, "accepted.json"))
			case "raw-drift":
				os.WriteFile(p, append(b, ' '), 0600)
			case "wrong-ack-op":
				reloadMutate(t, dir, "accepted.json", "operation_id", strings.Repeat("b", 32))
			case "extra-ack":
				reloadMutate(t, dir, "accepted.json", "extra", true)
			case "pending":
				os.WriteFile(filepath.Join(dir, "pending.json"), []byte("{}"), 0600)
			case "dangling-pending":
				os.Symlink("missing", filepath.Join(dir, "pending.json"))
			case "result-mode":
				os.Chmod(p, 0644)
			case "root-mode":
				os.Chmod(dir, 0755)
			case "hardlink":
				os.Link(p, filepath.Join(dir, "linked"))
			case "symlink":
				os.Rename(p, p+".original")
				os.Symlink(p+".original", p)
			case "fifo":
				os.Remove(p)
				if e := syscall.Mkfifo(p, 0600); e != nil {
					t.Fatal(e)
				}
			case "oversize":
				os.WriteFile(p, bytes.Repeat([]byte(" "), reloadReceiptLimit+1), 0600)
			case "duplicate":
				os.WriteFile(p, append([]byte(`{"state":"UNKNOWN",`), b[1:]...), 0600)
				reloadRehash(t, dir)
			case "case-alias":
				os.WriteFile(p, append([]byte(`{"STATE":"UNKNOWN",`), b[1:]...), 0600)
				reloadRehash(t, dir)
			case "nested-duplicate":
				os.WriteFile(p, bytes.Replace(b, []byte(`"uid": 0`), []byte(`"uid":0,"UID":1`), 1), 0600)
				reloadRehash(t, dir)
			case "trailing":
				os.WriteFile(p, append(b, []byte(" {}")...), 0600)
				reloadRehash(t, dir)
			case "null":
				reloadMutate(t, dir, "result.json", "new_core", nil)
			case "unsupported":
				os.WriteFile(filepath.Join(dir, "operator-reconciled.json"), []byte("{}"), 0600)
			case "mixed":
				os.Mkdir(filepath.Join(filepath.Dir(dir), ".core-reload-"+strings.Repeat("b", 32)), 0700)
			case "short-id":
				os.Rename(dir, dir[:len(dir)-1])
			case "upper-id":
				os.Rename(dir, strings.Replace(dir, strings.Repeat("a", 32), strings.Repeat("A", 32), 1))
			case "ancillary":
				os.WriteFile(filepath.Join(dir, "worker.log"), []byte("retained log"), 0600)
			}
			e := m.pending("")
			if kind == "ancillary" {
				if e != nil {
					t.Fatal(e)
				}
			} else if e == nil {
				t.Fatal("unsafe accepted")
			}
			if *calls != 0 {
				t.Fatal("STOP")
			}
		})
	}
}
func TestDesktopReloadStopProofGuards(t *testing.T) {
	for _, kind := range []string{"orphan-read", "orphan-response", "intent-only", "hash-extra", "hash-omitted", "op-reused", "wrong-action", "insecure", "epoch", "response", "trace"} {
		t.Run(kind, func(t *testing.T) {
			m, _, _ := migrationFixture(t)
			dir := reloadFixture(t, m, "stop-response", strings.Repeat("a", 32))
			switch kind {
			case "orphan-read":
				os.Remove(filepath.Join(dir, "stop-intent.json"))
				os.Remove(filepath.Join(dir, "stop-response.json"))
			case "orphan-response":
				os.Remove(filepath.Join(dir, "stop-intent.json"))
				os.Remove(filepath.Join(dir, "stop-read.json"))
			case "intent-only":
				os.Remove(filepath.Join(dir, "stop-read.json"))
				os.Remove(filepath.Join(dir, "stop-response.json"))
			case "hash-extra":
				reloadMutate(t, dir, "reconciled.json", "stop_sha256.extra", strings.Repeat("0", 64))
			case "hash-omitted":
				reloadMutate(t, dir, "reconciled.json", "stop_sha256.stop-response/json", "DELETE")
			case "op-reused":
				reloadMutate(t, dir, "stop-intent.json", "operation_id", strings.Repeat("a", 32))
			case "wrong-action":
				reloadMutate(t, dir, "stop-intent.json", "action", "reload")
			case "insecure":
				reloadMutate(t, dir, "stop-intent.json", "allow_insecure", true)
			case "epoch":
				reloadMutate(t, dir, "stop-intent.json", "helper_epoch", strings.Repeat("f", 32))
			case "response":
				reloadMutate(t, dir, "stop-response.json", "diagnostics.job", "RUNNING")
			case "trace":
				reloadMutate(t, dir, "stop-read.json", "trace.streams.0.events.2.code", "FAILED")
			}
			if e := m.pending(""); e == nil {
				t.Fatal("unsafe STOP proof accepted")
			}
		})
	}
}
func TestDesktopReloadCommitRevalidates(t *testing.T) {
	for _, kind := range []string{"busy", "new-pending", "drift", "closed"} {
		t.Run(kind, func(t *testing.T) {
			m, _, calls := migrationFixture(t)
			dir := reloadFixture(t, m, "accepted", strings.Repeat("a", 32))
			p, e := m.inspect()
			if e != nil {
				t.Fatal(e)
			}
			var lock *os.File
			switch kind {
			case "busy":
				lock, e = m.lock()
				if e != nil {
					t.Fatal(e)
				}
				defer lock.Close()
			case "new-pending":
				os.WriteFile(filepath.Join(dir, "pending.json"), []byte("{}"), 0600)
			case "drift":
				os.WriteFile(filepath.Join(dir, "accepted.json"), []byte("{}"), 0600)
			}
			_, e = m.commit(p.Plan)
			if kind == "closed" {
				if e != nil || *calls != 1 {
					t.Fatal(e, *calls)
				}
			} else {
				if e == nil || *calls != 0 {
					t.Fatal(e, *calls)
				}
				stages, _ := filepath.Glob(filepath.Join(m.home, ".anytls/.desktop-candidate-*"))
				if len(stages) != 0 {
					t.Fatal("staged before guard")
				}
				if kind == "busy" && e.Error() != "INSTALL_BUSY" {
					t.Fatal(e)
				}
			}
		})
	}
}
func TestDesktopReloadHistoricalNotCurrent(t *testing.T) {
	m, r, calls := migrationFixture(t)
	reloadFixture(t, m, "reconciled", strings.Repeat("a", 32))
	r.HelperSHA256 = strings.Repeat("f", 64)
	r.HelperVersion = "v9.9.9"
	r.Running = true
	r.Loaded = true
	os.WriteFile(filepath.Join(m.home, ".anytls/config.yaml"), []byte("changed current bytes"), 0600)
	if _, e := m.inspect(); e != nil {
		t.Fatal(e)
	}
	r.ConfigIdentity = strings.Repeat("0", 64)
	if _, e := m.inspect(); e == nil || e.Error() != "HELPER_CONFIG_MISMATCH" {
		t.Fatal(e)
	}
	if *calls != 0 {
		t.Fatal("STOP")
	}
	m.status = func(context.Context) (controlHelperResponse, error) {
		t.Fatal("historical classifier probed helper")
		return controlHelperResponse{}, nil
	}
	if e := m.pending(""); e != nil {
		t.Fatal(e)
	}
}

func TestDesktopReloadPrivateOriginals(t *testing.T) {
	path := os.Getenv("ANYTLS_PRIVATE_RELOAD_FIXTURE")
	if path == "" {
		t.Skip("private original capture not supplied")
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal("private fixture unavailable")
	}
	var journals map[string]struct {
		RootMode int      `json:"root_mode"`
		RootUID  int      `json:"root_uid"`
		Members  []string `json:"members"`
		Files    map[string]struct {
			Base64           string `json:"bytes_base64"`
			SHA              string `json:"sha256"`
			Mode, UID, Nlink int
		}
	}
	if json.Unmarshal(raw, &journals) != nil {
		t.Fatal("private fixture shape")
	}
	accepted, reconciled := 0, 0
	for name, j := range journals {
		if j.RootMode != 0700 {
			t.Fatal("private root mode")
		}
		files := map[string][]byte{}
		for n, f := range j.Files {
			b, e := base64.StdEncoding.Strict().DecodeString(f.Base64)
			if e != nil || desktopSum(b) != f.SHA || f.Mode != 0600 || f.UID != j.RootUID || f.Nlink != 1 {
				t.Fatal("private capture binding")
			}
			files[n] = b
		}
		for _, n := range j.Members {
			if n == "pending.json" {
				t.Fatal("private pending")
			}
		}
		op := strings.TrimPrefix(name, ".core-reload-")
		job, e := reloadJSON(files["job.json"])
		if e != nil {
			t.Fatal("private job shape")
		}
		app := reloadString(job["app"])
		if !reloadID.MatchString(op) {
			t.Fatal("private ID")
		}
		if files["accepted.json"] != nil {
			if !reloadAccepted(files, app, op) {
				t.Fatal("private accepted proof rejected")
			}
			accepted++
		} else {
			if !reloadReconciled(files, app, op) {
				t.Fatal("private reconciled proof rejected")
			}
			reconciled++
		}
	}
	if accepted != 3 || reconciled != 1 {
		t.Fatal("private census mismatch")
	}
	t.Log("original captured proofs validated: accepted=3 reconciled=1; no filesystem/live authority inferred")
}
func TestDesktopReloadAcceptedRehashedValues(t *testing.T) {
	for _, field := range []string{"helper_epoch", "interface", "tun", "sha_kind", "execution_mapping", "network", "state", "operation_id", "new_core.uid", "new_core.pid", "new_core.birth", "new_core.command"} {
		t.Run(field, func(t *testing.T) {
			m, _, _ := migrationFixture(t)
			dir := reloadFixture(t, m, "accepted", strings.Repeat("a", 32))
			var value any = "INVALID"
			if field == "new_core.birth" {
				value = ""
			}
			if field == "new_core.uid" || field == "new_core.pid" {
				value = true
			}
			reloadMutate(t, dir, "result.json", field, value)
			if e := m.pending(""); e == nil {
				t.Fatal("rehashed invalid success accepted")
			}
		})
	}
}
func TestDesktopReloadStrictEnvelopes(t *testing.T) {
	for _, raw := range []string{`{}`, `{"schema":1,"schema":1}`, `{"a":{"x":1,"X":1}}`, `{"a":true} {}`, `{"a":[1,]}`, `{"a":"\u0000"}`} {
		if _, e := reloadJSON([]byte(raw)); e == nil && raw != "{}" {
			t.Fatal("bad JSON accepted")
		}
	}
}
func TestDesktopReloadStableCaptureMetadata(t *testing.T) {
	m, _, _ := migrationFixture(t)
	dir := reloadFixture(t, m, "accepted", strings.Repeat("a", 32))
	p := filepath.Join(dir, "result.json")
	b, first, e := reloadCapture(p, m.uid)
	if e != nil {
		t.Fatal(e)
	}
	_, same, e := reloadCapture(p, m.uid)
	if e != nil || !reloadStable(first, same) {
		t.Fatal("own read changed stamp", e)
	}
	os.Chmod(p, 0644)
	changed, _ := os.Lstat(p)
	if reloadStable(first, changed) {
		t.Fatal("mode drift")
	}
	os.Chmod(p, 0600)
	os.Rename(p, p+".old")
	os.WriteFile(p, b, 0600)
	replacement, _ := os.Lstat(p)
	if reloadStable(first, replacement) {
		t.Fatal("replacement")
	}
	if e := os.Chtimes(dir, time.Unix(1, 0), time.Unix(1, 0)); e != nil {
		t.Fatal(e)
	}
	root, _ := os.Lstat(dir)
	os.WriteFile(filepath.Join(dir, "pending.json"), []byte("{}"), 0600)
	after, _ := os.Lstat(dir)
	if reloadStable(root, after) {
		t.Fatal("directory membership drift")
	}
	if e := m.pending(""); e == nil {
		t.Fatal("new sentinel")
	}
}
func TestDesktopReloadJournalSymlinkAndOwner(t *testing.T) {
	for _, kind := range []string{"root-link", "leaf-directory", "uid", "setuid", "many-files", "invalid-prior"} {
		t.Run(kind, func(t *testing.T) {
			m, _, _ := migrationFixture(t)
			dir := reloadFixture(t, m, "reconciled", strings.Repeat("a", 32))
			switch kind {
			case "root-link":
				os.Rename(dir, dir+".original")
				os.Symlink(dir+".original", dir)
			case "leaf-directory":
				os.Remove(filepath.Join(dir, "claim.json"))
				os.Mkdir(filepath.Join(dir, "claim.json"), 0700)
			case "uid":
				m.uid++
			case "setuid":
				p := filepath.Join(dir, "claim.json")
				before, e := os.Lstat(p)
				if e != nil || before.Mode() != 0600 {
					t.Fatal("setuid fixture must exist as a regular 0600 file", e)
				}
				if e = m.pending(""); e != nil {
					t.Fatal("setuid fixture positive baseline", e)
				}
				if e = os.Chmod(p, os.ModeSetuid|0600); e != nil {
					t.Fatal("setuid fixture chmod", e)
				}
				// A sandbox can silently strip set-ID bits despite chmod success.
				// Require the actual unsafe file before testing the reader's guard.
				after, e := os.Lstat(p)
				if e != nil || !os.SameFile(before, after) || after.Mode() != os.ModeSetuid|0600 {
					t.Fatal("setuid fixture mode not retained", after, e)
				}
			case "many-files":
				for n := 0; n < 65; n++ {
					os.WriteFile(filepath.Join(dir, strconv.Itoa(n)), nil, 0600)
				}
			case "invalid-prior":
				reloadMutate(t, dir, "job.json", "before.status", map[string]any{})
			}
			if e := m.pending(""); e == nil {
				t.Fatal("unsafe journal")
			}
		})
	}
}
func TestDesktopMigrationRetainedCoreReloadTerminals(t *testing.T) {
	m, _, calls := migrationFixture(t)
	for i, kind := range []string{"accepted", "accepted", "accepted", "reconciled"} {
		reloadFixture(t, m, kind, strings.Repeat(string(rune('a'+i)), 32))
	}
	if e := m.pending(""); e != nil {
		t.Fatalf("retained terminal receipts block migration: %v", e)
	}
	if _, e := m.inspect(); e != nil {
		t.Fatal(e)
	}
	if *calls != 0 {
		t.Fatal("STOP in inspection")
	}
	if _, e := os.Lstat(filepath.Join(m.home, ".anytls/.install.lock")); !os.IsNotExist(e) {
		t.Fatal("inspection created lock", e)
	}
}

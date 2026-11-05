package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWebSelectionLinkUnsupportedNoWrites(t *testing.T) {
	for _, tc := range []struct{ name, config string }{
		{"missing-member", strings.Replace(selectionLinkConfig, "proxies: [a, b, DIRECT], selected: DIRECT}", "proxies: [a, DIRECT], selected: DIRECT}", 1)},
		{"nested", strings.Replace(selectionLinkConfig, "proxies: [a, b, DIRECT], selected: DIRECT}", "proxies: [a, b, DIRECT, dedicated], selected: dedicated}", 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, cookie, csrf := linkFixture(t, tc.config, "a")
			before, _ := w.profileFiles()
			w.state = func() (bool, bool, error) { t.Error("rejected validation touched service"); return true, true, nil }
			out := groupETagRequest(w, cookie, csrf, "/api/v1/nodes/selection", `{"name":"b"}`, `"`+shaHex(before[0].data)+`"`)
			if out.Code != 422 {
				t.Fatalf("%d %s", out.Code, out.Body.String())
			}
			for _, f := range before {
				if !webProfileSame(f) {
					t.Fatal("rejection wrote source")
				}
			}
		})
	}
}

func TestWebSelectionLinkLegacyAndExplicitPolicy(t *testing.T) {
	for _, tc := range []struct{ name, config, want string }{
		{"no-rules", strings.Replace(selectionLinkConfig, "rules: ['DOMAIN,example.test,dedicated', 'MATCH,default']", "", 1), "b"},
		{"explicit-node", strings.Replace(selectionLinkConfig, "MATCH,default", "MATCH,a", 1), "b"},
		{"explicit-direct", strings.Replace(selectionLinkConfig, "MATCH,default", "MATCH,DIRECT", 1), "b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, cookie, csrf := linkFixture(t, tc.config, "a")
			before, _ := os.ReadFile(w.configPath)
			linkPost(t, w, cookie, csrf, "/api/v1/nodes/selection", `{"name":"b"}`)
			after, _ := os.ReadFile(w.configPath)
			if !bytes.Equal(before, after) {
				t.Fatal("legacy selection rewrote intentional policy")
			}
			nodes, _ := loadNodesBytes(after)
			if got := effectiveWebSelection(w.configPath, after, nodes); got != tc.want {
				t.Fatalf("effective=%q want=%q", got, tc.want)
			}
		})
	}
}

func TestWebSelectionLinkSpecialGroupChoice(t *testing.T) {
	for _, choice := range []string{"DIRECT", "dedicated"} {
		t.Run(choice, func(t *testing.T) {
			config := strings.Replace(selectionLinkConfig, "proxies: [a, b, DIRECT], selected: DIRECT}", "proxies: [a, b, DIRECT, dedicated], selected: b}", 1)
			w, cookie, csrf := linkFixture(t, config, "a")
			linkPost(t, w, cookie, csrf, "/api/v1/groups/selection", `{"group":"default","choice":"`+choice+`"}`)
			nodes, _ := loadNodes(w.configPath)
			got, _ := selectedNode(w.configPath, nodes)
			if got != "a" {
				t.Fatal("special/nested choice became concrete selection")
			}
			b, _ := os.ReadFile(w.configPath)
			if effectiveWebSelection(w.configPath, b, nodes) != "a" {
				t.Fatal("special group choice hid actual startup selection")
			}
		})
	}
}

func TestWebSelectionLinkUnsafeStoreNeverActs(t *testing.T) {
	for _, kind := range []string{"config-symlink", "selected-symlink", "backup-symlink"} {
		t.Run(kind, func(t *testing.T) {
			w, cookie, csrf := linkFixture(t, selectionLinkConfig, "a")
			b, _ := os.ReadFile(w.configPath)
			target := w.configPath
			if kind == "selected-symlink" {
				target = selectedPath(w.configPath)
			}
			if kind == "backup-symlink" {
				target = filepath.Join(filepath.Dir(w.configPath), "import-backups")
			} else {
				if err := os.Rename(target, target+".original"); err != nil {
					t.Fatal(err)
				}
			}
			destination := target + ".original"
			if kind == "backup-symlink" {
				destination = t.TempDir()
			}
			if err := os.Symlink(destination, target); err != nil {
				t.Fatal(err)
			}
			calls := 0
			w.state = func() (bool, bool, error) { calls++; return true, true, nil }
			w.serviceAction = func(context.Context, string, bool) error { calls++; return nil }
			out := groupETagRequest(w, cookie, csrf, "/api/v1/nodes/selection", `{"name":"b"}`, `"`+shaHex(b)+`"`)
			got, _ := os.ReadFile(w.configPath)
			if out.Code < 400 || calls != 0 || !bytes.Equal(b, got) {
				t.Fatalf("unsafe target: %d calls=%d %s", out.Code, calls, out.Body.String())
			}
			sel, _ := os.ReadFile(selectedPath(w.configPath))
			if string(sel) != "a\n" {
				t.Fatal("selection changed")
			}
		})
	}
}

// Exercise the exact transaction called by the router with controlled I/O
// faults, including write-then-error and silent corrupt readback.
func TestWebSelectionLinkTransactionFailures(t *testing.T) {
	for _, kind := range []string{"second-write", "write-then-error", "readback", "rollback-failure", "cas-config", "cas-selection", "absent-selection"} {
		t.Run(kind, func(t *testing.T) {
			saved := "a"
			if kind == "absent-selection" {
				saved = ""
			}
			w, _, _ := linkFixture(t, selectionLinkConfig, saved)
			old, err := w.profileFiles()
			if err != nil {
				t.Fatal(err)
			}
			target := append([]webProfileFile(nil), old...)
			for i := range target {
				target[i].info = nil
			}
			target[0].data, err = groupChoiceBytes(old[0].data, "default", "b")
			if err != nil {
				t.Fatal(err)
			}
			target[1].exists = true
			target[1].data = []byte("b\n")
			calls := 0
			write := func(path string, b []byte) error {
				calls++
				if calls == 2 {
					if kind == "readback" {
						return webAtomicWrite(path, []byte("corrupt\n"))
					}
					if kind == "write-then-error" {
						if err := webAtomicWrite(path, b); err != nil {
							return err
						}
						return errors.New("after publication")
					}
					return errors.New("injected second write")
				}
				if kind == "rollback-failure" && calls > 2 {
					return errors.New("injected rollback failure")
				}
				return webAtomicWrite(path, b)
			}
			want := "PROFILE_SWITCH_FAILED_ROLLED_BACK"
			if kind == "rollback-failure" {
				want = "PROFILE_STATE_UNCERTAIN"
			}
			if strings.HasPrefix(kind, "cas-") {
				index := 0
				if kind == "cas-selection" {
					index = 1
				}
				if err := webAtomicWrite(old[index].path, append(bytes.Clone(old[index].data), ' ')); err != nil {
					t.Fatal(err)
				}
				want = "PROFILE_CONFLICT"
			}
			code := w.commitProfileFiles(target, old, func() bool { return true }, write)
			if code != want {
				t.Fatalf("code=%s want=%s calls=%d", code, want, calls)
			}
			if want == "PROFILE_CONFLICT" {
				if calls != 0 {
					t.Fatal("CAS failure wrote")
				}
				return
			}
			if want == "PROFILE_STATE_UNCERTAIN" {
				return
			}
			current, err := w.profileFiles()
			if err != nil || !webProfileEqual(current, old) {
				t.Fatalf("rollback failed: %v", err)
			}
		})
	}
}

func TestWebSelectionLinkActionLock(t *testing.T) {
	w, cookie, csrf := linkFixture(t, selectionLinkConfig, "a")
	w.actionMu.Lock()
	out := groupETagRequest(w, cookie, csrf, "/api/v1/nodes/selection", `{"name":"b"}`, "")
	w.actionMu.Unlock()
	if out.Code != 409 {
		t.Fatalf("busy request=%d %s", out.Code, out.Body.String())
	}
	linkPost(t, w, cookie, csrf, "/api/v1/nodes/selection", `{"name":"b"}`)
}

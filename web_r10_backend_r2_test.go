package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestR10R2SwitchSnapshotCAS(t *testing.T) {
	for _, change := range []string{"selection", "subscription", "active-id", "yaml", "unchanged", "header", "missing", "bad-snapshot-with-valid-legacy", "empty-snapshot-with-valid-legacy"} {
		t.Run(change, func(t *testing.T) {
			w, c, csrf := profileRouterFixture(t)
			w.state = func() (bool, bool, error) { return false, false, nil }
			a := r10Body(t, r10Call(t, w, c, csrf, "POST", "/api/v1/profiles", map[string]any{"name": "A"}, ""))["id"].(string)
			b := r10Body(t, r10Call(t, w, c, csrf, "POST", "/api/v1/profiles/copy", map[string]any{"id": a, "name": "B"}, ""))["id"].(string)
			if change == "subscription" {
				p, f, _ := w.readProfile(a)
				sub := `{"url":"https://example.com/source"}`
				p.Subscription = &sub
				p.Link = &webProfileLink{Auto: true, Next: time.Now().Add(time.Hour).Format(time.RFC3339Nano)}
				p.Link.Baseline = profileContent(p)
				if e := webAtomicWrite(w.subscriptionPath(), []byte(sub)); e != nil {
					t.Fatal(e)
				}
				if e := w.replaceProfile(p, f); e != nil {
					t.Fatal(e)
				}
			}
			detail := r10Body(t, r10Call(t, w, c, "", "GET", "/api/v1/profiles?detail=1", nil, ""))
			token, _ := detail["switch_version"].(string)
			if token == "" {
				t.Error("detail missing complete snapshot switch_version")
			}
			switch change {
			case "selection":
				r10Body(t, r10Call(t, w, c, csrf, "POST", "/api/v1/nodes/selection", map[string]any{"name": "imported", "confirm_insecure": true}, detail["etag"].(string)))
			case "subscription":
				p, _, _ := w.readProfile(a)
				r10Body(t, r10Call(t, w, c, csrf, "POST", "/api/v1/subscriptions/unlink", map[string]any{"id": a, "version": profileVersion(p), "confirm": true}, ""))
			case "yaml":
				raw, _ := os.ReadFile(w.configPath)
				r10Body(t, r10Call(t, w, c, csrf, "PUT", "/api/v1/config", map[string]any{"yaml": string(raw) + "# edit\n", "confirm_insecure": true}, detail["etag"].(string)))
			case "active-id":
				r10Body(t, r10Call(t, w, c, csrf, "POST", "/api/v1/profiles/switch", map[string]any{"id": b, "confirm_replace": true, "confirm_insecure": true}, detail["etag"].(string)))
			}
			before, _ := w.profileFiles()
			marker, _ := os.ReadFile(w.activePath())
			body := map[string]any{"id": a, "confirm_replace": true, "confirm_insecure": true, "snapshot_version": token}
			etag := ""
			want := 412
			switch change {
			case "unchanged":
				want = 200
			case "header":
				delete(body, "snapshot_version")
				etag = `"` + token + `"`
				want = 200
			case "missing":
				delete(body, "snapshot_version")
				want = 428
			case "bad-snapshot-with-valid-legacy":
				body["snapshot_version"] = "switch-v1-bad"
				etag = detail["etag"].(string)
			case "empty-snapshot-with-valid-legacy":
				body["snapshot_version"] = ""
				etag = detail["etag"].(string)
			}
			out := r10Call(t, w, c, csrf, "POST", "/api/v1/profiles/switch", body, etag)
			if out.Code != want {
				t.Fatalf("want %d got %d %s", want, out.Code, out.Body.String())
			}
			if want != 200 {
				after, _ := w.profileFiles()
				got, _ := os.ReadFile(w.activePath())
				if !webProfileEqual(before, after) || !bytes.Equal(marker, got) {
					t.Fatal("rejected switch mutated snapshot")
				}
			}
		})
	}
}

func TestR10R2ManualAuthorityCompletion(t *testing.T) {
	for _, op := range []string{"check", "preview"} {
		for _, revoke := range []string{"logout", "password", "expiry", "csrf"} {
			for _, failed := range []bool{false, true} {
				t.Run(op+"/"+revoke+"/"+map[bool]string{false: "success", true: "fetch-failed"}[failed], func(t *testing.T) {
					w, c, csrf := profileRouterFixture(t)
					w.importFetch = func(context.Context, string) ([]byte, error) { return []byte(webImportYAML), nil }
					id := r10Import(t, w, c, csrf, "Provider")
					_, old, _ := w.readProfile(id)
					started, release := make(chan struct{}), make(chan struct{})
					defer func() {
						select {
						case <-release:
						default:
							close(release)
						}
					}()
					w.importFetch = func(context.Context, string) ([]byte, error) {
						close(started)
						<-release
						if failed {
							return nil, errors.New("offline")
						}
						return []byte(webImportYAML + "# changed\n"), nil
					}
					body := map[string]any{"id": id}
					if op == "preview" {
						body = map[string]any{"url": "https://example.com/secret", "name": "Preview"}
					}
					done := make(chan *httptest.ResponseRecorder, 1)
					go func() { done <- r10Call(t, w, c, csrf, "POST", "/api/v1/subscriptions/"+op, body, "") }()
					select {
					case <-started:
					case <-time.After(3 * time.Second):
						t.Fatal("network seam not reached")
					}
					switch revoke {
					case "logout":
						r10Body(t, r10Call(t, w, c, csrf, "POST", "/api/v1/logout", map[string]any{}, ""))
					case "password":
						if _, e := webPassword(w.passwordPath, true); e != nil {
							t.Fatal(e)
						}
					case "expiry":
						w.authMu.Lock()
						s := w.sessions[c.Value]
						s.expires = time.Unix(1, 0)
						w.sessions[c.Value] = s
						w.authMu.Unlock()
					case "csrf":
						w.authMu.Lock()
						s := w.sessions[c.Value]
						s.csrf = "replaced"
						w.sessions[c.Value] = s
						w.authMu.Unlock()
					}
					close(release)
					out := <-done
					if out.Code != 401 {
						t.Errorf("revoked completion HTTP %d: %s", out.Code, out.Body.String())
					}
					_, after, _ := w.readProfile(id)
					if !bytes.Equal(old.data, after.data) {
						t.Error("revoked session committed content/metadata")
					}
					if w.subscriptionPreview != nil {
						t.Error("revoked preview retained secret")
					}
				})
			}
		}
	}
}

func TestR10R2ApplyErrorStartupEnvelope(t *testing.T) {
	w, c, csrf := profileRouterFixture(t)
	w.importFetch = func(context.Context, string) ([]byte, error) { return []byte(webImportYAML), nil }
	id := r10Import(t, w, c, csrf, "Provider")
	prior := w.beginStartup("reload", "SAVE_YAML")
	out := r10Call(t, w, c, csrf, "POST", "/api/v1/subscriptions/apply", map[string]any{"id": id, "confirm": true, "confirm_insecure": true, "target_version": "stale", "candidate_version": "stale"}, "")
	var body map[string]any
	_ = json.Unmarshal(out.Body.Bytes(), &body)
	if v, ok := body["startup_operation"]; !ok || v != nil {
		t.Fatal("apply error missing explicit null", out.Body.String())
	}
	if w.startupLatest != prior {
		t.Fatal("error replaced previous operation")
	}
	if got := webStartupSource(httptest.NewRequest("POST", "/api/v1/subscriptions/apply", nil)); got != "IMPORT_COMMIT" {
		t.Fatal("source mapping", got)
	}
}

func TestR10R2WorkerAuthorityAfterLogout(t *testing.T) {
	w, c, csrf := profileRouterFixture(t)
	w.importFetch = func(context.Context, string) ([]byte, error) { return []byte(webImportYAML), nil }
	id := r10Import(t, w, c, csrf, "Provider")
	r10Body(t, r10Call(t, w, c, csrf, "POST", "/api/v1/logout", map[string]any{}, ""))
	if _, e := webPassword(w.passwordPath, true); e != nil {
		t.Fatal(e)
	}
	w.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	w.importFetch = func(context.Context, string) ([]byte, error) { return []byte(webImportYAML + "# worker update\n"), nil }
	w.checkSubscriptionsDue(context.Background())
	p, _, e := w.readProfile(id)
	if e != nil || p.Link.Result != "UPDATED" || !strings.Contains(p.YAML, "# worker update") {
		t.Fatal("service-owned worker depended on revoked browser", e, p.Link)
	}
}

func TestR10R2MarkerRollbackFourTargets(t *testing.T) {
	for _, mode := range []string{"present", "absent", "uncertain"} {
		t.Run(mode, func(t *testing.T) {
			w, c, csrf := profileRouterFixture(t)
			w.state = func() (bool, bool, error) { return false, false, nil }
			a := r10Body(t, r10Call(t, w, c, csrf, "POST", "/api/v1/profiles", map[string]any{"name": "A"}, ""))["id"].(string)
			b := r10Body(t, r10Call(t, w, c, csrf, "POST", "/api/v1/profiles/copy", map[string]any{"id": a, "name": "B"}, ""))["id"].(string)
			p, f, _ := w.readProfile(b)
			p.YAML += "# target B\n"
			selection := "imported\n"
			sub := `{"url":"https://example.com/B"}`
			p.Selected = &selection
			p.Subscription = &sub
			if e := w.replaceProfile(p, f); e != nil {
				t.Fatal(e)
			}
			if mode == "absent" {
				if e := os.Remove(w.activePath()); e != nil {
					t.Fatal(e)
				}
			}
			old, _ := w.profileFiles()
			marker, _ := webProfileCapture(w.activePath(), 128, true, true)
			active, _ := w.activeProfile()
			seen := 0
			w.profileMarkerReadback = func() error {
				seen++
				got, e := os.ReadFile(w.activePath())
				if e != nil || string(got) != b+"\n" {
					t.Fatal("seam not after marker rename")
				}
				if mode == "uncertain" {
					if e := os.Remove(w.activePath()); e != nil {
						t.Fatal(e)
					}
					if e := os.Symlink(w.passwordPath, w.activePath()); e != nil {
						t.Fatal(e)
					}
					return errors.New("readback unavailable")
				}
				// Real filesystem fault: violate private-file mode after successful rename.
				return os.Chmod(w.activePath(), 0644)
			}
			out := r10Call(t, w, c, csrf, "POST", "/api/v1/profiles/switch", map[string]any{"id": b, "snapshot_version": webProfileSwitchVersion(active, old), "confirm_replace": true, "confirm_insecure": true}, "")
			if seen != 1 || out.Code != 500 {
				t.Fatal(seen, out.Code, out.Body.String())
			}
			after, _ := w.profileFiles()
			if !webProfileEqual(old, after) {
				t.Fatal("three data targets not restored")
			}
			if mode == "uncertain" {
				if !strings.Contains(out.Body.String(), "PROFILE_STATE_UNCERTAIN") {
					t.Fatal(out.Body.String())
				}
				return
			}
			marker.info = nil
			if !webProfileSame(marker) || !strings.Contains(out.Body.String(), "PROFILE_SWITCH_FAILED_ROLLED_BACK") {
				t.Fatal("fourth target not restored", out.Body.String())
			}
		})
	}
}

func TestR10R2ApplyStartupMatrix(t *testing.T) {
	for _, mode := range []string{"running", "stopped", "noop", "inactive", "stale-target", "stale-candidate", "conversion", "selection"} {
		t.Run(mode, func(t *testing.T) {
			w, c, csrf := profileRouterFixture(t)
			w.state = func() (bool, bool, error) { return false, false, nil }
			w.importFetch = func(context.Context, string) ([]byte, error) { return []byte(webImportYAML), nil }
			id := r10Import(t, w, c, csrf, "Provider")
			if mode != "inactive" {
				raw, _ := os.ReadFile(w.configPath)
				r10Body(t, r10Call(t, w, c, csrf, "POST", "/api/v1/profiles/switch", map[string]any{"id": id, "confirm_replace": true, "confirm_insecure": true}, `"`+shaHex(raw)+`"`))
			}
			p, f, _ := w.readProfile(id)
			s := profileSnapshot(p)
			if mode != "noop" {
				s.YAML += "# candidate\n"
			}
			p.Link.Candidate = &webSubscriptionCandidate{Snapshot: s, Base: profileContent(p)}
			if mode == "conversion" {
				p.Link.Candidate.Conversion.Warnings = []string{"review required"}
			}
			if mode == "selection" {
				p.Link.Candidate.Invalid = true
			}
			if e := w.replaceProfile(p, f); e != nil {
				t.Fatal(e)
			}
			w.state = func() (bool, bool, error) { return mode != "stopped", mode != "stopped", nil }
			calls, mutation := webStartupRouteIPC(t, w, "reload", false)
			prior := w.beginStartup("reload", "SAVE_YAML")
			payload := map[string]any{"id": id, "target_version": profileVersion(p), "candidate_version": candidateVersion(p.Link.Candidate), "confirm": true, "confirm_insecure": true}
			if mode == "stale-target" {
				payload["target_version"] = "stale"
			}
			if mode == "stale-candidate" {
				payload["candidate_version"] = "stale"
			}
			out := r10Call(t, w, c, csrf, "POST", "/api/v1/subscriptions/apply", payload, "")
			if mode == "running" {
				if out.Code != 200 {
					t.Fatal(out.Code, out.Body.String())
				}
				webStartupAssertRouteReference(t, w, out.Body.Bytes(), "IMPORT_COMMIT", "reload", mutation)
				return
			}
			want := 200
			switch mode {
			case "stale-target", "stale-candidate":
				want = 412
			case "conversion":
				want = 400
			case "selection":
				want = 422
			}
			if out.Code != want || len(*calls) != 0 || w.startupLatest != prior {
				t.Fatal("unexpected apply/action", out.Code, *calls, out.Body.String())
			}
			var body map[string]any
			_ = json.Unmarshal(out.Body.Bytes(), &body)
			if v, ok := body["startup_operation"]; !ok || v != nil {
				t.Fatal("no-action needs explicit null", out.Body.String())
			}
		})
	}
}

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWebImportAppendTransactionBoundaries(t *testing.T) {
	for _, mode := range []string{"session", "ttl", "ifmatch", "selection", "subscription", "config", "backup", "busy", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			w, password := webFixture(t)
			c, csrf := webLogin(t, w, password)
			old, _ := os.ReadFile(w.configPath)
			p := importPreview(t, w, c, csrf, map[string]any{"yaml": webImportYAML, "mode": "append_nodes"})
			want := 409
			switch mode {
			case "session":
				c, csrf = webLogin(t, w, password)
			case "ttl":
				now := w.now()
				w.now = func() time.Time { return now.Add(10 * time.Minute) }
			case "ifmatch":
				p["etag"] = ""
				want = 428
			case "selection":
				os.WriteFile(selectedPath(w.configPath), []byte("external\n"), 0600)
				want = 412
			case "subscription":
				os.WriteFile(w.subscriptionPath(), []byte("external"), 0600)
				want = 412
			case "config":
				os.WriteFile(w.configPath, append(old, []byte("# external\n")...), 0600)
				want = 412
			case "backup":
				os.WriteFile(filepath.Join(filepath.Dir(w.configPath), "import-backups"), []byte("block"), 0600)
				want = 500
			case "busy":
				w.actionMu.Lock()
				defer w.actionMu.Unlock()
			case "canceled":
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				r := httptest.NewRequest("POST", "http://127.0.0.1:18089/api/v1/import/commit", nil).WithContext(ctx)
				rec := httptest.NewRecorder()
				w.importAppendCommit(rec, r, w.importPending, true)
				if rec.Code != 422 {
					t.Fatal(rec.Code)
				}
				got, _ := os.ReadFile(w.configPath)
				if !bytes.Equal(got, old) {
					t.Fatal("canceled wrote")
				}
				return
			}
			rec := importRequest(t, w, c, csrf, "import/commit", map[string]any{"token": p["token"], "confirm_append": true, "confirm_insecure": true}, p["etag"].(string))
			if rec.Code != want {
				t.Fatal(rec.Code, rec.Body.String())
			}
			if mode != "config" {
				got, _ := os.ReadFile(w.configPath)
				if !bytes.Equal(got, old) {
					t.Fatal("rejected request wrote")
				}
			}
		})
	}
}

func TestWebImportPinnedNoRedirectAndCancellation(t *testing.T) {
	token := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://127.0.0.1/private")
		w.WriteHeader(302)
	}))
	defer server.Close()
	sum := sha256.Sum256(server.Certificate().Raw)
	raw := "https://8.8.8.8/subscribe/" + token + "#anytls-cert-sha256=" + hex.EncodeToString(sum[:])
	calls := 0
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		calls++
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	if _, e := webImportPinnedFetch(context.Background(), raw, dial); e == nil || calls != 1 {
		t.Fatal("redirect followed", e, calls)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := webImportPinnedFetch(ctx, raw, dial); e == nil {
		t.Fatal("cancellation ignored")
	}
}

func TestWebImportAppendReadbackRollbackPreservesSidecars(t *testing.T) {
	for _, kind := range []string{"absent", "empty", "bytes"} {
		t.Run(kind, func(t *testing.T) {
			w, password := webFixture(t)
			c, csrf := webLogin(t, w, password)
			old, _ := os.ReadFile(w.configPath)
			if kind != "absent" {
				value := []byte{}
				if kind == "bytes" {
					value = []byte("preserve exact\n")
				}
				for _, path := range []string{selectedPath(w.configPath), w.subscriptionPath()} {
					if e := os.WriteFile(path, value, 0600); e != nil {
						t.Fatal(e)
					}
				}
			}
			_ = importPreview(t, w, c, csrf, map[string]any{"yaml": webImportYAML, "mode": "append_nodes"})
			p := w.importPending
			req := httptest.NewRequest("POST", "http://127.0.0.1:18089/api/v1/import/commit", nil)
			rec := httptest.NewRecorder()
			w.importAppendCommit(rec, req, p, true, func(path string, data []byte) error {
				if e := webAtomicWrite(path, []byte("partial")); e != nil {
					return e
				}
				return errors.New("injected post-write error")
			})
			if rec.Code != 500 || !strings.Contains(rec.Body.String(), "IMPORT_WRITE_FAILED_ROLLED_BACK") {
				t.Fatal(rec.Code, rec.Body.String())
			}
			got, _ := os.ReadFile(w.configPath)
			if !bytes.Equal(got, old) || !webImportSame(p.oldSelected) || !webImportSame(p.oldSubscription) {
				t.Fatal("rollback changed state")
			}
		})
	}
}

func TestWebImportAppendRemoteAndPublicBoundaries(t *testing.T) {
	bad := strings.Replace(webImportYAML, "skip-cert-verify: true", "ca: /never/read/private.pem", 1)
	if _, e := webImportAppendInput([]byte(bad), true); e == nil || e.Error() != "IMPORT_REMOTE_FILE_REFERENCE" {
		t.Fatal(e)
	}
	for _, ip := range []string{"0.0.0.0", "10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.169.254", "172.16.0.1", "192.168.1.1", "192.0.2.1", "198.18.0.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "240.0.0.1", "168.63.129.16", "::1", "::ffff:127.0.0.1", "fc00::1", "fe80::1", "2001:db8::1", "2002::1"} {
		if webImportPublic(net.ParseIP(ip)) {
			t.Fatal("unsafe public", ip)
		}
	}
}

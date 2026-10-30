package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"io"
	"net/http/httptest"
	"strconv"
	"testing"
)

func TestWebStaticGzip(t *testing.T) {
	w, _ := webFixture(t)
	for _, asset := range []struct{ path, name, mime string }{
		{"/", "index.html", "text/html; charset=utf-8"},
		{"/app.js", "app.js", "text/javascript; charset=utf-8"},
		{"/startup.js", "startup.js", "text/javascript; charset=utf-8"},
		{"/style.css", "style.css", "text/css; charset=utf-8"},
	} {
		t.Run(asset.name, func(t *testing.T) {
			original, err := webAssets.ReadFile("web_assets/" + asset.name)
			if err != nil {
				t.Fatal(err)
			}
			for _, encoding := range []string{"identity", "gzip"} {
				t.Run(encoding, func(t *testing.T) {
					r := httptest.NewRequest("GET", "http://127.0.0.1:18089"+asset.path, nil)
					r.Header.Set("Accept-Encoding", encoding)
					rec := httptest.NewRecorder()
					w.ServeHTTP(rec, r)
					if rec.Code != 200 {
						t.Fatalf("status=%d", rec.Code)
					}
					expected := ""
					if encoding == "gzip" {
						expected = "gzip"
					}
					if got := rec.Header().Get("Content-Encoding"); got != expected {
						t.Fatalf("Content-Encoding=%q, want %q", got, expected)
					}
					if got := rec.Header().Get("Vary"); got != "Accept-Encoding" {
						t.Fatalf("Vary=%q", got)
					}
					if got := rec.Header().Get("Content-Length"); got != strconv.Itoa(rec.Body.Len()) {
						t.Fatalf("Content-Length=%q body=%d", got, rec.Body.Len())
					}
					if rec.Header().Get("Content-Type") != asset.mime || rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Content-Type-Options") != "nosniff" || rec.Header().Get("X-Frame-Options") != "DENY" || rec.Header().Get("Referrer-Policy") != "no-referrer" || rec.Header().Get("Content-Security-Policy") == "" {
						t.Fatal("MIME/security headers changed")
					}
					body := rec.Body.Bytes()
					if encoding == "gzip" {
						zr, err := gzip.NewReader(bytes.NewReader(body))
						if err != nil {
							t.Fatal(err)
						}
						body, err = io.ReadAll(zr)
						if err != nil {
							t.Fatal(err)
						}
						if err := zr.Close(); err != nil {
							t.Fatal(err)
						}
						if rec.Body.Len() >= len(original) {
							t.Fatal("gzip did not reduce embedded asset")
						}
					}
					if !bytes.Equal(body, original) || sha256.Sum256(body) != sha256.Sum256(original) {
						t.Fatal("embedded bytes/SHA mismatch")
					}
					t.Logf("identity_bytes=%d wire_bytes=%d sha256=%x", len(original), rec.Body.Len(), sha256.Sum256(body))
				})
			}
		})
	}
}

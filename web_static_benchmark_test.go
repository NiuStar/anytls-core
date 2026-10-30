package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The same file compiles against the frozen pre-optimization source. It accepts
// old gzip requests returning identity, and reports those actual wire bytes.
type webStaticDiscardWriter struct {
	header          http.Header
	status, written int
}

func (w *webStaticDiscardWriter) Header() http.Header    { return w.header }
func (w *webStaticDiscardWriter) WriteHeader(status int) { w.status = status }
func (w *webStaticDiscardWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	w.written += len(p)
	return len(p), nil
}

func BenchmarkWebStaticAssets(b *testing.B) {
	w := &webConsole{port: 18089}
	for _, asset := range []struct{ path, name string }{{"/", "index.html"}, {"/app.js", "app.js"}, {"/startup.js", "startup.js"}, {"/style.css", "style.css"}} {
		for _, encoding := range []string{"identity", "gzip"} {
			b.Run(asset.name+"/"+encoding, func(b *testing.B) {
				original, err := webAssets.ReadFile("web_assets/" + asset.name)
				if err != nil {
					b.Fatal(err)
				}
				r := httptest.NewRequest("GET", "http://127.0.0.1:18089"+asset.path, nil)
				r.Header.Set("Accept-Encoding", encoding)
				rec := httptest.NewRecorder()
				w.ServeHTTP(rec, r)
				body := rec.Body.Bytes()
				if rec.Header().Get("Content-Encoding") == "gzip" {
					zr, err := gzip.NewReader(bytes.NewReader(body))
					if err != nil {
						b.Fatal(err)
					}
					body, err = io.ReadAll(zr)
					if err != nil {
						b.Fatal(err)
					}
					if err = zr.Close(); err != nil {
						b.Fatal(err)
					}
				} else if rec.Header().Get("Content-Encoding") != "" {
					b.Fatal("unexpected representation")
				}
				if rec.Code != 200 || !bytes.Equal(original, body) || sha256.Sum256(body) != sha256.Sum256(original) {
					b.Fatal("HTTP wire integrity")
				}
				wireBytes := rec.Body.Len()
				rw := webStaticDiscardWriter{header: make(http.Header)}
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					rw.status = 0
					rw.written = 0
					w.ServeHTTP(&rw, r)
					if rw.status != 200 || rw.written != wireBytes {
						b.Fatal("HTTP output changed")
					}
				}
				b.StopTimer()
				b.ReportMetric(float64(wireBytes), "wire-B/op")
			})
		}
	}
}

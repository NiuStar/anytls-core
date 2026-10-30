package main

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
)

type webStaticCountingFS struct {
	fs.FS
	reads atomic.Int32
	fail  bool
}

func (f *webStaticCountingFS) ReadFile(name string) ([]byte, error) {
	f.reads.Add(1)
	if f.fail {
		return nil, fs.ErrNotExist
	}
	return fs.ReadFile(f.FS, name)
}

func TestWebStaticBuildOnceConcurrent(t *testing.T) {
	var store webStaticStore
	source := &webStaticCountingFS{FS: webAssets}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				assets, err := store.load(source)
				if err != nil || len(assets) != 4 {
					t.Errorf("load error=%v count=%d", err, len(assets))
					return
				}
				for path, asset := range assets {
					zr, err := gzip.NewReader(bytes.NewReader(asset.gzip))
					if err != nil {
						t.Error(err)
						return
					}
					body, err := io.ReadAll(zr)
					closeErr := zr.Close()
					if err != nil || closeErr != nil || !bytes.Equal(body, asset.identity) {
						t.Errorf("concurrent bytes changed: %s", path)
						return
					}
				}
			}
		}()
	}
	wg.Wait()
	if n := source.reads.Load(); n != 4 {
		t.Fatalf("source reads=%d, want exactly four per store lifetime", n)
	}
	assets, _ := store.load(source)
	again, _ := store.load(source)
	var identityBytes, gzipBytes, capacity int
	for path, asset := range assets {
		if &asset.identity[0] != &again[path].identity[0] || &asset.gzip[0] != &again[path].gzip[0] {
			t.Fatal("representation copied on load")
		}
		identityBytes += len(asset.identity)
		gzipBytes += len(asset.gzip)
		capacity += cap(asset.identity) + cap(asset.gzip)
	}
	t.Logf("retained identity=%d gzip=%d backing_slice_capacity=%d (excludes map/header overhead, not RSS)", identityBytes, gzipBytes, capacity)
}

func TestWebStaticBuildFailureSticky(t *testing.T) {
	var store webStaticStore
	source := &webStaticCountingFS{FS: webAssets, fail: true}
	for i := 0; i < 3; i++ {
		assets, err := store.load(source)
		if !errors.Is(err, fs.ErrNotExist) || assets != nil {
			t.Fatal("failed build published partial assets or lost error")
		}
	}
	if source.reads.Load() != 1 {
		t.Fatal("failed initialization retried")
	}
}

func TestWebStaticWireHTTP(t *testing.T) {
	w, _ := webFixture(t)
	// A real loopback HTTP server/client catches response framing; the Host still
	// matches the console's exact existing policy, not the random listener port.
	server := httptest.NewServer(w)
	defer server.Close()
	transport := &http.Transport{DisableCompression: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	for _, path := range []string{"/", "/app.js", "/startup.js", "/style.css"} {
		for _, encoding := range []string{"identity", "gzip"} {
			r, err := http.NewRequest("GET", server.URL+path, nil)
			if err != nil {
				t.Fatal(err)
			}
			r.Host = "127.0.0.1:18089"
			r.Header.Set("Accept-Encoding", encoding)
			resp, err := client.Do(r)
			if err != nil {
				t.Fatal(err)
			}
			wire, readErr := io.ReadAll(resp.Body)
			closeErr := resp.Body.Close()
			if readErr != nil || closeErr != nil || resp.StatusCode != 200 {
				t.Fatalf("HTTP response status=%d read=%v close=%v", resp.StatusCode, readErr, closeErr)
			}
			if resp.Header.Get("Content-Length") != strconv.Itoa(len(wire)) || resp.ContentLength != int64(len(wire)) || resp.Uncompressed {
				t.Fatal("wrong framing or client auto-decompression")
			}
			name := path[1:]
			if name == "" {
				name = "index.html"
			}
			original, err := webAssets.ReadFile("web_assets/" + name)
			if err != nil {
				t.Fatal(err)
			}
			body := wire
			if encoding == "gzip" {
				if resp.Header.Get("Content-Encoding") != "gzip" {
					t.Fatal("wire gzip missing")
				}
				zr, err := gzip.NewReader(bytes.NewReader(wire))
				if err != nil {
					t.Fatal(err)
				}
				body, err = io.ReadAll(zr)
				if err != nil {
					t.Fatal(err)
				}
				if err = zr.Close(); err != nil {
					t.Fatal(err)
				}
			} else if resp.Header.Get("Content-Encoding") != "" {
				t.Fatal("identity encoded")
			}
			if !bytes.Equal(original, body) {
				t.Fatal("wire embedded bytes changed")
			}
		}
	}
}

func BenchmarkWebStaticColdBuild(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var store webStaticStore
		assets, err := store.load(webAssets)
		if err != nil || len(assets) != 4 {
			b.Fatal("cold build failed", err)
		}
	}
}

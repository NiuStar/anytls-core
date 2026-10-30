package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io/fs"
	"net/http"
	"strconv"
	"sync"
)

// Only these public, build-time assets are retained. Never cache API data or
// request headers. Published byte slices are read-only for the process lifetime.
type webStaticAsset struct {
	identity, gzip []byte
	mime           string
}
type webStaticStore struct {
	once   sync.Once
	assets map[string]webStaticAsset
	err    error
}

var webStatic webStaticStore

func (s *webStaticStore) load(source fs.FS) (map[string]webStaticAsset, error) {
	s.once.Do(func() {
		assets := make(map[string]webStaticAsset, 4)
		for _, spec := range []struct{ path, name, mime string }{
			{"/", "index.html", "text/html; charset=utf-8"},
			{"/app.js", "app.js", "text/javascript; charset=utf-8"},
			{"/startup.js", "startup.js", "text/javascript; charset=utf-8"},
			{"/style.css", "style.css", "text/css; charset=utf-8"},
		} {
			body, err := fs.ReadFile(source, "web_assets/"+spec.name)
			if err != nil {
				s.err = fmt.Errorf("read static asset: %w", err)
				return
			}
			var encoded bytes.Buffer
			zw := gzip.NewWriter(&encoded)
			_, writeErr := zw.Write(body)
			closeErr := zw.Close()
			if writeErr != nil {
				s.err = fmt.Errorf("gzip static asset: %w", writeErr)
				return
			}
			if closeErr != nil {
				s.err = fmt.Errorf("close static gzip: %w", closeErr)
				return
			}
			assets[spec.path] = webStaticAsset{identity: body, gzip: encoded.Bytes(), mime: spec.mime}
		}
		s.assets = assets
	})
	return s.assets, s.err
}

func webServeStatic(rw http.ResponseWriter, r *http.Request) {
	// Reject unknown paths before initializing even the bounded static store.
	switch r.URL.Path {
	case "/", "/app.js", "/startup.js", "/style.css":
	default:
		http.NotFound(rw, r)
		return
	}
	assets, err := webStatic.load(webAssets)
	if err != nil {
		webError(rw, 500, "ASSET_UNAVAILABLE")
		return
	}
	asset := assets[r.URL.Path]
	body := asset.identity
	if r.Header.Get("Accept-Encoding") == "gzip" {
		body = asset.gzip
		rw.Header().Set("Content-Encoding", "gzip")
	}
	rw.Header().Set("Vary", "Accept-Encoding")
	rw.Header().Set("Content-Type", asset.mime)
	rw.Header().Set("Content-Length", strconv.Itoa(len(body)))
	_, _ = rw.Write(body)
}

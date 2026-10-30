package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
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
	rw.Header().Set("Vary", "Accept-Encoding")
	encoding, acceptable := webStaticEncoding(r.Header.Values("Accept-Encoding"))
	if !acceptable {
		webError(rw, http.StatusNotAcceptable, "ENCODING_NOT_ACCEPTABLE")
		return
	}
	assets, err := webStatic.load(webAssets)
	if err != nil {
		webError(rw, 500, "ASSET_UNAVAILABLE")
		return
	}
	asset := assets[r.URL.Path]
	body := asset.identity
	if encoding == "gzip" {
		body = asset.gzip
		rw.Header().Set("Content-Encoding", "gzip")
	}
	rw.Header().Set("Vary", "Accept-Encoding")
	rw.Header().Set("Content-Type", asset.mime)
	rw.Header().Set("Content-Length", strconv.Itoa(len(body)))
	_, _ = rw.Write(body)
}

// Honor quality preferences (implicit identity is q=1), choosing gzip on a tie.
// Invalid explicit entries are unacceptable, not implicit q=1. Duplicated
// codings use their lowest quality so an explicit refusal cannot be bypassed.
func webStaticEncoding(values []string) (string, bool) {
	gzipQ, identityQ, wildcardQ := -1, -1, -1
	for _, field := range values {
		for token := range strings.SplitSeq(field, ",") {
			coding, params, hasParams := strings.Cut(token, ";")
			coding = strings.Trim(coding, " 	")
			var target *int
			switch {
			case strings.EqualFold(coding, "gzip"):
				target = &gzipQ
			case strings.EqualFold(coding, "identity"):
				target = &identityQ
			case coding == "*":
				target = &wildcardQ
			default:
				continue
			}
			q := 1000
			if hasParams {
				key, value, ok := strings.Cut(params, "=")
				if !ok || !strings.EqualFold(strings.Trim(key, " 	"), "q") {
					q = 0
				} else {
					q = webStaticQuality(strings.Trim(value, " 	"))
				}
			}
			if *target < 0 || q < *target {
				*target = q
			}
		}
	}
	if gzipQ < 0 {
		gzipQ = wildcardQ
	}
	if identityQ < 0 {
		identityQ = 1000
		if wildcardQ == 0 {
			identityQ = 0
		}
	}
	if gzipQ > 0 && gzipQ >= identityQ {
		return "gzip", true
	}
	return "", identityQ > 0
}

// RFC qvalue grammar: 0[.DIGIT{0,3}] or 1[.0{0,3}]. No floats,
// exponents, signs, NaN or rounding of overprecise inputs.
func webStaticQuality(value string) int {
	if value == "0" {
		return 0
	}
	if value == "1" {
		return 1000
	}
	if len(value) < 2 || len(value) > 5 || value[1] != '.' || (value[0] != '0' && value[0] != '1') {
		return 0
	}
	q, scale := 0, 100
	for i := 2; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' || value[0] == '1' && value[i] != '0' {
			return 0
		}
		q += int(value[i]-'0') * scale
		scale /= 10
	}
	if value[0] == '1' {
		return 1000
	}
	return q
}

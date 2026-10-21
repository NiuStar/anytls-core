package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type webImportFile struct {
	path   string
	data   []byte
	exists bool
}
type webImportCandidate struct {
	conversion                              webConversionReport
	token, csrf, etag, selected, sourceURL  string
	expires                                 time.Time
	data                                    []byte
	oldConfig, oldSelected, oldSubscription webImportFile
}

func (w *webConsole) subscriptionPath() string {
	return filepath.Join(filepath.Dir(w.configPath), "subscription.json")
}
func webImportCapture(path string, limit int64, optional bool) (webImportFile, error) {
	f := webImportFile{path: path}
	b, e := readSnapshotSource(path, limit, false)
	if optional && errors.Is(e, os.ErrNotExist) {
		return f, nil
	}
	if e != nil {
		return f, e
	}
	f.exists = true
	f.data = b
	return f, nil
}
func webImportSame(f webImportFile) bool {
	g, e := webImportCapture(f.path, snapshotConfigLimit, !f.exists)
	return e == nil && g.exists == f.exists && bytes.Equal(g.data, f.data)
}
func webImportURL(raw string) (*url.URL, error) {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil || u.Fragment != "" || strings.Contains(raw, "#") || u.Host == "" || (u.Port() != "" && u.Port() != "443") {
		return nil, errors.New("IMPORT_URL_UNSAFE")
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil && !webImportPublic(ip) {
		return nil, errors.New("IMPORT_URL_UNSAFE")
	}
	if strings.HasSuffix(u.Host, ":") {
		return nil, errors.New("IMPORT_URL_UNSAFE")
	}
	if host == "" || strings.ContainsAny(host, "%\\ \t\r\n") {
		return nil, errors.New("IMPORT_URL_UNSAFE")
	}
	if net.ParseIP(host) == nil {
		h := strings.TrimSuffix(host, ".")
		if len(h) > 253 || !strings.Contains(h, ".") {
			return nil, errors.New("IMPORT_URL_UNSAFE")
		}
		for _, label := range strings.Split(h, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return nil, errors.New("IMPORT_URL_UNSAFE")
			}
			for _, c := range label {
				if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
					return nil, errors.New("IMPORT_URL_UNSAFE")
				}
			}
		}
	}
	return u, nil
}
func webImportPublic(ip net.IP) bool {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	a = a.Unmap()
	if a.Is6() && !netip.MustParsePrefix("2000::/3").Contains(a) {
		return false
	}
	if !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsUnspecified() {
		return false
	}
	for _, p := range []string{"0.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "168.63.129.16/32", "2001:db8::/32", "2001::/23", "2002::/16", "64:ff9b::/96", "64:ff9b:1::/48"} {
		if netip.MustParsePrefix(p).Contains(a) {
			return false
		}
	}
	return true
}

// DNS and URL checks always run, including with a fake transport in tests.
func webImportFetchWith(ctx context.Context, raw string, lookup func(context.Context, string) ([]net.IPAddr, error), roundTrip func(*http.Request, *http.Transport) (*http.Response, error), dial ...func(context.Context, string, string) (net.Conn, error)) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for hop := 0; hop <= 3; hop++ {
		u, e := webImportURL(raw)
		if e != nil {
			return nil, e
		}
		ips, e := lookup(ctx, u.Hostname())
		if e != nil || len(ips) == 0 {
			return nil, errors.New("IMPORT_FETCH_FAILED")
		}
		for _, ip := range ips {
			if ip.Zone != "" || !webImportPublic(ip.IP) {
				return nil, errors.New("IMPORT_URL_UNSAFE")
			}
		}
		pinned := net.JoinHostPort(ips[0].IP.String(), "443")
		tr := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 15 * time.Second, DisableKeepAlives: true, DialContext: func(c context.Context, network, address string) (net.Conn, error) {
			if len(dial) > 0 && dial[0] != nil {
				return dial[0](c, "tcp", pinned)
			}
			return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(c, "tcp", pinned)
		}}
		req, e := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
		if e != nil {
			return nil, errors.New("IMPORT_FETCH_FAILED")
		}
		req.Header.Set("Accept", "application/yaml, text/yaml, text/plain, */*")
		req.Header.Set("User-Agent", "clash.meta/AnyTLS-Core")
		var resp *http.Response
		if roundTrip == nil {
			resp, e = tr.RoundTrip(req)
		} else {
			resp, e = roundTrip(req, tr)
		}
		if e != nil {
			if resp != nil && resp.Body != nil {
				resp.Body.Close()
			}
			tr.CloseIdleConnections()
			return nil, errors.New("IMPORT_FETCH_FAILED")
		}
		if resp == nil || resp.Body == nil {
			tr.CloseIdleConnections()
			return nil, errors.New("IMPORT_FETCH_FAILED")
		}
		if resp.StatusCode == 301 || resp.StatusCode == 302 || resp.StatusCode == 303 || resp.StatusCode == 307 || resp.StatusCode == 308 {
			location, e := u.Parse(resp.Header.Get("Location"))
			if resp.Header.Get("Location") == "" {
				e = errors.New("missing redirect")
			}
			resp.Body.Close()
			tr.CloseIdleConnections()
			if e != nil || hop == 3 {
				return nil, errors.New("IMPORT_FETCH_FAILED")
			}
			raw = location.String()
			continue
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			tr.CloseIdleConnections()
			return nil, errors.New("IMPORT_FETCH_FAILED")
		}
		b, e := io.ReadAll(io.LimitReader(resp.Body, snapshotConfigLimit+1))
		ce := resp.Body.Close()
		tr.CloseIdleConnections()
		if e != nil || ce != nil || ctx.Err() != nil {
			return nil, errors.New("IMPORT_FETCH_FAILED")
		}
		if int64(len(b)) > snapshotConfigLimit {
			return nil, errors.New("IMPORT_TOO_LARGE")
		}
		return b, nil
	}
	return nil, errors.New("IMPORT_FETCH_FAILED")
}
func webImportSecureFetch(ctx context.Context, raw string) ([]byte, error) {
	return webImportFetchWith(ctx, raw, net.DefaultResolver.LookupIPAddr, nil)
}
func webImportSubscription(f webImportFile) (string, error) {
	if !f.exists {
		return "", nil
	}
	st, e := os.Lstat(f.path)
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 {
		return "", errors.New("subscription unavailable")
	}
	dec := json.NewDecoder(bytes.NewReader(f.data))
	tok, e := dec.Token()
	if e != nil || tok != json.Delim('{') {
		return "", errors.New("subscription unavailable")
	}
	if !dec.More() {
		return "", errors.New("subscription unavailable")
	}
	key, e := dec.Token()
	if e != nil || key != "url" {
		return "", errors.New("subscription unavailable")
	}
	var raw string
	if dec.Decode(&raw) != nil || dec.More() {
		return "", errors.New("subscription unavailable")
	}
	if tok, e = dec.Token(); e != nil || tok != json.Delim('}') {
		return "", errors.New("subscription unavailable")
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return "", errors.New("subscription unavailable")
	}
	if _, e = webImportURL(raw); e != nil {
		return "", errors.New("subscription unavailable")
	}
	return raw, nil
}
func (w *webConsole) getSubscription(rw http.ResponseWriter) {
	f, e := webImportCapture(w.subscriptionPath(), snapshotConfigLimit, true)
	if e != nil {
		webError(rw, 503, "SUBSCRIPTION_UNAVAILABLE")
		return
	}
	raw, e := webImportSubscription(f)
	if e != nil {
		webError(rw, 503, "SUBSCRIPTION_UNAVAILABLE")
		return
	}
	host := ""
	if raw != "" {
		u, _ := webImportURL(raw)
		host = u.Hostname()
	}
	webJSON(rw, 200, map[string]any{"configured": raw != "", "host": host})
}

// Validate the converted native schema. Clash templates and provider paths
// are interpreted by the converter rather than rejected by a generic AST scan.
func webImportFormat(b []byte, _ bool) error {
	if len(b) == 0 || int64(len(b)) > snapshotConfigLimit {
		return errors.New("IMPORT_TOO_LARGE")
	}
	var doc yaml.Node
	d := yaml.NewDecoder(bytes.NewReader(b))
	if d.Decode(&doc) != nil || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return errors.New("IMPORT_FORMAT_UNSUPPORTED")
	}
	var extra yaml.Node
	if d.Decode(&extra) != io.EOF {
		return errors.New("IMPORT_FORMAT_UNSUPPORTED")
	}
	for i := 0; i < len(doc.Content[0].Content); i += 2 {
		if doc.Content[0].Content[i].Value == "proxy-providers" || doc.Content[0].Content[i].Value == "rule-providers" {
			return errors.New("IMPORT_FORMAT_UNSUPPORTED")
		}
	}
	var typed struct {
		Providers map[string]any `yaml:"proxy-providers"`
		Groups    []proxyGroup   `yaml:"proxy-groups"`
	}
	if doc.Decode(&typed) != nil {
		return errors.New("IMPORT_FORMAT_UNSUPPORTED")
	}
	if len(typed.Providers) > 0 {
		return errors.New("IMPORT_FORMAT_UNSUPPORTED")
	}
	for _, g := range typed.Groups {
		if g.Type != "select" {
			return errors.New("IMPORT_FORMAT_UNSUPPORTED")
		}
	}
	nodes, e := loadNodesBytes(b)
	if e != nil {
		return errors.New("CONFIG_VALIDATION_FAILED")
	}
	for _, n := range nodes {
		if n.Type != "anytls" {
			return errors.New("IMPORT_FORMAT_UNSUPPORTED")
		}
	}
	return nil
}
func (w *webConsole) importPreview(rw http.ResponseWriter, r *http.Request) {
	w.importPending = nil // Every new attempt revokes the previous preview, even on failure.
	var fields struct {
		YAML     json.RawMessage `json:"yaml"`
		URL      json.RawMessage `json:"url"`
		UseSaved json.RawMessage `json:"use_saved"`
	}
	if webDecode(rw, r, &fields) != nil {
		webError(rw, 400, "INVALID_INPUT")
		return
	}
	var in struct {
		YAML     *string
		URL      *string
		UseSaved *bool
	}
	count := 0
	invalid := false
	for _, field := range []struct {
		raw    json.RawMessage
		target any
	}{{fields.YAML, &in.YAML}, {fields.URL, &in.URL}, {fields.UseSaved, &in.UseSaved}} {
		if len(field.raw) > 0 {
			count++
			if bytes.Equal(bytes.TrimSpace(field.raw), []byte("null")) || json.Unmarshal(field.raw, field.target) != nil {
				invalid = true
			}
		}
	}
	if invalid || count != 1 || (in.UseSaved != nil && !*in.UseSaved) {
		webError(rw, 400, "INVALID_INPUT")
		return
	}
	old, e := webImportCapture(w.configPath, snapshotConfigLimit, false)
	if e != nil {
		webError(rw, 503, "CONFIG_UNAVAILABLE")
		return
	}
	sel, e := webImportCapture(selectedPath(w.configPath), snapshotSelectedLimit, true)
	if e != nil {
		webError(rw, 503, "SELECTION_UNAVAILABLE")
		return
	}
	sub, e := webImportCapture(w.subscriptionPath(), snapshotConfigLimit, true)
	if e != nil {
		webError(rw, 503, "SUBSCRIPTION_UNAVAILABLE")
		return
	}
	saved, e := webImportSubscription(sub)
	if e != nil {
		webError(rw, 503, "SUBSCRIPTION_UNAVAILABLE")
		return
	}
	raw := ""
	if in.URL != nil {
		raw = *in.URL
	}
	if in.UseSaved != nil {
		raw = saved
		if raw == "" {
			webError(rw, 409, "SUBSCRIPTION_NOT_CONFIGURED")
			return
		}
	}
	var b []byte
	host := ""
	if in.YAML != nil {
		b = []byte(*in.YAML)
	} else {
		u, e := webImportURL(raw)
		if e != nil {
			webError(rw, 422, "IMPORT_URL_UNSAFE")
			return
		}
		host = u.Hostname()
		fetch := w.importFetch
		if fetch == nil {
			fetch = webImportSecureFetch
		}
		b, e = fetch(r.Context(), raw)
		if e != nil {
			code := "IMPORT_FETCH_FAILED"
			for _, known := range []string{"IMPORT_URL_UNSAFE", "IMPORT_TOO_LARGE"} {
				if e.Error() == known {
					code = known
				}
			}
			webError(rw, 422, code)
			return
		}
	}
	fetch := w.importFetch
	if fetch == nil {
		fetch = webImportSecureFetch
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if raw != "" {
		if code := webSubscriptionResponseCode(b); code != "" {
			webError(rw, 422, code)
			return
		}
	}
	converted, conversion, convertErr := webConvertConfiguration(ctx, b, raw != "", fetch)
	if convertErr != nil {
		webError(rw, 422, "CONFIG_CONVERSION_INVALID")
		return
	}
	if len(conversion.Issues) > 0 {
		webJSON(rw, 422, map[string]any{"error": "CONFIG_CONVERSION_UNSUPPORTED", "conversion": conversion})
		return
	}
	b = converted
	if e = webImportFormat(b, false); e != nil {
		webError(rw, 422, e.Error())
		return
	}
	if webValidateConfig(w.configPath, b) != nil {
		webError(rw, 422, "CONFIG_VALIDATION_FAILED")
		return
	}
	nodes, e := loadNodesBytes(b)
	if e != nil {
		webError(rw, 422, "CONFIG_VALIDATION_FAILED")
		return
	}
	selected, _ := selectedBytes(sel.data, nodes)
	if selected == "" {
		for _, n := range nodes {
			if selectable(n) {
				selected = n.Name
				break
			}
		}
	}
	if selected == "" {
		webError(rw, 422, "IMPORT_NO_SELECTABLE_NODES")
		return
	}
	chosen, e := choose(nodes, selected)
	if e != nil {
		webError(rw, 422, "CONFIG_VALIDATION_FAILED")
		return
	}
	if _, e = buildNode(chosen, "proxy", 11080, true); e != nil {
		webError(rw, 422, "CONFIG_VALIDATION_FAILED")
		return
	}
	if !webImportSame(old) || !webImportSame(sel) || !webImportSame(sub) {
		webError(rw, 412, "CONFIG_CONFLICT")
		return
	}
	token, e := webRandom(32)
	if e != nil {
		webError(rw, 500, "RANDOM_UNAVAILABLE")
		return
	}
	etag := `"` + shaHex(old.data) + `"`
	w.importPending = &webImportCandidate{conversion: conversion, token: token, csrf: r.Header.Get("X-CSRF-Token"), etag: etag, selected: selected, sourceURL: raw, expires: w.now().Add(10 * time.Minute), data: bytes.Clone(b), oldConfig: old, oldSelected: sel, oldSubscription: sub}
	var doc struct {
		Groups []proxyGroup `yaml:"proxy-groups"`
		Rules  []string     `yaml:"rules"`
	}
	_ = yaml.Unmarshal(b, &doc)
	warning := "Only AnyTLS nodes and supported select/routing rules are accepted. Saving replaces the full configuration; a running VPN may briefly disconnect. Local file references are retained: CA paths resolve from the application's working directory; rule-set paths resolve from the config directory."
	for _, n := range nodes {
		if n.SkipVerify {
			warning += " This configuration explicitly disables certificate verification for one or more nodes."
			break
		}
	}
	if raw == "" && saved != "" {
		warning += " Existing subscription is kept unchanged; this local import does not refresh it."
	}
	out := map[string]any{"conversion": conversion, "token": token, "etag": etag, "nodes": len(nodes), "groups": len(doc.Groups), "rules": len(doc.Rules), "selected": selected, "warning": warning}
	if host != "" {
		out["source_host"] = host
	}
	webJSON(rw, 200, out)
}
func webImportBackup(files []webImportFile, config string) error {
	root := filepath.Join(filepath.Dir(config), "import-backups")
	if e := os.Mkdir(root, 0700); e != nil && !errors.Is(e, os.ErrExist) {
		return e
	}
	st, e := os.Lstat(root)
	if e != nil || !st.IsDir() || st.Mode().Perm() != 0700 {
		return errors.New("backup unavailable")
	}
	dir, e := os.MkdirTemp(root, "import-")
	if e != nil {
		return e
	}
	for i, f := range files {
		if !f.exists {
			continue
		}
		name := []string{"config.yaml", "config.yaml.selected", "subscription.json"}[i]
		path := filepath.Join(dir, name)
		if e = webAtomicWrite(path, f.data); e != nil {
			return e
		}
		b, e := readSnapshotSource(path, snapshotConfigLimit, false)
		if e != nil || !bytes.Equal(b, f.data) {
			return errors.New("backup readback failed")
		}
	}
	return nil
}
func webImportRollback(files []webImportFile) bool {
	ok := true
	for _, f := range files {
		if f.exists {
			if webAtomicWrite(f.path, f.data) != nil {
				ok = false
			}
		} else {
			if e := os.Remove(f.path); e != nil && !errors.Is(e, os.ErrNotExist) {
				ok = false
			}
		}
	}
	for _, f := range files {
		if !webImportSame(f) {
			ok = false
		}
	}
	return ok
}
func (w *webConsole) importCommit(rw http.ResponseWriter, r *http.Request) {
	var in struct {
		Token            string `json:"token"`
		ConfirmReplace   bool   `json:"confirm_replace"`
		ConfirmInsecure  bool   `json:"confirm_insecure"`
		AcceptConversion bool   `json:"accept_conversion"`
	}
	if webDecode(rw, r, &in) != nil || !in.ConfirmReplace || !in.ConfirmInsecure {
		webError(rw, 400, "IMPORT_CONFIRMATION_REQUIRED")
		return
	}
	p := w.importPending
	if p == nil || !w.now().Before(p.expires) || !webEqual(in.Token, p.token) || !webEqual(r.Header.Get("X-CSRF-Token"), p.csrf) {
		webError(rw, 409, "IMPORT_PREVIEW_EXPIRED")
		return
	}
	if (len(p.conversion.Warnings) > 0 || len(p.conversion.Skipped) > 0) && !in.AcceptConversion {
		webError(rw, 400, "CONVERSION_CONFIRMATION_REQUIRED")
		return
	}
	if r.Header.Get("If-Match") == "" {
		webError(rw, 428, "IF_MATCH_REQUIRED")
		return
	}
	if r.Header.Get("If-Match") != p.etag {
		webError(rw, 412, "CONFIG_CONFLICT")
		return
	}
	files := []webImportFile{p.oldConfig, p.oldSelected, p.oldSubscription}
	for _, f := range files {
		if !webImportSame(f) {
			webError(rw, 412, "CONFIG_CONFLICT")
			return
		}
	}
	if webValidateConfig(w.configPath, p.data) != nil {
		webError(rw, 422, "CONFIG_VALIDATION_FAILED")
		return
	}
	nodes, e := loadNodesBytes(p.data)
	if e != nil {
		webError(rw, 422, "CONFIG_VALIDATION_FAILED")
		return
	}
	n, e := choose(nodes, p.selected)
	if e != nil {
		webError(rw, 422, "CONFIG_VALIDATION_FAILED")
		return
	}
	if _, e = buildNode(n, "proxy", 11080, true); e != nil {
		webError(rw, 422, "CONFIG_VALIDATION_FAILED")
		return
	}
	for _, f := range files {
		if !webImportSame(f) {
			webError(rw, 412, "CONFIG_CONFLICT")
			return
		}
	}
	configChanged := !bytes.Equal(p.data, p.oldConfig.data)
	oldName, _ := selectedBytes(p.oldSelected.data, nodes)
	selectionChanged := oldName != p.selected
	var metadata []byte
	if p.sourceURL != "" {
		metadata, _ = json.Marshal(struct {
			URL string `json:"url"`
		}{p.sourceURL})
	}
	metadataChanged := metadata != nil && !bytes.Equal(metadata, p.oldSubscription.data)
	if configChanged || selectionChanged || metadataChanged {
		if webImportBackup(files, w.configPath) != nil {
			webError(rw, 500, "IMPORT_BACKUP_FAILED")
			return
		}
		// Recheck after backup I/O; no claim of protection from hostile same-UID races.
		for _, f := range files {
			if !webImportSame(f) {
				webError(rw, 412, "CONFIG_CONFLICT")
				return
			}
		}
		failed := false
		if metadataChanged {
			failed = webAtomicWrite(w.subscriptionPath(), metadata) != nil
		}
		if !failed && configChanged {
			failed = webAtomicWrite(w.configPath, p.data) != nil
		}
		if !failed && selectionChanged {
			failed = saveSelection(w.configPath, p.selected, nodes) != nil
		}
		if !failed {
			got, err := readSnapshotSource(w.configPath, snapshotConfigLimit, false)
			name, se := selectedNode(w.configPath, nodes)
			failed = err != nil || !bytes.Equal(got, p.data) || se != nil || name != p.selected
			if metadataChanged {
				got, err = readSnapshotSource(w.subscriptionPath(), snapshotConfigLimit, false)
				failed = failed || err != nil || !bytes.Equal(got, metadata)
			}
		}
		if failed {
			w.importPending = nil
			code := "IMPORT_STATE_UNCERTAIN"
			if webImportRollback(files) {
				code = "IMPORT_WRITE_FAILED_ROLLED_BACK"
			}
			webError(rw, 500, code)
			return
		}
	}
	w.importPending = nil
	w.finishConfigSave(rw, r, configChanged || selectionChanged, `"`+shaHex(p.data)+`"`, in.ConfirmInsecure)
}

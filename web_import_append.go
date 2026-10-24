package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// The bootstrap fragment is local pin-only trust, never PKIX plus pin.
func webImportPinnedURL(raw string) (*url.URL, []byte, error) {
	fail := func() (*url.URL, []byte, error) { return nil, nil, errors.New("IMPORT_URL_UNSAFE") }
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.RawPath != "" || u.RawFragment != "" || strings.Count(raw, "#") != 1 {
		return fail()
	}
	ip, e := netip.ParseAddr(u.Hostname())
	if e != nil || ip.Zone() != "" || !webImportPublic(net.ParseIP(ip.String())) || netip.MustParsePrefix("3fff::/20").Contains(ip) {
		return fail()
	}
	port := u.Port()
	if port != "" {
		p, e := strconv.Atoi(port)
		if e != nil || p < 1 || p > 65535 || strconv.Itoa(p) != port {
			return fail()
		}
	}
	// Require the standard, unambiguous numeric authority spelling.
	authority := ip.String()
	if ip.Is6() {
		authority = "[" + authority + "]"
	}
	if port != "" {
		authority += ":" + port
	}
	if u.Host != authority {
		return fail()
	}
	const prefix = "anytls-cert-sha256="
	if !strings.HasPrefix(u.Fragment, prefix) {
		return fail()
	}
	pinText := strings.TrimPrefix(u.Fragment, prefix)
	pin, e := hex.DecodeString(pinText)
	if e != nil || len(pin) != 32 || hex.EncodeToString(pin) != pinText {
		return fail()
	}
	const route = "/subscribe/"
	if !strings.HasPrefix(u.Path, route) {
		return fail()
	}
	token := strings.TrimPrefix(u.Path, route)
	decoded, e := base64.RawURLEncoding.DecodeString(token)
	if e != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != token {
		return fail()
	}
	u.Fragment = ""
	return u, pin, nil
}

// dial is a package-private fixture seam; production always dials the exact
// validated numeric public address. No resolver, proxy or redirect is involved.
func webImportPinnedFetch(ctx context.Context, raw string, dial ...func(context.Context, string, string) (net.Conn, error)) ([]byte, error) {
	u, pin, e := webImportPinnedURL(raw)
	if e != nil {
		return nil, e
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	address := net.JoinHostPort(u.Hostname(), port)
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 15 * time.Second,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true, VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("IMPORT_FETCH_FAILED")
			}
			sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if subtle.ConstantTimeCompare(sum[:], pin) != 1 {
				return errors.New("IMPORT_FETCH_FAILED")
			}
			return nil
		}}, DialContext: func(c context.Context, network, _ string) (net.Conn, error) {
			if len(dial) > 0 && dial[0] != nil {
				return dial[0](c, "tcp", address)
			}
			return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(c, "tcp", address)
		}}
	defer tr.CloseIdleConnections()
	req, e := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if e != nil {
		return nil, errors.New("IMPORT_FETCH_FAILED")
	}
	req.Header.Set("Accept", "application/yaml, text/yaml, text/plain, */*")
	req.Header.Set("User-Agent", "clash.meta/AnyTLS-Core")
	resp, e := tr.RoundTrip(req)
	if e != nil {
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		return nil, errors.New("IMPORT_FETCH_FAILED")
	}
	if resp == nil || resp.Body == nil {
		return nil, errors.New("IMPORT_FETCH_FAILED")
	}
	closed := false
	defer func() {
		if !closed {
			resp.Body.Close()
		}
	}()
	if resp.StatusCode != 200 {
		return nil, errors.New("IMPORT_FETCH_FAILED")
	}
	b, e := io.ReadAll(io.LimitReader(resp.Body, snapshotConfigLimit+1))
	closed = true
	ce := resp.Body.Close()
	if e != nil || ce != nil || ctx.Err() != nil {
		return nil, errors.New("IMPORT_FETCH_FAILED")
	}
	if int64(len(b)) > snapshotConfigLimit {
		return nil, errors.New("IMPORT_TOO_LARGE")
	}
	return b, nil
}

// Restrict only the append target and imported node subtrees; unrelated aliases
// and unknown fields remain intact. No generic-map round trip of destination.
func webImportAppendSequence(b []byte) (*yaml.Node, *yaml.Node, error) {
	fail := func() (*yaml.Node, *yaml.Node, error) { return nil, nil, errors.New("IMPORT_APPEND_UNSAFE") }
	var doc yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(b))
	if dec.Decode(&doc) != nil || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return fail()
	}
	var extra yaml.Node
	if dec.Decode(&extra) != io.EOF {
		return fail()
	}
	root := doc.Content[0]
	seen := map[string]bool{}
	var seq *yaml.Node
	for i := 0; i < len(root.Content); i += 2 {
		k, v := root.Content[i], root.Content[i+1]
		if k.Kind != yaml.ScalarNode || k.Tag != "!!str" || k.Value == "<<" || seen[k.Value] {
			return fail()
		}
		seen[k.Value] = true
		if k.Value == "nodes" || k.Value == "proxies" {
			if seq != nil || v.Kind != yaml.SequenceNode || v.Anchor != "" {
				return fail()
			}
			seq = v
		}
	}
	if seq == nil {
		return fail()
	}
	return &doc, seq, nil
}
func webImportAppendPlain(n *yaml.Node) bool {
	if n.Kind == yaml.AliasNode || n.Anchor != "" {
		return false
	}
	if n.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for i := 0; i < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode || k.Tag != "!!str" || k.Value == "<<" || seen[k.Value] {
				return false
			}
			seen[k.Value] = true
		}
	}
	for _, child := range n.Content {
		if !webImportAppendPlain(child) {
			return false
		}
	}
	return true
}

// Validate every incoming node before conversion can filter an inactive node.
// Remove routing/provider content before conversion: add-only never fetches it.
func webImportAppendInput(input []byte, remote bool) ([]byte, error) {
	doc, seq, e := webImportAppendSequence(input)
	if e != nil {
		return nil, e
	}
	nodes, e := loadNodesBytes(input)
	if e != nil || len(nodes) == 0 {
		return nil, errors.New("IMPORT_NO_SELECTABLE_NODES")
	}
	for i, n := range nodes {
		if remote && n.CA != "" {
			return nil, errors.New("IMPORT_REMOTE_FILE_REFERENCE")
		}
		if !webImportAppendPlain(seq.Content[i]) {
			return nil, errors.New("IMPORT_APPEND_UNSAFE")
		}
		if _, e := buildNode(n, "proxy", 11080, true); e != nil {
			return nil, errors.New("CONFIG_VALIDATION_FAILED")
		}
	}
	root := doc.Content[0]
	var key *yaml.Node
	for i := 0; i < len(root.Content); i += 2 {
		if root.Content[i].Value == "nodes" || root.Content[i].Value == "proxies" {
			key = root.Content[i]
			break
		}
	}
	root.Content = []*yaml.Node{key, seq}
	b, e := yaml.Marshal(doc)
	if e != nil {
		return nil, errors.New("IMPORT_APPEND_UNSAFE")
	}
	return b, nil
}
func webImportAppend(old, incoming []byte) ([]byte, int, error) {
	doc, dest, e := webImportAppendSequence(old)
	if e != nil {
		return nil, 0, e
	}
	_, source, e := webImportAppendSequence(incoming)
	if e != nil {
		return nil, 0, e
	}
	existing, e := loadNodesBytes(old)
	if e != nil {
		return nil, 0, errors.New("IMPORT_APPEND_UNSAFE")
	}
	incomingNodes, e := loadNodesBytes(incoming)
	if e != nil || len(incomingNodes) == 0 {
		return nil, 0, errors.New("IMPORT_NO_SELECTABLE_NODES")
	}
	byName := map[string]node{}
	for _, n := range existing {
		byName[n.Name] = n
	}
	// Decode full node maps for equality as well as typed fields: unknown options
	// must not silently mask a same-name difference.
	oldMaps := map[string]any{}
	for _, entry := range dest.Content {
		if !webImportAppendPlain(entry) {
			return nil, 0, errors.New("IMPORT_APPEND_UNSAFE")
		}
		var n node
		var full any
		if entry.Decode(&n) != nil || entry.Decode(&full) != nil {
			return nil, 0, errors.New("IMPORT_APPEND_UNSAFE")
		}
		oldMaps[n.Name] = full
	}
	added := 0
	for i, n := range incomingNodes {
		if _, e := buildNode(n, "proxy", 11080, true); e != nil {
			return nil, 0, errors.New("CONFIG_VALIDATION_FAILED")
		}
		entry := source.Content[i]
		if !webImportAppendPlain(entry) {
			return nil, 0, errors.New("IMPORT_APPEND_UNSAFE")
		}
		if previous, ok := byName[n.Name]; ok {
			var full any
			if entry.Decode(&full) != nil || !reflect.DeepEqual(previous, n) || !reflect.DeepEqual(oldMaps[n.Name], full) {
				return nil, 0, errors.New("IMPORT_NODE_CONFLICT")
			}
			continue
		}
		dest.Content = append(dest.Content, entry)
		added++
	}
	if added == 0 {
		return bytes.Clone(old), 0, nil
	}
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if enc.Encode(doc) != nil || enc.Close() != nil {
		return nil, 0, errors.New("IMPORT_APPEND_UNSAFE")
	}
	if int64(out.Len()) > snapshotConfigLimit {
		return nil, 0, errors.New("IMPORT_TOO_LARGE")
	}
	return out.Bytes(), added, nil
}

func (w *webConsole) importAppendCommit(rw http.ResponseWriter, r *http.Request, p *webImportCandidate, consent bool, write ...func(string, []byte) error) {
	if r.Context().Err() != nil {
		webError(rw, 422, "CONFIG_CONVERSION_CANCELED")
		return
	}
	if webValidateConfig(w.configPath, p.data) != nil {
		webError(rw, 422, "CONFIG_VALIDATION_FAILED")
		return
	}
	files := []webImportFile{p.oldConfig, p.oldSelected, p.oldSubscription}
	for _, f := range files {
		if !webImportSame(f) {
			webError(rw, 412, "CONFIG_CONFLICT")
			return
		}
	}
	changed := !bytes.Equal(p.data, p.oldConfig.data)
	if changed {
		if webImportBackup(files, w.configPath) != nil {
			webError(rw, 500, "IMPORT_BACKUP_FAILED")
			return
		}
		for _, f := range files {
			if !webImportSame(f) {
				webError(rw, 412, "CONFIG_CONFLICT")
				return
			}
		}
		if r.Context().Err() != nil {
			webError(rw, 422, "CONFIG_CONVERSION_CANCELED")
			return
		}
		publish := webAtomicWrite
		if len(write) > 0 && write[0] != nil {
			publish = write[0]
		}
		failed := publish(w.configPath, p.data) != nil
		got, e := readSnapshotSource(w.configPath, snapshotConfigLimit, false)
		failed = failed || e != nil || !bytes.Equal(got, p.data) || !webImportSame(p.oldSelected) || !webImportSame(p.oldSubscription)
		if failed {
			w.importPending = nil
			code := "IMPORT_STATE_UNCERTAIN"
			if webImportRollback([]webImportFile{p.oldConfig}) && webImportSame(p.oldSelected) && webImportSame(p.oldSubscription) {
				code = "IMPORT_WRITE_FAILED_ROLLED_BACK"
			}
			webError(rw, 500, code)
			return
		}
	}
	w.importPending = nil
	w.finishConfigSave(rw, r, changed, `"`+shaHex(p.data)+`"`, consent)
}

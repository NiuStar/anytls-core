package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

//go:embed web_assets/*
var webAssets embed.FS

// API contract and operating notes are embedded alongside the application.
// Authentication and brief state locks never enclose system actions or update.
type webConsole struct {
	configPath, passwordPath string
	port                     int
	authMu                   sync.Mutex
	sessions                 map[string]webSession
	failures                 int
	loginWindow              time.Time
	blockedUntil             time.Time
	actionMu                 sync.Mutex
	metaMu                   sync.Mutex
	pending                  bool
	pendingKnown             bool
	baseline                 string
	now                      func() time.Time
	state                    func() (bool, bool, error)
	serviceAction            func(context.Context, string, bool) error
	updateAction             func(context.Context, bool) (json.RawMessage, error)
}

func newWebConsole(config, password string, port int) *webConsole {
	w := &webConsole{configPath: config, passwordPath: password, port: port, sessions: make(map[string]webSession), now: time.Now, state: serviceState, serviceAction: webServiceAction, updateAction: webUpdateAction}
	w.baseline = w.fingerprint()
	return w
}
func webuiCommand(args []string) error {
	fs := flag.NewFlagSet("webui", flag.ContinueOnError)
	port := fs.Int("port", 18089, "loopback HTTP port (1024-65535)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *port < 1024 || *port > 65535 {
		return errors.New("usage: anytls webui [--port 18089]; port must be 1024-65535")
	}
	if os.Geteuid() == 0 {
		return errors.New("WebUI must run as your ordinary user, never root")
	}
	_, config, _, err := servicePaths()
	if err != nil {
		return err
	}
	passwordPath := filepath.Join(filepath.Dir(config), "webui.password")
	if _, err := webPassword(passwordPath, false); err != nil {
		return err
	}
	listener, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(*port)))
	if err != nil {
		return err
	}
	defer listener.Close()
	fmt.Printf("WebUI: http://127.0.0.1:%d\nLocal HTTP only (no TLS). Do not expose or forward this port.\nAccount: admin; recover password with 'anytls password'.\n", *port)
	server := &http.Server{Handler: newWebConsole(config, passwordPath, *port), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, IdleTimeout: 45 * time.Second, MaxHeaderBytes: 16 << 10, ErrorLog: log.New(io.Discard, "", 0)}
	return server.Serve(listener)
}
func (w *webConsole) allowedHost(host string) bool {
	p := strconv.Itoa(w.port)
	return host == "127.0.0.1:"+p || host == "localhost:"+p || host == "[::1]:"+p
}
func (w *webConsole) originOK(r *http.Request) bool {
	// Origin is mandatory, including login and non-browser clients. No CORS.
	values := r.Header.Values("Origin")
	if len(values) != 1 {
		return false
	}
	u, err := url.Parse(values[0])
	return err == nil && u.Scheme == "http" && u.Host == r.Host && u.User == nil && u.Path == "" && u.RawQuery == "" && u.Fragment == "" && values[0] == "http://"+r.Host
}
func webJSON(rw http.ResponseWriter, status int, data any) {
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	rw.WriteHeader(status)
	_ = json.NewEncoder(rw).Encode(data)
}
func webError(rw http.ResponseWriter, status int, code string) {
	webJSON(rw, status, map[string]string{"error": code})
}
func webDecode(rw http.ResponseWriter, r *http.Request, dst any) error {
	if strings.Split(r.Header.Get("Content-Type"), ";")[0] != "application/json" {
		return errors.New("JSON required")
	}
	// JSON escaping can expand the 4MiB config by up to six times.
	limit := int64(16 << 10)
	if r.URL.Path == "/api/v1/config" && r.Method == "PUT" {
		limit = 24 << 20
	}
	dec := json.NewDecoder(http.MaxBytesReader(rw, r.Body, limit))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("single JSON value required")
	}
	return nil
}
func (w *webConsole) authenticated(r *http.Request) (webSession, bool) {
	cookie, err := r.Cookie(webCookieName)
	if err != nil || len(cookie.Value) != 43 {
		return webSession{}, false
	}
	// Read the recoverable secret each request so CLI reset invalidates live sessions.
	password, err := webReadPassword(w.passwordPath)
	if err != nil {
		return webSession{}, false
	}
	digest := sha256.Sum256([]byte(password))
	w.authMu.Lock()
	defer w.authMu.Unlock()
	session, ok := w.sessions[cookie.Value]
	if !ok || !w.now().Before(session.expires) || session.passwordHash != digest {
		delete(w.sessions, cookie.Value)
		return webSession{}, false
	}
	return session, true
}
func (w *webConsole) login(rw http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := webDecode(rw, r, &in); err != nil {
		webError(rw, 400, "INVALID_INPUT")
		return
	}
	w.authMu.Lock()
	defer w.authMu.Unlock()
	now := w.now()
	if now.Before(w.blockedUntil) {
		rw.Header().Set("Retry-After", "60")
		webError(rw, 429, "LOGIN_THROTTLED")
		return
	}
	if w.loginWindow.IsZero() || now.Sub(w.loginWindow) >= time.Minute {
		w.loginWindow = now
		w.failures = 0
	}
	password, err := webReadPassword(w.passwordPath)
	// Hash both credentials, then constant-time compare fixed-size digests.
	userOK := webEqual(in.Username, "admin")
	passOK := webEqual(in.Password, password)
	if err != nil || !userOK || !passOK {
		w.failures++
		if w.failures >= 5 {
			w.blockedUntil = now.Add(time.Minute)
		}
		webError(rw, 401, "INVALID_CREDENTIALS")
		return
	}
	for token, s := range w.sessions {
		if !now.Before(s.expires) {
			delete(w.sessions, token)
		}
	}
	if len(w.sessions) >= 32 {
		webError(rw, 429, "SESSION_LIMIT")
		return
	}
	token, err := webRandom(32)
	if err != nil {
		webError(rw, 500, "RANDOM_UNAVAILABLE")
		return
	}
	csrf, err := webRandom(32)
	if err != nil {
		webError(rw, 500, "RANDOM_UNAVAILABLE")
		return
	}
	w.sessions[token] = webSession{csrf: csrf, expires: now.Add(webSessionTTL), passwordHash: sha256.Sum256([]byte(password))}
	if old, e := r.Cookie(webCookieName); e == nil {
		delete(w.sessions, old.Value)
	}
	w.failures = 0
	http.SetCookie(rw, &http.Cookie{Name: webCookieName, Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: int(webSessionTTL.Seconds()), Expires: now.Add(webSessionTTL)})
	webJSON(rw, 200, map[string]any{"csrf": csrf, "expiresIn": int(webSessionTTL.Seconds()), "username": "admin"})
}
func (w *webConsole) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	rw.Header().Set("Cache-Control", "no-store")
	rw.Header().Set("X-Content-Type-Options", "nosniff")
	rw.Header().Set("X-Frame-Options", "DENY")
	rw.Header().Set("Referrer-Policy", "no-referrer")
	rw.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	if !w.allowedHost(r.Host) {
		webError(rw, 403, "INVALID_HOST")
		return
	}
	if r.Method != "GET" && r.Method != "POST" && r.Method != "PUT" {
		webError(rw, 405, "METHOD_NOT_ALLOWED")
		return
	}
	if r.Method != "GET" && !w.originOK(r) {
		webError(rw, 403, "INVALID_ORIGIN")
		return
	}
	if r.URL.Path == "/api/v1/login" {
		if r.Method != "POST" {
			webError(rw, 405, "METHOD_NOT_ALLOWED")
			return
		}
		w.login(rw, r)
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/api/") {
		if r.Method != "GET" {
			webError(rw, 405, "METHOD_NOT_ALLOWED")
			return
		}
		names := map[string]string{"/": "index.html", "/app.js": "app.js", "/style.css": "style.css"}
		name, ok := names[r.URL.Path]
		if !ok {
			http.NotFound(rw, r)
			return
		}
		b, err := webAssets.ReadFile("web_assets/" + name)
		if err != nil {
			webError(rw, 500, "ASSET_UNAVAILABLE")
			return
		}
		mime := map[string]string{"index.html": "text/html; charset=utf-8", "app.js": "text/javascript; charset=utf-8", "style.css": "text/css; charset=utf-8"}
		if name == "index.html" {
			b = bytes.Replace(b, []byte(`<div class="note">升级后`), []byte(`<div class="note">安装开始后，关闭网页、断开连接或十分钟请求超时均不会停止安装；其他修改会保持忙碌，直到安装退出并完成版本核验。请勿强制退出控制台或更新进程；进程崩溃不保证安装生命周期安全。升级后`), 1)
		}
		rw.Header().Set("Content-Type", mime[name])
		rw.Write(b)
		return
	}
	session, ok := w.authenticated(r)
	if !ok {
		webError(rw, 401, "AUTH_REQUIRED")
		return
	}
	if r.Method != "GET" && !webEqual(r.Header.Get("X-CSRF-Token"), session.csrf) {
		webError(rw, 403, "CSRF_REQUIRED")
		return
	}
	if r.Method == "GET" {
		w.get(rw, r, session)
		return
	}
	if r.URL.Path == "/api/v1/logout" && r.Method == "POST" {
		cookie, _ := r.Cookie(webCookieName)
		w.authMu.Lock()
		delete(w.sessions, cookie.Value)
		w.authMu.Unlock()
		http.SetCookie(rw, &http.Cookie{Name: webCookieName, Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1, Expires: time.Unix(1, 0)})
		webJSON(rw, 200, map[string]bool{"ok": true})
		return
	}
	// A long native authorization or build does not monopolize auth/status GETs.
	if !w.actionMu.TryLock() {
		webError(rw, 409, "ACTION_BUSY")
		return
	}
	defer w.actionMu.Unlock()
	w.mutate(rw, r)
}
func (w *webConsole) fingerprint() string {
	b, err := readSnapshotSource(w.configPath, snapshotConfigLimit, false)
	if err != nil {
		return ""
	}
	selection, err := readSnapshotSource(selectedPath(w.configPath), snapshotSelectedLimit, false)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return ""
	}
	return shaHex([]byte(shaHex(b) + ":" + shaHex(selection)))
}
func (w *webConsole) pendingState() (bool, bool) {
	fingerprint := w.fingerprint()
	w.metaMu.Lock()
	defer w.metaMu.Unlock()
	if fingerprint != "" && fingerprint != w.baseline {
		w.pending = true
	}
	return w.pending, w.pendingKnown
}
func (w *webConsole) get(rw http.ResponseWriter, r *http.Request, session webSession) {
	switch r.URL.Path {
	case "/api/v1/session":
		webJSON(rw, 200, map[string]any{"csrf": session.csrf, "username": "admin"})
	case "/api/v1/status":
		loaded, running, err := w.state()
		pending, known := w.pendingState()
		availability := "AVAILABLE"
		if err != nil {
			availability = "UNAVAILABLE"
		}
		webJSON(rw, 200, map[string]any{"loaded": loaded, "running": running, "availability": availability, "pendingReload": pending, "pendingKnown": known, "version": currentVersion(), "readiness": "NOT_OBSERVED", "transport": "loopback-http"})
	case "/api/v1/nodes", "/api/v1/groups":
		b, err := readSnapshotSource(w.configPath, snapshotConfigLimit, false)
		if err != nil {
			webError(rw, 500, "CONFIG_UNAVAILABLE")
			return
		}
		nodes, err := loadNodesBytes(b)
		if err != nil {
			webError(rw, 422, "CONFIG_INVALID")
			return
		}
		if r.URL.Path == "/api/v1/nodes" {
			selected, _ := selectedNode(w.configPath, nodes)
			list := make([]map[string]any, 0, len(nodes))
			for _, n := range nodes {
				list = append(list, map[string]any{"name": n.Name, "type": n.Type, "server": n.Server, "port": n.Port, "hasPassword": n.Password != "", "selectable": selectable(n), "skipVerify": n.SkipVerify, "sni": n.SNI, "selected": selected == n.Name})
			}
			webJSON(rw, 200, map[string]any{"nodes": list, "etag": `"` + shaHex(b) + `"`})
			return
		}
		var doc struct {
			Groups []proxyGroup `yaml:"proxy-groups"`
		}
		if yaml.Unmarshal(b, &doc) != nil {
			webError(rw, 422, "CONFIG_INVALID")
			return
		}
		list := make([]map[string]any, 0, len(doc.Groups))
		for _, g := range doc.Groups {
			resolved, err := resolveGroup(g.Name, nodes, doc.Groups)
			list = append(list, map[string]any{"name": g.Name, "type": g.Type, "choices": g.Proxies, "selected": g.Selected, "resolved": resolved, "valid": err == nil})
		}
		webJSON(rw, 200, map[string]any{"groups": list})
	case "/api/v1/rules":
		b, err := readSnapshotSource(w.configPath, snapshotConfigLimit, false)
		if err != nil {
			webError(rw, 500, "CONFIG_UNAVAILABLE")
			return
		}
		var doc struct {
			Rules []string `yaml:"rules"`
		}
		if yaml.Unmarshal(b, &doc) != nil {
			webError(rw, 422, "CONFIG_INVALID")
			return
		}
		if doc.Rules == nil {
			doc.Rules = []string{}
		}
		webJSON(rw, 200, map[string]any{"rules": doc.Rules})
	case "/api/v1/config":
		b, err := readSnapshotSource(w.configPath, snapshotConfigLimit, false)
		if err != nil {
			webError(rw, 500, "CONFIG_UNAVAILABLE")
			return
		}
		etag := `"` + shaHex(b) + `"`
		rw.Header().Set("ETag", etag)
		webJSON(rw, 200, map[string]string{"yaml": string(b), "etag": etag})
	case "/api/v1/version":
		webJSON(rw, 200, map[string]string{"version": currentVersion()})
	case "/api/v1/update-check":
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		result, err := w.updateAction(ctx, true)
		if err != nil {
			webError(rw, 503, "UPDATE_UNAVAILABLE")
			return
		}
		webJSON(rw, 200, result)
	default:
		webError(rw, 404, "NOT_FOUND")
	}
}
func (w *webConsole) saved() { w.metaMu.Lock(); w.pending = true; w.metaMu.Unlock() }
func (w *webConsole) mutate(rw http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/api/v1/config" && r.Method == "PUT":
		var in struct {
			YAML string `json:"yaml"`
		}
		if webDecode(rw, r, &in) != nil {
			webError(rw, 400, "INVALID_INPUT")
			return
		}
		old, err := readSnapshotSource(w.configPath, snapshotConfigLimit, false)
		if err != nil {
			webError(rw, 500, "CONFIG_UNAVAILABLE")
			return
		}
		etag := `"` + shaHex(old) + `"`
		if r.Header.Get("If-Match") == "" {
			webError(rw, 428, "IF_MATCH_REQUIRED")
			return
		}
		if r.Header.Get("If-Match") != etag {
			webError(rw, 412, "CONFIG_CONFLICT")
			return
		}
		candidate := []byte(in.YAML)
		if err := webValidateConfig(w.configPath, candidate); err != nil {
			webError(rw, 422, "CONFIG_VALIDATION_FAILED")
			return
		}
		// Recheck after rule/CA reads. The in-process mutex covers all WebUI writes;
		// external CLI/editors are detected optimistically, not an OS-wide lock.
		latest, err := readSnapshotSource(w.configPath, snapshotConfigLimit, false)
		if err != nil || !bytes.Equal(latest, old) {
			webError(rw, 412, "CONFIG_CONFLICT")
			return
		}
		changed := !bytes.Equal(candidate, old)
		if changed {
			if webAtomicWrite(w.configPath, candidate) != nil {
				webError(rw, 500, "CONFIG_WRITE_FAILED")
				return
			}
			w.saved()
		}
		readback, err := readSnapshotSource(w.configPath, snapshotConfigLimit, false)
		if err != nil || !bytes.Equal(candidate, readback) {
			webError(rw, 500, "CONFIG_READBACK_FAILED")
			return
		}
		etag = `"` + shaHex(readback) + `"`
		rw.Header().Set("ETag", etag)
		pending, _ := w.pendingState()
		webJSON(rw, 200, map[string]any{"ok": true, "changed": changed, "etag": etag, "pendingReload": pending})
	case r.URL.Path == "/api/v1/nodes" && r.Method == "PUT":
		var in webNodeEdit
		if webDecode(rw, r, &in) != nil || in.Name == "" {
			webError(rw, 400, "INVALID_INPUT")
			return
		}
		old, err := readSnapshotSource(w.configPath, snapshotConfigLimit, false)
		if err != nil {
			webError(rw, 500, "CONFIG_UNAVAILABLE")
			return
		}
		if r.Header.Get("If-Match") == "" {
			webError(rw, 428, "IF_MATCH_REQUIRED")
			return
		}
		if r.Header.Get("If-Match") != `"`+shaHex(old)+`"` {
			webError(rw, 412, "CONFIG_CONFLICT")
			return
		}
		candidate, err := webEditNode(old, in)
		if err != nil || webValidateConfig(w.configPath, candidate) != nil {
			webError(rw, 422, "CONFIG_VALIDATION_FAILED")
			return
		}
		latest, err := readSnapshotSource(w.configPath, snapshotConfigLimit, false)
		if err != nil || !bytes.Equal(old, latest) {
			webError(rw, 412, "CONFIG_CONFLICT")
			return
		}
		changed := !bytes.Equal(old, candidate)
		if changed {
			if webAtomicWrite(w.configPath, candidate) != nil {
				webError(rw, 500, "CONFIG_WRITE_FAILED")
				return
			}
			w.saved()
		}
		readback, err := readSnapshotSource(w.configPath, snapshotConfigLimit, false)
		if err != nil || !bytes.Equal(readback, candidate) {
			webError(rw, 500, "CONFIG_READBACK_FAILED")
			return
		}
		pending, _ := w.pendingState()
		webJSON(rw, 200, map[string]any{"ok": true, "changed": changed, "etag": `"` + shaHex(readback) + `"`, "pendingReload": pending})
	case r.URL.Path == "/api/v1/groups/selection" && r.Method == "POST":
		var in struct {
			Group  string `json:"group"`
			Choice string `json:"choice"`
		}
		if webDecode(rw, r, &in) != nil || in.Group == "" || in.Choice == "" {
			webError(rw, 400, "INVALID_INPUT")
			return
		}
		before := w.fingerprint()
		if err := saveGroupChoice(w.configPath, in.Group, in.Choice); err != nil {
			webError(rw, 422, "GROUP_SELECTION_REJECTED")
			return
		}
		after := w.fingerprint()
		changed := before != after
		if changed {
			w.saved()
		}
		b, err := readSnapshotSource(w.configPath, snapshotConfigLimit, false)
		var doc struct {
			Groups []proxyGroup `yaml:"proxy-groups"`
		}
		verified := false
		if err == nil && yaml.Unmarshal(b, &doc) == nil {
			for _, g := range doc.Groups {
				if g.Name == in.Group && g.Selected == in.Choice {
					verified = true
				}
			}
		}
		if !verified {
			webError(rw, 500, "GROUP_READBACK_FAILED")
			return
		}
		pending, _ := w.pendingState()
		webJSON(rw, 200, map[string]any{"ok": true, "changed": changed, "pendingReload": pending})
	case r.URL.Path == "/api/v1/nodes/selection" && r.Method == "POST":
		var in struct {
			Name string `json:"name"`
		}
		if webDecode(rw, r, &in) != nil || in.Name == "" {
			webError(rw, 400, "INVALID_INPUT")
			return
		}
		nodes, err := loadNodes(w.configPath)
		if err != nil {
			webError(rw, 422, "CONFIG_INVALID")
			return
		}
		before, _ := selectedNode(w.configPath, nodes)
		if before != in.Name {
			if saveSelection(w.configPath, in.Name, nodes) != nil {
				webError(rw, 422, "NODE_SELECTION_REJECTED")
				return
			}
			w.saved()
		}
		after, err := selectedNode(w.configPath, nodes)
		if err != nil || after != in.Name {
			webError(rw, 500, "SELECTION_READBACK_FAILED")
			return
		}
		pending, _ := w.pendingState()
		webJSON(rw, 200, map[string]any{"ok": true, "changed": before != after, "pendingReload": pending})
	case strings.HasPrefix(r.URL.Path, "/api/v1/service/") && r.Method == "POST":
		action := strings.TrimPrefix(r.URL.Path, "/api/v1/service/")
		if action != "start" && action != "stop" && action != "reload" {
			webError(rw, 404, "NOT_FOUND")
			return
		}
		var in struct {
			ConfirmInsecure bool `json:"confirm_insecure"`
		}
		if webDecode(rw, r, &in) != nil {
			webError(rw, 400, "INVALID_INPUT")
			return
		}
		before := w.fingerprint()
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
		defer cancel()
		if err := w.serviceAction(ctx, action, in.ConfirmInsecure); err != nil {
			webError(rw, 503, "SERVICE_ACTION_FAILED_OR_AUTHORIZATION_UNAVAILABLE")
			return
		}
		// Read actual launchd state. Do not infer ready/TUN health from the child exit.
		loaded, running, err := w.state()
		if err != nil || (action == "stop" && (loaded || running)) || (action != "stop" && !running) {
			webError(rw, 503, "SERVICE_STATE_NOT_CONFIRMED")
			return
		}
		if action != "stop" {
			w.metaMu.Lock()
			w.baseline = before
			w.pending = false
			w.pendingKnown = before != ""
			w.metaMu.Unlock()
		}
		pending, _ := w.pendingState()
		webJSON(rw, 200, map[string]any{"ok": true, "loaded": loaded, "running": running, "pendingReload": pending, "readiness": "NOT_OBSERVED"})
	case r.URL.Path == "/api/v1/update" && r.Method == "POST":
		var in struct {
			Confirm bool `json:"confirm"`
		}
		if webDecode(rw, r, &in) != nil || !in.Confirm {
			webError(rw, 400, "UPDATE_CONFIRMATION_REQUIRED")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
		defer cancel()
		result, err := w.updateAction(ctx, false)
		if err != nil {
			webError(rw, 503, "UPDATE_UNAVAILABLE")
			return
		}
		webJSON(rw, 200, result)
	default:
		webError(rw, 405, "METHOD_OR_PATH_NOT_ALLOWED")
	}
}

// Validate the same captured candidate through the real typed loader and routing
// compiler. A neutral mixed inbound avoids changing TLS semantics or requiring a
// selected node for an incomplete config. Every routed AnyTLS node still passes
// buildNode (including existing CA/TLS policy). Validation recognizes an explicit
// skip-cert-verify setting but grants no runtime consent; Start still requires its
// separate boolean authorization. TUN checks remain Start's responsibility.
// Unknown YAML fields and original scalar spelling are retained
// because we persist the original candidate bytes, not a typed reserialization.
func webValidateConfig(path string, b []byte) error {
	if len(b) == 0 || int64(len(b)) > snapshotConfigLimit {
		return errors.New("invalid config size")
	}
	var doc yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(&doc); err != nil {
		return err
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return errors.New("single YAML mapping required")
	}
	var trailing yaml.Node
	if err := dec.Decode(&trailing); err != io.EOF {
		return errors.New("single YAML document required")
	}
	nodes, err := loadNodesBytes(b)
	if err != nil {
		return err
	}
	cfg := map[string]any{"route": map[string]any{}, "inbounds": []any{map[string]any{"type": "mixed"}}, "outbounds": []any{}}
	return applyRoutingBytes(path, b, nodes, node{}, cfg, true)
}

// Only trusted self path and fixed command/boolean enter the native prompt.
// argv carries these strings into AppleScript, never interpolated source text.
func webServiceAction(ctx context.Context, action string, insecure bool) error {
	if runtime.GOOS != "darwin" {
		return errors.New("native authorization requires macOS GUI")
	}
	if action != "start" && action != "stop" && action != "reload" {
		return errors.New("invalid service action")
	}
	if action == "stop" && insecure {
		return errors.New("insecure consent is not a stop argument")
	}
	binary, _, _, err := servicePaths()
	if err != nil || !filepath.IsAbs(binary) {
		return errors.New("self executable unavailable")
	}
	script := `on run argv
set commandText to quoted form of (item 1 of argv) & " " & quoted form of (item 2 of argv)
if (item 3 of argv) is "true" then set commandText to commandText & " -allow-insecure"
do shell script commandText with administrator privileges
end run`
	cmd := exec.CommandContext(ctx, "/usr/bin/osascript", "-e", script, "--", binary, "service-"+action, strconv.FormatBool(insecure))
	// Child output can contain user config. Never return it to HTTP or logs.
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return errors.New("native authorization or service action failed")
	}
	return nil
}

// The actual sibling update CLI exposes JSON on `update --check`; the install
// operation prints human output, which is discarded. Read the new executable's
// version back before claiming installation. Missing contracts stay unavailable.
func webUpdateAction(ctx context.Context, check bool) (json.RawMessage, error) {
	binary, _, _, err := servicePaths()
	if err != nil {
		return nil, err
	}
	return webUpdateWithCommands(ctx, check, binary, exec.CommandContext, exec.Command)
}

// Command constructors are per-call dependencies, never mutable globals.
func webUpdateWithCommands(ctx context.Context, check bool, binary string, commandContext func(context.Context, string, ...string) *exec.Cmd, command func(string, ...string) *exec.Cmd) (json.RawMessage, error) {
	cmd := commandContext(ctx, binary, "update", "--check")
	var out webBoundedOutput
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil || out.overflow {
		return nil, errors.New("update check unavailable")
	}
	var result struct {
		Current    string `json:"current_version"`
		Latest     string `json:"latest_version"`
		Available  *bool  `json:"update_available"`
		SourceOnly bool   `json:"source_only"`
	}
	dec := json.NewDecoder(bytes.NewReader(out.b))
	if err := dec.Decode(&result); err != nil {
		return nil, errors.New("update response unavailable")
	}
	var extra any
	if dec.Decode(&extra) != io.EOF || result.Available == nil || result.Current == "" || result.Latest == "" {
		return nil, errors.New("invalid update response")
	}
	for _, s := range []string{result.Current, result.Latest} {
		if len(s) > 128 || strings.ContainsAny(s, "\r\n\x00") {
			return nil, errors.New("invalid update version")
		}
	}
	response := map[string]any{"current": result.Current, "latest": result.Latest, "available": *result.Available, "sourceOnly": result.SourceOnly, "updated": false, "restartRequired": false, "status": "UP_TO_DATE"}
	if *result.Available {
		response["status"] = "UPDATE_AVAILABLE"
	}
	if !check && *result.Available {
		// Pin the checked stable version, not a request-controlled URL/command.
		// Cancellation still aborts the read-only check, or admission before install.
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// Once admitted, synchronously own and join the CLI, independent of HTTP
		// cancellation. ServeHTTP retains actionMu through Run AND version readback.
		// The CLI's 35-minute context kills and waits its Python publisher; surviving
		// build grandchildren cannot publish. CLI/WebUI crash is NOT supervised here.
		cmd = command(binary, "update", "--version", result.Latest)
		cmd.Stdin = nil
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		if err := cmd.Run(); err != nil {
			return nil, errors.New("update install unavailable")
		}
		verifyCtx, verifyCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer verifyCancel()
		verify := commandContext(verifyCtx, binary, "version")
		var version webBoundedOutput
		verify.Stdout = &version
		verify.Stderr = io.Discard
		if err := verify.Run(); err != nil || version.overflow || strings.TrimSpace(string(version.b)) != result.Latest {
			return nil, errors.New("updated executable version not confirmed")
		}
		response["status"] = "UPDATED"
		response["updated"] = true
		response["restartRequired"] = true
	}
	return json.Marshal(response)
}

type webBoundedOutput struct {
	b        []byte
	overflow bool
}

func (b *webBoundedOutput) Write(p []byte) (int, error) {
	n := len(p)
	if len(b.b)+n > 64<<10 {
		b.overflow = true
		return n, nil
	}
	b.b = append(b.b, p...)
	return n, nil
}

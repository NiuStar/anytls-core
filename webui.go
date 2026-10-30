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
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	cr "github.com/NiuStar/anytls-core/internal/connectionrecords"
	st "github.com/NiuStar/anytls-core/internal/startuptimeline"
	"gopkg.in/yaml.v3"
)

//go:embed web_assets/*
var webAssets embed.FS

// API contract and operating notes are embedded alongside the application.
// Authentication and brief state locks never enclose system actions or update.
type webConsole struct {
	configPath, passwordPath string
	port                     int
	listenHost               string // empty preserves the original loopback constructor
	authMu                   sync.Mutex
	sessions                 map[string]webSession
	failures                 int
	loginWindow              time.Time
	blockedUntil             time.Time
	actionMu                 sync.RWMutex
	metaMu                   sync.Mutex
	pending                  bool
	pendingKnown             bool
	baseline                 string
	now                      func() time.Time
	state                    func() (bool, bool, error)
	serviceAction            func(context.Context, string, bool) error
	updateAction             func(context.Context, bool) (json.RawMessage, error)
	importPending            *webImportCandidate // guarded by actionMu
	importFetch              func(context.Context, string) ([]byte, error)
	nodeProbe                func(context.Context, node, string) (float64, error)
	recordsRequest           func(context.Context, cr.PageRequest) (cr.PageResponse, error)
	startupMu                sync.Mutex
	startupLatest            *webStartupOperation
	startupReadRequest       webStartupReadFunc
	startupControlRequest    webStartupControlFunc
	startupLegacyRequest     webControlRequestFunc
	startupRandom            io.Reader
	probeSlotsOnce           sync.Once
	probeSlots               chan struct{} // published by probeSlotsOnce; TCP/HTTPS share eight slots
	// Restart authority is installed only by the verified managed CLI path.
	restartCheck   func() error
	restartRequest func()
	restartPending bool // guarded by actionMu
}

func newWebConsole(config, password string, port int) *webConsole {
	w := &webConsole{configPath: config, passwordPath: password, port: port, sessions: make(map[string]webSession), now: time.Now, state: serviceState, updateAction: webUpdateAction, importFetch: webImportSecureFetch}
	w.baseline = w.fingerprint()
	return w
}
func webuiCommand(args []string) error {
	if len(args) > 0 && (args[0] == "install-agent" || args[0] == "agent-status") {
		return webAgentCommand(args[0], args[1:])
	}
	fs := flag.NewFlagSet("webui", flag.ContinueOnError)
	managed := fs.String("managed-agent", "", "internal LaunchAgent identity (not authorization)")
	port := fs.Int("port", 18089, "HTTP port (1024-65535)")
	listen := fs.String("listen", "127.0.0.1", "literal local IPv4 address or 0.0.0.0 for all IPv4 interfaces (HTTP has no TLS)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *port < 1024 || *port > 65535 {
		return errors.New("usage: anytls webui [--listen 127.0.0.1] [--port 18089]; port must be 1024-65535")
	}
	if err := webValidateListen(*listen); err != nil {
		return err
	}
	if *listen != "0.0.0.0" {
		addresses, err := net.InterfaceAddrs()
		if err != nil {
			return err
		}
		if err := webListenAssigned(*listen, addresses); err != nil {
			return err
		}
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
	listener, err := net.Listen("tcp4", net.JoinHostPort(*listen, strconv.Itoa(*port)))
	if err != nil {
		return err
	}
	defer listener.Close()
	w := newWebConsole(config, passwordPath, *port)
	w.listenHost = *listen
	if *managed != "" {
		spec, err := webAgentCurrent(*listen, *port)
		if err != nil {
			return err
		}
		if *managed != spec.label() {
			return errors.New("managed agent label mismatch")
		}
		// At process startup launchd may still be publishing its PID field.
		deadline := time.Now().Add(3 * time.Second)
		for {
			err = spec.verify(os.Getpid())
			if err == nil || time.Now().After(deadline) {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if err != nil {
			return fmt.Errorf("managed agent identity rejected: %w", err)
		}
		w.restartCheck = func() error { return spec.verify(os.Getpid()) }
	}
	fmt.Printf("WebUI listening on %s:%d\nTransport: %s (HTTP, no TLS). Network access transmits credentials and session data without encryption; use a reachable host/IP, not 0.0.0.0, in your browser.\nAccount: admin; recover password with 'anytls password'.\n", *listen, *port, w.transport())
	server := &http.Server{Handler: w, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, IdleTimeout: 45 * time.Second, MaxHeaderBytes: 16 << 10, ErrorLog: log.New(io.Discard, "", 0)}
	return webAgentServe(server, listener, w, *managed != "")
}
func (w *webConsole) allowedHost(host string) bool {
	p := strconv.Itoa(w.port)
	if w.listenHost == "0.0.0.0" {
		h, port, err := net.SplitHostPort(host)
		return err == nil && port == p && host == net.JoinHostPort(h, port) && cr.ValidHost(h)
	}
	if w.networkListen() {
		return host == net.JoinHostPort(w.listenHost, p)
	}
	return host == "127.0.0.1:"+p || host == "localhost:"+p || host == "[::1]:"+p || w.listenHost != "" && host == net.JoinHostPort(w.listenHost, p)
}
func webValidateListen(host string) error {
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.Is4() || ip.String() != host {
		return errors.New("listen must be a canonical literal IPv4 address (0.0.0.0 listens on all IPv4 interfaces)")
	}
	return nil
}
func webListenAssigned(host string, addresses []net.Addr) error {
	if err := webValidateListen(host); err != nil {
		return err
	}
	if host == "0.0.0.0" {
		return nil
	}
	for _, a := range addresses {
		ip, _, err := net.ParseCIDR(a.String())
		if err == nil && ip.String() == host {
			return nil
		}
	}
	return errors.New("listen address is not assigned to a local interface")
}
func (w *webConsole) networkListen() bool {
	ip, err := netip.ParseAddr(w.listenHost)
	return err == nil && ip.Is4() && !ip.IsLoopback()
}
func (w *webConsole) transport() string {
	if w.networkListen() {
		return "network-http"
	}
	return "loopback-http"
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
	if _, ok := rw.(webStartupResponseWriter); ok {
		webJSON(rw, status, map[string]any{"error": code, "startup_operation": nil})
		return
	}
	webJSON(rw, status, map[string]string{"error": code})
}
func webDecode(rw http.ResponseWriter, r *http.Request, dst any) error {
	if strings.Split(r.Header.Get("Content-Type"), ";")[0] != "application/json" {
		return errors.New("JSON required")
	}
	// JSON escaping can expand each config byte sixfold; allow envelope overhead.
	limit := int64(16 << 10)
	if (r.URL.Path == "/api/v1/config" && r.Method == "PUT") || (r.URL.Path == "/api/v1/import/preview" && r.Method == "POST") {
		limit = 6*snapshotConfigLimit + (16 << 10)
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
		webServeStatic(rw, r)
		return
	}
	session, ok := w.authenticated(r)
	if !ok {
		webError(rw, 401, "AUTH_REQUIRED")
		return
	}
	if r.URL.Path == "/api/v1/startup-trace" {
		if r.Method != "GET" {
			webError(rw, 405, "METHOD_NOT_ALLOWED")
			return
		}
		w.getStartupTrace(rw, r)
		return
	}
	if r.URL.Path == "/api/v1/connections" {
		if r.Method != "GET" {
			webError(rw, 405, "METHOD_NOT_ALLOWED")
			return
		}
		w.getConnections(rw, r)
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
	// Read-only probes own their short action-lock phases, never the network wait.
	if r.URL.Path == "/api/v1/nodes/probe" && r.Method == http.MethodPost {
		w.probeNodeHandler(rw, r)
		return
	}
	// A long native authorization or build does not monopolize auth/status GETs.
	if webStartupMutationPath(r) {
		rw = webStartupResponseWriter{rw}
	}
	if !w.actionMu.TryLock() {
		webError(rw, 409, "ACTION_BUSY")
		return
	}
	defer w.actionMu.Unlock()
	if w.restartPending {
		webError(rw, 409, "RESTART_PENDING")
		return
	}
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
	case "/api/v1/profiles":
		// getProfiles owns actionMu; acquiring it here would reject every list.
		w.getProfiles(rw, r)
	case "/api/v1/config/export":
		w.exportCurrent(rw, r)
	case "/api/v1/subscription":
		w.getSubscription(rw)
	case "/api/v1/session":
		webJSON(rw, 200, map[string]any{"csrf": session.csrf, "username": "admin"})
	case "/api/v1/status":
		loaded, running, err := w.state()
		pending, known := w.pendingState()
		availability := "AVAILABLE"
		if err != nil {
			availability = "UNAVAILABLE"
		}
		webJSON(rw, 200, map[string]any{"loaded": loaded, "running": running, "availability": availability, "pendingReload": pending, "pendingKnown": known, "version": currentVersion(), "readiness": "NOT_OBSERVED", "transport": w.transport(), "listenHost": w.listenHost})
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
		webJSON(rw, 200, map[string]any{"groups": list, "etag": `"` + shaHex(b) + `"`})
	case "/api/v1/rules":
		w.getRules(rw, r)
	case "/api/v1/config":
		b, err := readSnapshotSource(w.configPath, snapshotConfigLimit, false)
		if err != nil {
			webError(rw, 500, "CONFIG_UNAVAILABLE")
			return
		}
		etag := `"` + shaHex(b) + `"`
		rw.Header().Set("ETag", etag)
		webJSON(rw, 200, map[string]string{"yaml": string(b), "etag": etag})
	case "/api/v1/helper/status":
		webControlStatus(rw, r)
	case "/api/v1/version":
		webJSON(rw, 200, map[string]string{"version": currentVersion()})
	case "/api/v1/update-check":
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		result, err := w.updateAction(ctx, true)
		if err != nil {
			webError(rw, 503, webUpdateErrorName(err))
			return
		}
		var body map[string]any
		if json.Unmarshal(result, &body) != nil || body == nil {
			webError(rw, 503, "UPDATE_RESPONSE_INVALID")
			return
		}
		body["restartManaged"] = w.restartCheck != nil && w.restartRequest != nil && w.restartCheck() == nil
		body["restartScheduled"] = false
		webJSON(rw, 200, body)
	default:
		webError(rw, 404, "NOT_FOUND")
	}
}
func (w *webConsole) saved() { w.metaMu.Lock(); w.pending = true; w.metaMu.Unlock() }

// Called only after save readback, while ServeHTTP still owns actionMu. A
// successful disk write is never reported as a failed save if apply fails.
func (w *webConsole) finishConfigSave(rw http.ResponseWriter, r *http.Request, changed bool, etag string, consent bool, extra ...map[string]any) {
	status, applied := "NO_CHANGE", false
	applyError := ""
	var diagnostics *startDiagnostics
	var startup *webStartupOperation
	var startupErr error
	if changed {
		w.saved()
		loaded, running, err := w.state()
		switch {
		case err != nil || (running && !loaded):
			status = "STATE_UNAVAILABLE"
		case !running:
			// Loaded-but-stopped is stopped too. Saving never starts a VPN.
			status = "SAVED_STOPPED"
		default:
			status = "APPLY_FAILED"
			before := w.fingerprint()
			if before != "" {
				// Own and synchronously join the helper despite HTTP disconnects.
				// No detached worker or supervisor; the action lock remains held.
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
				startup = w.beginStartup("reload", webStartupSource(r))
				err = w.startupAction(ctx, "reload", consent, startup)
				startupErr = err
				cancel()
				if err != nil {
					applyError = webControlFailureCode(err)
					diagnostics = webControlDiagnostics(err)
				}
				if err == nil {
					diagnostics = startup.diagnostics
					verify := startup.recorder.Begin("FINALIZE", "WEB_VERIFY_STATE", st.Fields{})
					loaded, running, err = w.state()
					code := "OK"
					if err != nil || !loaded || !running {
						code = "FAILED"
					}
					startup.recorder.End(verify, code, st.Fields{})
					after := w.fingerprint()
					if err == nil && loaded && running && after == before {
						w.metaMu.Lock()
						w.baseline, w.pending, w.pendingKnown = before, false, true
						w.metaMu.Unlock()
						status, applied = "APPLIED", true
					}
				}
			}
		}
	}
	pending, known := w.pendingState()
	result := map[string]any{"ok": true, "saved": true, "changed": changed, "applied": applied, "apply_status": status, "pendingReload": pending, "pendingKnown": known}
	result["startup_operation"] = nil
	if startup != nil {
		var finishErr error
		if !applied {
			finishErr = startupErr
			if finishErr == nil {
				finishErr = errors.New("apply not confirmed")
			}
		}
		w.finishStartup(startup, finishErr)
		result["startup_operation"] = w.startupReference(startup)
	}
	if applyError != "" {
		result["apply_error"] = applyError
	}
	if diagnostics != nil {
		result["diagnostics"] = diagnostics
	}
	if etag != "" {
		rw.Header().Set("ETag", etag)
		result["etag"] = etag
	}
	for _, fields := range extra {
		for key, value := range fields {
			result[key] = value
		}
	}
	webJSON(rw, 200, result)
}

func (w *webConsole) mutate(rw http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/api/v1/rules/delete" && r.Method == "POST":
		w.deleteRule(rw, r)
	case r.URL.Path == "/api/v1/rules" && r.Method == "POST":
		w.addRule(rw, r)
	case r.URL.Path == "/api/v1/profiles" && r.Method == "POST":
		w.saveProfile(rw, r)
	case r.URL.Path == "/api/v1/profiles/copy" && r.Method == "POST":
		w.copyProfile(rw, r)
	case r.URL.Path == "/api/v1/profiles/switch" && r.Method == "POST":
		w.switchProfile(rw, r)
	case r.URL.Path == "/api/v1/import/export" && r.Method == "POST":
		w.exportConverted(rw, r)
	case r.URL.Path == "/api/v1/import/preview" && r.Method == "POST":
		w.importPreview(rw, r)
	case r.URL.Path == "/api/v1/import/commit" && r.Method == "POST":
		w.importCommit(rw, r)
	case r.URL.Path == "/api/v1/config" && r.Method == "PUT":
		var in struct {
			YAML            string `json:"yaml"`
			ConfirmInsecure bool   `json:"confirm_insecure"`
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
		w.finishConfigSave(rw, r, changed, etag, in.ConfirmInsecure)
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
		w.finishConfigSave(rw, r, changed, `"`+shaHex(readback)+`"`, in.ConfirmInsecure)
	case r.URL.Path == "/api/v1/groups/selection" && r.Method == "POST":
		var in struct {
			Group           string `json:"group"`
			Choice          string `json:"choice"`
			ConfirmInsecure bool   `json:"confirm_insecure"`
		}
		if webDecode(rw, r, &in) != nil || in.Group == "" || in.Choice == "" {
			webError(rw, 400, "INVALID_INPUT")
			return
		}
		// Older clients omit If-Match; a supplied snapshot must still match
		// before saving or consulting the running service.
		if match := r.Header.Get("If-Match"); match != "" {
			b, err := readSnapshotSource(w.configPath, snapshotConfigLimit, false)
			if err != nil {
				webError(rw, 500, "CONFIG_UNAVAILABLE")
				return
			}
			if match != `"`+shaHex(b)+`"` {
				webError(rw, 412, "CONFIG_CONFLICT")
				return
			}
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
		w.finishConfigSave(rw, r, changed, "", in.ConfirmInsecure)
	case r.URL.Path == "/api/v1/nodes/selection" && r.Method == "POST":
		var in struct {
			Name            string `json:"name"`
			ConfirmInsecure bool   `json:"confirm_insecure"`
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
		w.finishConfigSave(rw, r, before != after, "", in.ConfirmInsecure)
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
		startup := w.beginStartup(action, "MANUAL_"+strings.ToUpper(action))
		if err := w.startupAction(ctx, action, in.ConfirmInsecure, startup); err != nil {
			w.finishStartup(startup, err)
			body := webControlErrorBody(err)
			body["startup_operation"] = w.startupReference(startup)
			webJSON(rw, 503, body)
			return
		}
		// Read actual launchd state. Do not infer ready/TUN health from the child exit.
		verify := startup.recorder.Begin("FINALIZE", "WEB_VERIFY_STATE", st.Fields{})
		loaded, running, err := w.state()
		code := "OK"
		if err != nil || (action == "stop" && (loaded || running)) || (action != "stop" && !running) {
			code = "FAILED"
		}
		startup.recorder.End(verify, code, st.Fields{})
		if err != nil || (action == "stop" && (loaded || running)) || (action != "stop" && !running) {
			w.finishStartup(startup, errors.New("state not confirmed"))
			webJSON(rw, 503, map[string]any{"error": "SERVICE_STATE_NOT_CONFIRMED", "startup_operation": w.startupReference(startup)})
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
		w.finishStartup(startup, nil)
		body := map[string]any{"ok": true, "loaded": loaded, "running": running, "pendingReload": pending, "readiness": "NOT_OBSERVED", "startup_operation": w.startupReference(startup)}
		if startup.diagnostics != nil {
			body["diagnostics"] = startup.diagnostics
		}
		webJSON(rw, 200, body)
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
			webError(rw, 503, webUpdateErrorName(err))
			return
		}
		var body map[string]any
		if json.Unmarshal(result, &body) != nil || body == nil {
			webError(rw, 503, "UPDATE_RESPONSE_INVALID")
			return
		}
		body["restartScheduled"] = false
		installed, _ := body["installed"].(string)
		latest, _ := body["latest"].(string)
		eligible := body["updated"] == true && body["status"] == "UPDATED" && body["restartRequired"] == true && installed == latest && validateUpdateVersion(installed) == nil
		if eligible && w.restartCheck != nil && w.restartRequest != nil {
			if w.restartCheck() != nil {
				body["restartError"] = "RESTART_MANAGED_UNAVAILABLE"
			} else {
				w.restartPending = true
				body["restartScheduled"] = true
			}
		}
		rw.Header().Set("Content-Type", "application/json; charset=utf-8")
		if err := json.NewEncoder(rw).Encode(body); err != nil {
			w.restartPending = false
			return
		}
		if w.restartPending {
			if err := http.NewResponseController(rw).Flush(); err != nil {
				w.restartPending = false
				return
			}
			// This signals the server owner, never waits for Shutdown in-handler.
			// Flush proves only a local write, not delivery to the browser.
			w.restartRequest()
		}
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

// WebUI never elevates through its SSH/GUI session. The root-owned helper
// authenticates the caller and executes only registered fixed operations.
func webServiceAction(ctx context.Context, action string, insecure bool) error {
	_, config, _, err := servicePaths()
	if err != nil {
		return &webControlError{Code: "HELPER_UNAVAILABLE"}
	}
	return webControlAction(ctx, config, action, insecure, controlHelperRequest)
}

// Per-call command seam keeps tests on owned, non-root helper subprocesses.
func webServiceWithCommand(ctx context.Context, action string, insecure bool, binary string, command func(context.Context, string, ...string) *exec.Cmd) error {
	if action != "start" && action != "stop" && action != "reload" {
		return errors.New("invalid service action")
	}
	if action == "stop" && insecure {
		return errors.New("insecure consent is not a stop argument")
	}
	script := `on run argv
set commandText to quoted form of (item 1 of argv) & " " & quoted form of (item 2 of argv)
if (item 3 of argv) is "true" then set commandText to commandText & " -allow-insecure"
do shell script commandText with administrator privileges
end run`
	cmd := command(ctx, "/usr/bin/osascript", "-e", script, "--", binary, "service-"+action, strconv.FormatBool(insecure))
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
	if err := cmd.Run(); err != nil {
		return nil, updateChildFailure(err)
	}
	if out.overflow {
		return nil, updateFailure(40, errors.New("update check output overflow"))
	}
	var result struct {
		Current    string `json:"current_version"`
		Latest     string `json:"latest_version"`
		Available  *bool  `json:"update_available"`
		SourceOnly *bool  `json:"source_only"`
	}
	dec := json.NewDecoder(bytes.NewReader(out.b))
	if err := dec.Decode(&result); err != nil {
		return nil, updateFailure(40, err)
	}
	var extra any
	if dec.Decode(&extra) != io.EOF || result.Available == nil || result.SourceOnly == nil || result.Current == "" || validateUpdateVersion(result.Latest) != nil {
		return nil, updateFailure(40, errors.New("invalid update response"))
	}
	if len(result.Current) > 128 || strings.ContainsAny(result.Current, "\r\n\x00") {
		return nil, updateFailure(40, errors.New("invalid installed version"))
	}
	// The sibling check runs from disk; it cannot identify this running WebUI.
	restart := result.Current != currentVersion()
	response := map[string]any{"current": currentVersion(), "installed": result.Current, "latest": result.Latest, "available": *result.Available, "sourceOnly": *result.SourceOnly, "updated": false, "restartRequired": restart, "status": "UP_TO_DATE"}
	if restart {
		response["status"] = "RESTART_REQUIRED"
	}
	if *result.Available {
		response["status"] = "UPDATE_AVAILABLE"
	}
	if !check && *result.Available {
		if *result.SourceOnly {
			return nil, updateFailure(42, errors.New("prebuilt materials unavailable"))
		}
		// Pin the checked stable version, never a request-controlled value.
		if err := ctx.Err(); err != nil {
			return nil, updateFailure(47, err)
		}
		// Once admitted, synchronously own and join the CLI independent of HTTP
		// cancellation. actionMu is held through Run and independent readback.
		// The CLI separately bounds and waits its sole Python publisher at 35m.
		cmd = command(binary, "update", "--version", result.Latest)
		cmd.Stdin = nil
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		if err := cmd.Run(); err != nil {
			return nil, updateChildFailure(err)
		}
		verifyCtx, verifyCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer verifyCancel()
		verify := commandContext(verifyCtx, binary, "version")
		var version webBoundedOutput
		verify.Stdout = &version
		verify.Stderr = io.Discard
		if err := verify.Run(); err != nil || version.overflow || strings.TrimSpace(string(version.b)) != result.Latest {
			return nil, updateFailure(46, errors.New("installed executable version not confirmed"))
		}
		response["status"] = "UPDATED"
		response["installed"] = strings.TrimSpace(string(version.b))
		response["available"] = false
		response["updated"] = true
		response["restartRequired"] = true
	}
	response["restartScheduled"] = false
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

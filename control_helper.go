package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	controlHelperRoot             = "/Library/PrivilegedHelperTools/com.nousresearch.anytls-control"
	controlHelperExecutable       = controlHelperRoot + "/anytls-control"
	controlHelperRegistrationPath = controlHelperRoot + "/registration.json"
	controlHelperSocketDir        = controlHelperRoot + "/run"
	controlHelperSocketPath       = controlHelperSocketDir + "/control.sock"
	controlHelperLabel            = "com.nousresearch.anytls-control"
	controlHelperJSONLimit        = 4096 // IPC only; not a configuration/project limit.
	controlHelperIOTimeout        = 5 * time.Second
)

type controlHelperRegistration struct {
	UID    uint32 `json:"uid"`
	Config string `json:"config"`
	Home   string `json:"home"`
}
type controlHelperResponse struct {
	OK             bool   `json:"ok"`
	Code           string `json:"code"`
	Message        string `json:"message"`
	Loaded         bool   `json:"loaded"`
	Running        bool   `json:"running"`
	HelperVersion  string `json:"helper_version"`
	HelperSHA256   string `json:"helper_sha256"`
	ConfigIdentity string `json:"config_identity"`
}
type controlHelperWireRequest struct {
	Action        string `json:"action"`
	AllowInsecure bool   `json:"allow_insecure"`
}

// A single JSON object followed by EOF. Clients half-close their write side;
// this rejects trailing values without waiting for an unbounded stream.
func controlHelperDecode(r io.Reader, fields map[string]any) error {
	b, err := io.ReadAll(io.LimitReader(r, controlHelperJSONLimit+1))
	if err != nil || len(b) > controlHelperJSONLimit {
		return errors.New("invalid IPC frame")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	tok, err := d.Token()
	if err != nil || tok != json.Delim('{') {
		return errors.New("expected object")
	}
	seen := make(map[string]bool)
	for d.More() {
		tok, err = d.Token()
		if err != nil {
			return errors.New("invalid object")
		}
		key, ok := tok.(string)
		dst, known := fields[key]
		if !ok || !known || seen[key] {
			return errors.New("invalid field")
		}
		seen[key] = true
		var raw json.RawMessage
		if d.Decode(&raw) != nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, dst) != nil {
			return errors.New("invalid field type")
		}
	}
	if _, err = d.Token(); err != nil {
		return errors.New("invalid object")
	}
	if _, err = d.Token(); err != io.EOF {
		return errors.New("trailing input")
	}
	for key := range fields {
		if !seen[key] {
			return errors.New("missing field")
		}
	}
	return nil
}
func controlHelperReadRequest(r io.Reader) (controlHelperWireRequest, error) {
	var q controlHelperWireRequest
	err := controlHelperDecode(r, map[string]any{"action": &q.Action, "allow_insecure": &q.AllowInsecure})
	if err == nil && !controlHelperValidRequest(q) {
		err = errors.New("invalid action or consent")
	}
	return q, err
}
func controlHelperValidRequest(q controlHelperWireRequest) bool {
	switch q.Action {
	case "start", "reload":
		return true
	case "status", "stop":
		return !q.AllowInsecure
	}
	return false
}
func controlHelperFailure(code string) controlHelperResponse {
	messages := map[string]string{
		"PREFLIGHT_FAILED": "Configuration preflight failed; service unchanged.",
		"STOP_FAILED":      "Stop or restoration failed; inspect local service diagnostics.",
		"START_FAILED":     "Start failed; inspect local service diagnostics; recovery is not guaranteed.",
		"STATE_FAILED":     "Service state unavailable.", "BUSY": "Another service mutation is in progress; request was not queued.",
		"FORBIDDEN": "Peer is not authorized.", "INVALID_REQUEST": "Invalid control request.",
	}
	message, ok := messages[code]
	if !ok {
		code = "INVALID_REQUEST"
		message = messages[code]
	}
	return controlHelperResponse{Code: code, Message: message}
}

type controlHelperServer struct {
	registration controlHelperRegistration
	peer         func(net.Conn) (uint32, error)
	state        func() (bool, bool, error)
	preflight    func(context.Context, bool) error
	start        func(context.Context, bool) error
	stop         func(context.Context) error
	version, sha string
	mutation     sync.Mutex
}

func (s *controlHelperServer) handle(c net.Conn) {
	defer c.Close()
	identity, identityErr := controlHelperConfigIdentity(s.registration.Config)
	reply := func(r controlHelperResponse) {
		r.HelperVersion = s.version
		r.HelperSHA256 = s.sha
		r.ConfigIdentity = identity
		_ = c.SetWriteDeadline(time.Now().Add(controlHelperIOTimeout))
		_ = json.NewEncoder(c).Encode(r)
	}
	uid, err := s.peer(c)
	if err != nil || uid == 0 || s.registration.UID == 0 || uid != s.registration.UID {
		reply(controlHelperFailure("FORBIDDEN"))
		return
	}
	if identityErr != nil {
		reply(controlHelperFailure("STATE_FAILED"))
		return
	}
	_ = c.SetReadDeadline(time.Now().Add(controlHelperIOTimeout))
	q, err := controlHelperReadRequest(c)
	if err != nil {
		reply(controlHelperFailure("INVALID_REQUEST"))
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	reply(s.execute(q))
}
func (s *controlHelperServer) execute(q controlHelperWireRequest) controlHelperResponse {
	if !controlHelperValidRequest(q) {
		return controlHelperFailure("INVALID_REQUEST")
	}
	if q.Action != "status" {
		if !s.mutation.TryLock() {
			return controlHelperFailure("BUSY")
		}
		defer s.mutation.Unlock()
		// Owned by the server, never by the client connection. Cancellation cannot
		// release the lock while a lifecycle operation is still cleaning up.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		if q.Action == "start" || q.Action == "reload" {
			if err := s.preflight(ctx, q.AllowInsecure); err != nil {
				return controlHelperFailure("PREFLIGHT_FAILED")
			}
		}
		if q.Action == "reload" {
			loaded, _, err := s.state()
			if err != nil {
				return controlHelperFailure("STATE_FAILED")
			}
			if !loaded {
				return controlHelperFailure("PREFLIGHT_FAILED")
			}
		}
		if q.Action == "stop" || q.Action == "reload" {
			if err := s.stop(ctx); err != nil {
				return controlHelperFailure("STOP_FAILED")
			}
		}
		if q.Action == "start" || q.Action == "reload" {
			if err := s.start(ctx, q.AllowInsecure); err != nil {
				return controlHelperFailure("START_FAILED")
			}
		}
	}
	loaded, running, err := s.state()
	if err != nil {
		return controlHelperFailure("STATE_FAILED")
	}
	return controlHelperResponse{OK: true, Loaded: loaded, Running: running, Message: "Control request completed."}
}

// Reject symlinks at every component, including the leaf. Fixed protected
// ancestors prevent an unprivileged process racing replacement of these paths.
func controlHelperTrustedPath(path string, directory bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("unsafe helper path")
	}
	for p := path; ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 || !controlHelperRootOwned(info) {
			return errors.New("untrusted helper path")
		}
		if p != path || directory {
			if !info.IsDir() {
				return errors.New("invalid helper directory")
			}
		} else if !info.Mode().IsRegular() {
			return errors.New("invalid helper file")
		}
		if p == "/" {
			break
		}
	}
	return nil
}
func controlHelperReadRegistration() (controlHelperRegistration, error) {
	var r controlHelperRegistration
	if err := controlHelperTrustedPath(controlHelperRegistrationPath, false); err != nil {
		return r, err
	}
	info, err := os.Lstat(controlHelperRegistrationPath)
	if err != nil || info.Mode().Perm() != 0600 {
		return r, errors.New("invalid registration permissions")
	}
	f, err := os.Open(controlHelperRegistrationPath)
	if err != nil {
		return r, errors.New("registration unavailable")
	}
	defer f.Close()
	err = controlHelperDecode(f, map[string]any{"uid": &r.UID, "config": &r.Config, "home": &r.Home})
	if err != nil || r.UID == 0 || !controlHelperAbsolute(r.Config) || !controlHelperAbsolute(r.Home) {
		return r, errors.New("invalid helper registration")
	}
	return r, nil
}
func controlHelperAbsolute(p string) bool {
	return filepath.IsAbs(p) && filepath.Clean(p) == p && !strings.ContainsAny(p, "\x00\n\r") && p != "/"
}

// Path identity only: never hash config contents and never accept a path over
// IPC. Resolve symlinks identically in the registered helper and local WebUI.
func controlHelperConfigIdentity(path string) (string, error) {
	if !filepath.IsAbs(path) || strings.ContainsAny(path, "\x00\n\r") {
		return "", errors.New("configuration identity unavailable")
	}
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", errors.New("configuration identity unavailable")
	}
	canonical, err = filepath.Abs(canonical)
	if err != nil {
		return "", errors.New("configuration identity unavailable")
	}
	canonical = filepath.Clean(canonical)
	if !controlHelperAbsolute(canonical) {
		return "", errors.New("configuration identity unavailable")
	}
	info, err := os.Stat(canonical)
	if err != nil || !info.Mode().IsRegular() {
		return "", errors.New("configuration identity unavailable")
	}
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:]), nil
}

func controlHelperConfigPreflight(ctx context.Context, captured serviceConfigBytes, allow bool) error {
	cfg, err := captured.compile(allow)
	if err != nil {
		return err
	}
	// Check every effective outbound, not merely the selected node: a secure
	// selection does not revoke explicit consent for routed insecure groups.
	for _, entry := range cfg["outbounds"].([]any) {
		if err := ctx.Err(); err != nil {
			return err
		}
		out := entry.(map[string]any)
		if out["type"] != "anytls" {
			continue
		}
		tls := out["tls"].(map[string]any)
		if path, ok := tls["certificate_path"].(string); ok {
			if _, err := readSnapshotCA(path); err != nil {
				return err
			}
		}
	}
	return controlHelperEnginePreflight(ctx, cfg)
}

func controlHelperServe() error {
	if !controlHelperSupported() || os.Geteuid() != 0 || externalCoreRequired() {
		return errors.New("control helper requires root, macOS and embedded_core")
	}
	self, err := os.Executable()
	if err != nil || self != controlHelperExecutable {
		return errors.New("control helper must run from its fixed installed executable")
	}
	if err = controlHelperTrustedPath(self, false); err != nil {
		return err
	}
	reg, err := controlHelperReadRegistration()
	if err != nil {
		return err
	}
	if _, err := controlHelperConfigIdentity(reg.Config); err != nil {
		return errors.New("registered configuration identity unavailable")
	}
	// Hash once at startup. No binary size cap: 32MB+ embedded builds are valid.
	f, err := os.Open(self)
	if err != nil {
		return errors.New("helper identity unavailable")
	}
	h := sha256.New()
	_, err = io.Copy(h, f)
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return errors.New("helper identity unavailable")
	}
	if err = controlHelperPrepareSocket(reg.UID); err != nil {
		return err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: controlHelperSocketPath, Net: "unix"})
	if err != nil {
		return errors.New("control socket unavailable")
	}
	defer listener.Close()
	if err = os.Chmod(controlHelperSocketPath, 0600); err != nil {
		return errors.New("control socket permissions failed")
	}
	if err = os.Chown(controlHelperSocketPath, int(reg.UID), 0); err != nil {
		return errors.New("control socket ownership failed")
	}
	lifecycle := newServiceLifecycle(filepath.Join(filepath.Dir(reg.Config), "service"))
	// Tool contexts retain each existing short timeout, also bounded by the
	// independent server action context passed into each lifecycle invocation.
	withContext := func(ctx context.Context) serviceLifecycle {
		d := lifecycle
		d.tool = func(toolCtx context.Context, name string, args ...string) (string, error) {
			linked, cancel := context.WithCancel(toolCtx)
			defer cancel()
			stop := context.AfterFunc(ctx, cancel)
			defer stop()
			return runTool(linked, name, args...)
		}
		return d
	}
	s := &controlHelperServer{registration: reg, peer: controlHelperPeerUID, state: lifecycle.state, version: currentVersion(), sha: hex.EncodeToString(h.Sum(nil)),
		preflight: func(ctx context.Context, allow bool) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			captured, err := captureServiceConfig(reg.Config)
			if err != nil {
				return err
			}
			return controlHelperConfigPreflight(ctx, captured, allow)
		},
		start: func(ctx context.Context, allow bool) error {
			return withContext(ctx).start(self, reg.Config, "", allow)
		},
		stop: func(ctx context.Context) error { return withContext(ctx).stop() },
	}
	for {
		c, err := listener.AcceptUnix()
		if err != nil {
			return errors.New("control socket accept failed")
		}
		go s.handle(c)
	}
}

func controlHelperRequest(ctx context.Context, action string, allow bool) (controlHelperResponse, error) {
	q := controlHelperWireRequest{action, allow}
	if !controlHelperValidRequest(q) {
		return controlHelperResponse{}, errors.New("INVALID_REQUEST: invalid helper action or consent")
	}
	if !controlHelperSupported() {
		return controlHelperResponse{}, errors.New("control helper requires macOS")
	}
	if err := controlHelperValidateSocket(); err != nil {
		return controlHelperResponse{}, errors.New("control helper unavailable or untrusted; run anytls helper install locally")
	}
	c, err := (&net.Dialer{}).DialContext(ctx, "unix", controlHelperSocketPath)
	if err != nil {
		return controlHelperResponse{}, errors.New("control helper unavailable; run anytls helper install locally")
	}
	defer c.Close()
	return controlHelperExchange(ctx, c, q, controlHelperPeerUID)
}
func controlHelperExchange(ctx context.Context, c net.Conn, q controlHelperWireRequest, peer func(net.Conn) (uint32, error)) (controlHelperResponse, error) {
	var r controlHelperResponse
	// Authenticate the kernel peer before disclosing even the requested action.
	uid, err := peer(c)
	if err != nil || uid != 0 {
		return r, errors.New("FORBIDDEN: control helper peer is not root")
	}
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	deadline := time.Now().Add(6 * time.Minute)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = c.SetReadDeadline(deadline)
	_ = c.SetWriteDeadline(time.Now().Add(controlHelperIOTimeout))
	if err = json.NewEncoder(c).Encode(q); err != nil {
		return r, errors.New("control helper request write failed")
	}
	half, ok := c.(interface{ CloseWrite() error })
	if !ok {
		return r, errors.New("control socket cannot finish request")
	}
	if err = half.CloseWrite(); err != nil {
		return r, errors.New("control helper request completion failed")
	}
	err = controlHelperDecode(c, map[string]any{"ok": &r.OK, "code": &r.Code, "message": &r.Message, "loaded": &r.Loaded, "running": &r.Running, "helper_version": &r.HelperVersion, "helper_sha256": &r.HelperSHA256, "config_identity": &r.ConfigIdentity})
	if err != nil {
		return controlHelperResponse{}, errors.New("HELPER_UNAVAILABLE: incompatible or invalid control helper response; reinstall with anytls helper install locally")
	}
	if r.ConfigIdentity != "" {
		decoded, err := hex.DecodeString(r.ConfigIdentity)
		if err != nil || len(decoded) != sha256.Size || strings.ToLower(r.ConfigIdentity) != r.ConfigIdentity {
			return controlHelperResponse{}, errors.New("HELPER_UNAVAILABLE: invalid helper config identity; reinstall with anytls helper install locally")
		}
	} else if r.OK {
		return controlHelperResponse{}, errors.New("HELPER_UNAVAILABLE: missing helper config identity; reinstall with anytls helper install locally")
	}
	if !r.OK {
		safe := controlHelperFailure(r.Code)
		if safe.Code != r.Code {
			return controlHelperResponse{}, errors.New("invalid control helper error code")
		}
		// Never reflect arbitrary error text supplied over IPC.
		r.Message = safe.Message
		return r, fmt.Errorf("%s: %s", r.Code, r.Message)
	}
	if r.Code != "" {
		return controlHelperResponse{}, errors.New("invalid control helper success code")
	}
	return r, nil
}

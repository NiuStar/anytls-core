package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"
)

func controlHelperReadSelectionResponse(r io.Reader, p *controlHelperResponse) error {
	return controlHelperDecodeOptional(r, map[string]any{"ok": &p.OK, "code": &p.Code, "message": &p.Message, "loaded": &p.Loaded, "running": &p.Running, "helper_version": &p.HelperVersion, "helper_sha256": &p.HelperSHA256, "config_identity": &p.ConfigIdentity, "diagnostics": &p.Diagnostics, "selection_operation": &p.SelectionOperation}, "diagnostics,selection_operation")
}

const liveSourceName = "selection-source.json"
const liveSocketName = "selection.sock"

type liveSource struct {
	Config   []byte                 `json:"config"`
	Selected []byte                 `json:"selected"`
	CAs      map[string]string      `json:"cas"`
	Rules    map[string]liveFilePin `json:"rules"`
	CAPins   map[string]liveFilePin `json:"ca_pins"`
	Origin   string                 `json:"origin"`
	Staged   map[string]liveFilePin `json:"staged"`
}
type liveRequest struct {
	Action     string `json:"action"`
	Generation string `json:"generation"`
	Revision   uint64 `json:"revision"`
	Node       string `json:"node"`
}
type liveResponse struct {
	Code       string `json:"code"`
	Generation string `json:"generation"`
	Revision   uint64 `json:"revision"`
	Node       string `json:"node"`
	PID        int    `json:"pid"`
}

func readLiveRequest(r io.Reader) (q liveRequest, e error) {
	e = controlHelperDecode(r, map[string]any{"action": &q.Action, "generation": &q.Generation, "revision": &q.Revision, "node": &q.Node})
	if e == nil && (q.Action != "read" && q.Action != "switch" || len(q.Node) > 512 || q.Action == "read" && (q.Generation != "" || q.Revision != 0 || q.Node != "") || q.Action == "switch" && (!liveGeneration(q.Generation) || q.Node == "")) {
		e = errors.New("invalid live request")
	}
	return
}
func liveExchange(ctx context.Context, path string, q liveRequest, authenticate func(net.Conn) bool) (liveResponse, error) {
	var r liveResponse
	c, e := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if e != nil {
		return r, e
	}
	defer c.Close()
	if !authenticate(c) {
		return r, errors.New("untrusted selection peer")
	}
	deadline := time.Now().Add(2 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	c.SetDeadline(deadline)
	if e = json.NewEncoder(c).Encode(q); e != nil {
		return r, e
	}
	if e = c.(*net.UnixConn).CloseWrite(); e != nil {
		return r, e
	}
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(closed); _ = c.Close() })
	defer func() {
		if !stop() {
			<-closed
		}
	}()
	e = controlHelperDecode(c, map[string]any{"code": &r.Code, "generation": &r.Generation, "revision": &r.Revision, "node": &r.Node, "pid": &r.PID})
	if e == nil && (!liveGeneration(r.Generation) || len(r.Node) == 0 || len(r.Node) > 512 || r.PID <= 0 || (r.Code != "READY" && r.Code != "NOT_READY" && r.Code != "APPLIED" && r.Code != "STALE")) {
		e = errors.New("invalid selection response")
	}
	if e == nil && ctx.Err() != nil {
		e = ctx.Err()
	}
	if e == nil && !authenticate(c) {
		e = errors.New("selection peer changed during exchange")
	}
	return r, e
}
func liveGeneration(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func liveAppliedReadback(before, after liveResponse, name string) bool {
	expected := before.Revision
	if before.Node != name {
		if expected == ^uint64(0) {
			return false
		}
		expected++
	}
	return after.Code == "READY" && liveGeneration(after.Generation) && after.Generation == before.Generation && after.PID == before.PID && after.Node == name && after.Revision == expected
}
func stageLiveSource(config, root string) error {
	source, e := captureServiceConfig(config)
	if e != nil {
		return e
	}
	if !liveSourceEligibleStage(source.config) {
		return nil
	}
	staged, e := captureServiceConfig(filepath.Join(root, "config.yaml"))
	if e != nil || !bytes.Equal(staged.config, source.config) || !bytes.Equal(staged.selection, source.selection) {
		return errors.New("selection source differs from staged configuration")
	}
	cas := map[string]string{}
	nodes, e := loadNodesBytes(source.config)
	if e != nil {
		return e
	}
	for _, n := range nodes {
		if n.CA != "" {
			b, e := readSnapshotCA(n.CA)
			if e != nil {
				return nil
			}
			cas[n.CA] = shaHex(b)
		}
	}
	rules, caPins, e := liveSourceFiles(config, source.config)
	if e != nil {
		return nil
	} // Optional hot capability never breaks cold start for unused sources.
	raw, e := json.Marshal(liveSource{Config: source.config, Selected: source.selection, CAs: cas, Rules: rules, CAPins: caPins, Origin: config, Staged: map[string]liveFilePin{}})
	if e != nil {
		return e
	}
	return writeSnapshotLeaf(filepath.Join(root, liveSourceName), raw, 0600)
}

// No fallback reload: after a dispatched request all failures remain UNKNOWN.
func (s *controlHelperServer) selectSaved(ctx context.Context) controlHelperResponse {
	root := filepath.Join(filepath.Dir(s.registration.Config), "service")
	s.dns.mu.Lock()
	binding := s.dns.binding
	if binding != nil {
		copyBinding := *binding
		if binding.process != nil {
			process := *binding.process
			copyBinding.process = &process
		}
		binding = &copyBinding
	}
	s.dns.mu.Unlock()
	if binding == nil || binding.root != root || !binding.check() || s.selectionRootCheck(root) != nil {
		return controlHelperFailure("RELOAD_REQUIRED")
	}
	raw, e := readSnapshotSource(filepath.Join(root, liveSourceName), 48<<20, false)
	if e != nil {
		return controlHelperFailure("RELOAD_REQUIRED")
	}
	source, e := decodeLiveSource(raw)
	if e != nil || source.Origin != s.registration.Config || !source.stagedCheck(root) {
		return controlHelperFailure("RELOAD_REQUIRED")
	}
	saved, e := captureServiceConfig(s.registration.Config)
	if e != nil {
		return controlHelperFailure("RELOAD_REQUIRED")
	}
	name, e := selectionOnlyChange(source.Config, source.Selected, saved.config, saved.selection)
	if e != nil {
		return controlHelperFailure("RELOAD_REQUIRED")
	}
	// References with independently mutable contents need a future source lease.
	// Fail closed rather than applying against a changed rules/CA source.
	if !liveSourceEligible(saved.config) {
		return controlHelperFailure("RELOAD_REQUIRED")
	}
	for path, digest := range source.CAs {
		b, e := readSnapshotCA(path)
		if e != nil || shaHex(b) != digest {
			return controlHelperFailure("RELOAD_REQUIRED")
		}
	}
	path := filepath.Join(root, liveSocketName)
	if s.selectionSocketCheck(path) != nil {
		return controlHelperFailure("RELOAD_REQUIRED")
	}
	parentInfo, e := os.Lstat(filepath.Dir(root))
	if e != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return controlHelperFailure("RELOAD_REQUIRED")
	}
	socketInfo, e := os.Lstat(path)
	if e != nil {
		return controlHelperFailure("RELOAD_REQUIRED")
	}
	authenticate := func(c net.Conn) bool {
		current, err := os.Lstat(path)
		parentNow, parentErr := os.Lstat(filepath.Dir(root))
		return err == nil && parentErr == nil && os.SameFile(parentInfo, parentNow) && parentNow.Mode() == parentInfo.Mode() && binding.check() && os.SameFile(socketInfo, current) && s.selectionSocketCheck(path) == nil && s.selectionAuthenticate(c, binding)
	}
	before, e := liveExchange(ctx, path, liveRequest{Action: "read"}, authenticate)
	if e != nil || before.Code != "READY" || binding.process == nil || before.PID != binding.process.PID || !binding.check() {
		return controlHelperFailure("RELOAD_REQUIRED")
	}
	// Fence saved bytes again after handshake and before the single dispatch.
	check, e := captureServiceConfig(s.registration.Config)
	if e != nil || !bytes.Equal(check.config, saved.config) || !bytes.Equal(check.selection, saved.selection) || !source.filesCheck() || ctx.Err() != nil {
		return controlHelperFailure("RELOAD_REQUIRED")
	}
	if before.Node != name && before.Revision == ^uint64(0) {
		return controlHelperFailure("RELOAD_REQUIRED")
	}
	opID := make([]byte, 16)
	if _, e = rand.Read(opID); e != nil {
		return controlHelperFailure("RELOAD_REQUIRED")
	}
	expected := before.Revision
	if before.Node != name {
		expected++
	}
	s.liveLease = &liveSelectionLease{operation: liveSelectionOperation{Operation: hex.EncodeToString(opID), Generation: before.Generation, Revision: expected, Node: name}, binding: binding, socket: socketInfo, parent: parentInfo, config: append([]byte(nil), saved.config...), selected: append([]byte(nil), saved.selection...), unknown: true, cas: source.CAs, source: source}
	if before.Node != name {
		// Exactly one dispatch. A missing ACK is reconciled by an authenticated
		// read only; never blindly resend the mutation.
		_, _ = liveExchange(ctx, path, liveRequest{Action: "switch", Generation: before.Generation, Revision: before.Revision, Node: name}, authenticate)
	}
	return s.readSelection(ctx)
}

// Public tuple is an observation key, not client-supplied mutation authority.
// Only this helper's in-memory lease may select the expected CAS revision.
type liveSelectionOperation struct {
	Operation  string `json:"operation"`
	Generation string `json:"generation"`
	Revision   uint64 `json:"revision"`
	Node       string `json:"node"`
}

func (o *liveSelectionOperation) valid() bool {
	return o != nil && liveGeneration(o.Operation) && liveGeneration(o.Generation) && o.Node != "" && len(o.Node) <= 512
}
func (o *liveSelectionOperation) UnmarshalJSON(raw []byte) error {
	return controlHelperDecode(bytes.NewReader(raw), map[string]any{"operation": &o.Operation, "generation": &o.Generation, "revision": &o.Revision, "node": &o.Node})
}

type liveSelectionLease struct {
	operation        liveSelectionOperation
	binding          *startupBinding
	socket           os.FileInfo
	parent           os.FileInfo
	config, selected []byte
	cas              map[string]string
	unknown          bool
	source           liveSource
}

func (l *liveSelectionLease) response(applied bool) controlHelperResponse {
	r := controlHelperFailure("SWITCH_UNKNOWN")
	op := l.operation
	r.SelectionOperation = &op
	if applied {
		r.OK = true
		r.Code = "HOT_APPLIED"
		r.Loaded = true
		r.Running = true
		r.Message = "New connections use the selected node; existing connections retain their previous exit."
	}
	return r
}
func (s *controlHelperServer) selectionRootCheck(path string) error {
	if s.liveRootCheck != nil {
		return s.liveRootCheck(path)
	}
	return livePrivateRoot(path)
}
func (s *controlHelperServer) selectionSocketCheck(path string) error {
	if s.liveSocketCheck != nil {
		return s.liveSocketCheck(path)
	}
	return liveTrustedSocket(path)
}
func (s *controlHelperServer) selectionAuthenticate(c net.Conn, b *startupBinding) bool {
	if s.livePeer != nil {
		return s.livePeer(c, b)
	}
	return startupAuthenticatePush(c, b)
}

// select-read has no mutation fallback, including after helper restart or a
// superseding process. An unowned observation must not manufacture APPLIED.
func (s *controlHelperServer) readSelection(ctx context.Context) controlHelperResponse {
	l := s.liveLease
	if l == nil {
		return controlHelperFailure("SWITCH_UNKNOWN")
	}
	l.unknown = true
	b := l.binding
	path := filepath.Join(b.root, liveSocketName)
	check := func() bool {
		parent, e := os.Lstat(filepath.Dir(b.root))
		if e != nil || !os.SameFile(parent, l.parent) || parent.Mode() != l.parent.Mode() {
			return false
		}
		if !l.source.filesCheck() || !b.check() || s.selectionRootCheck(b.root) != nil || s.selectionSocketCheck(path) != nil {
			return false
		}
		info, e := os.Lstat(path)
		if e != nil || !os.SameFile(l.socket, info) {
			return false
		}
		for path, digest := range l.cas {
			raw, e := readSnapshotCA(path)
			if e != nil || shaHex(raw) != digest {
				return false
			}
		}
		saved, e := captureServiceConfig(s.registration.Config)
		return e == nil && bytes.Equal(saved.config, l.config) && bytes.Equal(saved.selection, l.selected)
	}
	if !check() {
		return l.response(false)
	}
	after, e := liveExchange(ctx, path, liveRequest{Action: "read"}, func(c net.Conn) bool { return check() && s.selectionAuthenticate(c, b) })
	if e != nil || after.Code != "READY" || after.Generation != l.operation.Generation || after.Revision != l.operation.Revision || after.Node != l.operation.Node || b.process == nil || after.PID != b.process.PID || !check() {
		return l.response(false)
	}
	l.unknown = false
	return l.response(true)
}
func livePrivateRoot(root string) error {
	info, e := os.Lstat(root)
	if e != nil || !info.IsDir() || info.Mode().Perm() != 0700 || info.Mode()&os.ModeSymlink != 0 || !controlHelperRootOwned(info) {
		return errors.New("untrusted private root")
	}
	return nil
}
func liveTrustedSocket(path string) error {
	if livePrivateRoot(filepath.Dir(path)) != nil {
		return errors.New("untrusted socket root")
	}
	info, e := os.Lstat(path)
	if e != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0600 || !controlHelperRootOwned(info) {
		return errors.New("untrusted socket")
	}
	return nil
}

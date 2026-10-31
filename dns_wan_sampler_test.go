//go:build embedded_core && with_utls && (linux || darwin)

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/NiuStar/anytls-core/internal/engine"
	"github.com/miekg/dns"
)

// Evidence-only entry. Neither environment variables nor ordinary go test enable
// WAN. The official wrapper builds this binary; it needs no new wrapper flags.
var wanManifestPath = flag.String("wan-manifest", "", "private approved manifest (no default)")
var wanManifestDigest = flag.String("wan-manifest-sha256", "", "approved manifest exact bytes SHA256")
var wanApproved = flag.Bool("sample-approved-input", false, "consume exact approved input on designated host")

const wanRoot = "/Users/lihaiyan/.ais2/doh-wan-sampler-r1"
const wanConfig = "/Users/lihaiyan/.anytls/config.yaml"

var wanDomains = []string{"example.com.", "www.cloudflare.com.", "www.google.com."}

type wanCode string

func (c wanCode) Error() string { return string(c) }

type wanSource struct {
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
	Inode   uint64 `json:"inode"`
	MtimeNS int64  `json:"mtime_ns"`
}
type wanManifest struct {
	Schema                string    `json:"schema"`
	Root                  string    `json:"root"`
	ConfigPath            string    `json:"config_path"`
	SelectionPath         string    `json:"selection_path"`
	BinarySHA256          string    `json:"binary_sha256"`
	Config                wanSource `json:"config"`
	Selection             wanSource `json:"selection"`
	NodeFingerprint       string    `json:"node_fingerprint"`
	CreatedUnix           int64     `json:"created_unix"`
	UID                   int       `json:"uid"`
	GOOS                  string    `json:"goos"`
	GOARCH                string    `json:"goarch"`
	SelectedOnly          bool      `json:"selected_only"`
	PublicQueriesApproved bool      `json:"public_queries_approved"`
	PhysicalRouteVerified bool      `json:"physical_route_verified"`
	ProtectionVerified    bool      `json:"protection_verified"`
	Domains               []string  `json:"domains"`
	Engines               int       `json:"engines"`
	WarmRepeats           int       `json:"warm_repeats"`
	MaxQuestions          int       `json:"max_questions"`
	DeadlineSeconds       int       `json:"deadline_seconds"`
}

func wanHash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func wanValidHash(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && s == strings.ToLower(s)
}

func wanValidateManifest(raw []byte, digest string, now int64) (wanManifest, error) {
	var m wanManifest
	if !wanValidHash(digest) || wanHash(raw) != digest {
		return m, wanCode("MANIFEST_DIGEST")
	}
	// Decoder disallows unknown fields; duplicate keys are rejected independently.
	var tree any
	if !wanUniqueJSON(raw, &tree) || !wanCanonicalManifest(raw) {
		return m, wanCode("MANIFEST_SCHEMA")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&m) != nil || d.Decode(new(any)) != io.EOF {
		return m, wanCode("MANIFEST_SCHEMA")
	}
	if m.Schema != "anytls-doh-wan-v1" || m.Root != wanRoot || m.ConfigPath != wanConfig || m.SelectionPath != wanConfig+".selected" || m.UID != 501 || m.GOOS != "darwin" || m.GOARCH != "arm64" || !m.SelectedOnly || !m.PublicQueriesApproved || !m.PhysicalRouteVerified || !m.ProtectionVerified || !reflect.DeepEqual(m.Domains, wanDomains) || m.Engines != 3 || m.WarmRepeats != 2 || m.MaxQuestions != 54 || m.DeadlineSeconds != 120 {
		return m, wanCode("MANIFEST_POLICY")
	}
	if m.CreatedUnix < 1 || m.CreatedUnix > now || now-m.CreatedUnix > 120 {
		return m, wanCode("MANIFEST_STALE")
	}
	if !wanValidHash(m.BinarySHA256) || !wanValidHash(m.NodeFingerprint) || !wanValidHash(m.Config.SHA256) || !wanValidHash(m.Selection.SHA256) || m.Config.Size < 1 || m.Config.Size > 8<<20 || m.Selection.Size < 1 || m.Selection.Size > 4096 || m.Config.Inode == 0 || m.Selection.Inode == 0 || m.Config.MtimeNS <= 0 || m.Selection.MtimeNS <= 0 {
		return m, wanCode("MANIFEST_SOURCE")
	}
	return m, nil
}

// Validate exact canonical keys before encoding/json's case-insensitive struct
// matching. Require every key, including nested source metadata.
func wanCanonicalManifest(raw []byte) bool {
	var object func([]byte, reflect.Type) bool
	object = func(b []byte, typ reflect.Type) bool {
		var fields map[string]json.RawMessage
		if json.Unmarshal(b, &fields) != nil || len(fields) != typ.NumField() {
			return false
		}
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			value, ok := fields[f.Tag.Get("json")]
			if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				return false
			}
			if f.Type.Kind() == reflect.Struct && !object(value, f.Type) {
				return false
			}
		}
		return true
	}
	return object(raw, reflect.TypeOf(wanManifest{}))
}

// Reject duplicate keys at every depth instead of accepting JSON last-wins.
func wanUniqueJSON(raw []byte, result *any) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	var value func() bool
	value = func() bool {
		tok, e := d.Token()
		if e != nil {
			return false
		}
		delim, ok := tok.(json.Delim)
		if !ok {
			return true
		}
		if delim == '{' {
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				s, ok := k.(string)
				if e != nil || !ok || seen[s] {
					return false
				}
				seen[s] = true
				if !value() {
					return false
				}
			}
			end, e := d.Token()
			return e == nil && end == json.Delim('}')
		}
		if delim == '[' {
			for d.More() {
				if !value() {
					return false
				}
			}
			end, e := d.Token()
			return e == nil && end == json.Delim(']')
		}
		return false
	}
	return value() && d.Decode(result) == io.EOF
}
func wanNoSymlinks(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	for p := path; ; p = filepath.Dir(p) {
		s, e := os.Lstat(p)
		if e != nil || s.Mode()&os.ModeSymlink != 0 {
			return false
		}
		if p == "/" {
			return true
		}
	}
}
func wanStatOK(s os.FileInfo, uid int, mode os.FileMode) bool {
	x, ok := s.Sys().(*syscall.Stat_t)
	return ok && s.Mode().IsRegular() && s.Mode().Perm() == mode && x.Uid == uint32(uid) && x.Nlink == 1
}

// Open O_NOFOLLOW, bounded single read, compare the same inode before/after.
// All source errors are fixed enums: never return or print parser/path errors.
func wanReadPrivate(path string, uid int, limit int64) ([]byte, os.FileInfo, error) {
	if !wanNoSymlinks(path) {
		return nil, nil, wanCode("SOURCE_PATH")
	}
	before, e := os.Lstat(path)
	if e != nil || !wanStatOK(before, uid, 0600) || before.Size() < 1 || before.Size() > limit {
		return nil, nil, wanCode("SOURCE_METADATA")
	}
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, nil, wanCode("SOURCE_OPEN")
	}
	f := os.NewFile(uintptr(fd), "private-input")
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(before, opened) || !wanStatOK(opened, uid, 0600) {
		return nil, nil, wanCode("SOURCE_CHANGED")
	}
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	after, e2 := f.Stat()
	current, e3 := os.Lstat(path)
	if e != nil || e2 != nil || e3 != nil || int64(len(b)) != before.Size() || !wanSameStat(before, after) || !wanSameStat(before, current) {
		return nil, nil, wanCode("SOURCE_CHANGED")
	}
	return b, before, nil
}
func wanSameStat(a, b os.FileInfo) bool {
	x, xok := a.Sys().(*syscall.Stat_t)
	y, yok := b.Sys().(*syscall.Stat_t)
	return xok && yok && os.SameFile(a, b) && a.Size() == b.Size() && a.ModTime() == b.ModTime() && a.Mode() == b.Mode() && x.Uid == y.Uid && x.Gid == y.Gid && x.Nlink == y.Nlink
}
func wanMatches(b []byte, s os.FileInfo, want wanSource) bool {
	x, ok := s.Sys().(*syscall.Stat_t)
	return ok && wanHash(b) == want.SHA256 && int64(len(b)) == want.Size && x.Ino == want.Inode && s.ModTime().UnixNano() == want.MtimeNS
}
func wanSelected(config, selection []byte) (node, error) {
	nodes, e := loadNodesBytes(config)
	if e != nil || len(nodes) != 10 {
		return node{}, wanCode("CONFIG_DECODE")
	}
	for _, n := range nodes {
		if n.Type != "anytls" {
			return node{}, wanCode("CONFIG_NODE_TYPES")
		}
	}
	name, e := selectedBytes(selection, nodes)
	if e != nil {
		return node{}, wanCode("SELECTION")
	}
	n, e := choose(nodes, name)
	if e != nil {
		return node{}, wanCode("SELECTION")
	}
	ip := net.ParseIP(n.Server)
	if ip == nil || ip.To4() == nil || n.SkipVerify || n.CA != "" || n.CertificatePublicKeySHA256 != "" || len(n.CertificateSHA256) != 64 || validateNodeLeafTrust(n) != nil {
		return node{}, wanCode("NODE_TRUST")
	}
	return n, nil
}
func wanNodeFingerprint(n node) string {
	return wanHash([]byte(n.Server + "\n" + strconv.Itoa(n.Port) + "\n" + n.CertificateSHA256))
}

// Pure assembly: never use full user groups/rules, never write runtime JSON.
func wanAssemble(n node, port int, token string) (map[string]any, error) {
	if n.MinIdle > 1 || n.CA != "" || n.SkipVerify || n.CertificatePublicKeySHA256 != "" || n.CertificateSHA256 == "" || net.ParseIP(n.Server) == nil || net.ParseIP(n.Server).To4() == nil {
		return nil, wanCode("NODE_TRUST")
	}
	cfg, e := buildNode(n, "proxy", port, false)
	if e != nil {
		return nil, wanCode("COMPILER")
	}
	cfg["inbounds"].([]any)[0].(map[string]any)["users"] = []any{map[string]any{"username": "sampler", "password": token}}
	cfg["log"] = map[string]any{"disabled": true}
	cfg["dns"] = unifiedTUNDNS()
	cfg["route"].(map[string]any)["rules"] = unifiedTUNDNSRules()
	if e = wanAssertPolicy(cfg, n, port, token); e != nil {
		return nil, e
	}
	return cfg, nil
}
func wanAssertPolicy(cfg map[string]any, n node, port int, token string) error {
	expected, e := buildNode(n, "proxy", port, false)
	if e != nil {
		return wanCode("COMPILER")
	}
	expected["inbounds"].([]any)[0].(map[string]any)["users"] = []any{map[string]any{"username": "sampler", "password": token}}
	expected["log"] = map[string]any{"disabled": true}
	expected["dns"] = unifiedTUNDNS()
	expected["route"].(map[string]any)["rules"] = unifiedTUNDNSRules()
	// Entire-map comparison rejects extra outbounds, DIRECT, fallback, file logs,
	// TUN, endpoints, route overrides, or weakened node/DoH TLS options.
	if !reflect.DeepEqual(cfg, expected) {
		return wanCode("RUNTIME_POLICY")
	}
	d := cfg["dns"].(map[string]any)
	servers := d["servers"].([]any)
	if len(servers) != 1 || d["final"] != "secure-dns" {
		return wanCode("DNS_POLICY")
	}
	s := servers[0].(map[string]any)
	tls := s["tls"].(map[string]any)
	if s["type"] != "https" || s["server"] != "1.1.1.1" || s["detour"] != "anytls-out" || tls["server_name"] != "cloudflare-dns.com" || tls["insecure"] == true || len(tls) != 1 || len(s) != 5 {
		return wanCode("DNS_POLICY")
	}
	r := cfg["route"].(map[string]any)
	if r["final"] != "anytls-out" || len(cfg["outbounds"].([]any)) != 1 || len(cfg["inbounds"].([]any)) != 1 {
		return wanCode("ROUTE_POLICY")
	}
	if !reflect.DeepEqual(r["rules"], []any{map[string]any{"port": 53, "action": "hijack-dns"}, map[string]any{"action": "sniff"}, map[string]any{"protocol": []string{"dns"}, "action": "hijack-dns"}}) {
		return wanCode("DNS_CAPTURE_POLICY")
	}
	return nil
}
func wanPhysicalRoute(n node) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, e := exec.CommandContext(ctx, "/sbin/route", "-n", "get", n.Server).Output()
	if e != nil {
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == "interface: en0" {
			return true
		}
	}
	return false
}

type wanRow struct {
	DomainIndex int    `json:"domain_index"`
	Engine      int    `json:"engine"`
	Mode        string `json:"mode"`
	QType       string `json:"qtype"`
	Outcome     string `json:"outcome"`
	ElapsedNS   int64  `json:"elapsed_ns"`
}
type wanReport struct {
	Schema           string                      `json:"schema"`
	Rows             []wanRow                    `json:"rows"`
	Metrics          []engine.DNSMetricsSnapshot `json:"metrics"`
	Questions        int                         `json:"questions"`
	EnginesJoined    int                         `json:"engines_joined"`
	ListenersRebound int                         `json:"listeners_rebound"`
	ServerTLS        string                      `json:"server_tls_connections"`
	ColdMeaning      string                      `json:"cold_meaning"`
	Recovery         string                      `json:"recovery"`
}

// Own the TCP socket before any SOCKS bytes. Authentication is deliberately
// strict: pinned SDK ClientHandshake5 also accepts unoffered NOAUTH. A secret
// challenge attributes an ordinary unowned port claimant, not a malicious same-
// UID process able to inspect this process's memory/configuration.
func wanAuthenticated(ctx context.Context, addr, token string) (net.Conn, func(), error) {
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, nil, wanCode("CONNECT_FAILURE")
	}
	// AfterFunc owns cancellation closure; cleanup joins its completion. Close on
	// TCP is local/nonblocking, with no linger enabled. No helper goroutine remains.
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = c.Close(); close(done) })
	cleanup := func() {
		if stop() {
			_ = c.Close()
		} else {
			<-done
		}
	}
	fail := func(code string) (net.Conn, func(), error) { cleanup(); return nil, nil, wanCode(code) }
	deadline, ok := ctx.Deadline()
	if !ok || c.SetDeadline(deadline) != nil {
		return fail("DEADLINE_FAILURE")
	}
	exchange := func(request []byte, response []byte) bool {
		n, e := c.Write(request)
		if e != nil || n != len(request) {
			return false
		}
		_, e = io.ReadFull(c, response)
		return e == nil
	}
	method := make([]byte, 2)
	if !exchange([]byte{5, 1, 2}, method) || !bytes.Equal(method, []byte{5, 2}) {
		return fail("AUTH_FAILURE")
	}
	if len(token) == 0 || len(token) > 255 {
		return fail("AUTH_FAILURE")
	}
	auth := append([]byte{1, 7}, []byte("sampler")...)
	auth = append(auth, byte(len(token)))
	auth = append(auth, []byte(token)...)
	status := make([]byte, 2)
	if !exchange(auth, status) || !bytes.Equal(status, []byte{1, 0}) {
		return fail("AUTH_FAILURE")
	}
	return c, cleanup, nil
}

func wanQuery(ctx context.Context, addr, token, name string, typ uint16, id uint16) (string, time.Duration) {
	start := time.Now()
	// Budget includes TCP dial, auth, CONNECT, DNS write and DNS read, not just
	// the payload exchange. Cancellation actively closes the owned socket.
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	c, cleanup, e := wanAuthenticated(ctx, addr, token)
	if e != nil {
		return e.Error(), time.Since(start)
	}
	defer cleanup()
	// RFC1928 CONNECT to the fixed DNS capture target, only after strict auth.
	request := []byte{5, 1, 0, 1, 1, 1, 1, 1, 0, 53}
	if n, e := c.Write(request); e != nil || n != len(request) {
		return "CONNECT_FAILURE", time.Since(start)
	}
	reply := make([]byte, 4)
	if _, e := io.ReadFull(c, reply); e != nil || reply[0] != 5 || reply[1] != 0 || reply[2] != 0 {
		return "CONNECT_FAILURE", time.Since(start)
	}
	size := 0
	switch reply[3] {
	case 1:
		size = 4 + 2
	case 4:
		size = 16 + 2
	case 3:
		b := make([]byte, 1)
		if _, e := io.ReadFull(c, b); e != nil {
			return "CONNECT_FAILURE", time.Since(start)
		}
		size = int(b[0]) + 2
	default:
		return "CONNECT_FAILURE", time.Since(start)
	}
	if _, e := io.ReadFull(c, make([]byte, size)); e != nil {
		return "CONNECT_FAILURE", time.Since(start)
	}
	q := new(dns.Msg)
	q.SetQuestion(name, typ)
	q.Id = id
	dc := &dns.Conn{Conn: c}
	if dc.WriteMsg(q) != nil {
		return "WRITE_FAILURE", time.Since(start)
	}
	a, e := dc.ReadMsg()
	if e != nil {
		var ne net.Error
		if errors.As(e, &ne) && ne.Timeout() {
			return "TIMEOUT", time.Since(start)
		}
		return "READ_FAILURE", time.Since(start)
	}
	if a == nil || !a.Response || a.Id != q.Id || !reflect.DeepEqual(a.Question, q.Question) {
		return "IDENTITY_FAILURE", time.Since(start)
	}
	switch a.Rcode {
	case dns.RcodeSuccess:
		return "NOERROR", time.Since(start)
	case dns.RcodeNameError:
		return "NXDOMAIN", time.Since(start)
	case dns.RcodeServerFailure:
		return "SERVFAIL", time.Since(start)
	}
	return "OTHER_RCODE", time.Since(start)
}

// Accept wrappers/joins only when every leaf is exactly context.Canceled.
// errors.Is is insufficient: a cancellation joined with a Close failure is not
// successful cleanup. Bound recursion also rejects malformed/cyclic wrappers.
func wanCancellationOnly(err error) bool {
	var visit func(error, int) bool
	visit = func(e error, depth int) bool {
		if e == nil || depth > 64 {
			return false
		}
		if e == context.Canceled {
			return true
		}
		if many, ok := e.(interface{ Unwrap() []error }); ok {
			children := many.Unwrap()
			if len(children) == 0 {
				return false
			}
			for _, child := range children {
				if !visit(child, depth+1) {
					return false
				}
			}
			return true
		}
		if one, ok := e.(interface{ Unwrap() error }); ok {
			return visit(one.Unwrap(), depth+1)
		}
		return false
	}
	return visit(err, 0)
}

// One owned engine at a time; no fault injection into any system resource.
func wanRunEngine(ctx context.Context, n node, index int, report *wanReport) error {
	return wanRunEngineWithRunner(ctx, n, index, report, engine.Run)
}

func wanRunEngineWithRunner(ctx context.Context, n node, index int, report *wanReport, runner func(context.Context, []byte) error) error {
	spare, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		return wanCode("PORT_PROBE")
	}
	addr := spare.Addr().String()
	port := spare.Addr().(*net.TCPAddr).Port
	if spare.Close() != nil {
		return wanCode("PORT_CLOSE")
	}
	secret := make([]byte, 32)
	if _, e := rand.Read(secret); e != nil {
		return wanCode("LOCAL_AUTH")
	}
	token := hex.EncodeToString(secret)
	cfg, e := wanAssemble(n, port, token)
	if e != nil {
		return e
	}
	wire, e := json.Marshal(cfg)
	if e != nil {
		return wanCode("RUNTIME_ENCODE")
	}
	metrics := new(engine.DNSMetrics)
	ctx, cancel := context.WithCancel(engine.WithDNSMetrics(ctx, metrics))
	ended := make(chan error, 1)
	go func() { ended <- runner(ctx, wire) }()
	// Always join, even readiness failure. Fixed errors never expose SDK text.
	var runErr error
	ownerEnded := false
	var ownerErr error
	checkOwner := func() bool {
		if !ownerEnded {
			select {
			case ownerErr = <-ended:
				ownerEnded = true
				report.EnginesJoined++
			default:
			}
		}
		return ownerEnded
	}
	ready := false
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		if checkOwner() {
			runErr = wanCode("ENGINE_START")
			break
		}
		authCtx, authCancel := context.WithTimeout(ctx, 100*time.Millisecond)
		_, closeAuth, authErr := wanAuthenticated(authCtx, addr, token)
		if authErr == nil {
			closeAuth()
		}
		authCancel()
		if checkOwner() {
			runErr = wanCode("ENGINE_START")
			break
		}
		if authErr == nil {
			ready = true
			break
		}
		select {
		case <-ctx.Done():
		case <-time.After(10 * time.Millisecond):
		}
	}
	if ready {
		for domainIndex, name := range wanDomains {
			for _, typ := range []uint16{dns.TypeA, dns.TypeAAAA} {
				for repeat := 0; repeat < 3; repeat++ {
					if checkOwner() {
						runErr = wanCode("ENGINE_EARLY_EXIT")
						break
					}
					if ctx.Err() != nil || report.Questions >= 54 {
						runErr = wanCode("QUESTION_BUDGET")
						break
					}
					mode := "warm"
					if repeat == 0 {
						mode = "sdk_cache_cold"
					}
					outcome, elapsed := wanQuery(ctx, addr, token, name, typ, uint16(report.Questions+1))
					report.Questions++
					report.Rows = append(report.Rows, wanRow{domainIndex, index, mode, dns.TypeToString[typ], outcome, elapsed.Nanoseconds()})
					if checkOwner() {
						runErr = wanCode("ENGINE_EARLY_EXIT")
						break
					}
					if outcome != "NOERROR" {
						runErr = wanCode("QUERY_FAILED")
						break
					}
				}
				if runErr != nil {
					break
				}
			}
			if runErr != nil {
				break
			}
		}
	} else if runErr == nil {
		runErr = wanCode("READINESS")
	}
	if checkOwner() && runErr == nil {
		runErr = wanCode("ENGINE_EARLY_EXIT")
	}
	cancel()
	if !ownerEnded {
		select {
		case ownerErr = <-ended:
			report.EnginesJoined++
			ownerEnded = true
		// Overall root admission deadline plus at most five seconds for SDK join.
		// Unknown cleanup is always failure; rebind cannot override this marker.
		case <-time.After(5 * time.Second):
			return wanCode("ENGINE_JOIN")
		}
	}
	if ownerErr != nil && !wanCancellationOnly(ownerErr) {
		runErr = wanCode("ENGINE_STOP")
	}
	report.Metrics = append(report.Metrics, metrics.Snapshot())
	l, e := net.Listen("tcp", addr)
	if e != nil {
		return wanCode("LISTENER_RELEASE")
	}
	l.Close()
	report.ListenersRebound++
	return runErr
}

func TestDNSWANSampleApprovedInput(t *testing.T) {
	if !*wanApproved && *wanManifestPath == "" && *wanManifestDigest == "" {
		t.Skip("WAN_NOT_APPROVED")
		return
	}
	fail := func(code string) { t.Fatal(code) }
	if flag.Lookup("test.run").Value.String() != "^TestDNSWANSampleApprovedInput$" || flag.Lookup("test.count").Value.String() != "1" || flag.Lookup("test.parallel").Value.String() != "1" {
		fail("TEST_INVOCATION")
	}
	if !*wanApproved || runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" || os.Getuid() != 501 || os.Geteuid() != 501 {
		fail("HOST_GATE")
	}
	if *wanManifestPath != wanRoot+"/manifest.json" {
		fail("MANIFEST_PATH")
	}
	if !wanNoSymlinks(wanRoot) {
		fail("ROOT_PATH")
	}
	root, e := os.Stat(wanRoot)
	if e != nil || !root.IsDir() || root.Mode().Perm() != 0700 || root.Sys().(*syscall.Stat_t).Uid != 501 {
		fail("ROOT_METADATA")
	}
	raw, _, e := wanReadPrivate(*wanManifestPath, 501, 16384)
	if e != nil {
		fail("MANIFEST_READ")
	}
	m, e := wanValidateManifest(raw, *wanManifestDigest, time.Now().Unix())
	if e != nil {
		fail(string(e.(wanCode)))
	}
	executable, e := os.Executable()
	if e != nil || executable != wanRoot+"/sampler.test" || !wanNoSymlinks(executable) {
		fail("BINARY_PATH")
	}
	binary, e := os.Open(executable)
	if e != nil {
		fail("BINARY_READ")
	}
	h := sha256.New()
	_, e = io.Copy(h, binary)
	binary.Close()
	if e != nil || hex.EncodeToString(h.Sum(nil)) != m.BinarySHA256 {
		fail("BINARY_DIGEST")
	}
	config, cs, e := wanReadPrivate(wanConfig, 501, 8<<20)
	if e != nil {
		fail("CONFIG_READ")
	}
	selected, ss, e := wanReadPrivate(wanConfig+".selected", 501, 4096)
	if e != nil {
		fail("SELECTION_READ")
	}
	if !wanMatches(config, cs, m.Config) || !wanMatches(selected, ss, m.Selection) {
		fail("SOURCE_BINDING")
	}
	n, e := wanSelected(config, selected)
	if e != nil {
		fail(string(e.(wanCode)))
	}
	if wanNodeFingerprint(n) != m.NodeFingerprint {
		fail("NODE_BINDING")
	}
	if !wanPhysicalRoute(n) {
		fail("NODE_ROUTE")
	}
	// Product SDK Check precedes the first public query; it does not Start.
	cfg, e := wanAssemble(n, 11080, "SYNTHETIC_AUTH")
	if e != nil {
		fail("COMPILER_POLICY")
	}
	wire, e := json.Marshal(cfg)
	if e != nil || engine.Check(context.Background(), wire) != nil {
		fail("SDK_CHECK")
	}
	if time.Now().Unix()-m.CreatedUnix > 120 {
		fail("MANIFEST_STALE")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	report := wanReport{Schema: "anytls-doh-wan-report-v1", ServerTLS: "NOT_OBSERVED", ColdMeaning: "fresh_sdk_engine_not_os_cache", Recovery: "NOT_RUN"}
	var sampleErr error
	for i := 0; i < 3; i++ {
		if sampleErr = wanRunEngine(ctx, n, i, &report); sampleErr != nil {
			break
		}
	}
	// Metadata only: the captured private bytes are not reread during this run.
	ca, ce := os.Lstat(wanConfig)
	sa, se := os.Lstat(wanConfig + ".selected")
	if ce != nil || se != nil || !wanSameStat(cs, ca) || !wanSameStat(ss, sa) {
		sampleErr = wanCode("SOURCE_CHANGED")
	}
	b, e := json.Marshal(report)
	if e != nil {
		fail("REPORT_ENCODE")
	}
	t.Logf("DNS_WAN_REPORT %s", b)
	if sampleErr != nil {
		fail(string(sampleErr.(wanCode)))
	}
	if report.Questions != 54 || report.EnginesJoined != 3 || report.ListenersRebound != 3 {
		fail("INCOMPLETE")
	}
}

func wanSyntheticManifest() wanManifest {
	return wanManifest{Schema: "anytls-doh-wan-v1", Root: wanRoot, ConfigPath: wanConfig, SelectionPath: wanConfig + ".selected", BinarySHA256: strings.Repeat("a", 64), Config: wanSource{strings.Repeat("b", 64), 128, 1, 1}, Selection: wanSource{strings.Repeat("c", 64), 2, 2, 2}, NodeFingerprint: strings.Repeat("d", 64), CreatedUnix: 1000, UID: 501, GOOS: "darwin", GOARCH: "arm64", SelectedOnly: true, PublicQueriesApproved: true, PhysicalRouteVerified: true, ProtectionVerified: true, Domains: append([]string(nil), wanDomains...), Engines: 3, WarmRepeats: 2, MaxQuestions: 54, DeadlineSeconds: 120}
}
func TestDNSWANSamplerSchema(t *testing.T) {
	m := wanSyntheticManifest()
	raw, _ := json.Marshal(m)
	if _, e := wanValidateManifest(raw, wanHash(raw), 1000); e != nil {
		t.Fatal("SYNTHETIC_VALID_REJECTED")
	}
	cases := []struct {
		name   string
		change func(*wanManifest)
	}{
		{"approval", func(m *wanManifest) { m.PublicQueriesApproved = false }}, {"selection", func(m *wanManifest) { m.SelectedOnly = false }}, {"route", func(m *wanManifest) { m.PhysicalRouteVerified = false }}, {"protection", func(m *wanManifest) { m.ProtectionVerified = false }}, {"path", func(m *wanManifest) { m.ConfigPath = "/arbitrary" }}, {"host", func(m *wanManifest) { m.UID = 0 }}, {"domain", func(m *wanManifest) { m.Domains = []string{"internal.invalid."} }}, {"quota", func(m *wanManifest) { m.MaxQuestions = 55 }}, {"engines", func(m *wanManifest) { m.Engines = 4 }}, {"warm", func(m *wanManifest) { m.WarmRepeats = 3 }}, {"deadline", func(m *wanManifest) { m.DeadlineSeconds = 121 }}, {"stale", func(m *wanManifest) { m.CreatedUnix = 879 }}, {"future", func(m *wanManifest) { m.CreatedUnix = 1001 }}, {"hash", func(m *wanManifest) { m.Config.SHA256 = "BAD" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := wanSyntheticManifest()
			c.change(&m)
			b, _ := json.Marshal(m)
			if _, e := wanValidateManifest(b, wanHash(b), 1000); e == nil {
				t.Fatal("UNSAFE_ACCEPTED")
			}
		})
	}
	for _, b := range [][]byte{append(append([]byte(nil), raw...), []byte(" {}")...), []byte(`{"schema":"x","schema":"y"}`), []byte(`{"unknown":true}`)} {
		if _, e := wanValidateManifest(b, wanHash(b), 1000); e == nil {
			t.Fatal("JSON_ACCEPTED")
		}
	}
	if _, e := wanValidateManifest(raw, strings.Repeat("0", 64), 1000); e == nil {
		t.Fatal("DIGEST_ACCEPTED")
	}
}
func TestDNSWANSamplerCompiler(t *testing.T) {
	n := node{Name: "SYNTHETIC", Type: "anytls", Server: "127.0.0.1", Port: 9, Password: "SYNTHETIC_SECRET_NEVER_EXPORT", CertificateSHA256: strings.Repeat("a", 64), Fingerprint: "golang"}
	cfg, e := wanAssemble(n, 11080, "SYNTHETIC_AUTH")
	if e != nil {
		t.Fatal("ASSEMBLY")
	}
	b, _ := json.Marshal(cfg)
	if engine.Check(context.Background(), b) != nil {
		t.Fatal("SDK_CHECK")
	}
	for _, mutation := range []func(map[string]any){func(c map[string]any) {
		c["outbounds"] = append(c["outbounds"].([]any), map[string]any{"type": "direct"})
	}, func(c map[string]any) { c["route"].(map[string]any)["final"] = "DIRECT" }, func(c map[string]any) { c["dns"].(map[string]any)["final"] = "local" }, func(c map[string]any) { c["inbounds"].([]any)[0].(map[string]any)["listen"] = "0.0.0.0" }} {
		c, _ := wanAssemble(n, 11080, "SYNTHETIC_AUTH")
		mutation(c)
		if wanAssertPolicy(c, n, 11080, "SYNTHETIC_AUTH") == nil {
			t.Fatal("MUTATION_ACCEPTED")
		}
	}
	for _, bad := range []node{{Type: "anytls", Server: "example.com", CertificateSHA256: strings.Repeat("a", 64)}, {Type: "anytls", Server: "127.0.0.1", CA: "/never/read"}, {Type: "anytls", Server: "127.0.0.1", SkipVerify: true}} {
		if _, e := wanAssemble(bad, 11080, "SYNTHETIC_AUTH"); e == nil {
			t.Fatal("TRUST_ACCEPTED")
		}
	}
	// Explicit synthetic loopback fixture exercises THIS assembler and query
	// helper, with leaf-pin authenticated AnyTLS. Private DoH substitution is
	// confined to this offline test, never accepted by WAN policy validation.
	_, cert := runtimeCertificate(t)
	doh := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 65536))
		q := new(dns.Msg)
		if q.Unpack(raw) != nil || len(q.Question) != 1 || q.Question[0].Name != "sampler.invalid." {
			http.Error(w, "fixture", 400)
			return
		}
		dnsPerfWrite(w, unifiedDNSAnswer(q, false))
	}))
	doh.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	doh.EnableHTTP2 = true
	doh.StartTLS()
	defer doh.Close()
	_, peerPort := unifiedDNSStartPeer(t, doh.Listener.Addr().String(), cert)
	pin := sha256.Sum256(cert.Certificate[0])
	n.Port = peerPort
	n.Password = "synthetic-unified-only"
	n.CertificateSHA256 = hex.EncodeToString(pin[:])
	spare, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("FIXTURE_LISTEN")
	}
	addr := spare.Addr().String()
	port := spare.Addr().(*net.TCPAddr).Port
	spare.Close()
	cfg, e = wanAssemble(n, port, "SYNTHETIC_AUTH")
	if e != nil {
		t.Fatal("FIXTURE_ASSEMBLY")
	}
	server := cfg["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)
	server["server"] = "127.0.0.1"
	server["server_port"] = doh.Listener.Addr().(*net.TCPAddr).Port
	server["tls"] = map[string]any{"certificate_sha256": []string{base64.StdEncoding.EncodeToString(pin[:])}}
	wire, _ := json.Marshal(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	ended := make(chan error, 1)
	go func() { ended <- engine.Run(ctx, wire) }()
	defer func() {
		cancel()
		select {
		case <-ended:
		case <-time.After(3 * time.Second):
			t.Error("FIXTURE_JOIN")
		}
		l, e := net.Listen("tcp", addr)
		if e != nil {
			t.Error("FIXTURE_RELEASE")
		} else {
			l.Close()
		}
	}()
	ready := false
	until := time.Now().Add(time.Second)
	for time.Now().Before(until) {
		c, e := net.DialTimeout("tcp", addr, 20*time.Millisecond)
		if e == nil {
			c.Close()
			ready = true
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !ready {
		t.Fatal("FIXTURE_READY")
	}
	for _, typ := range []uint16{dns.TypeA, dns.TypeAAAA} {
		for i := 0; i < 2; i++ {
			code, _ := wanQuery(ctx, addr, "SYNTHETIC_AUTH", "sampler.invalid.", typ, uint16(typ)+uint16(i))
			if code != "NOERROR" {
				t.Fatal("FIXTURE_QUERY")
			}
		}
	}
}
func TestDNSWANSamplerSelection(t *testing.T) {
	var source strings.Builder
	for i := 0; i < 10; i++ {
		if i == 0 {
			source.WriteString("nodes:\n")
		}
		source.WriteString(" - {name: fixture" + strconv.Itoa(i) + ", type: anytls, server: 127.0.0.1, port: 9, password: SYNTHETIC_SECRET, client-fingerprint: golang, fingerprint: '" + strings.Repeat("a", 64) + "'}\n")
	}
	raw := []byte(source.String())
	selection := []byte("fixture3\n")
	n, e := wanSelected(raw, selection)
	if e != nil || n.Name != "fixture3" {
		t.Fatal("SELECTION_VALID")
	}
	for _, bad := range [][]byte{[]byte("other\n"), []byte("fixture3\n\n"), nil} {
		if _, e := wanSelected(raw, bad); e == nil {
			t.Fatal("SELECTION_UNSAFE")
		}
	}
	for _, bad := range []string{strings.ReplaceAll(source.String(), "fixture4", "fixture3"), strings.Replace(source.String(), "127.0.0.1", "internal.example", 4), strings.ReplaceAll(source.String(), "port: 9", "port: null"), strings.ReplaceAll(source.String(), "password: SYNTHETIC_SECRET", "password: [SYNTHETIC_SECRET]"), strings.ReplaceAll(source.String(), "type: anytls", "type: direct")} {
		if _, e := wanSelected([]byte(bad), selection); e == nil {
			t.Fatal("CONFIG_UNSAFE")
		}
	}
	// Raw source/parser diagnostics must not appear in error text.
	_, e = wanSelected([]byte("SYNTHETIC_SECRET: ["), selection)
	if e == nil || e.Error() != "CONFIG_DECODE" {
		t.Fatal("ERROR_PRIVACY")
	}
}
func TestDNSWANSamplerPrivateFiles(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "input")
	if os.WriteFile(p, []byte("SYNTHETIC"), 0600) != nil {
		t.Fatal("FIXTURE")
	}
	// Go reads update atime on some filesystems: stable identity deliberately does
	// not compare atime; metadata integrity still covers uid/gid/nlink/dev/inode.
	b, s, e := wanReadPrivate(p, os.Getuid(), 32)
	if e != nil || string(b) != "SYNTHETIC" || s == nil {
		t.Fatal("PRIVATE_READ")
	}
	if os.Chmod(p, 0644) != nil {
		t.Fatal("FIXTURE")
	}
	if _, _, e = wanReadPrivate(p, os.Getuid(), 32); e == nil {
		t.Fatal("MODE_ACCEPTED")
	}
	os.Chmod(p, 0600)
	link := filepath.Join(dir, "alias")
	if os.Symlink(p, link) != nil {
		t.Fatal("FIXTURE")
	}
	if _, _, e = wanReadPrivate(link, os.Getuid(), 32); e == nil {
		t.Fatal("SYMLINK_ACCEPTED")
	}
	hard := filepath.Join(dir, "hard")
	if os.Link(p, hard) != nil {
		t.Fatal("FIXTURE")
	}
	if _, _, e = wanReadPrivate(p, os.Getuid(), 32); e == nil {
		t.Fatal("HARDLINK_ACCEPTED")
	}
}

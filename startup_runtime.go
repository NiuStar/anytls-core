package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	st "github.com/NiuStar/anytls-core/internal/startuptimeline"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"
)

func startupCode(err error) string { return st.ResultCode(err) }
func validStartupDigest(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == s
}
func startupCoreFlags(operation, epoch string, o runtimeOptions) bool {
	return st.Validate(st.PushAck{TimelineSchema: 1, Code: "OK", OperationID: operation}) == nil && st.Validate(st.PushAck{TimelineSchema: 1, Code: "OK", OperationID: epoch}) == nil && !externalCoreRequired() && os.Geteuid() == 0 && o.Command == "run" && o.Mode == "tun" && o.RecordService && filepath.Base(o.Config) == "config.yaml"
}
func startupSpan(ctx context.Context, segment, stage string, fn func() error) error {
	r := st.FromContext(ctx)
	id := r.Begin(segment, stage, st.Fields{})
	e := fn()
	r.End(id, startupCode(e), st.Fields{})
	return e
}
func (d serviceLifecycle) withStartup(ctx context.Context, s *controlHelperServer) serviceLifecycle {
	d.startupCtx = ctx
	d.startupServer = s
	return d
}
func (d serviceLifecycle) traceRecorder() *st.Recorder {
	if d.startupCtx == nil {
		return nil
	}
	return st.FromContext(d.startupCtx)
}
func (d serviceLifecycle) traceBegin(stage string) uint64 {
	segment := d.startupSegment
	if segment == "" {
		segment = "START"
	}
	return d.traceRecorder().Begin(segment, stage, d.traceFields())
}
func (d serviceLifecycle) traceFields() st.Fields {
	f := st.Fields{}
	if d.startupRound > 0 {
		v := strconv.Itoa(d.startupRound)
		f.Round = &v
	}
	return f
}
func (d serviceLifecycle) traceEnd(span uint64, err error) {
	d.traceRecorder().End(span, startupCode(err), d.traceFields())
}
func (d serviceLifecycle) traceCapture() {
	if d.startupServer != nil {
		segment := d.startupSegment
		if segment == "" {
			segment = "START"
		}
		d.startupServer.startupCapture(d.startupCtx, segment)
	}
}
func (d serviceLifecycle) traceState(stage string) (bool, bool, error) {
	span := d.traceBegin(stage)
	l, r, e := d.state()
	f := d.traceFields()
	f.Job = "UNKNOWN"
	if e == nil {
		f.Job = "UNLOADED"
		if l {
			f.Job = "NOT_RUNNING"
		}
		if l && r {
			f.Job = "RUNNING"
		}
	}
	d.traceRecorder().End(span, startupCode(e), f)
	return l, r, e
}
func (d serviceLifecycle) traceRoute(stage, ip string) (string, error) {
	span := d.traceBegin(stage)
	v, e := d.route(ip)
	f := d.traceFields()
	f.Tun = "UNKNOWN"
	if e == nil {
		f.Tun = "NOT_TUN"
		if strings.HasPrefix(v, "utun") {
			f.Tun = "TUN"
		}
	}
	d.traceRecorder().End(span, startupCode(e), f)
	return v, e
}
func (d serviceLifecycle) traceDNS(stage string) ([]string, error) {
	span := d.traceBegin(stage)
	v, e := d.dns()
	d.traceEnd(span, e)
	return v, e
}
func (d serviceLifecycle) tracePause() {
	span := d.traceBegin("READINESS_PAUSE")
	d.pause()
	d.traceEnd(span, nil)
}
func (d serviceLifecycle) traceRemove() error {
	d.traceCapture()
	span := d.traceBegin("SNAPSHOT_REMOVE")
	e := d.owned.remove(d.remove)
	d.traceEnd(span, e)
	return e
}
type lifecycleDiagnosticsKey struct{}

func (d serviceLifecycle) finishReceipt(r *serviceDiagnostic, result *error) {
	span := d.traceBegin("RECEIPT_FINISH")
	r.startupCtx = d.startupCtx
	if r.startupCtx == nil {
		r.startupCtx = context.Background()
	}
	r.startupSegment = d.startupSegment
	r.finish(d.root, result)
	if dst, ok := r.startupCtx.Value(lifecycleDiagnosticsKey{}).(**startDiagnostics); ok && r.diagnostic != nil {
		copy := *r.diagnostic
		*dst = &copy
	}
	d.traceEnd(span, *result)
	if d.startupServer != nil && r.diagnostic != nil {
		o := startupFrom(d.startupCtx)
		if o != nil {
			d.startupServer.startup.mu.Lock()
			o.trace.ReceiptResult = startupReceiptAggregate(o.trace.ReceiptResult, r.diagnostic.Receipt)
			d.startupServer.startup.mu.Unlock()
		}
	}
}
func startupReceiptAggregate(a, b string) string { return st.AggregateReceipt(a, b) }
func (d serviceLifecycle) traceOutbounds(config string, allow bool) (servers []string, insecure bool, err error) {
	span := d.traceBegin("CONFIG_OUTBOUNDS_COMPILE")
	defer func() { d.traceEnd(span, err) }()
	return serviceOutbounds(config, allow)
}
func (d serviceLifecycle) traceReceiptCapture(r *serviceDiagnostic, stage string) {
	span := d.traceBegin(stage)
	r.capture(d.root)
	d.traceEnd(span, nil)
}
func (d serviceLifecycle) startupPlist(insecure bool) (string, error) {
	binary, config, core, log := filepath.Join(d.root, "anytls-macos"), filepath.Join(d.root, "config.yaml"), filepath.Join(d.root, "sing-box"), filepath.Join(d.root, serviceLogName)
	o := startupFrom(d.startupCtx)
	if o != nil && d.startupServer != nil && o.trace.HelperEpoch != nil {
		args := serviceArgs(binary, config, core, insecure, o.trace.OperationID, *o.trace.HelperEpoch)
		if d.startupServer.startupBind(d.startupCtx, d.root, args, d.owned, d.receipt) {
			return servicePlistStartup(binary, config, core, log, insecure, o.trace.OperationID, *o.trace.HelperEpoch)
		}
	}
	return servicePlist(binary, config, core, log, insecure)
}
func (d serviceLifecycle) traceRouteAggregateEnd(span uint64, completed int, err error) {
	f := d.traceFields()
	n := strconv.Itoa(completed)
	f.CompletedCount = &n
	if err != nil {
		v := strconv.Itoa(completed + 1)
		f.Ordinal = &v
	}
	d.traceRecorder().End(span, startupCode(err), f)
}

type startupProcessIdentity struct {
	PID       int
	UID       uint32
	Sec, Usec int64
}
type startupBinding struct {
	root, executable, config             string
	rootInfo, executableInfo, configInfo os.FileInfo
	args                                 []string
	process                              *startupProcessIdentity
	sha                                  string
}

func (b *startupBinding) check() bool {
	for _, x := range []struct {
		path string
		info os.FileInfo
	}{{b.root, b.rootInfo}, {b.executable, b.executableInfo}, {b.config, b.configInfo}} {
		info, e := os.Lstat(x.path)
		if e != nil || x.info == nil || info.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, x.info) || info.Mode() != x.info.Mode() {
			return false
		}
		if x.path != b.root && (info.Size() != x.info.Size() || !info.ModTime().Equal(x.info.ModTime())) {
			return false
		}
	}
	return true
}

// Composite authentication precedes reading even the request body. One actual
// work slot owns all blocking identity reads, framing and cache publication.
func (s *controlHelperServer) startupRootHandle(c net.Conn) {
	if !s.startupPushSlot.TryLock() {
		return
	}
	defer s.startupPushSlot.Unlock()
	s.startup.mu.Lock()
	o := s.startup.latest
	var binding *startupBinding
	if o != nil && !o.finished {
		binding = o.binding
	}
	s.startup.mu.Unlock()
	reject := func() { _ = json.NewEncoder(c).Encode(controlHelperFailure("FORBIDDEN")) }
	if binding == nil {
		reject()
		return
	}
	registration := s.startupRegistration
	if registration == nil {
		registration = controlHelperReadRegistration
	}
	reg, e := registration()
	if e != nil || reg != s.registration {
		reject()
		return
	}
	identity, e := controlHelperConfigIdentity(reg.Config)
	if e != nil || o.trace.ConfigIdentity == nil || identity != *o.trace.ConfigIdentity {
		reject()
		return
	}
	authenticate := s.startupAuthenticate
	if authenticate == nil {
		authenticate = startupAuthenticatePush
	}
	if !authenticate(c, binding) {
		s.startup.mu.Lock()
		if s.startup.latest == o && !o.finished {
			o.coreAvailability = "IDENTITY_MISMATCH"
		}
		s.startup.mu.Unlock()
		reject()
		return
	}
	_ = c.SetDeadline(time.Now().Add(500 * time.Millisecond))
	raw, e := io.ReadAll(io.LimitReader(c, st.PushBytes+1))
	timeline, frameErr := startupFrame(raw)
	if e != nil || !timeline || frameErr != nil {
		reject()
		return
	}
	var q st.PushRequest
	if st.Decode(bytes.NewReader(raw), &q) != nil {
		reject()
		return
	}
	code := "OPERATION_MISMATCH"
	reg, e = registration()
	if e != nil || reg != s.registration {
		code = "IDENTITY_MISMATCH"
	} else if current, e := controlHelperConfigIdentity(reg.Config); e != nil || current != identity {
		code = "IDENTITY_MISMATCH"
	} else if !authenticate(c, binding) {
		code = "IDENTITY_MISMATCH"
	} else {
		s.startup.mu.Lock()
		if s.startup.latest == o && !o.finished && o.binding == binding && q.OperationID == o.trace.OperationID && q.HelperEpoch == s.startup.epoch {
			code = o.acceptCore(q.Snapshot)
		}
		s.startup.mu.Unlock()
	}
	startupWrite(c, st.PushAck{TimelineSchema: 1, Code: code, OperationID: q.OperationID})
}

// The caller holds cache.mu after authenticating the exact bound process.
func (o *startupOperation) acceptCore(snapshot st.CoreSnapshot) string {
	if o.finished {
		return "OPERATION_MISMATCH"
	}
	if st.Validate(snapshot) != nil {
		return "INVALID_REQUEST"
	}
	if o.binding != nil && validStartupDigest(o.binding.sha) {
		sha := o.binding.sha
		snapshot.Stream.Provenance.SHA256 = &sha
		snapshot.Stream.Provenance.SHAKind = "FILE_BYTES"
	}
	if o.core != nil {
		old := o.core.Stream
		next := snapshot.Stream
		a, _ := strconv.ParseUint(old.GeneratedEvents, 10, 64)
		n, _ := strconv.ParseUint(next.GeneratedEvents, 10, 64)
		if old.ClockID != next.ClockID || old.OriginAt != next.OriginAt || n < a || o.core.Complete && (!snapshot.Complete || o.core.StartupResult != snapshot.StartupResult) {
			return "IDENTITY_MISMATCH"
		}
		// Cumulative snapshots cannot rewrite their previously retained prefix.
		prefix := len(old.Events)
		if len(next.Events) < prefix || !reflect.DeepEqual(old.Events, next.Events[:prefix]) {
			return "IDENTITY_MISMATCH"
		}
	}
	o.core = &snapshot
	o.coreAvailability = ""
	o.received = time.Now()
	o.receiveElapsed = o.recorder.Snapshot().ElapsedNS
	return "OK"
}
func (s *controlHelperServer) startupCapture(ctx context.Context, segment string) {
	o := startupFrom(ctx)
	if o == nil {
		return
	}
	s.startup.mu.Lock()
	observation := o.observation()
	s.startup.mu.Unlock()
	code := "UNAVAILABLE"
	if observation.Availability == "OBSERVED" {
		code = "OK"
	}
	if observation.Availability == "STALE" {
		code = "STALE"
	}
	o.recorder.Observe(segment, "CORE_SNAPSHOT_CAPTURE", code, st.Fields{})
}
func (s *controlHelperServer) startupBind(ctx context.Context, root string, args []string, owned *snapshotRootIdentity, receipt *serviceDiagnostic) bool {
	o := startupFrom(ctx)
	if o == nil {
		return false
	}
	if owned == nil || owned.info == nil || receipt == nil || receipt.startupAppInfo == nil || receipt.startupConfigInfo == nil {
		return false
	}
	b := &startupBinding{root: root, executable: filepath.Join(root, "anytls-macos"), config: filepath.Join(root, "config.yaml"), args: append([]string(nil), args...), rootInfo: owned.info, executableInfo: receipt.startupAppInfo, configInfo: receipt.startupConfigInfo, sha: receipt.Identity.App}
	s.startup.mu.Lock()
	o.binding = b
	s.startup.mu.Unlock()
	return true
}

// A once-only reporter is independent of service mutation and shutdown joins.
type startupReporter struct {
	ctx              context.Context
	recorder         *st.Recorder
	operation, epoch string
	done             chan struct{}
	once             sync.Once
}

func (r *startupReporter) finish(result string) {
	if r == nil {
		return
	}
	r.recorder.Observe("FINALIZE", "CORE_FINISH", map[bool]string{true: "OK", false: "FAILED"}[result == "SUCCEEDED"], st.Fields{})
	r.recorder.Finish(result)
	r.once.Do(func() { close(r.done) })
}

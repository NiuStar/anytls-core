package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	st "github.com/NiuStar/anytls-core/internal/startuptimeline"
	"io"
	"net"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Only memory belongs to this lock. File, kernel and launchd observations run
// outside it in the independent, single actual-work push slot.
type startupCache struct {
	mu          sync.Mutex
	epoch       string
	latest      *startupOperation
	initialized bool
}
type startupOperation struct {
	recorder         *st.Recorder
	trace            st.Trace
	core             *st.CoreSnapshot
	received         time.Time
	receiveElapsed   string
	binding          *startupBinding
	finished         bool
	coreAvailability string
}
type startupOperationKey struct{}

func startupFrom(ctx context.Context) *startupOperation {
	if ctx == nil {
		return nil
	}
	o, _ := ctx.Value(startupOperationKey{}).(*startupOperation)
	return o
}
func startupProvenance(sha string) st.Provenance {
	p := st.Provenance{SHAKind: "UNKNOWN", ExecutionMapping: "NOT_ATTESTED"}
	v := currentVersion()
	if v != "" {
		p.Version = &v
	}
	if len(sha) == 64 {
		p.SHA256 = &sha
		p.SHAKind = "FILE_BYTES"
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				v := setting.Value
				if len(v) == 40 {
					p.GitRevision = &v
				}
			case "vcs.modified":
				if setting.Value == "true" || setting.Value == "false" {
					v := setting.Value == "true"
					p.Dirty = &v
				}
			}
		}
	}
	if st.Validate(p) != nil {
		return st.Provenance{SHAKind: "UNKNOWN", ExecutionMapping: "NOT_ATTESTED"}
	}
	return p
}
func (s *controlHelperServer) startupInit() {
	s.startupOnce.Do(func() {
		s.startup.mu.Lock()
		s.startup.initialized = true
		s.startup.mu.Unlock()
		id, e := st.NewID()
		if e == nil {
			s.startup.mu.Lock()
			s.startup.epoch = id
			s.startup.mu.Unlock()
		}
	})
}
func (s *controlHelperServer) startupBegin(id, action, identity, source string) *startupOperation {
	s.startupInit()
	s.startup.mu.Lock()
	epoch := s.startup.epoch
	s.startup.mu.Unlock()
	if epoch == "" {
		return nil
	}
	r, e := st.NewRecorder("HELPER", startupProvenance(s.sha))
	if e != nil {
		return nil
	}
	o := &startupOperation{recorder: r, trace: st.Trace{Authority: st.Authority, OperationID: id, HelperEpoch: &epoch, ConfigIdentity: &identity, Operation: strings.ToUpper(action), Source: source, State: "IN_PROGRESS", LifecycleResult: "IN_PROGRESS", HelperReturn: "IN_PROGRESS", WebReturn: "NOT_ATTEMPTED", ReceiptResult: "NOT_ATTEMPTED", Streams: []st.ProcessStream{}, CoreObservation: st.CoreObservation{Availability: "NOT_OBSERVED", Gap: true}, Gap: true}}
	o.trace.StartedAt = r.Snapshot().OriginAt
	r.Observe("PREFLIGHT", "HELPER_ACCEPT", "OK", st.Fields{})
	s.startup.mu.Lock()
	s.startup.latest = o
	s.startup.mu.Unlock()
	return o
}
func (s *controlHelperServer) startupFinish(o *startupOperation, r controlHelperResponse) {
	if o == nil {
		return
	}
	// The business call and every receipt defer have returned before this point.
	result := "FAILED"
	if r.OK {
		result = "SUCCEEDED"
	}
	s.startup.mu.Lock()
	defer s.startup.mu.Unlock()
	o.finished = true
	o.recorder.Observe("FINALIZE", "HELPER_FINISH", map[bool]string{true: "OK", false: "FAILED"}[r.OK], st.Fields{})
	o.recorder.Finish(result)
	o.trace.State = "FINISHED"
	now := time.Now().UTC().Format(time.RFC3339Nano)
	o.trace.FinishedAt = &now
	o.trace.HelperReturn = result
	o.trace.LifecycleResult = result
	o.trace.Diagnostics = startupDiagnostics(r.Diagnostics)
	if r.Diagnostics != nil {
		o.trace.LifecycleResult = r.Diagnostics.Outcome
	}
}
func startupDiagnostics(d *startDiagnostics) *st.Diagnostics {
	if d == nil {
		return nil
	}
	return &st.Diagnostics{Schema: d.Schema, Operation: d.Operation, Outcome: d.Outcome, Stage: d.Stage, Reason: d.Reason, Rollback: d.Rollback, Restoration: d.Restoration, Cleanup: d.Cleanup, Receipt: d.Receipt, Job: d.Job, Tun: d.Tun}
}
func (s *controlHelperServer) startupReadCache(q st.ReadRequest) st.ReadResponse {
	s.startup.mu.Lock()
	defer s.startup.mu.Unlock()
	r := st.ReadResponse{TimelineSchema: 1, Code: "NO_OPERATION"}
	if s.startup.epoch == "" {
		if s.startup.initialized {
			r.Code = "UNAVAILABLE"
		}
		return r
	}
	epoch := s.startup.epoch
	r.HelperEpoch = &epoch
	// The cached binding is established at acceptance, never by a read-side stat.
	if s.startupIdentity != "" {
		v := s.startupIdentity
		r.ConfigIdentity = &v
	}
	o := s.startup.latest
	if o == nil {
		return r
	}
	r.OperationID = &o.trace.OperationID
	r.ConfigIdentity = o.trace.ConfigIdentity
	if q.OperationID != nil && *q.OperationID != o.trace.OperationID {
		r.Code = "OPERATION_MISMATCH"
		return r
	}
	trace := o.trace
	trace.Streams = []st.ProcessStream{o.recorder.Snapshot()}
	trace.CoreObservation = o.observation()
	trace.Gap = trace.CoreObservation.Gap || trace.Streams[0].Gap
	if o.core != nil {
		trace.Streams = append(trace.Streams, o.core.Stream)
		trace.Gap = trace.Gap || o.core.Stream.Gap || !o.core.Complete || o.finished && o.core.Stream.Terminal == nil
	}
	r.Code = "OK"
	r.Trace = &trace
	return r
}

// Caller holds cache.mu; this never contacts the core or launchd.
func (o *startupOperation) observation() st.CoreObservation {
	if o.coreAvailability != "" {
		return st.CoreObservation{Availability: o.coreAvailability, Gap: true}
	}
	if o.core == nil {
		return st.CoreObservation{Availability: "NOT_OBSERVED", Gap: true}
	}
	age := time.Since(o.received)
	if age < 0 {
		age = 0
	}
	a := strconv.FormatInt(int64(age), 10)
	receivedElapsed := o.receiveElapsed
	at := o.received.UTC().Format(time.RFC3339Nano)
	clock := o.core.Stream.ClockID
	availability := "OBSERVED"
	if age > 1500*time.Millisecond {
		availability = "STALE"
	}
	return st.CoreObservation{Availability: availability, CapturedAt: &at, HelperReceiveElapsedNS: &receivedElapsed, AgeNS: &a, ClockID: &clock, Phase: o.core.Stream.Current, Gap: o.core.Stream.Gap || !o.core.Complete}
}
func startupFrame(raw []byte) (bool, error) {
	// Scan every top-level key, including duplicates and mixed discriminators.
	d := json.NewDecoder(bytes.NewReader(raw))
	tok, e := d.Token()
	if e != nil || tok != json.Delim('{') {
		return false, st.Invalid
	}
	seen := map[string]bool{}
	timeline, records := false, false
	bad := false
	for d.More() {
		tok, e = d.Token()
		if e != nil {
			return timeline, st.Invalid
		}
		key, ok := tok.(string)
		if !ok {
			return timeline, st.Invalid
		}
		if seen[key] {
			bad = true
		}
		seen[key] = true
		if key == "timeline_schema" {
			timeline = true
		}
		if key == "schema_version" {
			records = true
		}
		var v json.RawMessage
		if d.Decode(&v) != nil {
			return timeline, st.Invalid
		}
	}
	if _, e = d.Token(); e != nil {
		return timeline, st.Invalid
	}
	if _, e = d.Token(); e != io.EOF {
		return timeline, st.Invalid
	}
	if bad || timeline && records {
		return timeline, st.Invalid
	}
	return timeline, nil
}
func startupWrite(c net.Conn, v any) {
	if b, e := st.Encode(v); e == nil {
		_, _ = c.Write(b)
	}
}
func (s *controlHelperServer) startupHandle(c net.Conn, uid uint32, raw []byte, readErr, errorFrame error) {
	var head struct {
		Action string `json:"action"`
	}
	_ = json.Unmarshal(raw, &head)
	if head.Action == "startup.push" {
		var q st.PushRequest
		if st.Decode(bytes.NewReader(raw), &q) == nil {
			startupWrite(c, st.PushAck{TimelineSchema: 1, Code: "FORBIDDEN", OperationID: q.OperationID})
		}
		return
	}
	if head.Action == "startup.read" {
		var q st.ReadRequest
		if readErr != nil || errorFrame != nil || st.Decode(bytes.NewReader(raw), &q) != nil {
			startupWrite(c, st.ReadResponse{TimelineSchema: 1, Code: "INVALID_REQUEST"})
			return
		}
		registration := s.startupRegistration
		if registration == nil {
			registration = controlHelperReadRegistration
		}
		reg, e := registration()
		if e != nil || reg != s.registration {
			startupWrite(c, st.ReadResponse{TimelineSchema: 1, Code: "FORBIDDEN"})
			return
		}
		response := s.startupReadCache(q)
		again, e := registration()
		if e != nil || again != reg {
			startupWrite(c, st.ReadResponse{TimelineSchema: 1, Code: "FORBIDDEN"})
			return
		}
		startupWrite(c, response)
		return
	}
	var q st.MutationRequest
	if readErr != nil || errorFrame != nil || st.Decode(bytes.NewReader(raw), &q) != nil {
		startupWrite(c, st.ReadResponse{TimelineSchema: 1, Code: "INVALID_REQUEST"})
		return
	}
	registration := s.startupRegistration
	if registration == nil {
		registration = controlHelperReadRegistration
	}
	reg, registrationErr := registration()
	if registrationErr != nil || reg != s.registration {
		startupWrite(c, st.ReadResponse{TimelineSchema: 1, Code: "FORBIDDEN"})
		return
	}
	identity, e := controlHelperConfigIdentity(s.registration.Config)
	if e != nil {
		startupWrite(c, st.ReadResponse{TimelineSchema: 1, Code: "HELPER_UNAVAILABLE"})
		return
	}
	_ = c.SetDeadline(time.Time{})
	r, o := s.executeStartup(controlHelperWireRequest{q.Action, q.AllowInsecure}, q.OperationID, identity, "MANUAL_"+strings.ToUpper(q.Action))
	response := st.MutationResponse{TimelineSchema: 1, Code: r.Code, OK: r.OK, TimelineAvailability: "UNAVAILABLE", ConfigIdentity: identity, Loaded: r.Loaded, Running: r.Running, Diagnostics: startupDiagnostics(r.Diagnostics)}
	p := startupProvenance(s.sha)
	response.HelperVersion = p.Version
	response.HelperSHA256 = p.SHA256
	if o != nil {
		response.HelperEpoch = o.trace.HelperEpoch
		response.OperationID = &o.trace.OperationID
		response.TimelineAvailability = "AVAILABLE"
	}
	_ = c.SetWriteDeadline(time.Now().Add(controlHelperIOTimeout))
	startupWrite(c, response)
}

type startupUnsupportedError struct{}

func (startupUnsupportedError) Error() string { return "UNSUPPORTED" }
func startupUnsupported(err error) bool {
	var target startupUnsupportedError
	return errors.As(err, &target)
}
func startupRead(ctx context.Context, operationID *string) (st.ReadResponse, error) {
	var r st.ReadResponse
	e := startupRequest(ctx, st.ReadRequest{TimelineSchema: 1, Action: "startup.read", OperationID: operationID}, &r, 2*time.Second)
	return r, e
}
func startupControl(ctx context.Context, action string, allow bool, operationID string) (st.MutationResponse, error) {
	var r st.MutationResponse
	e := startupRequest(ctx, st.MutationRequest{TimelineSchema: 1, Action: action, AllowInsecure: allow, OperationID: operationID}, &r, 6*time.Minute)
	if e == nil && !r.OK {
		e = errors.New(r.Code)
	}
	return r, e
}
func startupRequest(ctx context.Context, q, dst any, bound time.Duration) error {
	if !controlHelperSupported() {
		return st.Unavailable
	}
	if e := controlHelperValidateSocket(); e != nil {
		return st.Unavailable
	}
	c, e := (&net.Dialer{}).DialContext(ctx, "unix", controlHelperSocketPath)
	if e != nil {
		return st.Unavailable
	}
	defer c.Close()
	return startupExchange(ctx, c, q, dst, bound, controlHelperPeerUID)
}
func startupExchange(ctx context.Context, c net.Conn, q, dst any, bound time.Duration, peer func(net.Conn) (uint32, error)) error {
	uid, e := peer(c)
	if e != nil || uid != 0 {
		return st.Unavailable
	}
	b, e := st.Encode(q)
	if e != nil {
		return e
	}
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	deadline := time.Now().Add(bound)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = c.SetDeadline(deadline)
	if _, e = c.Write(b); e != nil {
		return st.Unavailable
	}
	half, ok := c.(interface{ CloseWrite() error })
	if !ok || half.CloseWrite() != nil {
		return st.Unavailable
	}
	limit := int64(st.ReadBytes)
	switch dst.(type) {
	case *st.MutationResponse, *st.PushAck:
		limit = st.LegacyBytes
	}
	raw, e := io.ReadAll(io.LimitReader(c, limit+1))
	if e != nil {
		return st.Unavailable
	}
	if st.Decode(bytes.NewReader(raw), dst) == nil {
		switch request := q.(type) {
		case st.ReadRequest:
			response, ok := dst.(*st.ReadResponse)
			if !ok {
				return st.Invalid
			}
			if request.OperationID != nil && response.Code == "OK" && (response.OperationID == nil || *response.OperationID != *request.OperationID) {
				return st.Invalid
			}
		case st.MutationRequest:
			response, ok := dst.(*st.MutationResponse)
			if !ok {
				return st.Invalid
			}
			if response.TimelineAvailability == "AVAILABLE" && (response.OperationID == nil || *response.OperationID != request.OperationID) {
				return st.Invalid
			}
		case st.PushRequest:
			response, ok := dst.(*st.PushAck)
			if !ok || response.OperationID != request.OperationID {
				return st.Invalid
			}
		}
		return nil
	}
	// Only the exact authenticated, config-bound legacy INVALID_REQUEST is a
	// capability refusal. Never turn malformed new frames into legacy fallback.
	if _, read := q.(st.ReadRequest); read && len(raw) <= st.LegacyBytes {
		var old controlHelperResponse
		if controlHelperReadResponse(bytes.NewReader(raw), &old) == nil && !old.OK && !old.Loaded && !old.Running && old.Code == "INVALID_REQUEST" && old.Message == controlHelperFailure("INVALID_REQUEST").Message && validStartupDigest(old.ConfigIdentity) && old.Diagnostics == nil {
			if response, ok := dst.(*st.ReadResponse); ok {
				*response = st.ReadResponse{TimelineSchema: 1, Code: "UNSUPPORTED", ConfigIdentity: &old.ConfigIdentity}
			}
			return startupUnsupportedError{}
		}
	}
	return st.Invalid
}

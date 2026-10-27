package startuptimeline

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"strconv"
	"sync"
	"time"
)

// Fields contains only counters and fixed observations, never raw errors.
type Fields struct {
	Round, Ordinal, RuleCount, CompletedCount *string
	Job, Tun                                  string
}

// Recorder serializes short bounded memory operations. Emit never encodes,
// invokes readers, or performs filesystem/network I/O. It is not lock-free or
// hard-real-time. A full notification channel is intentionally lossy.
type Recorder struct {
	mu                  sync.Mutex
	stream              ProcessStream
	events              [HelperHead + HelperTail]Event
	stack               [StackDepth]CurrentPhase
	depth, retained     int
	generated, nextSpan uint64
	lastElapsed         time.Duration
	origin              time.Time
	tick                func() (time.Time, time.Duration) // private deterministic test clock
	done                bool
	notify              chan struct{}
}

func NewID() (string, error) { return newID(rand.Reader) }
func newID(r io.Reader) (string, error) {
	var b [16]byte
	if _, e := io.ReadFull(r, b[:]); e != nil {
		return "", Unavailable
	}
	return hex.EncodeToString(b[:]), nil
}
func NewRecorder(role string, p Provenance) (*Recorder, error) {
	return newRecorder(role, p, time.Now(), rand.Reader, nil)
}
func newRecorder(role string, p Provenance, origin time.Time, random io.Reader, tick func() (time.Time, time.Duration)) (*Recorder, error) {
	if h, _ := capacity(role); h == 0 || !provenance(p) || !wall(origin.UTC().Format(time.RFC3339Nano)) {
		return nil, Invalid
	}
	clock, e := newID(random)
	if e != nil {
		return nil, e
	}
	return &Recorder{stream: ProcessStream{Role: role, ClockID: clock, OriginAt: origin.UTC().Format(time.RFC3339Nano), ElapsedNS: "0", Provenance: cloneProvenance(p), Events: []Event{}, GeneratedEvents: "0", DroppedEvents: "0", RetainedRanges: []SeqRange{}}, origin: origin, tick: tick, notify: make(chan struct{}, 1)}, nil
}
func (r *Recorder) now() (string, time.Duration) {
	wallNow := time.Now()
	elapsed := wallNow.Sub(r.origin)
	if r.tick != nil {
		wallNow, elapsed = r.tick()
	}
	if elapsed < r.lastElapsed {
		elapsed = r.lastElapsed
		r.stream.Gap = true
	}
	if elapsed < 0 {
		elapsed = 0
		r.stream.Gap = true
	}
	r.lastElapsed = elapsed
	return wallNow.UTC().Format(time.RFC3339Nano), elapsed
}
func (r *Recorder) signal() {
	select {
	case r.notify <- struct{}{}:
	default:
	}
}
func (r *Recorder) emit(segment, stage, state, code string, span *string, duration *string, f Fields, at string, elapsed time.Duration) bool {
	if r.generated == math.MaxUint64 {
		r.stream.Gap = true
		return false
	}
	if f.Job == "" {
		f.Job = "NOT_OBSERVED"
	}
	if f.Tun == "" {
		f.Tun = "NOT_OBSERVED"
	}
	e := Event{Seq: strconv.FormatUint(r.generated+1, 10), SpanID: span, Segment: segment, Stage: stage, State: state, Code: code, At: at, ElapsedNS: strconv.FormatInt(int64(elapsed), 10), DurationNS: duration, Round: f.Round, Ordinal: f.Ordinal, RuleCount: f.RuleCount, CompletedCount: f.CompletedCount, Job: f.Job, Tun: f.Tun}
	if !event(e) || stageRole(stage) != r.stream.Role {
		r.stream.Gap = true
		r.signal()
		return false
	}
	e = cloneEvent(e)
	r.generated++
	h, tail := capacity(r.stream.Role)
	if r.retained < h+tail {
		r.events[r.retained] = e
		r.retained++
	} else if tail > 0 {
		copy(r.events[h:h+tail-1], r.events[h+1:h+tail])
		r.events[h+tail-1] = e
	}
	r.stream.ElapsedNS = e.ElapsedNS
	if r.generated > uint64(r.retained) {
		r.stream.Gap = true
	}
	r.signal()
	return true
}
func (r *Recorder) Begin(segment, stage string, f Fields) uint64 {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.done {
		return 0
	}
	if r.depth == StackDepth || r.nextSpan == math.MaxUint64 {
		r.stream.Gap = true
		r.signal()
		return 0
	}
	at, elapsed := r.now()
	span := r.nextSpan + 1
	s := strconv.FormatUint(span, 10)
	if !r.emit(segment, stage, "BEGIN", "NONE", &s, nil, f, at, elapsed) {
		return 0
	}
	r.nextSpan = span
	r.stack[r.depth] = CurrentPhase{Stage: stage, Segment: segment, SpanID: s, BeganAt: at, BeganElapsedNS: strconv.FormatInt(int64(elapsed), 10)}
	r.depth++
	return span
}
func (r *Recorder) End(span uint64, code string, f Fields) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.done {
		return
	}
	s := strconv.FormatUint(span, 10)
	if r.depth == 0 || r.stack[r.depth-1].SpanID != s {
		r.stream.Gap = true
		r.signal()
		return
	}
	a := r.stack[r.depth-1]
	at, elapsed := r.now()
	start, _ := dec(a.BeganElapsedNS)
	duration := strconv.FormatUint(uint64(elapsed)-start, 10)
	if r.emit(a.Segment, a.Stage, "END", code, &s, &duration, f, at, elapsed) {
		r.depth--
	}
}
func (r *Recorder) Observe(segment, stage, code string, f Fields) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.done {
		return
	}
	at, elapsed := r.now()
	var span *string
	if r.depth > 0 {
		s := r.stack[r.depth-1].SpanID
		span = &s
	}
	r.emit(segment, stage, "OBSERVATION", code, span, nil, f, at, elapsed)
}
func (r *Recorder) Finish(result string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.done {
		return
	}
	if !in(result, "SUCCEEDED FAILED CANCELLED UNKNOWN") {
		r.stream.Gap = true
		r.signal()
		return
	}
	at, elapsed := r.now()
	r.stream.ElapsedNS = strconv.FormatInt(int64(elapsed), 10)
	r.stream.Terminal = &Terminal{result, at, r.stream.ElapsedNS}
	if r.depth != 0 {
		r.stream.Gap = true
	}
	r.depth = 0
	r.done = true
	r.signal()
}
func (r *Recorder) Snapshot() ProcessStream {
	if r == nil {
		return ProcessStream{Gap: true}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.done {
		_, elapsed := r.now()
		r.stream.ElapsedNS = strconv.FormatInt(int64(elapsed), 10)
	}
	s := r.stream
	s.Provenance = cloneProvenance(s.Provenance)
	s.Events = make([]Event, r.retained)
	for i := range s.Events {
		s.Events[i] = cloneEvent(r.events[i])
	}
	h, tail := capacity(s.Role)
	s.RetainedRanges = ranges(r.generated, h, tail)
	s.GeneratedEvents = strconv.FormatUint(r.generated, 10)
	s.DroppedEvents = strconv.FormatUint(r.generated-uint64(r.retained), 10)
	if r.generated > uint64(r.retained) {
		f := strconv.Itoa(h + 1)
		s.FirstMissingSeq = &f
	}
	if r.depth > 0 {
		p := r.stack[r.depth-1]
		s.Current = &p
	}
	if s.Terminal != nil {
		t := *s.Terminal
		s.Terminal = &t
	}
	return s
}
func (r *Recorder) Notifications() <-chan struct{} {
	if r == nil {
		return nil
	}
	return r.notify
}

type contextKey struct{}

func WithRecorder(ctx context.Context, r *Recorder) context.Context {
	return context.WithValue(ctx, contextKey{}, r)
}
func FromContext(ctx context.Context) *Recorder {
	r, _ := ctx.Value(contextKey{}).(*Recorder)
	return r
}
func ResultCode(err error) string {
	if err == nil {
		return "OK"
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "CANCELLED"
	}
	return "FAILED"
}
func AggregateReceipt(a, b string) string {
	if !receipt(a) || !receipt(b) {
		return "UNKNOWN"
	}
	for _, x := range []string{"FAILED", "UNKNOWN", "WRITTEN"} {
		if a == x || b == x {
			return x
		}
	}
	return "NOT_ATTEMPTED"
}
func capacity(role string) (int, int) {
	switch role {
	case "HELPER":
		return HelperHead, HelperTail
	case "CORE":
		return CoreEvents, 0
	case "WEB":
		return WebEvents, 0
	}
	return 0, 0
}
func ranges(n uint64, head, tail int) []SeqRange {
	out := []SeqRange{}
	if n == 0 {
		return out
	}
	if n <= uint64(head+tail) || tail == 0 {
		last := n
		if last > uint64(head+tail) {
			last = uint64(head + tail)
		}
		return append(out, SeqRange{"1", strconv.FormatUint(last, 10)})
	}
	return append(out, SeqRange{"1", strconv.Itoa(head)}, SeqRange{strconv.FormatUint(n-uint64(tail)+1, 10), strconv.FormatUint(n, 10)})
}
func cloneString(s *string) *string {
	if s == nil {
		return nil
	}
	x := *s
	return &x
}
func cloneEvent(e Event) Event {
	e.SpanID = cloneString(e.SpanID)
	e.DurationNS = cloneString(e.DurationNS)
	e.Round = cloneString(e.Round)
	e.Ordinal = cloneString(e.Ordinal)
	e.RuleCount = cloneString(e.RuleCount)
	e.CompletedCount = cloneString(e.CompletedCount)
	return e
}
func cloneProvenance(p Provenance) Provenance {
	p.Version = cloneString(p.Version)
	p.GitRevision = cloneString(p.GitRevision)
	p.SHA256 = cloneString(p.SHA256)
	if p.Dirty != nil {
		x := *p.Dirty
		p.Dirty = &x
	}
	return p
}

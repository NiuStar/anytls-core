// Package trafficstats counts only SDK routed TCP/UDP tracker transport payload.
// ICMP and raw Flow packets (including their headers and payload) are excluded.
package trafficstats

import (
	"math"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	cr "github.com/NiuStar/anytls-core/internal/connectionrecords"
)

const Source = "SDK_ROUTED_PAYLOAD"
const MaxHistory = 1440
const MaxBytes = 512 << 10
const FreshFor = 15 * time.Second

type Counter struct {
	up, down  atomic.Uint64
	saturated atomic.Bool
}

func (c *Counter) add(a *atomic.Uint64, n int64) {
	if c == nil || n <= 0 {
		return
	}
	for {
		old := a.Load()
		next := old + uint64(n)
		if uint64(n) > math.MaxUint64-old {
			next = math.MaxUint64
			c.saturated.Store(true)
		}
		if a.CompareAndSwap(old, next) {
			return
		}
	}
}
func (c *Counter) Upload(n int64) {
	if c != nil {
		c.add(&c.up, n)
	}
}
func (c *Counter) Download(n int64) {
	if c != nil {
		c.add(&c.down, n)
	}
}
func (c *Counter) Totals() (uint64, uint64, bool) {
	if c == nil {
		return 0, 0, false
	}
	return c.up.Load(), c.down.Load(), c.saturated.Load()
}

type Interval struct {
	StartNS  cr.Decimal `json:"start_ns"`
	EndNS    cr.Decimal `json:"end_ns"`
	Upload   cr.Decimal `json:"upload_bytes"`
	Download cr.Decimal `json:"download_bytes"`
}
type Snapshot struct {
	TrafficSchema int        `json:"traffic_schema"`
	Header        cr.Header  `json:"header"`
	Source        string     `json:"source"`
	State         string     `json:"state"`
	SampledAt     string     `json:"sampled_at"`
	ElapsedNS     cr.Decimal `json:"elapsed_ns"`
	Upload        cr.Decimal `json:"upload_bytes"`
	Download      cr.Decimal `json:"download_bytes"`
	Saturated     bool       `json:"saturated"`
	Rate          *Interval  `json:"rate"`
	History       []Interval `json:"history"`
}
type Read struct {
	Action        string `json:"action"`
	TrafficSchema int    `json:"traffic_schema"`
}
type Response struct {
	TrafficSchema int       `json:"traffic_schema"`
	Availability  string    `json:"availability"`
	Snapshot      *Snapshot `json:"snapshot"`
}

func Request() Read               { return Read{"traffic.read", 1} }
func Unavailable() Response       { return Response{1, "UNAVAILABLE", nil} }
func decimal(n uint64) cr.Decimal { return cr.Decimal(strconv.FormatUint(n, 10)) }
func value(d cr.Decimal) uint64   { n, _ := d.Uint64(); return n }

// Sampler uses a process monotonic clock only. Disk history is never imported.
// A minute interval describes the actual span, including scheduler delays.
type Sampler struct {
	mu                                     sync.Mutex
	counter                                *Counter
	header                                 cr.Header
	start, previous, bucket                time.Time
	prevUp, prevDown, bucketUp, bucketDown uint64
	previousRunning                        bool
	history                                []Interval
}

func New(c *Counter, h cr.Header) *Sampler {
	return &Sampler{counter: c, header: h, history: []Interval{}}
}
func (s *Sampler) Sample(now time.Time, state string) Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	up, down, saturated := s.counter.Totals()
	var rate *Interval
	if s.start.IsZero() {
		s.start = now
		s.bucket = now
		s.bucketUp = up
		s.bucketDown = down
	}
	elapsed := now.Sub(s.start)
	if elapsed < 0 {
		elapsed = 0
	}
	validClock := s.previous.IsZero() || now.After(s.previous)
	running := state == "RUNNING" && validClock && !saturated
	if !validClock {
		state = "UNAVAILABLE"
	}
	// Reset the unfinished bucket across gaps; never call startup or unavailable
	// time a running rate/history interval.
	if !running || !s.previousRunning {
		s.bucket, s.bucketUp, s.bucketDown = now, up, down
	}
	if running && s.previousRunning && up >= s.prevUp && down >= s.prevDown {
		v := Interval{decimal(uint64(s.previous.Sub(s.start))), decimal(uint64(elapsed)), decimal(up - s.prevUp), decimal(down - s.prevDown)}
		rate = &v
	}
	if state == "RUNNING" && !saturated && now.Sub(s.bucket) >= time.Minute && up >= s.bucketUp && down >= s.bucketDown {
		s.history = append(s.history, Interval{decimal(uint64(s.bucket.Sub(s.start))), decimal(uint64(elapsed)), decimal(up - s.bucketUp), decimal(down - s.bucketDown)})
		s.bucket = now
		s.bucketUp = up
		s.bucketDown = down
	}
	cutoff := elapsed - 24*time.Hour
	for len(s.history) > 0 && (len(s.history) > MaxHistory || time.Duration(value(s.history[0].StartNS)) < cutoff) {
		s.history = s.history[1:]
	}
	// A negative clock/overflow is fail closed, never a fabricated delta.
	if !s.previous.IsZero() && !now.After(s.previous) {
		state = "UNAVAILABLE"
		rate = nil
	}
	s.previousRunning = running
	s.previous = now
	s.prevUp = up
	s.prevDown = down
	history := append([]Interval{}, s.history...)
	return Snapshot{1, s.header, Source, state, now.UTC().Format(time.RFC3339Nano), decimal(uint64(elapsed)), decimal(up), decimal(down), saturated, rate, history}
}

func Validate(v any) error {
	switch x := v.(type) {
	case Read:
		if x != Request() {
			return cr.ErrInvalid
		}
	case Response:
		if x.TrafficSchema != 1 || x.Availability != "OBSERVED" && x.Availability != "UNAVAILABLE" || (x.Availability == "OBSERVED") != (x.Snapshot != nil) {
			return cr.ErrInvalid
		}
		if x.Snapshot != nil {
			if x.Snapshot.State != "RUNNING" || x.Snapshot.Saturated {
				return cr.ErrInvalid
			}
			return Validate(*x.Snapshot)
		}
	case Snapshot:
		if x.TrafficSchema != 1 || cr.Validate(x.Header) != nil || x.Source != Source || (x.State != "STARTING" && x.State != "RUNNING" && x.State != "CLOSED" && x.State != "UNAVAILABLE") || len(x.History) > MaxHistory || x.History == nil {
			return cr.ErrInvalid
		}
		if _, e := time.Parse(time.RFC3339Nano, x.SampledAt); e != nil || x.SampledAt[len(x.SampledAt)-1:] != "Z" {
			return cr.ErrInvalid
		}
		for _, d := range []cr.Decimal{x.ElapsedNS, x.Upload, x.Download} {
			if _, e := d.Uint64(); e != nil {
				return cr.ErrInvalid
			}
		}
		if value(x.ElapsedNS) > math.MaxInt64 || x.State != "RUNNING" && x.Rate != nil || x.Saturated && x.Rate != nil {
			return cr.ErrInvalid
		}
		check := func(i Interval) bool {
			for _, d := range []cr.Decimal{i.StartNS, i.EndNS, i.Upload, i.Download} {
				if _, e := d.Uint64(); e != nil {
					return false
				}
			}
			return value(i.StartNS) < value(i.EndNS) && value(i.EndNS) <= value(x.ElapsedNS) && value(i.Upload) <= value(x.Upload) && value(i.Download) <= value(x.Download)
		}
		if x.Rate != nil && (!check(*x.Rate) || x.Rate.EndNS != x.ElapsedNS) {
			return cr.ErrInvalid
		}
		var end, historyUp, historyDown uint64
		for _, i := range x.History {
			if !check(i) || value(i.StartNS) < end || value(x.ElapsedNS)-value(i.StartNS) > uint64(24*time.Hour) || value(i.EndNS)-value(i.StartNS) < uint64(time.Minute) {
				return cr.ErrInvalid
			}
			// Subtract before adding: disjoint retained deltas must fit the
			// cumulative totals, even at MaxUint64, without wrapping the sum.
			if value(i.Upload) > value(x.Upload)-historyUp || value(i.Download) > value(x.Download)-historyDown {
				return cr.ErrInvalid
			}
			historyUp += value(i.Upload)
			historyDown += value(i.Download)
			if r := x.Rate; r != nil && value(r.StartNS) >= value(i.StartNS) && value(r.EndNS) <= value(i.EndNS) && (value(r.Upload) > value(i.Upload) || value(r.Download) > value(i.Download)) {
				return cr.ErrInvalid
			}
			end = value(i.EndNS)
		}
	default:
		return cr.ErrInvalid
	}
	return nil
}
func Encode(v any) ([]byte, error) {
	if e := Validate(v); e != nil {
		return nil, e
	}
	return cr.EncodeBounded(v, MaxBytes)
}
func Decode(b []byte, out any) error {
	if e := cr.DecodeStrict(b, out, MaxBytes); e != nil {
		return e
	}
	switch v := out.(type) {
	case *Read:
		return Validate(*v)
	case *Response:
		return Validate(*v)
	case *Snapshot:
		return Validate(*v)
	}
	return cr.ErrInvalid
}

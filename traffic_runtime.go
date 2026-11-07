package main

import (
	"context"
	"os"
	"sync"
	"sync/atomic"
	"time"

	cr "github.com/NiuStar/anytls-core/internal/connectionrecords"
	ts "github.com/NiuStar/anytls-core/internal/trafficstats"
)

const trafficObservationInterval = 250 * time.Millisecond
const trafficHeartbeatInterval = 5 * time.Second

// One bounded reporter owns all sampling/encoding/storage. A slow or failed
// disk can delay the reporter, never the SDK counter or core shutdown result.
type runTrafficReporter struct {
	counter *ts.Counter
	running atomic.Bool
	stop    chan struct{}
	done    chan struct{}
	once    sync.Once
	lease   atomic.Pointer[os.File]
}

// Compare semantic changes, not timestamps/rate interval endpoints. Publish the
// first zero interval after a burst too, so readers cannot retain a stale rate.
// Only the reporter goroutine owns this state; counter callbacks stay atomic-only.
type trafficPublication struct {
	last                             time.Time
	up, down                         cr.Decimal
	state                            string
	saturated, rateValid, rateActive bool
}

func (p *trafficPublication) due(now time.Time, s ts.Snapshot) bool {
	valid := s.Rate != nil
	active := valid && (s.Rate.Upload != "0" || s.Rate.Download != "0")
	if !p.last.IsZero() && s.Upload == p.up && s.Download == p.down && s.State == p.state && s.Saturated == p.saturated && valid == p.rateValid && active == p.rateActive && now.Sub(p.last) < trafficHeartbeatInterval {
		return false
	}
	*p = trafficPublication{now, s.Upload, s.Download, s.State, s.Saturated, valid, active}
	return true
}

func newRunTrafficReporter() *runTrafficReporter {
	return &runTrafficReporter{counter: new(ts.Counter), stop: make(chan struct{}), done: make(chan struct{})}
}
func (p *runTrafficReporter) start(w *cr.Writer) {
	lease, e := w.OpenTrafficLease()
	if e != nil {
		close(p.done)
		return
	}
	p.lease.Store(lease)
	select {
	case <-p.stop:
		p.releaseLease()
		close(p.done)
		return
	default:
	}
	sampler := ts.New(p.counter, w.TrafficHeader())
	go p.report(sampler, time.Now, func(s ts.Snapshot) error { return w.PublishTraffic(s, ts.MaxBytes) })
}

// The injectable clock and sink keep cadence tests on this actual loop without
// opening a privileged production store. Production still uses PublishTraffic's
// unchanged fsync/atomic publication, authority checks and bounded codec.
func (p *runTrafficReporter) report(sampler *ts.Sampler, now func() time.Time, publish func(ts.Snapshot) error) {
	defer close(p.done)
	defer p.releaseLease()
	ticker := time.NewTicker(trafficObservationInterval)
	defer ticker.Stop()
	var policy trafficPublication
	for {
		select {
		case <-p.stop:
			return
		default:
		}
		state := "STARTING"
		if p.running.Load() {
			state = "RUNNING"
		}
		at := now()
		// Always advance sampling, including suppressed idle polls: minute history
		// and next-tick zero deltas must not depend on the disk publication cadence.
		snap := sampler.Sample(at, state)
		if policy.due(at, snap) {
			if _, e := ts.Encode(snap); e != nil {
				return
			}
			if e := publish(snap); e != nil {
				return
			}
		}
		// Do not catch up a queued tick after slow encoding/storage: even a
		// delayed disk must not cause back-to-back durable publications.
		ticker.Reset(trafficObservationInterval)
		select {
		case <-p.stop:
			return
		case <-ticker.C:
		}
	}
}
func (p *runTrafficReporter) releaseLease() {
	if lease := p.lease.Swap(nil); lease != nil {
		_ = lease.Close()
	}
}
func (p *runTrafficReporter) close() {
	// Invalidate observation immediately even when a filesystem call is stuck.
	p.once.Do(func() { close(p.stop); p.releaseLease() })
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	select {
	case <-p.done:
	case <-ctx.Done():
	}
}

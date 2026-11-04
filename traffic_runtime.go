package main

import (
	"context"
	cr "github.com/NiuStar/anytls-core/internal/connectionrecords"
	ts "github.com/NiuStar/anytls-core/internal/trafficstats"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

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
	go func() {
		defer close(p.done)
		defer p.releaseLease()
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			state := "STARTING"
			if p.running.Load() {
				state = "RUNNING"
			}
			snap := sampler.Sample(time.Now(), state)
			if _, e := ts.Encode(snap); e != nil {
				return
			}
			if e := w.PublishTraffic(snap, ts.MaxBytes); e != nil {
				return
			}
			select {
			case <-p.stop:
				return
			case <-ticker.C:
			}
		}
	}()
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

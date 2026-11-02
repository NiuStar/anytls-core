package main

import (
	"context"
	de "github.com/NiuStar/anytls-core/internal/dnsevidence"
	"sync"
	"time"
)

type dnsObservationKey struct{}
type dnsObservation struct{ operation, epoch string }

func withDNSObservation(ctx context.Context, operation, epoch string) context.Context {
	return context.WithValue(ctx, dnsObservationKey{}, dnsObservation{operation, epoch})
}

// One owned sender, no notification backlog. It snapshots only after Start and
// is joined at bounded shutdown. Sending failure never enters the DNS return path.
func launchDNSReporter(ctx context.Context, c *de.Collector, config string, send func(context.Context, de.Push) error) func() {
	o, ok := ctx.Value(dnsObservationKey{}).(dnsObservation)
	if !ok || c == nil {
		return func() {}
	}
	identity, e := controlHelperConfigIdentity(config)
	if e != nil {
		return func() {}
	}
	done := make(chan struct{})
	stop := make(chan struct{})
	var once sync.Once
	go func() {
		defer close(done)
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ctx.Done():
				return
			case <-tick.C:
				snapshot := c.Snapshot()
				if snapshot.State == "STARTING" {
					continue
				}
				q := de.Push{DNSSchema: 1, Action: "dns.push", HelperEpoch: o.epoch, OperationID: o.operation, ConfigIdentity: identity, Binding: c.Binding(), Snapshot: snapshot}
				work, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
				_ = send(work, q)
				cancel()
			}
		}
	}()
	return func() {
		once.Do(func() { close(stop) })
		select {
		case <-done:
		case <-time.After(650 * time.Millisecond):
		}
	}
}

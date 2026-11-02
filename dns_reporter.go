package main

import (
	"context"
	de "github.com/NiuStar/anytls-core/internal/dnsevidence"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type dnsObservationKey struct{}
type dnsObservation struct{ operation, epoch string }

type dnsReporterAuthorityKey struct{}
type dnsReporterAuthority struct {
	registration func() (controlHelperRegistration, error)
	protected    func(string, bool) error
}

// The namespace comes only from protected registration. The supplied runtime
// path must be the exact protected service snapshot derived FROM registration,
// never a guessed parent of an arbitrary caller path. Helper independently
// verifies the captured inode, launchd process and complete argv on each push.
func dnsReporterProtectedSnapshot(path string, directory bool) error {
	info, e := os.Lstat(path)
	if e != nil || info.Mode()&os.ModeSymlink != 0 || !controlHelperRootOwned(info) {
		return de.Invalid
	}
	if directory {
		if !info.IsDir() || info.Mode().Perm() != 0700 {
			return de.Invalid
		}
	} else if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return de.Invalid
	}
	return nil
}

func dnsReporterConfigIdentity(ctx context.Context, config string) (string, error) {
	a := dnsReporterAuthority{controlHelperReadRegistration, dnsReporterProtectedSnapshot}
	if simulated, ok := ctx.Value(dnsReporterAuthorityKey{}).(dnsReporterAuthority); ok {
		a = simulated
	}
	reg, e := a.registration()
	if e != nil || reg.UID == 0 {
		return "", de.Invalid
	}
	staged := filepath.Join(filepath.Dir(reg.Config), "service", "config.yaml")
	if config != staged || a.protected(filepath.Dir(staged), true) != nil || a.protected(staged, false) != nil {
		return "", de.Invalid
	}
	return controlHelperConfigIdentity(reg.Config)
}

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
	identity, e := dnsReporterConfigIdentity(ctx, config)
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

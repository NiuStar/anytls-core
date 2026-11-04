package main

import (
	"context"
	cr "github.com/NiuStar/anytls-core/internal/connectionrecords"
	ts "github.com/NiuStar/anytls-core/internal/trafficstats"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func trafficFixture(s *controlHelperServer) ts.Snapshot {
	identity, _ := controlHelperConfigIdentity(s.registration.Config)
	c := new(ts.Counter)
	c.Upload(9007199254740993)
	c.Download(31)
	return ts.New(c, recordsTestPage(identity).Header).Sample(time.Now(), "RUNNING")
}
func TestTrafficHelperRealUnixReadOnlyAndBinding(t *testing.T) {
	s := recordsTestServer(t)
	snap := trafficFixture(s)
	s.trafficStoreRead = func(_ context.Context, scope cr.Scope, out any, _ int) (cr.Header, error) {
		if scope.UID != 501 || scope.ConfigIdentity != snap.Header.ConfigIdentity {
			t.Error("bad scope")
		}
		*out.(*ts.Snapshot) = snap
		return snap.Header, nil
	}
	s.mutation.Lock()
	defer s.mutation.Unlock()
	c, _ := unitControlPair(t, s)
	r, e := trafficExchange(context.Background(), c, func(net.Conn) (uint32, error) { return 0, nil })
	if e != nil || r.Availability != "OBSERVED" || r.Snapshot.Upload != "9007199254740993" {
		t.Fatal(r, e)
	}
	for _, kind := range []string{"binding", "previous-binding", "expired", "source", "closed", "saturated", "registration"} {
		t.Run(kind, func(t *testing.T) {
			bad := snap
			s.recordsRegistration = func() (controlHelperRegistration, error) { return s.registration, nil }
			switch kind {
			case "binding":
				bad.Header.ConfigIdentity = strings.Repeat("f", 64)
			case "previous-binding":
				prior := bad.Header.Binding
				bad.Header.PreviousBinding = &prior
			case "expired":
				bad.SampledAt = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)
			case "source":
				bad.Source = "NIC"
			case "closed":
				bad.State = "CLOSED"
			case "saturated":
				bad.Saturated = true
			case "registration":
				s.recordsRegistration = func() (controlHelperRegistration, error) { r := s.registration; r.UID++; return r, nil }
			}
			s.trafficStoreRead = func(context.Context, cr.Scope, any, int) (cr.Header, error) {
				return cr.Header{}, cr.TelemetryUnavailable
			}
			if kind != "registration" {
				s.trafficStoreRead = func(_ context.Context, _ cr.Scope, out any, _ int) (cr.Header, error) {
					*out.(*ts.Snapshot) = bad
					return snap.Header, nil
				}
			}
			if r := s.trafficRead(context.Background()); r.Availability != "UNAVAILABLE" || r.Snapshot != nil {
				t.Fatal("accepted", kind)
			}
		})
	}
}
func TestTrafficHelperMalformedAndPeerNoRead(t *testing.T) {
	s := recordsTestServer(t)
	calls := 0
	s.trafficStoreRead = func(context.Context, cr.Scope, any, int) (cr.Header, error) { calls++; return cr.Header{}, nil }
	for _, raw := range []string{`{"action":"traffic.read","traffic_schema":1,"path":"/etc/passwd"}`, `{"action":"traffic.read","traffic_schema":1,"traffic_schema":1}`, `{"action":"traffic.read"}`, `{"action":"traffic.read","traffic_schema":2}`} {
		b := recordsRaw(t, s, []byte(raw))
		var r ts.Response
		if ts.Decode(b, &r) != nil || r.Availability != "UNAVAILABLE" {
			t.Fatal(string(b))
		}
	}
	if calls != 0 {
		t.Fatal("invalid request accessed store")
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if _, e := trafficExchange(context.Background(), a, func(net.Conn) (uint32, error) { return 501, nil }); e != cr.Forbidden {
		t.Fatal(e)
	}
}

func TestTrafficExchangeOldHelperAndCancellation(t *testing.T) {
	for _, kind := range []string{"legacy", "oversize", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(unitControlSocketDir(t), "old.sock"), Net: "unix"})
			if e != nil {
				t.Fatal(e)
			}
			defer listener.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan struct{})
			go func() {
				defer close(done)
				s, e := listener.AcceptUnix()
				if e != nil {
					return
				}
				defer s.Close()
				s.SetDeadline(time.Now().Add(time.Second))
				io.ReadAll(s)
				switch kind {
				case "legacy":
					io.WriteString(s, `{"ok":false,"code":"UNSUPPORTED_ACTION"}`)
				case "oversize":
					io.WriteString(s, strings.Repeat(" ", ts.MaxBytes+1))
				case "cancel":
					cancel()
					io.Copy(io.Discard, s)
				}
			}()
			c, e := net.DialUnix("unix", nil, listener.Addr().(*net.UnixAddr))
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			r, e := trafficExchange(ctx, c, func(net.Conn) (uint32, error) { return 0, nil })
			if e == nil || r.Availability != "UNAVAILABLE" || r.Snapshot != nil {
				t.Fatal(r, e)
			}
			<-done
		})
	}
}

func TestTrafficReporterStopImmediatelyReleasesLease(t *testing.T) {
	p := newRunTrafficReporter()
	f, e := os.OpenFile(filepath.Join(t.TempDir(), "lease"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		t.Fatal(e)
	}
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		t.Fatal(e)
	}
	p.lease.Store(f)
	done := make(chan struct{})
	go func() { p.close(); close(done) }()
	deadline := time.Now().Add(200 * time.Millisecond)
	for p.lease.Load() != nil && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if p.lease.Load() != nil {
		t.Fatal("Stop left live lease while reporter blocked")
	}
	probe, e := os.OpenFile(f.Name(), os.O_RDWR, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer probe.Close()
	if e = syscall.Flock(int(probe.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		t.Fatal("lease still held", e)
	}
	close(p.done)
	<-done
	p.close()
	failed := newRunTrafficReporter()
	failed.start(nil)
	failed.close()
}

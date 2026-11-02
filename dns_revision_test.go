package main

import (
	"context"
	"errors"
	de "github.com/NiuStar/anytls-core/internal/dnsevidence"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These assertions use existing APIs and compile on the exact held candidate.
func TestDNSRejectedPeerPreservesBinding(t *testing.T) {
	w, _ := webFixture(t)
	identity, _ := controlHelperConfigIdentity(w.configPath)
	s := &controlHelperServer{registration: controlHelperRegistration{UID: 501, Config: w.configPath}, peer: func(net.Conn) (uint32, error) { return 0, nil }}
	s.startupRegistration = func() (controlHelperRegistration, error) { return s.registration, nil }
	s.startupAuthenticate = func(net.Conn, *startupBinding) bool { return false }
	s.dnsBind(&startupBinding{}, strings.Repeat("e", 32), strings.Repeat("f", 32), identity)
	c, _ := unitControlPair(t, s)
	defer c.Close()
	var ack de.Ack
	raw := make([]byte, 1024)
	n, e := c.Read(raw)
	if e != nil || de.Decode(raw[:n], &ack) != nil || ack.Code != "FORBIDDEN" {
		t.Fatalf("reject: %s %v", raw[:n], e)
	}
	s.dns.mu.Lock()
	alive := s.dns.binding != nil
	s.dns.mu.Unlock()
	if !alive {
		t.Fatal("untrusted root peer erased legitimate DNS binding")
	}
}

func TestDNSStaleFailurePreservesReplacement(t *testing.T) {
	w, _ := webFixture(t)
	identity, _ := controlHelperConfigIdentity(w.configPath)
	s := &controlHelperServer{registration: controlHelperRegistration{UID: 501, Config: w.configPath}, peer: func(net.Conn) (uint32, error) { return 0, nil }}
	s.dnsBind(&startupBinding{}, strings.Repeat("e", 32), strings.Repeat("f", 32), identity)
	var replacement *startupBinding
	s.startupRegistration = func() (controlHelperRegistration, error) {
		s.dnsBind(&startupBinding{}, strings.Repeat("1", 32), strings.Repeat("2", 32), identity)
		s.dns.mu.Lock()
		replacement = s.dns.binding
		s.dns.mu.Unlock()
		return controlHelperRegistration{}, errors.New("old registration read failed")
	}
	c, _ := unitControlPair(t, s)
	defer c.Close()
	raw := make([]byte, 1024)
	_, _ = c.Read(raw)
	s.dns.mu.Lock()
	alive := s.dns.binding == replacement
	s.dns.mu.Unlock()
	if !alive {
		t.Fatal("stale A failure erased replacement B")
	}
}

func TestDNSProgressRetainedPrefix(t *testing.T) {
	c := de.New(de.Binding{InstanceID: strings.Repeat("a", 32), Generation: strings.Repeat("b", 32), ManifestID: strings.Repeat("c", 64), RuntimeSHA256: strings.Repeat("d", 64)})
	c.Loaded()
	for i := 0; i < 2; i++ {
		c.Complete(de.Event{TransportID: "1", QType: "A", Outcome: "NOERROR", Validation: "MATCHED", DurationNS: "1", Connections: de.Connections{Acquisitions: "0", New: "0", Reused: "0", Idle: "0"}})
	}
	a := c.Snapshot()
	b := c.Snapshot()
	b.Events = b.Events[1:]
	if dnsSnapshotProgress(a, b) {
		t.Fatal("lost retained prefix without dropped/GAP proof")
	}
}

// Two actual independent files, not symlinks or inferred source path.
func TestDNSReporterSourceNamespace(t *testing.T) {
	w, _ := webFixture(t)
	root := filepath.Join(filepath.Dir(w.configPath), "service")
	if e := os.Mkdir(root, 0700); e != nil {
		t.Fatal(e)
	}
	staged := filepath.Join(root, "config.yaml")
	raw, e := os.ReadFile(w.configPath)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(staged, raw, 0600); e != nil {
		t.Fatal(e)
	}
	expected, _ := controlHelperConfigIdentity(w.configPath)
	c := de.New(de.Binding{InstanceID: strings.Repeat("a", 32), Generation: strings.Repeat("b", 32), ManifestID: strings.Repeat("c", 64), RuntimeSHA256: strings.Repeat("d", 64)})
	c.Loaded()
	ctx := withDNSObservation(context.Background(), strings.Repeat("e", 32), strings.Repeat("f", 32))
	// Runtime authority is supplied by a private context seam in the successor;
	// baseline ignores it and hashes staged path, producing the business RED.
	ctx = context.WithValue(ctx, dnsReporterAuthorityKey{}, dnsReporterAuthority{
		registration: func() (controlHelperRegistration, error) {
			return controlHelperRegistration{UID: 501, Config: w.configPath}, nil
		},
		protected: func(string, bool) error { return nil }, // UNIT-SIMULATED protected root ownership.
	})
	got := make(chan de.Push, 1)
	stop := launchDNSReporter(ctx, c, staged, func(_ context.Context, q de.Push) error {
		select {
		case got <- q:
		default:
		}
		return nil
	})
	defer stop()
	select {
	case q := <-got:
		if q.ConfigIdentity != expected {
			t.Fatal("reporter associated staged identity instead of registered source namespace")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reporter did not send")
	}
}

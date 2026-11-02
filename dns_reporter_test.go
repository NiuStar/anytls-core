package main

import (
	"context"
	"errors"
	de "github.com/NiuStar/anytls-core/internal/dnsevidence"
	"strings"
	"testing"
	"time"
)

func TestDNSReporterBoundedFailure(t *testing.T) {
	c := de.New(de.Binding{InstanceID: strings.Repeat("a", 32), Generation: strings.Repeat("b", 32), ManifestID: strings.Repeat("c", 64), RuntimeSHA256: strings.Repeat("d", 64)})
	c.Loaded()
	w, _ := webFixture(t)
	ctx := withDNSObservation(context.Background(), strings.Repeat("e", 32), strings.Repeat("f", 32))
	entered := make(chan struct{})
	returned := make(chan struct{})
	stop := launchDNSReporter(ctx, c, w.configPath, func(work context.Context, q de.Push) error {
		close(entered)
		<-work.Done()
		close(returned)
		return errors.New("private sender failure")
	})
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("sender missing")
	}
	before := time.Now()
	for i := 0; i < 100; i++ {
		c.Complete(de.Event{TransportID: "1", QType: "A", Outcome: "NOERROR", Validation: "NOT_OBSERVED", DurationNS: "1", Connections: de.Connections{Acquisitions: "0", New: "0", Reused: "0", Idle: "0"}})
	}
	if time.Since(before) > 100*time.Millisecond {
		t.Fatal("slow observer blocked hooks")
	}
	stop()
	select {
	case <-returned:
	default:
		t.Fatal("owned sender not joined")
	}
	if len(c.Snapshot().Events) != 64 {
		t.Fatal("sender affected collector")
	}
}

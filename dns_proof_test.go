package main

import (
	"context"
	"errors"
	de "github.com/NiuStar/anytls-core/internal/dnsevidence"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDNSReporterRejectsUnboundConfig(t *testing.T) {
	w, _ := webFixture(t)
	staged := filepath.Join(filepath.Dir(w.configPath), "service", "config.yaml")
	for _, mode := range []string{"wrong_registration", "arbitrary_config", "unprotected_snapshot", "registration_failure"} {
		t.Run(mode, func(t *testing.T) {
			config := staged
			ctx := context.WithValue(context.Background(), dnsReporterAuthorityKey{}, dnsReporterAuthority{
				registration: func() (controlHelperRegistration, error) {
					if mode == "registration_failure" {
						return controlHelperRegistration{}, errors.New("unavailable")
					}
					source := w.configPath
					if mode == "wrong_registration" {
						source = filepath.Join(t.TempDir(), "config.yaml")
						os.WriteFile(source, []byte("independent"), 0600)
					}
					return controlHelperRegistration{UID: 501, Config: source}, nil
				},
				protected: func(string, bool) error {
					if mode == "unprotected_snapshot" {
						return errors.New("untrusted")
					}
					return nil
				},
			})
			if mode == "arbitrary_config" {
				config = w.configPath
			}
			if _, e := dnsReporterConfigIdentity(ctx, config); e == nil {
				t.Fatal("associated arbitrary snapshot with registered source")
			}
		})
	}
}

func TestDNSProgressProofMatrix(t *testing.T) {
	c := de.New(de.Binding{InstanceID: strings.Repeat("a", 32), Generation: strings.Repeat("b", 32), ManifestID: strings.Repeat("c", 64), RuntimeSHA256: strings.Repeat("d", 64)})
	c.Loaded()
	event := de.Event{TransportID: "1", QType: "A", Outcome: "NOERROR", Validation: "MATCHED", DurationNS: "1", Connections: de.Connections{Acquisitions: "0", New: "0", Reused: "0", Idle: "0"}}
	for i := 0; i < 64; i++ {
		c.Complete(event)
	}
	a := c.Snapshot()
	c.Complete(event)
	b := c.Snapshot()
	if !dnsSnapshotProgress(a, b) {
		t.Fatal("legitimate ring eviction rejected")
	}
	for _, mode := range []string{"drop_without_count", "drop_without_gap", "future_revision", "rewrite", "elapsed_regression", "dropped_regression"} {
		t.Run(mode, func(t *testing.T) {
			next := de.Clone(b)
			switch mode {
			case "drop_without_count":
				next.Coverage.Dropped = "0"
			case "drop_without_gap":
				next.Coverage.Gap = false
			case "future_revision":
				next.Revision = "18446744073709551615"
			case "rewrite":
				next.Events[0].Outcome = "TIMEOUT"
			case "elapsed_regression":
				next.ElapsedNS = "0"
			case "dropped_regression":
				next.Coverage.Dropped = "0"
			}
			if dnsSnapshotProgress(a, next) {
				t.Fatal("invalid proof accepted", mode)
			}
		})
	}
	// Missed reporter sends legitimately skip revisions. Do not guess prev+1.
	c.Snapshot()
	c.Snapshot()
	next := c.Snapshot()
	if !dnsSnapshotProgress(b, next) {
		t.Fatal("missed reporter sends rejected")
	}
}

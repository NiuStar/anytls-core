package engine

import (
	"context"
	"errors"
	"strings"
	"testing"

	de "github.com/NiuStar/anytls-core/internal/dnsevidence"
)

type dnsEvidenceCancelOnWait struct {
	context.Context
	cancel context.CancelFunc
}

func (c dnsEvidenceCancelOnWait) Done() <-chan struct{} {
	c.cancel()
	return c.Context.Done()
}

// Listener readiness and even a completed DNS operation can precede Start's
// return. Cancel at that exact boundary rather than relying on scheduler luck.
func TestDNSEvidenceLifecycleCloseOrdering(t *testing.T) {
	for _, mode := range []string{"cancel-during-start", "cancel-with-start-error", "already-canceled", "loaded-stop", "close-error", "check-only"} {
		t.Run(mode, func(t *testing.T) {
			c := de.New(de.Binding{InstanceID: strings.Repeat("a", 32), Generation: strings.Repeat("b", 32), ManifestID: strings.Repeat("c", 64), RuntimeSHA256: strings.Repeat("d", 64)})
			ctx, cancel := context.WithCancel(WithDNSEvidence(context.Background(), c))
			defer cancel()
			startErr, closeErr := errors.New("start fixture"), errors.New("close fixture")
			if mode == "already-canceled" {
				cancel()
			}
			starts, closes := 0, 0
			probe := lifecycleProbe{
				start: func() error {
					starts++
					if c.Snapshot().State != "STARTING" {
						t.Error("collector claimed loaded before Start returned")
					}
					if mode != "loaded-stop" && mode != "close-error" {
						cancel()
					}
					if mode == "cancel-with-start-error" {
						return startErr
					}
					return nil
				},
				close: func() error {
					closes++
					if c.Snapshot().State == "CLOSED" {
						t.Error("collector CLOSED before owned resource Close completed")
					}
					if mode == "close-error" {
						return closeErr
					}
					return nil
				},
			}
			var runCtx context.Context = ctx
			if mode == "loaded-stop" || mode == "close-error" {
				runCtx = dnsEvidenceCancelOnWait{Context: ctx, cancel: cancel}
			}
			running := mode != "check-only"
			err := execute(runCtx, probe, running)
			if !running {
				if err != nil || starts != 0 || closes != 1 || c.Snapshot().State != "STARTING" {
					t.Fatalf("check-only changed run state: err=%v starts=%d closes=%d state=%s", err, starts, closes, c.Snapshot().State)
				}
				return
			}
			if !errors.Is(err, context.Canceled) || mode == "cancel-with-start-error" && !errors.Is(err, startErr) || mode == "close-error" && !errors.Is(err, closeErr) {
				t.Fatalf("lifecycle errors lost: %v", err)
			}
			wantStarts := 1
			if mode == "already-canceled" {
				wantStarts = 0
			}
			if starts != wantStarts || closes != 1 {
				t.Fatalf("starts=%d closes=%d", starts, closes)
			}
			if state := c.Snapshot().State; state != "CLOSED" {
				t.Fatalf("collector after joined shutdown = %s, want CLOSED", state)
			}
		})
	}
}

//go:build with_upstream_cleanup_patch

package engine

import (
	"context"
	"errors"
	"testing"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/service"
)

type upstreamStartError struct{ message string }

func (e *upstreamStartError) Error() string { return e.message }

type upstreamCloseError struct{ message string }

func (e *upstreamCloseError) Error() string { return e.message }

// This private fixture replaces only the inbound constructor. Box.New, the
// managers, Scope, Start and Close are real upstream code, not a mock lifecycle.
type cleanupInbound struct {
	startErr, closeErr error
	closes             int
}

func (p *cleanupInbound) Type() string { return "mixed" }
func (p *cleanupInbound) Tag() string  { return "cleanup-regression" }
func (p *cleanupInbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage == adapter.StartStateStart {
		// Only one cleanup sentinel: Scope's own multi-error policy is out of scope.
		scope.Add(func() error { p.closes++; return p.closeErr })
		return p.startErr
	}
	return nil
}

type cleanupInboundRegistry struct {
	adapter.InboundRegistry
	probe *cleanupInbound
}

func (r cleanupInboundRegistry) Create(context.Context, adapter.Router, log.ContextLogger, string, string, any) (adapter.Inbound, error) {
	return r.probe, nil
}

func TestUpstreamStartPreservesCleanupErrors(t *testing.T) {
	for _, sameMessage := range []bool{false, true} {
		name, closeMessage := "distinct-message", "fixture-close"
		if sameMessage {
			name, closeMessage = "equal-text-distinct-identity", "fixture-start"
		}
		t.Run(name, func(t *testing.T) {
			startErr := &upstreamStartError{"fixture-start"}
			closeErr := &upstreamCloseError{closeMessage}
			probe := &cleanupInbound{startErr: startErr, closeErr: closeErr}
			ctx, options, err := decodeOptions(context.Background(), loopbackConfig(0))
			if err != nil {
				t.Fatal(err)
			}
			ctx = service.ContextWith[adapter.InboundRegistry](ctx, cleanupInboundRegistry{
				InboundRegistry: service.FromContext[adapter.InboundRegistry](ctx), probe: probe,
			})
			instance, err := box.New(box.Options{Options: options, Context: ctx})
			if err != nil {
				t.Fatal(err)
			}
			startResult := instance.Start()
			finalClose := instance.Close()
			if finalClose != nil || probe.closes != 1 {
				t.Errorf("second Close=%v; cleanup calls=%d, want nil/1", finalClose, probe.closes)
			}
			if !errors.Is(startResult, startErr) || !errors.Is(startResult, closeErr) {
				t.Errorf("Start lost error identity: start=%t cleanup=%t: %v", errors.Is(startResult, startErr), errors.Is(startResult, closeErr), startResult)
			}
			var gotStart *upstreamStartError
			var gotClose *upstreamCloseError
			if !errors.As(startResult, &gotStart) || gotStart != startErr || !errors.As(startResult, &gotClose) || gotClose != closeErr {
				t.Error("Start lost custom typed errors.As identity")
			}
		})
	}
}

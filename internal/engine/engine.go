package engine

import (
	"context"
	"errors"
	"strings"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
)

// operationError retains the cause for errors.Is/As without formatting upstream
// errors, which may contain user-provided fields (including credentials).
type operationError struct {
	stage string
	cause error
}

func (e *operationError) Error() string {
	if strings.Contains(e.cause.Error(), "uTLS is not included in this build") {
		return "embedded engine " + e.stage + ": uTLS is not included in this build; rebuild with -tags with_utls"
	}
	return "embedded engine " + e.stage + " failed"
}

func (e *operationError) Unwrap() error { return e.cause }

func lifecycleError(stage string, err error) error {
	if err == nil {
		return nil
	}
	return &operationError{stage: stage, cause: err}
}

// Check decodes and constructs a real Box, then closes it without ever starting
// it. It does not bind listeners or open TUN devices. Logging is disabled.
func Check(ctx context.Context, runtimeJSON []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ctx, options, err := decodeOptions(ctx, runtimeJSON)
	if err != nil {
		return err
	}
	instance, err := box.New(box.Options{Options: options, Context: ctx})
	if err != nil {
		return lifecycleError("construct", err)
	}
	return execute(ctx, instance, false)
}

// Run constructs and starts a real Box and waits for caller cancellation.
// Cancellation at any stage, including a normal requested stop, returns an
// error matching ctx.Err() via errors.Is. Cleanup errors are joined, never
// substituted for cancellation/start errors. Callers may treat context.Canceled
// as normal shutdown. No signals or process-global lifecycle are installed.
// Startup is synchronous: the inherited context cancels upstream startup, then
// cleanup runs after Start returns, never concurrently with resource allocation.
// Upstream v1.14.3 Start also auto-closes on failure but discards that internal
// Close error. Our final Close is still called, but cannot recover that error;
// this upstream limitation must be resolved before claiming lossless startup
// cleanup diagnostics.
func Run(ctx context.Context, runtimeJSON []byte) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, options, err := decodeOptions(ctx, runtimeJSON)
	if err != nil {
		return err
	}
	instance, err := box.New(box.Options{Options: options, Context: ctx})
	if err != nil {
		return lifecycleError("construct", err)
	}
	return execute(ctx, instance, true)
}

// execute is the only test seam; construction always uses the real box.New.
func execute(ctx context.Context, instance adapter.SimpleLifecycle, start bool) (err error) {
	defer func() {
		err = errors.Join(err, lifecycleError("close", instance.Close()))
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	if !start {
		return nil
	}
	if err := instance.Start(); err != nil {
		return errors.Join(ctx.Err(), lifecycleError("start", err))
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	<-ctx.Done()
	return ctx.Err()
}

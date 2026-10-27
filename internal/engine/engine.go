package engine

import (
	"context"
	"errors"
	"strconv"
	"strings"

	cr "github.com/NiuStar/anytls-core/internal/connectionrecords"
	st "github.com/NiuStar/anytls-core/internal/startuptimeline"

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
func Run(ctx context.Context, runtimeJSON []byte) error {
	return RunWithRecords(ctx, runtimeJSON, nil)
}

func RunWithRecords(ctx context.Context, runtimeJSON []byte, records *RecordsInput) (err error) {
	if records != nil {
		if reporter, ok := records.Sink.(cr.ProvenanceReporter); ok {
			reporter.SetProvenanceStatus(cr.ProvenanceUnknown)
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	recorder := st.FromContext(ctx)
	span := recorder.Begin("START", "CORE_DECODE", st.Fields{})
	ctx, options, err := decodeOptions(ctx, runtimeJSON)
	fields := st.Fields{}
	if err == nil && options.Route != nil {
		count := strconv.Itoa(len(options.Route.Rules))
		fields.RuleCount = &count
	}
	recorder.End(span, timelineCode(err), fields)
	if err != nil {
		return err
	}
	caVerified := false
	if records != nil && (records.Sink != nil || records.OpenSink != nil) {
		span = recorder.Begin("START", "CORE_PIN_CA", st.Fields{})
		caVerified = pinRecordsCA(&options, records.Manifest)
		recorder.End(span, map[bool]string{true: "OK", false: "UNAVAILABLE"}[caVerified], st.Fields{})
	}
	span = recorder.Begin("START", "CORE_BOX_NEW", st.Fields{})
	instance, err := box.New(box.Options{Options: options, Context: ctx})
	recorder.End(span, timelineCode(err), st.Fields{})
	if err != nil {
		return lifecycleError("construct", err)
	}
	if records != nil && records.Sink == nil && records.OpenSink != nil && ctx.Err() == nil {
		// Keep the caller's input immutable and open durable recording only once
		// runtime validation has succeeded. No second decode or Box is needed.
		input := *records
		span = recorder.Begin("START", "CORE_OPEN_SINK", st.Fields{})
		input.Sink = input.OpenSink()
		recorder.End(span, map[bool]string{true: "OK", false: "UNAVAILABLE"}[input.Sink != nil], st.Fields{})
		records = &input
		if reporter, ok := records.Sink.(cr.ProvenanceReporter); ok {
			reporter.SetProvenanceStatus(cr.ProvenanceUnknown)
		}
	}
	if records != nil && records.Sink != nil {
		span = recorder.Begin("START", "CORE_BIND_RECORDS", st.Fields{})
		instance.Router().AppendTracker(bindRecords(instance, runtimeJSON, records, caVerified))
		recorder.End(span, "OK", st.Fields{})
		return executeRecords(ctx, instance, true, records.StopAdmission)
	}
	return execute(ctx, instance, true)
}

// execute is the only test seam; construction always uses the real box.New.
func execute(ctx context.Context, instance adapter.SimpleLifecycle, start bool) error {
	return executeRecords(ctx, instance, start, nil)
}

func executeRecords(ctx context.Context, instance adapter.SimpleLifecycle, start bool, stopAdmission func()) (err error) {
	recorder := st.FromContext(ctx)
	defer func() {
		if stopAdmission != nil {
			stopAdmission()
		}
		span := recorder.Begin("FINALIZE", "CORE_CLOSE", st.Fields{})
		closeErr := instance.Close()
		recorder.End(span, timelineCode(closeErr), st.Fields{})
		err = errors.Join(err, lifecycleError("close", closeErr))
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	if !start {
		return nil
	}
	span := recorder.Begin("START", "CORE_START", st.Fields{})
	startErr := instance.Start()
	recorder.End(span, timelineCode(startErr), st.Fields{})
	if err := startErr; err != nil {
		return errors.Join(ctx.Err(), lifecycleError("start", err))
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	recorder.Observe("START", "CORE_WAIT", "OK", st.Fields{})
	<-ctx.Done()
	return ctx.Err()
}

func timelineCode(err error) string {
	if err == nil {
		return "OK"
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "CANCELLED"
	}
	return "FAILED"
}

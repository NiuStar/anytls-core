package engine

import (
	"context"
	"errors"
	"testing"

	cr "github.com/NiuStar/anytls-core/internal/connectionrecords"
)

func TestRecordsOpenOnlyAfterValidation(t *testing.T) {
	for _, raw := range []string{
		`{`,
		`{"outbounds":[{"type":"socks"}]}`,
		`{"outbounds":[{"type":"direct","tag":"d"},{"type":"direct","tag":"d"}]}`,
		`{"outbounds":[{"type":"anytls","server":"127.0.0.1","server_port":9,"password":"x","tls":{"enabled":true,"certificate_sha256":["bad"]}}]}`,
		`{"outbounds":[{"type":"anytls","server":"127.0.0.1","server_port":9,"password":"x","tls":{"enabled":true,"min_version":"invalid"}}]}`,
	} {
		calls := 0
		err := RunWithRecords(context.Background(), []byte(raw), &RecordsInput{OpenSink: func() cr.Sink { calls++; return nil }})
		if err == nil || calls != 0 {
			t.Fatalf("invalid runtime: err=%v opens=%d", err, calls)
		}
	}
}

func TestRecordsOpenFailureContinuesAndCancellationCloses(t *testing.T) {
	for _, available := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		calls, stops := 0, 0
		input := &RecordsInput{OpenSink: func() cr.Sink {
			calls++
			cancel()
			if available {
				return &recordsTestSink{}
			}
			return nil
		}, StopAdmission: func() { stops++ }}
		err := RunWithRecords(ctx, loopbackConfig(), input)
		if !errors.Is(err, context.Canceled) || calls != 1 {
			t.Fatalf("err=%v opens=%d", err, calls)
		}
		if input.Sink != nil {
			t.Fatal("caller input mutated")
		}
		if available && stops != 1 {
			t.Fatalf("stop calls %d", stops)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	err := RunWithRecords(ctx, []byte(`{`), &RecordsInput{OpenSink: func() cr.Sink { calls++; return nil }})
	if !errors.Is(err, context.Canceled) || calls != 0 {
		t.Fatal("pre-canceled run decoded/opened")
	}
}

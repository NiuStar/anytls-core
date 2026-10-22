package engine

import (
	"context"
	"errors"
	"testing"
)

func TestProbeCanceledAndRejectsNonAnyTLS(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Probe(ctx, []byte(`{}`)); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation not preserved")
	}
	if _, err := Probe(context.Background(), []byte(`{"outbounds":[{"type":"direct","tag":"anytls-out"}]}`)); err == nil {
		t.Fatal("non AnyTLS outbound accepted")
	}
	if _, err := probeHTTPS(context.Background(), nil, "http://127.0.0.1/", nil); err == nil {
		t.Fatal("non HTTPS endpoint accepted")
	}
	if probeEndpoint != "https://www.gstatic.com/generate_204" {
		t.Fatal("production endpoint changed")
	}
}

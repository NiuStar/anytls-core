package telemetry

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRealHTTPSDeadlineDoesNotPublishLatency(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(entered); <-release; w.WriteHeader(204) }))
	defer server.Close()
	defer close(release)
	trust := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- probeHTTPS(ctx, server.URL, trust) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("fixture did not enter HTTPS handler")
	}
	var err error
	select {
	case err = <-result:
	case <-time.After(time.Second):
		t.Fatal("deadline did not cancel probe")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout lost: %v", err)
	}
	now := time.Now()
	s := New("")
	s.Record(now.Add(-80*time.Millisecond), now, err)
	if g := s.Snapshot(now); g.Network.Attempts != 1 || g.Network.Succeeded != 0 || g.Network.LatencyMS != nil || g.Network.LatestError == nil || *g.Network.LatestError != "TIMEOUT" {
		t.Fatal(g.Network)
	}
}

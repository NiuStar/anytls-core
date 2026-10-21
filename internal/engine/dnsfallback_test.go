package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// The real proxy compiler can omit DNS. Check alone did not expose upstream's
// StartStateInitialize local fallback; exercise Run without any DNS block.
func TestRunWithoutDNSUsesLocalFallback(t *testing.T) {
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("no-dns:" + r.URL.Path))
	}))
	defer fixture.Close()
	port := freeLoopbackPort(t)
	content := []byte(fmt.Sprintf(`{"inbounds":[{"type":"mixed","listen":"127.0.0.1","listen_port":%d}],"outbounds":[{"type":"direct","tag":"direct"}]}`, port))
	if err := Check(context.Background(), content); err != nil {
		t.Fatalf("no-DNS Check failed: %v", err)
	}
	assertBindable(t, port)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, content) }()
	waited := false
	defer func() {
		cancel()
		if !waited {
			awaitRun(t, done)
		}
	}()
	proxy, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	deadline := time.Now().Add(5 * time.Second)
	for {
		response, err := client.Get(fixture.URL + "/literal-loopback-only")
		if err == nil {
			body, readErr := io.ReadAll(response.Body)
			response.Body.Close()
			if readErr != nil || response.StatusCode != http.StatusOK || string(body) != "no-dns:/literal-loopback-only" {
				t.Fatal("no-DNS direct loopback forwarding failed")
			}
			break
		}
		select {
		case runErr := <-done:
			waited = true
			t.Fatalf("no-DNS Run exited before forwarding: %v", runErr)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("no-DNS proxy never forwarded")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	err = awaitRun(t, done)
	waited = true
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("no-DNS Run lost cancellation: %v", err)
	}
	assertBindable(t, port)
}

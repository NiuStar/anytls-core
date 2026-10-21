package engine

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	stdjson "encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/socks"
	singjson "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
)

// Preserve the original explicit HTTPS fixture. It bypasses upstream's implicit
// local fallback; TestRunWithoutDNSUsesLocalFallback covers that startup path.
// Neither fixture makes a DNS request.
func loopbackConfig(ports ...int) []byte {
	inbounds := ""
	for i, port := range ports {
		if i > 0 {
			inbounds += ","
		}
		inbounds += fmt.Sprintf(`{"type":"mixed","tag":"in-%d","listen":"127.0.0.1","listen_port":%d}`, i, port)
	}
	return []byte(fmt.Sprintf(`{"log":{"disabled":true},"inbounds":[%s],"outbounds":[{"type":"direct","tag":"direct"}],"dns":{"servers":[{"type":"https","tag":"fixture","server":"127.0.0.1","server_port":9}]}}`, inbounds))
}

func holdLoopback(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	return listener
}

func freeLoopbackPort(t *testing.T) int {
	t.Helper()
	listener := holdLoopback(t)
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func awaitRun(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not finish within 5 seconds")
		return nil
	}
}

func assertBindable(t *testing.T, port int) {
	t.Helper()
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("listener not freed: %v", err)
	}
	listener.Close()
}

func TestRunForwardsLoopbackThenStops(t *testing.T) {
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("fixture:" + r.URL.Path))
	}))
	defer fixture.Close()
	port := freeLoopbackPort(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, loopbackConfig(port)) }()
	proxy, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	deadline := time.Now().Add(5 * time.Second)
	for {
		response, err := client.Get(fixture.URL + "/local-only")
		if err == nil {
			body, readErr := io.ReadAll(response.Body)
			response.Body.Close()
			if readErr != nil || response.StatusCode != http.StatusOK || string(body) != "fixture:/local-only" {
				t.Fatalf("local forwarding failed: status=%d body=%q err=%v", response.StatusCode, body, readErr)
			}
			break
		}
		select {
		case runErr := <-done:
			t.Fatalf("Run exited before forwarding: %v", runErr)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("proxy never forwarded: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := awaitRun(t, done); !errors.Is(err, context.Canceled) {
		t.Fatalf("requested stop must preserve cancellation: %v", err)
	}
	assertBindable(t, port)
}

// This narrow seam supplements real-Box tests: producing a Close error and
// pausing exactly inside Start are not available through the supported config.
type lifecycleProbe struct {
	start func() error
	close func() error
}

func (p lifecycleProbe) Start() error { return p.start() }
func (p lifecycleProbe) Close() error { return p.close() }

func TestLifecycleCloseErrors(t *testing.T) {
	closeErr := errors.New("fixture-close-error")
	startErr := errors.New("fixture-start-error")
	for _, tt := range []struct {
		name     string
		start    bool
		startErr error
	}{
		{"check", false, nil},
		{"run-stop", true, nil},
		{"run-partial-start", true, startErr},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			starts, closes := 0, 0
			probe := lifecycleProbe{
				start: func() error { starts++; cancel(); return tt.startErr },
				close: func() error { closes++; return closeErr },
			}
			err := execute(ctx, probe, tt.start)
			if !errors.Is(err, closeErr) || (tt.startErr != nil && !errors.Is(err, startErr)) {
				t.Fatalf("lifecycle errors lost: %v", err)
			}
			if closes != 1 || (tt.start && starts != 1) || (!tt.start && starts != 0) {
				t.Fatalf("starts=%d closes=%d", starts, closes)
			}
		})
	}
}

func TestLifecycleCancellationDuringStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered, release := make(chan struct{}), make(chan struct{})
	closed := make(chan struct{})
	probe := lifecycleProbe{
		start: func() error { close(entered); <-ctx.Done(); <-release; return nil },
		close: func() error { close(closed); return nil },
	}
	done := make(chan error, 1)
	go func() { done <- execute(ctx, probe, true) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("Start not called")
	}
	cancel()
	select {
	case <-closed:
		t.Fatal("Close raced resource allocation in Start")
	default:
	}
	close(release)
	if err := awaitRun(t, done); !errors.Is(err, context.Canceled) {
		t.Fatalf("startup cancellation lost: %v", err)
	}
	select {
	case <-closed:
	default:
		t.Fatal("startup cancellation did not close")
	}
}

// These regressions cover the real implementation after the tracer-bullet
// slices. They are verification-after, not claimed as independent test-first REDs.
func TestBoundaryOwnsRegistry(t *testing.T) {
	type parentKey struct{}
	parent, cancel := context.WithTimeout(context.WithValue(context.Background(), parentKey{}, "kept"), time.Minute)
	defer cancel()
	parent = Context(parent)
	wide := outbound.NewRegistry()
	direct.RegisterOutbound(wide)
	socks.RegisterOutbound(wide)
	parent = service.ContextWith[adapter.OutboundRegistry](parent, wide)
	parent = service.ContextWith[option.OutboundOptionsRegistry](parent, wide)
	unsupported := []byte(`{"outbounds":[{"type":"socks","server":"127.0.0.1","server_port":9}]}`)
	if _, err := singjson.UnmarshalExtendedContext[option.Options](Context(parent), unsupported); err != nil {
		t.Fatalf("fixture must demonstrate Context reuses broader parent: %v", err)
	}
	for name, call := range map[string]func(context.Context, []byte) error{"Check": Check, "Run": Run} {
		t.Run(name, func(t *testing.T) {
			err := call(parent, unsupported)
			var stageErr *operationError
			if !errors.As(err, &stageErr) || stageErr.stage != "decode options" {
				t.Fatal("broader parent must be rejected during decoding, not later startup")
			}
		})
	}
	owned, _, err := decodeOptions(parent, loopbackConfig())
	if err != nil {
		t.Fatal(err)
	}
	if owned.Value(parentKey{}) != "kept" {
		t.Fatal("lost parent value")
	}
	wantDeadline, _ := parent.Deadline()
	if got, ok := owned.Deadline(); !ok || !got.Equal(wantDeadline) {
		t.Fatal("lost parent deadline")
	}
	if service.RegistryFromContext(owned) == service.RegistryFromContext(parent) {
		t.Fatal("registry not owned")
	}
	if got := service.FromContext[option.OutboundOptionsRegistry](owned).OptionTypes(); !slices.Equal(got, []string{"anytls", "direct"}) {
		t.Fatalf("owned types = %v", got)
	}
	if err := Check(parent, loopbackConfig()); err != nil {
		t.Fatal(err)
	}
	if service.FromContext[adapter.OutboundRegistry](parent) != wide || service.FromContext[adapter.Router](parent) != nil {
		t.Fatal("Box construction mutated caller registry")
	}
	cancel()
	if !errors.Is(owned.Err(), context.Canceled) {
		t.Fatal("lost parent cancellation")
	}
}

func TestRejectsInvalidOptionsWithoutLeaking(t *testing.T) {
	const secret = "FIXTURE-SECRET-NOT-FOR-OUTPUT"
	for _, config := range []string{
		`{"` + secret + `":true}`,
		`{"outbounds":[{"type":"` + secret + `","password":"` + secret + `"}]}`,
		`{"inbounds":[{"type":"mixed","listen":"` + secret + `"}]}`,
		`{"outbounds":[{"type":"anytls","server":"127.0.0.1","server_port":9,"password":"` + secret + `"}]}`,
		`{"outbounds":[{"type":"direct","tag":"` + secret + `"},{"type":"direct","tag":"` + secret + `"}]}`,
		`{"inbounds":[{"type":"mixed","listen_port":70000}]}`,
		`{"log":{"level":"not-a-level"}}`,
		`{"outbounds":[{"type":"selector"}]}`,
		`{`,
		`{} {}`,
	} {
		for _, call := range []func(context.Context, []byte) error{Check, Run} {
			err := call(context.Background(), []byte(config))
			if err == nil {
				t.Fatal("invalid config accepted")
			}
			if strings.Contains(fmt.Sprintf("%v %+v %#v", err, err, err), secret) {
				t.Fatal("error exposed input")
			}
		}
	}
}

func TestPreCanceledBoundary(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, call := range []func(context.Context, []byte) error{Check, Run} {
		if err := call(ctx, loopbackConfig()); !errors.Is(err, context.Canceled) {
			t.Fatalf("pre-cancel = %v", err)
		}
	}
	ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if err := Run(ctx, loopbackConfig()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("pre-deadline = %v", err)
	}
}

func TestRunOccupiedPortCleansPartialStart(t *testing.T) {
	occupied := holdLoopback(t)
	occupiedPort := occupied.Addr().(*net.TCPAddr).Port
	for i := 0; i < 3; i++ {
		firstPort := freeLoopbackPort(t)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := Run(ctx, loopbackConfig(firstPort, occupiedPort))
		cancel()
		if err == nil || errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("must fail starting second listener: %v", err)
		}
		var listenErr *net.OpError
		if !errors.As(err, &listenErr) || listenErr.Addr == nil || listenErr.Addr.String() != occupied.Addr().String() {
			t.Fatalf("failure did not reach the second occupied listener: %v", err)
		}
		var stageErr *operationError
		if !errors.As(err, &stageErr) || stageErr.stage != "start" {
			t.Fatalf("not a Start error: %v", err)
		}
		assertBindable(t, firstPort)
	}
}

func TestRunCancellationDuringRealStartup(t *testing.T) {
	entered, finished := make(chan struct{}), make(chan struct{})
	var once sync.Once
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(entered) })
		<-r.Context().Done()
		close(finished)
	}))
	defer fixture.Close()
	port := freeLoopbackPort(t)
	var config map[string]any
	if err := stdjson.Unmarshal(loopbackConfig(port), &config); err != nil {
		t.Fatal(err)
	}
	config["route"] = map[string]any{"rule_set": []any{map[string]any{"type": "remote", "tag": "blocked-fixture", "format": "source", "url": fixture.URL + "/rules.json"}}}
	content, err := stdjson.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, content) }()
	select {
	case <-entered:
	case err := <-done:
		t.Fatalf("startup failed before local fetch: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("startup did not reach local fixture")
	}
	cancel()
	if err := awaitRun(t, done); !errors.Is(err, context.Canceled) {
		t.Fatalf("real startup cancellation = %v", err)
	}
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("startup request/socket not canceled")
	}
	assertBindable(t, port)
}

func TestRunRepeatedResources(t *testing.T) {
	// First warm the runtime poller before counting descriptors/goroutines.
	TestRunForwardsLoopbackThenStops(t)
	countFDs := func() int {
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		return len(entries)
	}
	if runtime.GOOS != "linux" {
		t.Skip("/proc FD accounting is Linux-only")
	}
	baselineFD, baselineG := countFDs(), runtime.NumGoroutine()
	for i := 0; i < 5; i++ {
		TestRunForwardsLoopbackThenStops(t)
	}
	deadline := time.Now().Add(3 * time.Second)
	for countFDs() > baselineFD || runtime.NumGoroutine() > baselineG+2 {
		if time.Now().After(deadline) {
			t.Fatalf("resource growth: fd %d -> %d; goroutines %d -> %d", baselineFD, countFDs(), baselineG, runtime.NumGoroutine())
		}
		runtime.GC()
		time.Sleep(10 * time.Millisecond)
	}
}

func TestLibrarySuppressesConfiguredLogFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "must-not-be-written.log")
	config := []byte(fmt.Sprintf(`{"log":{"level":"trace","output":%q},"outbounds":[{"type":"direct"}]}`, path))
	if err := Check(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("library wrote configured log file: %v", err)
	}
}

func TestUTLSConstructor(t *testing.T) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		t.Fatal("cannot determine test build tags")
	}
	var tags string
	for _, setting := range info.Settings {
		if setting.Key == "-tags" {
			tags = setting.Value
		}
	}
	if tags == "" {
		t.Fatal("test invocation must set explicit build tags")
	}
	withUTLS := slices.Contains(strings.Split(tags, ","), "with_utls")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-only CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	config := map[string]any{"outbounds": []any{map[string]any{"type": "anytls", "server": "127.0.0.1", "server_port": 9, "password": "constructor-fixture-only", "tls": map[string]any{"enabled": true, "server_name": "fixture.invalid", "certificate": []string{ca}, "utls": map[string]any{"enabled": true, "fingerprint": "chrome"}}}}}
	content, err := stdjson.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	err = Check(context.Background(), content)
	if withUTLS {
		if err != nil {
			t.Fatalf("real uTLS constructor failed: %v", err)
		}
		// A bad fingerprint must not silently fall back to normal TLS.
		config["outbounds"].([]any)[0].(map[string]any)["tls"].(map[string]any)["utls"].(map[string]any)["fingerprint"] = "not-a-fingerprint"
		bad, _ := stdjson.Marshal(config)
		if Check(context.Background(), bad) == nil {
			t.Fatal("invalid uTLS fingerprint accepted")
		}
	} else if err == nil || !strings.Contains(err.Error(), "uTLS is not included in this build") {
		t.Fatalf("missing-utls stub must fail explicitly: %v", err)
	}
}

func TestCheckConstructsWithoutStarting(t *testing.T) {
	listener := holdLoopback(t)
	port := listener.Addr().(*net.TCPAddr).Port
	if err := Check(context.Background(), loopbackConfig(port)); err != nil {
		t.Fatalf("Check must construct/close without binding an occupied port: %v", err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := Check(context.Background(), loopbackConfig(port)); err != nil {
		t.Fatal(err)
	}
	rebound, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("Check left a listener: %v", err)
	}
	rebound.Close()
}

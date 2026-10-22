//go:build with_utls

package engine

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	anytls "github.com/anytls/sing-anytls"
	"github.com/anytls/sing-anytls/padding"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type probeFixtureHandler struct {
	target string
	wg     sync.WaitGroup
}

func (h *probeFixtureHandler) NewConnectionEx(ctx context.Context, conn net.Conn, _ M.Socksaddr, destination M.Socksaddr, _ N.CloseHandlerFunc) {
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		defer conn.Close()
		if destination.String() != h.target {
			return
		}
		up, err := (&net.Dialer{}).DialContext(ctx, "tcp", h.target)
		if err != nil {
			return
		}
		defer up.Close()
		done := make(chan struct{})
		go func() { io.Copy(up, conn); up.Close(); close(done) }()
		io.Copy(conn, up)
		conn.Close()
		<-done
	}()
}

func TestProbeHTTPSActualAnyTLS(t *testing.T) {
	var hits atomic.Int64
	var status atomic.Int64
	status.Store(204)
	endpoint := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if status.Load() == 302 {
			w.Header().Set("Location", "/redirected")
		}
		w.WriteHeader(int(status.Load()))
	}))
	defer endpoint.Close()
	ca, cert := g13Cert(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	handler := &probeFixtureHandler{target: endpoint.Listener.Addr().String()}
	svc, err := anytls.NewService(anytls.ServiceConfig{Users: []anytls.User{{Name: "fixture", Password: "probe-fixture-secret"}}, PaddingScheme: padding.DefaultPaddingScheme, Handler: handler, Logger: logger.NOP()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var workers sync.WaitGroup
	var mu sync.Mutex
	connections := map[net.Conn]bool{}
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			connections[c] = true
			mu.Unlock()
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer c.Close()
				defer func() { mu.Lock(); delete(connections, c); mu.Unlock() }()
				tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
				_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
				if tc.HandshakeContext(ctx) == nil {
					_ = svc.NewConnection(ctx, tc, M.SocksaddrFromNet(c.RemoteAddr()), nil)
				}
			}()
		}
	}()
	defer func() {
		cancel()
		listener.Close()
		mu.Lock()
		for c := range connections {
			c.Close()
		}
		mu.Unlock()
		done := make(chan struct{})
		go func() { workers.Wait(); handler.wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(6 * time.Second):
			t.Error("probe fixture did not stop")
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	config := func(password, sni string) []byte {
		b, err := json.Marshal(map[string]any{"outbounds": []any{map[string]any{"type": "anytls", "tag": "anytls-out", "server": "127.0.0.1", "server_port": port, "password": password, "tls": map[string]any{"enabled": true, "server_name": sni, "certificate": []string{ca}, "utls": map[string]any{"enabled": true, "fingerprint": "chrome"}}}}})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	good := config("probe-fixture-secret", "anytls.fixture.invalid")
	trust := endpoint.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	// Keep endpoint verification strict, using only its fixture CA.
	trust.InsecureSkipVerify = false
	if ms, err := probeHTTPS(ctx, good, endpoint.URL+"/generate_204", trust); err != nil || ms < 0 {
		t.Fatalf("actual AnyTLS HTTPS: %v ms=%v", err, ms)
	}
	if hits.Load() != 1 {
		t.Fatal("HTTPS did not traverse fixture")
	}
	for i, bad := range [][]byte{config("wrong-password", "anytls.fixture.invalid"), config("probe-fixture-secret", "wrong.fixture.invalid")} {
		if _, err := probeHTTPS(ctx, bad, endpoint.URL, trust); err == nil {
			t.Fatal("node security negative accepted", strconv.Itoa(i))
		}
	}
	if hits.Load() != 1 {
		t.Fatal("security negative reached HTTPS")
	}
	if _, err := probeHTTPS(ctx, good, endpoint.URL, nil); err == nil {
		t.Fatal("untrusted endpoint certificate accepted")
	}
	if hits.Load() != 1 {
		t.Fatal("untrusted endpoint reached HTTP handler")
	}
	status.Store(302)
	if _, err := probeHTTPS(ctx, good, endpoint.URL, trust); err == nil {
		t.Fatal("redirect accepted")
	}
	if hits.Load() != 2 {
		t.Fatal("redirect followed")
	}
	status.Store(200)
	if _, err := probeHTTPS(ctx, good, endpoint.URL, trust); err == nil {
		t.Fatal("non-204 accepted")
	}
}

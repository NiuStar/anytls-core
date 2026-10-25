//go:build with_utls

package engine

import (
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Real TCP fault injection before AnyTLS authentication: consume ClientHello,
// send RST once, then forward unchanged TLS to the strict pinned fixture.
func TestAnyTLSRetrySecurityNoReplay(t *testing.T) {
	for _, kind := range []string{"wrong-pin", "wrong-password"} {
		t.Run(kind, func(t *testing.T) {
			f := g13New(t)
			port := freeLoopbackPort(t)
			pin := sha256.Sum256(f.cert.Certificate[0])
			if kind == "wrong-pin" {
				pin[0] ^= 1
			}
			config := f.config(port, func(ob map[string]any) {
				tls := ob["tls"].(map[string]any)
				delete(tls, "certificate")
				tls["certificate_sha256"] = []string{base64.StdEncoding.EncodeToString(pin[:])}
				if kind == "wrong-password" {
					ob["password"] = "wrong-password"
				}
			})
			client, _ := g13Start(t, config, port)
			e := g13Exchange(client, "tcp", f.tcp.Addr().String(), []byte("must-not-reach-business"))
			if !g13NonTimeoutClose(e) {
				t.Fatalf("missing actual rejection: %v", e)
			}
			class := "TLS_CERTIFICATE_REJECTED"
			if kind == "wrong-password" {
				class = "AUTH_REJECTED"
			}
			g13Witness(t, f, class, "", time.Second)
			g13Closed(t, f, 1, time.Second)
			time.Sleep(500 * time.Millisecond) // exceeds both possible retry delays
			if f.accepted.Load() != 1 || f.tcpBytes.Load() != 0 || f.udpBytes.Load() != 0 || f.uotStreams.Load() != 0 {
				t.Fatal("security failure replayed or business reached")
			}
		})
	}
}

func TestAnyTLSTransientResetThenPinnedBusiness(t *testing.T) {
	f := g13New(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var accepts atomic.Int64
	var wg sync.WaitGroup
	var mu sync.Mutex
	conns := map[net.Conn]bool{}
	track := func(c net.Conn) { mu.Lock(); conns[c] = true; mu.Unlock() }
	release := func(c net.Conn) { c.Close(); mu.Lock(); delete(conns, c); mu.Unlock() }
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			track(c)
			n := accepts.Add(1)
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer release(c)
				if n == 1 {
					_ = c.SetReadDeadline(time.Now().Add(time.Second))
					b := make([]byte, 4096)
					_, _ = c.Read(b)
					_ = c.(*net.TCPConn).SetLinger(0)
					return
				}
				upstream, e := net.DialTimeout("tcp", f.listener.Addr().String(), time.Second)
				if e != nil {
					return
				}
				track(upstream)
				defer release(upstream)
				copied := make(chan struct{})
				go func() { _, _ = io.Copy(upstream, c); _ = upstream.(*net.TCPConn).CloseWrite(); close(copied) }()
				_, _ = io.Copy(c, upstream)
				c.Close()
				upstream.Close()
				<-copied
			}()
		}
	}()
	t.Cleanup(func() {
		l.Close()
		<-done
		mu.Lock()
		for c := range conns {
			c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	port := freeLoopbackPort(t)
	pin := sha256.Sum256(f.cert.Certificate[0])
	config := f.config(port, func(ob map[string]any) {
		ob["server_port"] = l.Addr().(*net.TCPAddr).Port
		tls := ob["tls"].(map[string]any)
		delete(tls, "certificate")
		tls["certificate_sha256"] = []string{base64.StdEncoding.EncodeToString(pin[:])}
	})
	client, _ := g13Start(t, config, port)
	if e := g13Exchange(client, "tcp", f.tcp.Addr().String(), []byte("one-application-operation-no-replay")); e != nil {
		t.Fatalf("first pre-auth reset must recover within the SAME business operation: %v (TLS accepts=%d)", e, accepts.Load())
	}
	if accepts.Load() != 2 || f.accepted.Load() != 1 || f.tcpBytes.Load() != int64(len("one-application-operation-no-replay")) {
		t.Fatalf("retry/business boundary violated: upstream=%d pinned=%d bytes=%d", accepts.Load(), f.accepted.Load(), f.tcpBytes.Load())
	}
	t.Logf("one injected RST, two TLS dial attempts, one pinned authenticated business payload")
}

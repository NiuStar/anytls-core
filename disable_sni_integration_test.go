//go:build embedded_core && with_utls

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NiuStar/anytls-core/internal/engine"
	anytls "github.com/anytls/sing-anytls"
	"github.com/anytls/sing-anytls/padding"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
)

// Counts plaintext reads on the real TLS connection before AnyTLS service
// admission, in addition to authenticated streams and echoed business bytes.
type disableSNIAuthConn struct {
	net.Conn
	reads *atomic.Int64
}

func (c disableSNIAuthConn) Read(b []byte) (int, error) {
	n, e := c.Conn.Read(b)
	c.reads.Add(int64(n))
	return n, e
}

type disableSNIEcho struct {
	streams, payload atomic.Int64
	done             chan struct{}
}

func (h *disableSNIEcho) NewConnectionEx(_ context.Context, c net.Conn, _ M.Socksaddr, d M.Socksaddr, _ N.CloseHandlerFunc) {
	h.streams.Add(1)
	go func() {
		defer close(h.done)
		defer c.Close()
		if d.String() != "127.0.0.1:32123" {
			return
		}
		_, _ = io.Copy(c, routingCompiledReader{Reader: c, count: &h.payload})
	}()
}

// Full YAML -> buildNode -> engine -> real loopback TLS/AnyTLS peer. The same
// bytes compile on 70746ac, where explicit disable-sni still sends the name.
func TestDisableSNILocalTLS(t *testing.T) {
	for _, fp := range []string{"", "golang", "firefox"} {
		for _, kind := range []string{"leaf", "wrong-leaf", "ca", "wrong-hostname", "untrusted-ca", "default", "explicit-false", "ip-leaf-no-sni"} {
			t.Run(fp+"/"+kind, func(t *testing.T) {
				d := t.TempDir()
				ca, cert := runtimeCertificate(t)
				if kind == "untrusted-ca" {
					ca, _ = runtimeCertificate(t)
				}
				capath := filepath.Join(d, "ca.pem")
				runtimeWrite(t, capath, ca, 0600)
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				h := &disableSNIEcho{done: make(chan struct{})}
				svc, err := anytls.NewService(anytls.ServiceConfig{Users: []anytls.User{{Name: "fixture", Password: "synthetic-sni-only"}}, PaddingScheme: padding.DefaultPaddingScheme, Handler: h, Logger: logger.NOP()})
				if err != nil {
					t.Fatal(err)
				}
				hello := make(chan string, 1)
				handshake := make(chan error, 1)
				serverDone := make(chan struct{})
				admitted := atomic.Int64{}
				authReads := atomic.Int64{}
				accepted := make(chan net.Conn, 1)
				go func() {
					defer close(serverDone)
					c, e := listener.Accept()
					if e != nil {
						return
					}
					accepted <- c
					defer c.Close()
					tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) { hello <- h.ServerName; return nil, nil }})
					_ = tc.SetDeadline(time.Now().Add(8 * time.Second))
					e = tc.HandshakeContext(ctx)
					handshake <- e
					if e != nil {
						return
					}
					admitted.Add(1)
					_ = svc.NewConnection(ctx, disableSNIAuthConn{Conn: tc, reads: &authReads}, M.SocksaddrFromNet(c.RemoteAddr()), nil)
				}()
				t.Cleanup(func() {
					cancel()
					listener.Close()
					select {
					case c := <-accepted:
						c.Close()
					default:
					}
					select {
					case <-serverDone:
					case <-time.After(3 * time.Second):
						t.Error("TLS peer failed to join")
					}
					if h.streams.Load() > 0 {
						select {
						case <-h.done:
						case <-time.After(3 * time.Second):
							t.Error("echo failed to join")
						}
					}
				})
				spare, e := net.Listen("tcp", "127.0.0.1:0")
				if e != nil {
					t.Fatal(e)
				}
				port := spare.Addr().(*net.TCPAddr).Port
				spare.Close()
				pin := sha256.Sum256(cert.Certificate[0])
				if kind == "wrong-leaf" {
					pin[0] ^= 1
				}
				trust := "fingerprint: '" + hex.EncodeToString(pin[:]) + "'"
				name := "reference-not-in-cert.invalid"
				if kind == "ca" || kind == "wrong-hostname" || kind == "untrusted-ca" {
					trust = fmt.Sprintf("ca: %q", capath)
					name = "g21.invalid"
				}
				if kind == "wrong-hostname" {
					name = "wrong.invalid"
				}
				setting := ", disable-sni: true"
				wantSNI := ""
				if kind == "default" {
					setting = ""
					wantSNI = name
				}
				if kind == "explicit-false" {
					setting = ", disable-sni: false"
					wantSNI = name
				}
				sni := fmt.Sprintf(", sni: %s", name)
				if kind == "ip-leaf-no-sni" {
					setting = ""
					sni = ""
				}
				input := []byte(fmt.Sprintf("nodes:\n - {name: P, type: anytls, server: 127.0.0.1, port: %d, password: synthetic-sni-only, client-fingerprint: %q, %s%s%s}\n", listener.Addr().(*net.TCPAddr).Port, fp, trust, sni, setting))
				nodes, err := loadNodesBytes(input)
				if err != nil {
					t.Fatal(err)
				}
				cfg, err := buildNodeWithListen(nodes[0], "proxy", port, false, "127.0.0.1")
				if err != nil {
					t.Fatal(err)
				}
				b, err := json.Marshal(cfg)
				if err != nil {
					t.Fatal(err)
				}
				runCtx, stop := context.WithCancel(ctx)
				ended := make(chan error, 1)
				go func() { ended <- engine.Run(runCtx, b) }()
				t.Cleanup(func() {
					stop()
					select {
					case err := <-ended:
						if err != nil && !errors.Is(err, context.Canceled) {
							t.Errorf("engine cleanup: %v", err)
						}
					case <-time.After(3 * time.Second):
						t.Error("engine failed to join")
					}
				})
				addr := fmt.Sprintf("127.0.0.1:%d", port)
				until := time.Now().Add(3 * time.Second)
				for {
					c, e := net.DialTimeout("tcp", addr, 50*time.Millisecond)
					if e == nil {
						c.Close()
						break
					}
					if time.Now().After(until) {
						t.Fatal("mixed listener not ready")
					}
					time.Sleep(10 * time.Millisecond)
				}
				client := socks.NewClient(embeddedDialer{}, M.ParseSocksaddr(addr), socks.Version5, "", "")
				dialctx, dialcancel := context.WithTimeout(ctx, 4*time.Second)
				defer dialcancel()
				c, exchangeErr := client.DialContext(dialctx, "tcp", M.ParseSocksaddr("127.0.0.1:32123"))
				payload := []byte{0x81, 0x00, 0xff, 0x55, 0x11, 0x12, 0x13, 0x14}
				if exchangeErr == nil {
					_ = c.SetDeadline(time.Now().Add(4 * time.Second))
					_, exchangeErr = c.Write(payload)
					if exchangeErr == nil {
						got := make([]byte, len(payload))
						_, exchangeErr = io.ReadFull(c, got)
						if exchangeErr == nil && !bytes.Equal(got, payload) {
							t.Fatal("echo mismatch")
						}
					}
					c.Close()
				}
				select {
				case got := <-hello:
					if got != wantSNI {
						t.Errorf("wire SNI=%q want=%q", got, wantSNI)
					}
				case <-time.After(time.Second):
					t.Fatal("missing real ClientHello")
				}
				reject := kind == "wrong-leaf" || kind == "wrong-hostname" || kind == "untrusted-ca"
				select {
				case e := <-handshake:
					if reject {
						var op *net.OpError
						if e == nil || !errors.As(e, &op) || op.Op != "remote error" || op.Err.Error() != "tls: bad certificate" {
							t.Fatalf("missing real certificate rejection: %v", e)
						}
					} else if e != nil {
						t.Fatalf("strict handshake: %v", e)
					}
				case <-time.After(time.Second):
					t.Fatal("handshake witness missing")
				}
				if reject {
					if exchangeErr == nil {
						t.Fatal("bad trust returned business")
					}
					var ne net.Error
					if errors.As(exchangeErr, &ne) && ne.Timeout() {
						t.Fatal("timeout is not rejection evidence")
					}
					if admitted.Load() != 0 || authReads.Load() != 0 || h.streams.Load() != 0 || h.payload.Load() != 0 {
						t.Fatal("certificate rejection reached AnyTLS auth/business")
					}
					t.Log("certificate rejection before auth: service_calls=0 auth_bytes=0 streams=0 payload=0")
				} else {
					if exchangeErr != nil || admitted.Load() != 1 || authReads.Load() == 0 || h.streams.Load() != 1 || h.payload.Load() != int64(len(payload)) {
						t.Fatalf("strict authenticated echo failed: %v", exchangeErr)
					}
					t.Logf("strict echo wire_sni=%q auth_bytes=%d streams=1 payload=%d", wantSNI, authReads.Load(), len(payload))
				}
			})
		}
	}
}

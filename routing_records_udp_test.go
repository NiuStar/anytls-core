//go:build embedded_core && with_utls

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cr "github.com/NiuStar/anytls-core/internal/connectionrecords"
	"github.com/NiuStar/anytls-core/internal/engine"
	anytls "github.com/anytls/sing-anytls"
	"github.com/anytls/sing-anytls/padding"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
	"github.com/sagernet/sing/protocol/socks"
)

type recordsUDPPeer struct {
	target string
	bytes  atomic.Int64
	wg     sync.WaitGroup
}

func (p *recordsUDPPeer) NewConnectionEx(_ context.Context, c net.Conn, _ M.Socksaddr, d M.Socksaddr, _ N.CloseHandlerFunc) {
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		defer c.Close()
		if d.Fqdn != uot.MagicAddress {
			return
		}
		request, err := uot.ReadRequest(c)
		if err != nil {
			return
		}
		packet := uot.NewConn(c, *request)
		b := make([]byte, 65535)
		for {
			n, dest, err := packet.ReadFrom(b)
			if err != nil {
				return
			}
			if dest.String() != p.target {
				return
			}
			up, err := net.DialTimeout("udp", p.target, time.Second)
			if err != nil {
				return
			}
			up.SetDeadline(time.Now().Add(2 * time.Second))
			p.bytes.Add(int64(n))
			_, err = up.Write(b[:n])
			if err == nil {
				n, err = up.Read(b)
			}
			up.Close()
			if err != nil {
				return
			}
			if _, err = packet.WriteTo(b[:n], dest); err != nil {
				return
			}
		}
	}()
}

type recordsSOCKSDialer struct{}

func (recordsSOCKSDialer) DialContext(ctx context.Context, network string, d M.Socksaddr) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, d.String())
}
func (recordsSOCKSDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return net.ListenPacket("udp", "127.0.0.1:0")
}

func TestRecordsCompilerRealMixedUDP(t *testing.T) {
	for _, target := range []string{"DIRECT", "outer"} {
		t.Run(target, func(t *testing.T) {
			dir := t.TempDir()
			ca, cert := runtimeCertificate(t)
			caPath := filepath.Join(dir, "ca.pem")
			runtimeWrite(t, caPath, ca, 0600)
			echo, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			echoDone := make(chan struct{})
			go func() {
				defer close(echoDone)
				b := make([]byte, 65535)
				for {
					n, a, e := echo.ReadFrom(b)
					if e != nil {
						return
					}
					if _, e = echo.WriteTo(b[:n], a); e != nil {
						return
					}
				}
			}()
			t.Cleanup(func() {
				echo.Close()
				select {
				case <-echoDone:
				case <-time.After(3 * time.Second):
					t.Error("UDP fixture cleanup")
				}
			})
			peer := &recordsUDPPeer{target: echo.LocalAddr().String()}
			svc, err := anytls.NewService(anytls.ServiceConfig{Users: []anytls.User{{Name: "fixture", Password: "synthetic-records"}}, PaddingScheme: padding.DefaultPaddingScheme, Handler: peer, Logger: logger.NOP()})
			if err != nil {
				t.Fatal(err)
			}
			server, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			serverDone := make(chan struct{})
			conns := make(chan net.Conn, 1)
			handlerDone := make(chan struct{})
			go func() {
				defer close(serverDone)
				c, e := server.Accept()
				if e != nil {
					close(handlerDone)
					return
				}
				conns <- c
				defer close(handlerDone)
				defer c.Close()
				tlsConn := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
				tlsConn.SetDeadline(time.Now().Add(8 * time.Second))
				if tlsConn.HandshakeContext(ctx) == nil {
					_ = svc.NewConnection(ctx, tlsConn, M.SocksaddrFromNet(c.RemoteAddr()), nil)
				}
			}()
			t.Cleanup(func() {
				cancel()
				server.Close()
				select {
				case c := <-conns:
					c.Close()
				default:
				}
				select {
				case <-serverDone:
				case <-time.After(3 * time.Second):
					t.Error("AnyTLS fixture cleanup")
				}
				select {
				case <-handlerDone:
				case <-time.After(3 * time.Second):
					t.Error("AnyTLS handler cleanup")
				}
				workers := make(chan struct{})
				go func() { peer.wg.Wait(); close(workers) }()
				select {
				case <-workers:
				case <-time.After(3 * time.Second):
					t.Error("UoT worker cleanup")
				}
			})
			spare, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port := spare.Addr().(*net.TCPAddr).Port
			spare.Close()
			config := filepath.Join(dir, "config.yaml")
			data := fmt.Sprintf("nodes:\n - {name: P, type: anytls, server: 127.0.0.1, port: %d, password: synthetic-records, sni: g21.invalid, ca: %q, idle-session-check-interval: 6, idle-session-timeout: 6}\nproxy-groups:\n - {name: outer, type: select, proxies: [inner], selected: inner}\n - {name: inner, type: select, proxies: [P], selected: P}\nrules:\n - IP-CIDR,127.0.0.1/32,%s\n - MATCH,P\n", server.Addr().(*net.TCPAddr).Port, caPath, target)
			runtimeWrite(t, config, []byte(data), 0600)
			compiled, err := prepareRuntimeWithRecords(&runtimeOptions{Config: config, NodeName: "P", Mode: "proxy", LocalPort: port})
			if err != nil || compiled.Manifest == nil {
				t.Fatalf("actual compiler: %v", err)
			}
			sink := &routingRecordSink{}
			runCtx, stop := context.WithCancel(ctx)
			done := make(chan error, 1)
			go func() {
				done <- engine.RunWithRecords(runCtx, compiled.JSON, &engine.RecordsInput{Manifest: compiled.Manifest, Sink: sink})
			}()
			t.Cleanup(func() {
				stop()
				select {
				case err := <-done:
					if !errors.Is(err, context.Canceled) {
						t.Error(err)
					}
				case <-time.After(5 * time.Second):
					t.Error("engine cleanup")
				}
			})
			addr := fmt.Sprintf("127.0.0.1:%d", port)
			deadline := time.Now().Add(3 * time.Second)
			for {
				c, e := net.DialTimeout("tcp", addr, 100*time.Millisecond)
				if e == nil {
					c.Close()
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("mixed not ready")
				}
				time.Sleep(10 * time.Millisecond)
			}
			client := socks.NewClient(recordsSOCKSDialer{}, M.ParseSocksaddr(addr), socks.Version5, "", "")
			requestCtx, requestCancel := context.WithTimeout(ctx, 4*time.Second)
			defer requestCancel()
			conn, err := client.DialContext(requestCtx, "udp", M.ParseSocksaddr(echo.LocalAddr().String()))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(4 * time.Second))
			payload := []byte("compiler UDP\x00\xff")
			if _, err = conn.Write(payload); err != nil {
				t.Fatal(err)
			}
			b := make([]byte, 128)
			n, a, err := conn.(net.PacketConn).ReadFrom(b)
			if err != nil || string(b[:n]) != string(payload) || a.String() != echo.LocalAddr().String() {
				t.Fatal("exact UDP echo", err)
			}
			rows := sink.snapshot()
			if len(rows) != 1 || rows[0].Hook != cr.HookUDP || rows[0].Network != cr.NetworkUDP || rows[0].Route.Evidence != cr.ProvenanceVerified {
				t.Fatalf("actual UDP observation: %#v", rows)
			}
			route := rows[0].Route
			if route.SourceIndex == nil || *route.SourceIndex != 0 {
				t.Fatal("actual source ordinal")
			}
			if target == "DIRECT" {
				if route.TerminalKind != cr.TerminalDirect || peer.bytes.Load() != 0 {
					t.Fatal("DIRECT reached proxy")
				}
			} else {
				if route.TerminalKind != cr.TerminalNode || peer.bytes.Load() != int64(len(payload)) || len(route.GroupPath) != 2 {
					t.Fatal("proxy positive/group path")
				}
			}
		})
	}
}

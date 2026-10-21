//go:build with_utls

package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

func TestAnyTLSStrictTCP(t *testing.T) {
	for _, name := range []string{"proper-ca-sni", "wrong-ca", "wrong-sni", "wrong-password", "missing-tls"} {
		t.Run(name, func(t *testing.T) {
			f := g13New(t)
			port := freeLoopbackPort(t)
			b := f.config(port, func(ob map[string]any) {
				tls := ob["tls"].(map[string]any)
				switch name {
				case "wrong-ca":
					other, _ := g13Cert(t)
					tls["certificate"] = []string{other}
				case "wrong-sni":
					tls["server_name"] = "wrong.fixture.invalid"
				case "wrong-password":
					ob["password"] = "not-the-per-run-password"
				case "missing-tls":
					delete(ob, "tls")
				}
			})
			if name == "missing-tls" {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				if Check(ctx, b) == nil || Run(ctx, b) == nil {
					t.Fatal("AnyTLS accepted missing TLS")
				}
				if f.accepted.Load() != 0 || f.tcpBytes.Load() != 0 {
					t.Fatal("missing TLS opened server connection")
				}
				return
			}
			client, _ := g13Start(t, b, port)
			e := g13Exchange(client, "tcp", f.tcp.Addr().String(), []byte("G13 TCP\x00exact\xff"))
			if name == "proper-ca-sni" {
				if e != nil {
					t.Fatalf("strict TLS TCP echo: %v", e)
				}
				g13Hello(t, f, true)
			} else {
				if e == nil {
					t.Fatal("security negative returned echo")
				}
				if !g13NonTimeoutClose(e) {
					t.Fatal("security negative lacked non-timeout protocol/transport close")
				}
				want := "TLS_CERTIFICATE_REJECTED"
				if name == "wrong-password" {
					want = "AUTH_REJECTED"
				}
				g13Witness(t, f, want, "", 4*time.Second)
				g13Closed(t, f, 1, 4*time.Second)
				if f.tcpBytes.Load() != 0 || f.udpBytes.Load() != 0 {
					t.Fatal("security negative reached authorized echo")
				}
				// Same server, certificate and password: only the negative config field differs.
				goodPort := freeLoopbackPort(t)
				good, _ := g13Start(t, f.config(goodPort, nil), goodPort)
				if e := g13Exchange(good, "tcp", f.tcp.Addr().String(), []byte("positive-control")); e != nil {
					t.Fatal("same-fixture positive control failed")
				}
			}
		})
	}
}

// Synthetic classifier checks are not security-path evidence: the tests above
// require events from the actual engine connection, not a generic error/counter.
func TestAnyTLSEvidenceSensitivity(t *testing.T) {
	alert := &net.OpError{Op: "remote error", Err: errors.New("tls: bad certificate")}
	for _, tc := range []struct {
		name, stage string
		err         error
		complete    bool
		want        string
	}{
		{"certificate-alert", "tls", alert, false, "TLS_CERTIFICATE_REJECTED"},
		{"generic-handshake-error", "tls", errors.New("failure"), false, "OTHER_FAILURE"},
		{"local-certificate-text", "tls", errors.New("tls: bad certificate"), false, "OTHER_FAILURE"},
		{"successful-handshake", "tls", alert, true, "OTHER_FAILURE"},
		{"auth-return", "service", errors.New("unknown user password: fallback disabled"), true, "AUTH_REJECTED"},
		{"generic-service-error", "service", errors.New("failure"), true, "OTHER_FAILURE"},
		{"auth-at-wrong-stage", "tls", errors.New("unknown user password: fallback disabled"), false, "OTHER_FAILURE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := g13RejectionClass(tc.stage, tc.err, tc.complete); got != tc.want {
				t.Fatalf("class=%s want=%s", got, tc.want)
			}
		})
	}
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false}, {"generic", errors.New("failure"), false},
		{"deadline", context.DeadlineExceeded, false},
		{"wrapped-deadline", fmt.Errorf("wrapped: %w", context.DeadlineExceeded), false},
		{"network-timeout", &net.DNSError{IsTimeout: true}, false},
		{"eof", io.EOF, true}, {"reset", fmt.Errorf("wrapped: %w", syscall.ECONNRESET), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if g13NonTimeoutClose(tc.err) != tc.want {
				t.Fatal("close classification mismatch")
			}
		})
	}
	valid := g13Event{connection: 1, class: "TARGET_REFUSED", target: "127.0.0.1:1"}
	for _, ev := range []g13Event{{}, {connection: 2, class: valid.class, target: valid.target}, {connection: 1, class: "OTHER_FAILURE", target: valid.target}, {connection: 1, class: valid.class, target: "127.0.0.1:2"}} {
		if g13EvidenceMatches(ev, 1, valid.class, valid.target) {
			t.Fatal("missing/wrong connection/category/target accepted")
		}
	}
	if !g13EvidenceMatches(valid, 1, valid.class, valid.target) {
		t.Fatal("valid witness rejected")
	}
}

func TestAnyTLSUDP(t *testing.T) {
	for _, bad := range []bool{false, true} {
		t.Run(fmt.Sprintf("wrong-password-%v", bad), func(t *testing.T) {
			f := g13New(t)
			p := freeLoopbackPort(t)
			client, _ := g13Start(t, f.config(p, func(ob map[string]any) {
				if bad {
					ob["password"] = "unauthorized"
				}
			}), p)
			payload := []byte("SOCKS5 UDP -> AnyTLS UoT\x00\xff")
			e := g13Exchange(client, "udp", f.udp.LocalAddr().String(), payload)
			if bad {
				if e == nil {
					t.Fatal("unauthorized UDP echoed")
				}
				// UDP ASSOCIATE has no per-datagram rejection response; its read may
				// time out. The actual TLS session must independently report auth rejection.
				g13Witness(t, f, "AUTH_REJECTED", "", 4*time.Second)
				g13Closed(t, f, 1, 4*time.Second)
				if f.tcpBytes.Load() != 0 || f.udpBytes.Load() != 0 || f.uotStreams.Load() != 0 {
					t.Fatal("bad password reached UoT/UDP echo")
				}
				return
			}
			if e != nil {
				t.Fatalf("UDP echo: %v", e)
			}
			if f.udpBytes.Load() != int64(len(payload)) || f.uotStreams.Load() != 1 {
				t.Fatal("missing exact UDP payload/UoT stream witness")
			}
			g13Hello(t, f, true)
		})
	}
}

func TestAnyTLSClientHelloControl(t *testing.T) {
	f := g13New(t)
	p := freeLoopbackPort(t)
	client, _ := g13Start(t, f.config(p, func(ob map[string]any) { delete(ob["tls"].(map[string]any), "utls") }), p)
	if e := g13Exchange(client, "tcp", f.tcp.Addr().String(), []byte("stdlib-control")); e != nil {
		t.Fatal(e)
	}
	g13Hello(t, f, false)
}

func TestAnyTLSSlowTeardown(t *testing.T) {
	f := g13New(t)
	f.streamWait = make(chan struct{}, 8)
	f.teardownReached = make(chan struct{}, 8)
	release := make(chan struct{})
	f.teardownRelease = release
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	p := freeLoopbackPort(t)
	client, _ := g13Start(t, f.config(p, nil), p)
	done := make(chan error, 1)
	go func() { done <- g13Sequential(t, f, client) }()
	t.Cleanup(func() {
		unblock()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("sequential worker not joined")
		}
	})
	select {
	case <-f.teardownReached:
	case <-time.After(3 * time.Second):
		t.Fatal("fixture did not reach controlled teardown")
	}
	// The same helper used by ReuseIdleCancel must enter its event wait while
	// teardown is held, not complete early or guess a scheduling grace period.
	select {
	case <-f.streamWait:
	case e := <-done:
		done <- e
		t.Fatal("sequential helper completed before held teardown event")
	case <-time.After(2 * time.Second):
		t.Fatal("sequential helper never waited for teardown event")
	}
	select {
	case e := <-done:
		done <- e
		t.Fatal("sequential helper bypassed held teardown")
	default:
	}
	unblock()
	select {
	case e := <-done:
		done <- e
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("sequential helper did not resume after release")
	}
}

func TestAnyTLSCancelReadDeadline(t *testing.T) {
	for _, closePeer := range []bool{false, true} {
		t.Run(fmt.Sprintf("peer-close-%v", closePeer), func(t *testing.T) {
			l, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			defer l.Close()
			c, e := net.DialTimeout("tcp", l.Addr().String(), time.Second)
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			peer, e := l.Accept()
			if e != nil {
				t.Fatal(e)
			}
			defer peer.Close()
			// An already expired pre-cancel deadline must not masquerade as EOF.
			_ = c.SetReadDeadline(time.Now().Add(-time.Second))
			called := false
			e = g13CancelRead(c, func() {
				called = true
				if closePeer {
					peer.Close()
				}
			}, 20*time.Millisecond)
			if !called || (e == nil) != closePeer {
				t.Fatalf("caller accepted local read timeout=%v closePeer=%v", e == nil, closePeer)
			}
		})
	}
}

func TestAnyTLSReuseIdleCancel(t *testing.T) {
	f := g13New(t)
	p := freeLoopbackPort(t)
	client, cancel := g13Start(t, f.config(p, nil), p)
	if e := g13Sequential(t, f, client); e != nil {
		t.Fatal(e)
	}
	sequential := f.accepted.Load()
	const n = 4
	held := make([]net.Conn, n)
	ctx, stop := context.WithTimeout(context.Background(), 30*time.Second)
	defer stop()
	for i := range held {
		c, e := client.DialContext(ctx, "tcp", M.ParseSocksaddr(f.tcp.Addr().String()))
		if e != nil {
			t.Fatal(e)
		}
		held[i] = c
		t.Cleanup(func() { c.Close() })
	}
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i, c := range held {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(3 * time.Second))
			s := []byte(fmt.Sprintf("parallel-%d", i))
			_, e := c.Write(s)
			b := make([]byte, len(s))
			if e == nil {
				_, e = io.ReadFull(c, b)
			}
			if e == nil && string(b) != string(s) {
				e = fmt.Errorf("parallel payload mismatch")
			}
			errs <- e
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	accepted := f.accepted.Load()
	if accepted < 1 || accepted > sequential+n {
		t.Fatal("pool dial count outside request bound")
	}
	t.Logf("TLS accepted sequential=%d after concurrent=%d (no exactly-one concurrent assumption)", sequential, accepted)
	// v0.0.11 coerces <=5s to 30s. Effective 6s timeout + 6s sweep,
	// bounded 15s event wait, no fixed sleep and no dependency patch.
	g13Closed(t, f, accepted, 15*time.Second)
	if e := g13Exchange(client, "tcp", f.tcp.Addr().String(), []byte("after-idle")); e != nil {
		t.Fatal(e)
	}
	if f.accepted.Load() <= accepted {
		t.Fatal("expired session reused instead of redial")
	}
	active, e := client.DialContext(ctx, "tcp", M.ParseSocksaddr(f.tcp.Addr().String()))
	if e != nil {
		t.Fatal(e)
	}
	defer active.Close()
	_ = active.SetDeadline(time.Now().Add(3 * time.Second))
	if _, e = active.Write([]byte("active")); e != nil {
		t.Fatal(e)
	}
	b := make([]byte, 6)
	if _, e = io.ReadFull(active, b); e != nil {
		t.Fatal(e)
	}
	if e = g13CancelRead(active, cancel, 3*time.Second); e != nil {
		t.Fatal(e)
	}
	g13Closed(t, f, f.accepted.Load(), 5*time.Second)
}

func TestAnyTLSRemoteReset(t *testing.T) {
	f := g13New(t)
	p := freeLoopbackPort(t)
	client, cancel := g13Start(t, f.config(p, nil), p)
	if e := g13Exchange(client, "tcp", "127.0.0.1:1", []byte("must-reset")); !g13NonTimeoutClose(e) {
		t.Fatal("remote rejection lacked non-timeout EOF/reset/protocol close")
	}
	g13Witness(t, f, "TARGET_REFUSED", "127.0.0.1:1", 4*time.Second)
	if f.accepted.Load() < 1 || f.tcpBytes.Load() != 0 || f.udpBytes.Load() != 0 {
		t.Fatal("reset was not on AnyTLS or touched echo")
	}
	if e := g13Exchange(client, "tcp", f.tcp.Addr().String(), []byte("recovery")); e != nil {
		t.Fatalf("client unusable after reset: %v", e)
	}
	cancel()
	g13Closed(t, f, f.accepted.Load(), 5*time.Second)
}

func TestAnyTLSRouteDirectReject(t *testing.T) {
	for _, reject := range []bool{false, true} {
		t.Run(fmt.Sprintf("reject-%v", reject), func(t *testing.T) {
			f := g13New(t)
			p := freeLoopbackPort(t)
			var cfg map[string]any
			_ = json.Unmarshal(f.config(p, nil), &cfg)
			cfg["outbounds"] = append(cfg["outbounds"].([]any), map[string]any{"type": "direct", "tag": "local-direct"})
			rule := map[string]any{"ip_cidr": []string{"127.0.0.1/32"}, "action": "route", "outbound": "local-direct"}
			if reject {
				rule["action"] = "reject"
				delete(rule, "outbound")
			}
			cfg["route"].(map[string]any)["rules"] = []any{rule}
			b, _ := json.Marshal(cfg)
			client, _ := g13Start(t, b, p)
			e := g13Exchange(client, "tcp", f.tcp.Addr().String(), []byte("route-local"))
			if reject {
				if e == nil || f.tcpBytes.Load() != 0 {
					t.Fatal("REJECT reached target")
				}
			} else if e != nil || f.tcpBytes.Load() == 0 {
				t.Fatalf("DIRECT did not reach local target: %v", e)
			}
			if f.accepted.Load() != 0 {
				t.Fatal("DIRECT/REJECT unexpectedly selected secure AnyTLS tag")
			}
		})
	}
}

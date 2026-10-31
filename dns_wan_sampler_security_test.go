//go:build embedded_core && with_utls && (linux || darwin)

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// Same public helper/arguments as the independent reviewer; the contract now
// requires rejection, not successful reproduction of the vulnerability.
func TestDNSWANSecurityForeignNoAuth(t *testing.T) {
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	done := make(chan int, 1)
	go func() {
		c, e := l.Accept()
		if e != nil {
			done <- -1
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		hello := make([]byte, 3)
		if _, e = io.ReadFull(c, hello); e != nil || !bytes.Equal(hello, []byte{5, 1, 2}) {
			done <- -1
			return
		}
		c.Write([]byte{5, 0})
		req := make([]byte, 10)
		n, e := io.ReadFull(c, req)
		if e != nil {
			done <- n
			return
		}
		c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 1})
		dc := &dns.Conn{Conn: c}
		q, e := dc.ReadMsg()
		if e == nil {
			a := new(dns.Msg)
			a.SetReply(q)
			dc.WriteMsg(a)
		}
		done <- n
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	outcome, _ := wanQuery(ctx, l.Addr().String(), "UNRELATED_RANDOM_TOKEN", "sampler.invalid.", dns.TypeA, 1)
	n := <-done
	if outcome == "NOERROR" || n != 0 {
		t.Fatalf("FOREIGN_PEER_ACCEPTED outcome=%s post_selection_bytes=%d", outcome, n)
	}
}

func TestDNSWANSecurityHandshakeBound(t *testing.T) {
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, e := l.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		io.Copy(io.Discard, c)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	start := time.Now()
	outcome, elapsed := wanQuery(ctx, l.Addr().String(), "TOKEN", "sampler.invalid.", dns.TypeA, 1)
	if total := time.Since(start); total > 5*time.Second {
		t.Errorf("RETURN_CLEANUP_BOUND %s", total)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("PEER_NOT_QUIESCENT")
	}
	// Four-second operation plus one-second scheduling/cleanup allowance; the
	// six-second parent must not be what stops a stalled SOCKS handshake.
	if outcome == "NOERROR" || elapsed > 5*time.Second {
		t.Fatalf("CALLER_BOUND outcome=%s elapsed=%s", outcome, elapsed)
	}
}

func TestDNSWANSecurityManifestAliases(t *testing.T) {
	raw, _ := json.Marshal(wanSyntheticManifest())
	for _, pair := range [][2]string{
		{`"uid":501`, `"uid":0,"UID":501`},
		{`"uid":501`, `"UID":501`},
		{`"sha256":"` + strings.Repeat("b", 64) + `"`, `"SHA256":"` + strings.Repeat("b", 64) + `"`},
		{`"size":128`, `"size":0,"SIZE":128`},
		{`"inode":1`, `"Inode":1`},
		{`"mtime_ns":1`, `"MTIME_NS":1`},
	} {
		b := bytes.Replace(raw, []byte(pair[0]), []byte(pair[1]), 1)
		if bytes.Equal(b, raw) {
			t.Fatal("FIXTURE_NOT_MUTATED")
		}
		if _, e := wanValidateManifest(b, wanHash(b), 1000); e == nil {
			t.Errorf("AMBIGUOUS_SCHEMA_ACCEPTED %s", pair[0])
		}
	}
}

// Runner injection is per invocation, never a mutable global. This calls the
// actual orchestration entry (including authenticated readiness and teardown).
func TestDNSWANSecurityCleanupJoinedCause(t *testing.T) {
	for _, cleanup := range []error{errors.New("synthetic close failure"), nil} {
		t.Run(fmt.Sprint(cleanup == nil), func(t *testing.T) {
			report := new(wanReport)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			cancel()
			n := node{Type: "anytls", Server: "127.0.0.1", Port: 9, CertificateSHA256: strings.Repeat("a", 64), Fingerprint: "golang", Password: "synthetic"}
			err := wanRunEngineWithRunner(ctx, n, 0, report, func(ctx context.Context, _ []byte) error { <-ctx.Done(); return errors.Join(context.Canceled, cleanup) })
			if cleanup != nil && (err == nil || err.Error() != "ENGINE_STOP") {
				t.Fatalf("CLOSE_FAILURE_MASKED %v", err)
			}
			if report.EnginesJoined != 1 || report.ListenersRebound != 1 {
				t.Fatalf("OWNER_NOT_SETTLED joined=%d rebound=%d", report.EnginesJoined, report.ListenersRebound)
			}
		})
	}
}

func TestDNSWANSecurityCancelWithoutDeadlineExpiry(t *testing.T) {
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	accepted := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		c, e := l.Accept()
		if e != nil {
			done <- e
			return
		}
		defer c.Close()
		close(accepted)
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, e = io.Copy(io.Discard, c)
		done <- e
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	returned := make(chan string, 1)
	go func() {
		code, _ := wanQuery(ctx, l.Addr().String(), "TOKEN", "sampler.invalid.", dns.TypeA, 1)
		returned <- code
	}()
	<-accepted
	cancel()
	select {
	case code := <-returned:
		if code == "NOERROR" {
			t.Error("CANCEL_ACCEPTED")
		}
	case <-time.After(time.Second):
		t.Fatal("CANCEL_NOT_PROMPT")
	}
	select {
	case e := <-done:
		if ne, ok := e.(net.Error); ok && ne.Timeout() {
			t.Fatal("TIMEOUT_NOT_SOCKET_CLOSE")
		}
	case <-time.After(time.Second):
		t.Fatal("PEER_NOT_CLOSED")
	}
}

// An actual loopback claimant wins the released-port race via the per-call
// runner seam. It answers NOAUTH, never forwards. Auth readiness must not send
// CONNECT/DNS even while the owner goroutine is alive.
func TestDNSWANSecurityForeignPortClaim(t *testing.T) {
	report := new(wanReport)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	var postAuth int
	err := wanRunEngineWithRunner(ctx, node{Type: "anytls", Server: "127.0.0.1", Port: 9, CertificateSHA256: strings.Repeat("a", 64), Fingerprint: "golang", Password: "synthetic"}, 0, report, func(ctx context.Context, wire []byte) error {
		var cfg struct {
			Inbounds []struct {
				Listen string `json:"listen"`
				Port   int    `json:"listen_port"`
			} `json:"inbounds"`
		}
		if json.Unmarshal(wire, &cfg) != nil || len(cfg.Inbounds) != 1 {
			return errors.New("fixture decode")
		}
		l, e := net.Listen("tcp", net.JoinHostPort(cfg.Inbounds[0].Listen, fmt.Sprint(cfg.Inbounds[0].Port)))
		if e != nil {
			return errors.New("fixture listen")
		}
		stop := context.AfterFunc(ctx, func() { l.Close() })
		defer stop()
		defer l.Close()
		for {
			c, e := l.Accept()
			if e != nil {
				return context.Canceled
			}
			c.SetDeadline(time.Now().Add(time.Second))
			hello := make([]byte, 3)
			if _, e = io.ReadFull(c, hello); e == nil {
				c.Write([]byte{5, 0})
				b := make([]byte, 1)
				n, _ := c.Read(b)
				postAuth += n
			}
			c.Close()
		}
	})
	if err == nil || report.Questions != 0 || postAuth != 0 || report.EnginesJoined != 1 || report.ListenersRebound != 1 {
		t.Fatalf("FOREIGN_PORT_GATE err=%v questions=%d bytes=%d joined=%d rebound=%d", err, report.Questions, postAuth, report.EnginesJoined, report.ListenersRebound)
	}
}

func TestDNSWANSecuritySuccessfulQueriesCloseFailure(t *testing.T) {
	for _, closeFailure := range []bool{false, true} {
		t.Run(fmt.Sprint(closeFailure), func(t *testing.T) {
			report := new(wanReport)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			err := wanRunEngineWithRunner(ctx, node{Type: "anytls", Server: "127.0.0.1", Port: 9, CertificateSHA256: strings.Repeat("a", 64), Fingerprint: "golang", Password: "synthetic"}, 0, report, func(ctx context.Context, wire []byte) error {
				var cfg struct {
					Inbounds []struct {
						Listen string                                `json:"listen"`
						Port   int                                   `json:"listen_port"`
						Users  []struct{ Username, Password string } `json:"users"`
					} `json:"inbounds"`
				}
				if json.Unmarshal(wire, &cfg) != nil || len(cfg.Inbounds) != 1 || len(cfg.Inbounds[0].Users) != 1 {
					return errors.New("fixture decode")
				}
				inbound := cfg.Inbounds[0]
				l, e := net.Listen("tcp", net.JoinHostPort(inbound.Listen, fmt.Sprint(inbound.Port)))
				if e != nil {
					return errors.New("fixture listen")
				}
				stopped := make(chan struct{})
				stop := context.AfterFunc(ctx, func() { l.Close(); close(stopped) })
				defer func() {
					if !stop() {
						<-stopped
					}
					l.Close()
				}()
				for {
					c, e := l.Accept()
					if e != nil {
						if closeFailure {
							return fmt.Errorf("outer: %w", errors.Join(context.Canceled, errors.New("synthetic Close failure")))
						}
						return fmt.Errorf("outer: %w", errors.Join(context.Canceled, context.Canceled))
					}
					func() {
						defer c.Close()
						c.SetDeadline(time.Now().Add(time.Second))
						hello := make([]byte, 3)
						if _, e := io.ReadFull(c, hello); e != nil {
							return
						}
						if !bytes.Equal(hello, []byte{5, 1, 2}) {
							return
						}
						c.Write([]byte{5, 2})
						head := make([]byte, 2)
						if _, e := io.ReadFull(c, head); e != nil || head[0] != 1 {
							return
						}
						user := make([]byte, int(head[1]))
						if _, e := io.ReadFull(c, user); e != nil {
							return
						}
						if _, e := io.ReadFull(c, head[:1]); e != nil {
							return
						}
						pass := make([]byte, int(head[0]))
						if _, e := io.ReadFull(c, pass); e != nil {
							return
						}
						if string(user) != inbound.Users[0].Username || string(pass) != inbound.Users[0].Password {
							c.Write([]byte{1, 1})
							return
						}
						c.Write([]byte{1, 0})
						req := make([]byte, 10)
						if _, e := io.ReadFull(c, req); e != nil {
							return
						}
						if !bytes.Equal(req, []byte{5, 1, 0, 1, 1, 1, 1, 1, 0, 53}) {
							return
						}
						c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 1})
						dc := &dns.Conn{Conn: c}
						q, e := dc.ReadMsg()
						if e != nil {
							return
						}
						a := new(dns.Msg)
						a.SetReply(q)
						dc.WriteMsg(a)
					}()
				}
			})
			if report.Questions != 18 || report.EnginesJoined != 1 || report.ListenersRebound != 1 {
				t.Fatalf("SUCCESS_PATH_NOT_EXERCISED questions=%d joined=%d rebound=%d err=%v", report.Questions, report.EnginesJoined, report.ListenersRebound, err)
			}
			if closeFailure {
				if err == nil || err.Error() != "ENGINE_STOP" {
					t.Fatalf("CLOSE_FAILURE_MASKED %v", err)
				}
			} else if err != nil {
				t.Fatalf("CANCELLATION_ONLY_REJECTED %v", err)
			}
		})
	}
}

func TestDNSWANSecurityOwnerEarlyExit(t *testing.T) {
	report := new(wanReport)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := wanRunEngineWithRunner(ctx, node{Type: "anytls", Server: "127.0.0.1", Port: 9, CertificateSHA256: strings.Repeat("a", 64), Fingerprint: "golang", Password: "synthetic"}, 0, report, func(context.Context, []byte) error { return nil })
	if err == nil || report.Questions != 0 || report.EnginesJoined != 1 || report.ListenersRebound != 1 {
		t.Fatalf("OWNER_EARLY_EXIT err=%v questions=%d joined=%d rebound=%d", err, report.Questions, report.EnginesJoined, report.ListenersRebound)
	}
}

func TestDNSWANSecurityStrictAuthReplies(t *testing.T) {
	for _, reply := range [][4]byte{{4, 2, 1, 0}, {5, 0, 1, 0}, {5, 255, 1, 0}, {5, 2, 2, 0}, {5, 2, 1, 1}} {
		t.Run(fmt.Sprint(reply), func(t *testing.T) {
			l, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			defer l.Close()
			done := make(chan int, 1)
			go func() {
				c, e := l.Accept()
				if e != nil {
					done <- -1
					return
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(time.Second))
				hello := make([]byte, 3)
				if _, e = io.ReadFull(c, hello); e != nil {
					done <- -1
					return
				}
				c.Write(reply[:2])
				if reply[0] == 5 && reply[1] == 2 {
					h := make([]byte, 2)
					if _, e = io.ReadFull(c, h); e != nil {
						done <- -1
						return
					}
					u := make([]byte, int(h[1]))
					if _, e = io.ReadFull(c, u); e != nil {
						done <- -1
						return
					}
					if _, e = io.ReadFull(c, h[:1]); e != nil {
						done <- -1
						return
					}
					p := make([]byte, int(h[0]))
					if _, e = io.ReadFull(c, p); e != nil {
						done <- -1
						return
					}
					c.Write(reply[2:])
				}
				b := make([]byte, 1)
				n, _ := c.Read(b)
				done <- n
			}()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			code, _ := wanQuery(ctx, l.Addr().String(), "TOKEN", "sampler.invalid.", dns.TypeA, 1)
			if n := <-done; code == "NOERROR" || n != 0 {
				t.Fatalf("INVALID_AUTH_REACHED_CONNECT code=%s bytes=%d", code, n)
			}
		})
	}
}

func TestDNSWANSecurityCancelDuringDNSRead(t *testing.T) {
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	reading := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		c, e := l.Accept()
		if e != nil {
			done <- e
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		h := make([]byte, 3)
		if _, e = io.ReadFull(c, h); e != nil {
			done <- e
			return
		}
		c.Write([]byte{5, 2})
		if _, e = io.ReadFull(c, h[:2]); e != nil {
			done <- e
			return
		}
		if _, e = io.ReadFull(c, make([]byte, int(h[1]))); e != nil {
			done <- e
			return
		}
		if _, e = io.ReadFull(c, h[:1]); e != nil {
			done <- e
			return
		}
		if _, e = io.ReadFull(c, make([]byte, int(h[0]))); e != nil {
			done <- e
			return
		}
		c.Write([]byte{1, 0})
		if _, e = io.ReadFull(c, make([]byte, 10)); e != nil {
			done <- e
			return
		}
		c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 1})
		if _, e = (&dns.Conn{Conn: c}).ReadMsg(); e != nil {
			done <- e
			return
		}
		close(reading)
		_, e = io.Copy(io.Discard, c)
		done <- e
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	returned := make(chan string, 1)
	go func() {
		code, _ := wanQuery(ctx, l.Addr().String(), "TOKEN", "sampler.invalid.", dns.TypeA, 1)
		returned <- code
	}()
	select {
	case <-reading:
	case <-time.After(time.Second):
		t.Fatal("READ_STAGE_NOT_REACHED")
	}
	cancel()
	select {
	case code := <-returned:
		if code == "NOERROR" {
			t.Error("CANCEL_ACCEPTED")
		}
	case <-time.After(time.Second):
		t.Fatal("READ_CANCEL_NOT_PROMPT")
	}
	select {
	case e := <-done:
		if ne, ok := e.(net.Error); ok && ne.Timeout() {
			t.Fatal("TIMEOUT_NOT_SOCKET_CLOSE")
		}
	case <-time.After(time.Second):
		t.Fatal("READ_PEER_NOT_CLOSED")
	}
}

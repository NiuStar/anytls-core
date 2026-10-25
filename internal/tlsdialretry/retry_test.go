package tlsdialretry

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	stls "github.com/sagernet/sing-box/common/tls"
	M "github.com/sagernet/sing/common/metadata"
)

type countedConn struct {
	net.Conn
	closes   int
	closeErr error
}

func (c *countedConn) Close() error                           { c.closes++; return c.closeErr }
func (c *countedConn) NetConn() net.Conn                      { return c.Conn }
func (c *countedConn) HandshakeContext(context.Context) error { return nil }
func (c *countedConn) ConnectionState() tls.ConnectionState   { return tls.ConnectionState{} }

type countedDialer struct {
	stls.Dialer
	calls int
	fn    func(context.Context, int) (stls.Conn, error)
}

func (d *countedDialer) DialTLSContext(ctx context.Context, s M.Socksaddr) (stls.Conn, error) {
	d.calls++
	if s != M.ParseSocksaddr("127.0.0.1:1234") {
		panic("destination changed")
	}
	return d.fn(ctx, d.calls)
}
func reset() error {
	return &net.OpError{Op: "read", Net: "tcp", Err: os.NewSyscallError("read", syscall.ECONNRESET)}
}
func run(ctx context.Context, d *countedDialer, b time.Duration) (net.Conn, error) {
	return (Factory{}).DialAnyTLS(ctx, d, M.ParseSocksaddr("127.0.0.1:1234"), b)
}

func TestRetryCapPreservesAllFailureIdentities(t *testing.T) {
	failures := []error{reset(), reset(), reset()}
	conns := []*countedConn{{}, {}, {}}
	d := &countedDialer{fn: func(ctx context.Context, n int) (stls.Conn, error) {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("missing aggregate deadline")
		}
		return conns[n-1], failures[n-1]
	}}
	start := time.Now()
	c, e := run(context.Background(), d, time.Second)
	if c != nil || d.calls != 3 || time.Since(start) < 440*time.Millisecond {
		t.Fatalf("cap/delay failed: calls=%d elapsed=%v", d.calls, time.Since(start))
	}
	for i, f := range failures {
		if !errors.Is(e, f) || conns[i].closes != 1 {
			t.Fatalf("lost failure/close %d", i)
		}
	}
}
func TestRetryRejectsNonResetAndJoinedSecurityErrors(t *testing.T) {
	security := errors.New("certificate verification rejected")
	for name, e := range map[string]error{
		"bare-reset": syscall.ECONNRESET, "same-text": errors.New(reset().Error()), "eof": io.EOF, "unexpected-eof": io.ErrUnexpectedEOF,
		"timeout": &net.OpError{Op: "read", Err: os.ErrDeadlineExceeded}, "cancel": context.Canceled, "permission": syscall.EACCES, "protocol": errors.New("TLS alert"), "security": security,
		"joined-security": errors.Join(reset(), security), "joined-cancel": errors.Join(reset(), context.Canceled), "joined-permission": errors.Join(reset(), syscall.EACCES), "nested-join": fmt.Errorf("outer: %w", errors.Join(reset(), io.EOF)),
	} {
		t.Run(name, func(t *testing.T) {
			d := &countedDialer{fn: func(context.Context, int) (stls.Conn, error) { return nil, e }}
			_, got := run(context.Background(), d, time.Second)
			if d.calls != 1 || !errors.Is(got, e) {
				t.Fatalf("unexpected replay or lost error: %d %v", d.calls, got)
			}
		})
	}
}
func TestRetryCancellationDuringBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	failure := reset()
	d := &countedDialer{fn: func(context.Context, int) (stls.Conn, error) {
		time.AfterFunc(20*time.Millisecond, cancel)
		return nil, failure
	}}
	start := time.Now()
	_, e := run(ctx, d, time.Second)
	if d.calls != 1 || !errors.Is(e, context.Canceled) || !errors.Is(e, failure) || time.Since(start) > 120*time.Millisecond {
		t.Fatalf("cancel/backoff: calls=%d err=%v", d.calls, e)
	}
}
func TestRetryAggregateBudgetAndShorterCaller(t *testing.T) {
	for _, callerShorter := range []bool{false, true} {
		t.Run(fmt.Sprint(callerShorter), func(t *testing.T) {
			ctx := context.Background()
			var cancel context.CancelFunc
			budget := 240 * time.Millisecond
			if callerShorter {
				ctx, cancel = context.WithTimeout(ctx, 60*time.Millisecond)
				defer cancel()
				budget = time.Second
			}
			d := &countedDialer{fn: func(ctx context.Context, n int) (stls.Conn, error) {
				if n == 1 {
					return nil, reset()
				}
				<-ctx.Done()
				return nil, ctx.Err()
			}}
			start := time.Now()
			_, e := run(ctx, d, budget)
			elapsed := time.Since(start)
			expected := 2
			if callerShorter {
				expected = 1
			}
			if d.calls != expected || !errors.Is(e, context.DeadlineExceeded) || elapsed > 350*time.Millisecond {
				t.Fatalf("aggregate deadline extended: calls=%d elapsed=%v error=%v", d.calls, elapsed, e)
			}
		})
	}
}
func TestRetryOriginalDialerContextAndSuccessOwnership(t *testing.T) {
	type key struct{}
	ctx := context.WithValue(context.Background(), key{}, "original-value")
	good := &countedConn{}
	bad := &countedConn{}
	var deadline time.Time
	d := &countedDialer{fn: func(ctx context.Context, n int) (stls.Conn, error) {
		if ctx.Value(key{}) != "original-value" {
			t.Fatal("context value lost")
		}
		dl, _ := ctx.Deadline()
		if n == 1 {
			deadline = dl
			return bad, reset()
		}
		if dl != deadline {
			t.Fatal("per-attempt budget reset")
		}
		return good, nil
	}}
	c, e := run(ctx, d, time.Second)
	if e != nil || c != good || d.calls != 2 || bad.closes != 1 || good.closes != 0 {
		t.Fatalf("ownership/calls: %d %v", d.calls, e)
	}
}
func TestRetryCleanupFailureStopsReplay(t *testing.T) {
	failure := reset()
	closeFailure := errors.New("close failed")
	c := &countedConn{closeErr: closeFailure}
	d := &countedDialer{fn: func(context.Context, int) (stls.Conn, error) { return c, failure }}
	_, e := run(context.Background(), d, time.Second)
	if d.calls != 1 || c.closes != 1 || !errors.Is(e, failure) || !errors.Is(e, closeFailure) {
		t.Fatal("cleanup error lost or replayed")
	}
}
func TestRetryCanceledBeforeDial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d := &countedDialer{}
	_, e := run(ctx, d, time.Second)
	if d.calls != 0 || !errors.Is(e, context.Canceled) {
		t.Fatal("canceled dial executed")
	}
}
func TestRetryDefaultBudget(t *testing.T) {
	d := &countedDialer{fn: func(ctx context.Context, n int) (stls.Conn, error) {
		dl, ok := ctx.Deadline()
		if !ok || time.Until(dl) > 15*time.Second || time.Until(dl) < 14*time.Second {
			t.Fatal("wrong default budget")
		}
		return &countedConn{}, nil
	}}
	_, e := run(context.Background(), d, 0)
	if e != nil {
		t.Fatal(e)
	}
}

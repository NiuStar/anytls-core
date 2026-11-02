//go:build embedded_core

package engine

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	anytls "github.com/anytls/sing-anytls"
	"github.com/anytls/sing-anytls/padding"
	"github.com/anytls/sing-anytls/session"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type call struct {
	conn net.Conn
	dest M.Socksaddr
}
type peer struct {
	calls   chan call
	bytes   atomic.Int64
	stop    chan struct{}
	forward bool
	gate    chan struct{}
}

func (p *peer) NewConnectionEx(_ context.Context, c net.Conn, _ M.Socksaddr, d M.Socksaddr, _ N.CloseHandlerFunc) {
	p.calls <- call{c, d}
	if p.forward {
		<-p.gate
		up, e := net.Dial("tcp4", d.String())
		if e != nil {
			c.(*session.Stream).HandshakeFailure(e)
			return
		}
		defer up.Close()
		if e = c.(*session.Stream).HandshakeSuccess(); e != nil {
			return
		}
		go io.Copy(c, up)
		io.Copy(up, c)
		return
	}
	b := make([]byte, 128)
	for {
		n, e := c.Read(b)
		p.bytes.Add(int64(n))
		if e != nil {
			return
		}
		if _, e = c.Write(b[:n]); e != nil {
			return
		}
	}
}

type serverWire struct {
	net.Conn
	mode string
}

func (c serverWire) Write(b []byte) (int, error) {
	if len(b) >= 7 && b[0] == 10 {
		if c.mode == "silent" || c.mode == "negative-silent" {
			return len(b), nil
		}
		if c.mode == "v1" || c.mode == "negative-v1" {
			b = append([]byte(nil), b...)
			for i := 7; i+2 < len(b); i++ {
				if string(b[i:i+3]) == "v=2" {
					b[i+2] = '1'
				}
			}
		}
	}
	if len(b) >= 7 && b[0] == 7 && (c.mode == "silent" || c.mode == "v1") {
		return len(b), nil
	}
	return c.Conn.Write(b)
}
func fixture(t *testing.T) (*anytls.Client, *peer, func()) { return fixtureMode(t, "") }
func fixtureMode(t *testing.T, mode string) (*anytls.Client, *peer, func()) {
	t.Helper()
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ack.test"}, DNSNames: []string{"ack.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &k.PublicKey, k)
	if e != nil {
		t.Fatal(e)
	}
	cert, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	l, e := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: k}}, MinVersion: tls.VersionTLS13})
	if e != nil {
		t.Fatal(e)
	}
	p := &peer{calls: make(chan call, 20), stop: make(chan struct{})}
	svc, e := anytls.NewService(anytls.ServiceConfig{Users: []anytls.User{{Name: "test", Password: "synthetic-ack-only"}}, PaddingScheme: padding.DefaultPaddingScheme, Handler: p, Logger: logger.NOP()})
	if e != nil {
		t.Fatal(e)
	}
	var mu sync.Mutex
	var conns []net.Conn
	var wg sync.WaitGroup
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				_ = svc.NewConnection(context.Background(), serverWire{c, mode}, M.Socksaddr{}, nil)
			}()
		}
	}()
	client, e := anytls.NewClient(context.Background(), anytls.ClientConfig{Password: "synthetic-ack-only", Logger: logger.NOP(), DialOut: func(ctx context.Context) (net.Conn, error) {
		d := tls.Dialer{Config: &tls.Config{RootCAs: roots, ServerName: "ack.test", MinVersion: tls.VersionTLS13}}
		return d.DialContext(ctx, "tcp4", l.Addr().String())
	}})
	if e != nil {
		t.Fatal(e)
	}
	terminate := func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			c.Close()
		}
	}
	t.Cleanup(func() { client.Close(); l.Close(); terminate(); wg.Wait() })
	return client, p, terminate
}
func open(t *testing.T, c *anytls.Client, p *peer) (net.Conn, *session.Stream) {
	t.Helper()
	x, e := c.CreateProxy(context.Background(), M.ParseSocksaddr("127.0.0.1:23456"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { x.Close() })
	select {
	case y := <-p.calls:
		return x, y.conn.(*session.Stream)
	case <-time.After(2 * time.Second):
		t.Fatal("authenticated server did not receive target")
		return nil, nil
	}
}
func wait(c net.Conn, ctx context.Context) error {
	if w, ok := c.(interface{ WaitConnect(context.Context) error }); ok {
		return w.WaitConnect(ctx)
	}
	return errors.New("ACK API missing")
}
func bounded() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), time.Second)
}
func held(t *testing.T, ch <-chan error) {
	t.Helper()
	select {
	case e := <-ch:
		t.Fatalf("returned before remote ACK: %v", e)
	case <-time.After(60 * time.Millisecond):
	}
}
func result(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case e := <-ch:
		return e
	case <-time.After(2 * time.Second):
		t.Fatal("wait stuck")
		return nil
	}
}
func TestACKNegativeWithoutCapability(t *testing.T) {
	for _, mode := range []string{"negative-silent", "negative-v1", ""} {
		t.Run(mode, func(t *testing.T) {
			c, p, _ := fixtureMode(t, mode)
			x, s := open(t, c, p)
			// No WaitConnect: negative SYNACK alone must wake the legacy reader.
			x.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
			if e := s.HandshakeFailure(errors.New("synthetic-private-target")); e != nil {
				t.Fatal(e)
			}
			_, e := x.Read(make([]byte, 1))
			var remote *session.RemoteConnectError
			if !errors.As(e, &remote) {
				t.Errorf("B1 legacy Read lost negative report: %v", e)
			}
			if _, e = x.Write([]byte("forbidden")); !errors.As(e, &remote) {
				t.Errorf("B1 legacy Write accepted/changed failure: %v", e)
			}
			ctx, cancel := bounded()
			defer cancel()
			e = wait(x, ctx)
			if !errors.As(e, &remote) || errors.Is(e, session.ErrConnectACKUnconfirmed) {
				t.Errorf("B1 typed Wait lost negative report: %v", e)
			}
		})
	}
}
func TestACKUnknownSuccessNotTrusted(t *testing.T) {
	c, p, _ := fixtureMode(t, "negative-silent")
	x, s := open(t, c, p)
	if e := s.HandshakeSuccess(); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	e := wait(x, ctx)
	if !errors.Is(e, session.ErrConnectACKUnconfirmed) || !errors.Is(e, context.DeadlineExceeded) {
		t.Fatalf("unknown success trusted/classification wrong: %v", e)
	}
}
func TestACKCancelOneWaiterLaterACK(t *testing.T) {
	c, p, _ := fixture(t)
	x, s := open(t, c, p)
	ctx, cancel := context.WithCancel(context.Background())
	other, stop := bounded()
	defer stop()
	a, b := make(chan error, 1), make(chan error, 1)
	go func() { a <- wait(x, ctx) }()
	go func() { b <- wait(x, other) }()
	held(t, a)
	cancel()
	if e := result(t, a); !errors.Is(e, context.Canceled) || errors.Is(e, session.ErrConnectACKUnconfirmed) {
		t.Fatalf("cancel identity: %v", e)
	}
	held(t, b)
	if e := s.HandshakeSuccess(); e != nil {
		t.Fatal(e)
	}
	if e := result(t, b); e != nil {
		t.Fatal(e)
	}
}

// Same public-API delayed-target contract is compiled by the official product wrapper.
func TestACKRealTargetConnect(t *testing.T) {
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	var count atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, e := l.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		b := make([]byte, 4)
		n, _ := io.ReadFull(c, b)
		count.Add(int64(n))
		c.Write(b[:n])
	}()
	c, p, _ := fixture(t)
	p.forward = true
	p.gate = make(chan struct{})
	x, e := c.CreateProxy(context.Background(), M.ParseSocksaddr(l.Addr().String()))
	if e != nil {
		t.Fatal(e)
	}
	defer x.Close()
	<-p.calls
	ctx, cancel := bounded()
	defer cancel()
	d := make(chan error, 1)
	go func() { d <- wait(x, ctx) }()
	held(t, d)
	if count.Load() != 0 {
		t.Fatal("pre-ACK target data")
	}
	close(p.gate)
	if e = result(t, d); e != nil {
		t.Fatal(e)
	}
	if count.Load() != 0 {
		t.Fatal("pre-payload target data")
	}
	if _, e = x.Write([]byte("once")); e != nil {
		t.Fatal(e)
	}
	b := make([]byte, 4)
	if _, e = io.ReadFull(x, b); e != nil || string(b) != "once" {
		t.Fatalf("payload %q %v", b, e)
	}
	<-done
	if count.Load() != 4 {
		t.Fatal("payload not exactly once")
	}
}

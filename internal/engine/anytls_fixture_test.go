//go:build with_utls

package engine

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	anytls "github.com/anytls/sing-anytls"
	"github.com/anytls/sing-anytls/padding"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
	"github.com/sagernet/sing/protocol/socks"
)

// Ephemeral, memory-only CA/password. No product inbound registration or DNS.
type g13Fixture struct {
	ctx                                              context.Context
	cancel                                           context.CancelFunc
	listener, tcp                                    net.Listener
	udp                                              net.PacketConn
	ca, password                                     string
	cert                                             tls.Certificate
	accepted, closed, tcpBytes, udpBytes, uotStreams atomic.Int64
	hellos                                           chan *tls.ClientHelloInfo
	changed                                          chan struct{}
	mu                                               sync.Mutex
	conns                                            map[net.Conn]bool
	wg                                               sync.WaitGroup
	events                                           chan g13Event
	streamEnds                                       chan g13Event
	streamWait                                       chan struct{}
	// Immutable once requests start; only the slow-teardown regression sets these.
	teardownReached chan struct{}
	teardownRelease <-chan struct{}
}

// Only safe categories and fixture-owned IDs/targets escape the server worker.
// Never retain/log raw authentication errors, payloads or configuration values.
type g13Event struct {
	connection    int64
	class, target string
}
type g13ConnectionKey struct{}

func g13RejectionClass(stage string, err error, complete bool) string {
	if err == nil {
		return "OTHER_FAILURE"
	}
	if stage == "tls" && !complete {
		var op *net.OpError
		// crypto/tls TCP exposes the peer alert as net.OpError wrapping an
		// unexported alert (not tls.AlertError). Exact pinned constant only.
		if errors.As(err, &op) && op.Op == "remote error" && op.Err != nil && op.Err.Error() == "tls: bad certificate" {
			return "TLS_CERTIFICATE_REJECTED"
		}
	}
	// v0.0.11 has no exported auth sentinel; service.go:97 + fallback:129
	// returns this exact constant when no fallback handler is configured.
	if stage == "service" && complete && err.Error() == "unknown user password: fallback disabled" {
		return "AUTH_REJECTED"
	}
	return "OTHER_FAILURE"
}
func g13NonTimeoutClose(err error) bool {
	if err == nil || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return false
	}
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) || err.Error() == "socks5: request rejected, code=1"
}
func g13EvidenceMatches(ev g13Event, connection int64, class, target string) bool {
	return ev.connection == connection && ev.class == class && ev.target == target
}
func (f *g13Fixture) event(ev g13Event) {
	// Bounded buffer exceeds the number of fixture operations; never silently
	// drop witnesses. Cancellation releases a blocked producer during cleanup.
	select {
	case f.events <- ev:
	case <-f.ctx.Done():
	}
}
func g13Witness(t *testing.T, f *g13Fixture, class, target string, bound time.Duration) {
	t.Helper()
	timer := time.NewTimer(bound)
	defer timer.Stop()
	// Each caller uses a fresh fixture and one request, before any positive
	// control/recovery. No direct TLS probe or other client connects to it.
	select {
	case ev := <-f.events:
		if !g13EvidenceMatches(ev, 1, class, target) {
			t.Fatalf("wrong witness connection=%d category=%s target=%s", ev.connection, ev.class, ev.target)
		}
		t.Logf("fixture connection=%d category=%s target=%s", ev.connection, ev.class, ev.target)
	case <-timer.C:
		t.Fatal("missing actual-connection rejection witness")
	}
}

func g13Cert(t *testing.T) (string, tls.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ephemeral fixture CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"anytls.fixture.invalid"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), tls.Certificate{Certificate: [][]byte{leafDER, der}, PrivateKey: leafKey}
}
func (f *g13Fixture) job(fn func()) { f.wg.Add(1); go func() { defer f.wg.Done(); fn() }() }
func (f *g13Fixture) track(c net.Conn) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ctx.Err() != nil {
		c.Close()
	}
	f.conns[c] = true
}
func (f *g13Fixture) release(c net.Conn) { c.Close(); f.mu.Lock(); delete(f.conns, c); f.mu.Unlock() }
func (f *g13Fixture) serve(l net.Listener, fn func(net.Conn)) {
	f.job(func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			f.track(c)
			f.job(func() { defer f.release(c); fn(c) })
		}
	})
}
func g13New(t *testing.T) *g13Fixture {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	f := &g13Fixture{streamEnds: make(chan g13Event, 64), events: make(chan g13Event, 64), ctx: ctx, cancel: cancel, hellos: make(chan *tls.ClientHelloInfo, 64), changed: make(chan struct{}, 64), conns: make(map[net.Conn]bool)}
	f.ca, f.cert = g13Cert(t)
	secret := make([]byte, 24)
	if _, e := rand.Read(secret); e != nil {
		t.Fatal(e)
	}
	f.password = hex.EncodeToString(secret)
	var e error
	f.listener, e = net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		f.cancel()
		f.listener.Close()
		if f.tcp != nil {
			f.tcp.Close()
		}
		if f.udp != nil {
			f.udp.Close()
		}
		f.mu.Lock()
		for c := range f.conns {
			c.Close()
		}
		f.mu.Unlock()
		done := make(chan struct{})
		go func() { f.wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("fixture did not close listeners/sessions")
		}
	})
	f.tcp, e = net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	f.udp, e = net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	svc, e := anytls.NewService(anytls.ServiceConfig{Users: []anytls.User{{Name: "fixture", Password: f.password}}, PaddingScheme: padding.DefaultPaddingScheme, Handler: f, Logger: logger.NOP()})
	if e != nil {
		t.Fatal(e)
	}
	f.serve(f.listener, func(c net.Conn) {
		connection := f.accepted.Add(1)
		defer func() {
			f.closed.Add(1)
			select {
			case f.changed <- struct{}{}:
			default:
			}
		}()
		tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{f.cert}, MinVersion: tls.VersionTLS12, GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			select {
			case f.hellos <- h:
			default:
			}
			return nil, nil
		}})
		_ = tc.SetDeadline(time.Now().Add(30 * time.Second))
		if err := tc.HandshakeContext(ctx); err != nil {
			f.event(g13Event{connection: connection, class: g13RejectionClass("tls", err, tc.ConnectionState().HandshakeComplete)})
			return
		}
		serviceCtx := context.WithValue(ctx, g13ConnectionKey{}, connection)
		if err := svc.NewConnection(serviceCtx, tc, M.SocksaddrFromNet(c.RemoteAddr()), nil); err != nil {
			f.event(g13Event{connection: connection, class: g13RejectionClass("service", err, tc.ConnectionState().HandshakeComplete)})
		}
	})
	f.serve(f.tcp, func(c net.Conn) {
		b := make([]byte, 4096)
		for {
			n, e := c.Read(b)
			if n > 0 {
				f.tcpBytes.Add(int64(n))
				_, _ = c.Write(b[:n])
			}
			if e != nil {
				return
			}
		}
	})
	f.job(func() {
		b := make([]byte, 65535)
		for {
			n, a, e := f.udp.ReadFrom(b)
			if e != nil {
				return
			}
			f.udpBytes.Add(int64(n))
			_, _ = f.udp.WriteTo(b[:n], a)
		}
	})
	return f
}
func (f *g13Fixture) NewConnectionEx(ctx context.Context, c net.Conn, _ M.Socksaddr, d M.Socksaddr, _ N.CloseHandlerFunc) {
	f.job(func() {
		defer c.Close()
		if d.Fqdn == uot.MagicAddress {
			f.uotStreams.Add(1)
			r, e := uot.ReadRequest(c)
			if e != nil {
				return
			}
			uc := uot.NewConn(c, *r)
			b := make([]byte, 65535)
			for {
				n, a, e := uc.ReadFrom(b)
				if e != nil {
					return
				}
				if a.String() != f.udp.LocalAddr().String() {
					return
				}
				u, e := net.DialTimeout("udp", a.String(), time.Second)
				if e != nil {
					return
				}
				_ = u.SetDeadline(time.Now().Add(2 * time.Second))
				_, e = u.Write(b[:n])
				if e == nil {
					n, e = u.Read(b)
				}
				u.Close()
				if e != nil {
					return
				}
				if _, e = uc.WriteTo(b[:n], a); e != nil {
					return
				}
			}
		}
		// Fail closed before any non-fixture dial; unknown targets simulate remote reset.
		if d.String() != f.tcp.Addr().String() {
			connection, _ := ctx.Value(g13ConnectionKey{}).(int64)
			f.event(g13Event{connection: connection, class: "TARGET_REFUSED", target: d.String()})
			return
		}
		up, e := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", d.String())
		if e != nil {
			return
		}
		f.track(up)
		defer f.release(up)
		done := make(chan struct{})
		go func() { _, _ = io.Copy(up, c); up.Close(); close(done) }()
		_, _ = io.Copy(c, up)
		<-done
		if f.teardownReached != nil {
			select {
			case f.teardownReached <- struct{}{}:
			case <-f.ctx.Done():
				return
			}
			select {
			case <-f.teardownRelease:
			case <-f.ctx.Done():
				return
			}
		}
		c.Close()
		connection, _ := ctx.Value(g13ConnectionKey{}).(int64)
		select {
		case f.streamEnds <- g13Event{connection: connection, class: "STREAM_ENDED", target: d.String()}:
		case <-f.ctx.Done():
		}
	})
}

type g13Dialer struct{}

func g13Sequential(t *testing.T, f *g13Fixture, client *socks.Client) error {
	t.Helper()
	// stream.closeWithError calls the client's dieHook (pool insertion) before
	// writing FIN. recvLoop(cmdFIN) closes pipeR before closeLocally's dieHook,
	// however: a handler teardown/EOF alone is not a universal pool-return ack.
	// Observe real successive stream closures on the SAME TLS connection instead.
	// A fresh session is an eligibility probe, not a failure or a relaxed accept
	// bound. Each probe waits for its own completed handler before the next dial.
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	var previous int64
	consecutive := 0
	for probe := 0; probe < 64; probe++ {
		if ctx.Err() != nil {
			return errors.New("bounded sequential reuse eligibility expired")
		}
		if e := g13Exchange(client, "tcp", f.tcp.Addr().String(), []byte(fmt.Sprintf("sequential-%d", probe))); e != nil {
			return e
		}
		if f.streamWait != nil {
			select {
			case f.streamWait <- struct{}{}:
			default:
			}
		}
		var ev g13Event
		select {
		case ev = <-f.streamEnds:
		case <-ctx.Done():
			return errors.New("missing bounded stream teardown event")
		}
		if ev.connection < 1 || ev.class != "STREAM_ENDED" || ev.target != f.tcp.Addr().String() || f.closed.Load() != 0 {
			return errors.New("wrong or closed sequential stream witness")
		}
		if previous == ev.connection {
			consecutive++
		} else {
			previous, consecutive = ev.connection, 1
		}
		if consecutive == 4 {
			t.Logf("four completed sequential streams reused TLS connection=%d probes=%d accepts=%d", previous, probe+1, f.accepted.Load())
			return nil
		}
	}
	return errors.New("no four-stream same-TLS reuse proof within bounded probes")
}

func g13CancelRead(c net.Conn, cancel context.CancelFunc, bound time.Duration) error {
	cancel()
	if e := c.SetReadDeadline(time.Now().Add(bound)); e != nil {
		return e
	}
	b := make([]byte, 1)
	_, e := c.Read(b)
	if !g13NonTimeoutClose(e) {
		return errors.New("active cancellation lacked non-timeout transport close")
	}
	return nil
}

func (g13Dialer) DialContext(ctx context.Context, n string, d M.Socksaddr) (net.Conn, error) {
	return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, n, d.String())
}
func (g13Dialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("unused fixture method")
}
func (f *g13Fixture) config(port int, modify func(map[string]any)) []byte {
	tlsOptions := map[string]any{"enabled": true, "insecure": false, "server_name": "anytls.fixture.invalid", "certificate": []string{f.ca}, "utls": map[string]any{"enabled": true, "fingerprint": "chrome"}}
	// Pinned sing-anytls v0.0.11 clamps <=5s to 30s; 6s is the smallest effective value.
	ob := map[string]any{"type": "anytls", "tag": "secure", "server": "127.0.0.1", "server_port": f.listener.Addr().(*net.TCPAddr).Port, "password": f.password, "tls": tlsOptions, "idle_session_check_interval": "6s", "idle_session_timeout": "6s", "min_idle_session": 0}
	if modify != nil {
		modify(ob)
	}
	var cfg map[string]any
	_ = json.Unmarshal(loopbackConfig(port), &cfg)
	cfg["outbounds"] = []any{ob}
	cfg["route"] = map[string]any{"final": "secure"}
	b, _ := json.Marshal(cfg)
	return b
}
func g13Start(t *testing.T, b []byte, port int) (*socks.Client, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, b) }()
	t.Cleanup(func() {
		cancel()
		if e := awaitRun(t, done); !errors.Is(e, context.Canceled) {
			t.Errorf("Run cleanup: %v", e)
		}
		assertBindable(t, port)
	})
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, e := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond)
		if e == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("mixed listener not ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	return socks.NewClient(g13Dialer{}, M.ParseSocksaddr(fmt.Sprintf("127.0.0.1:%d", port)), socks.Version5, "", ""), cancel
}
func g13Exchange(client *socks.Client, network, target string, payload []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, e := client.DialContext(ctx, network, M.ParseSocksaddr(target))
	if e != nil {
		return e
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, e = c.Write(payload); e != nil {
		return e
	}
	b := make([]byte, 65535)
	if network == "udp" {
		n, a, err := c.(net.PacketConn).ReadFrom(b)
		if err != nil {
			return err
		}
		if a.String() != target || string(b[:n]) != string(payload) {
			return fmt.Errorf("UDP source/payload mismatch: bytes=%d", n)
		}
		return nil
	}
	b = b[:len(payload)]
	if _, e = io.ReadFull(c, b); e != nil {
		return e
	}
	if string(b) != string(payload) {
		return errors.New("echo payload mismatch")
	}
	return nil
}
func g13Hello(t *testing.T, f *g13Fixture, wantGREASE bool) {
	t.Helper()
	select {
	case h := <-f.hellos:
		grease := false
		for _, v := range h.CipherSuites {
			if v&0x0f0f == 0x0a0a && byte(v) == byte(v>>8) {
				grease = true
			}
		}
		if grease != wantGREASE || h.ServerName != "anytls.fixture.invalid" {
			t.Fatal("ClientHello GREASE/SNI profile signal mismatch")
		}
		t.Logf("ClientHello GREASE=%v ciphers=%d curves=%d; not exact browser fidelity", grease, len(h.CipherSuites), len(h.SupportedCurves))
	case <-time.After(3 * time.Second):
		t.Fatal("missing real TLS ClientHello")
	}
}
func g13Closed(t *testing.T, f *g13Fixture, want int64, bound time.Duration) {
	t.Helper()
	timer := time.NewTimer(bound)
	defer timer.Stop()
	for f.closed.Load() < want {
		select {
		case <-f.changed:
		case <-timer.C:
			t.Fatal("TLS sessions did not close within bound")
		}
	}
}

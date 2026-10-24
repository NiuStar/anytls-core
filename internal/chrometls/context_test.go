//go:build with_utls

package chrometls

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/service"
)

type testStore struct {
	adapter.CertificateStore
	pool *x509.CertPool
}

func (s testStore) Pool() *x509.CertPool { return s.pool }

type testClock struct{ now time.Time }

func (s testClock) TimeFunc() func() time.Time { return func() time.Time { return s.now } }

func TestContextTrustAndCancellation(t *testing.T) {
	pool := x509.NewCertPool()
	now := time.Unix(1700000000, 0)
	ctx := service.ContextWith[adapter.CertificateStore](context.Background(), testStore{pool: pool})
	ctx = service.ContextWith[ntp.TimeService](ctx, testClock{now: now})
	cfg, err := (Factory{}).NewChromeClient(ctx, "example.test", chromeOptions())
	if err != nil {
		t.Fatal(err)
	}
	c := cfg.(*clientConfig)
	if c.config.Time == nil || !c.config.Time().Equal(now) || c.config.RootCAs == pool || !c.config.RootCAs.Equal(pool) {
		t.Fatal("lost context time/root trust or retained mutable root pool")
	}
	clone := c.Clone().(*clientConfig)
	if clone.config.RootCAs == c.config.RootCAs || !clone.config.RootCAs.Equal(c.config.RootCAs) {
		t.Fatal("clone shares root pool")
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	conn, err := cfg.Client(left)
	if err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err = conn.HandshakeContext(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("lost cancellation: %v", err)
	}
	// Handshake cancellation closes the transport; Close may report the
	// already-closed pipe, but must remain safe to call for caller cleanup.
	_ = conn.Close()
}

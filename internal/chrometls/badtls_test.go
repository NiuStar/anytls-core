//go:build with_utls

package chrometls

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"

	"github.com/sagernet/sing-box/common/badtls"
)

func TestUnknownBackendReadWaitFallsBack(t *testing.T) {
	cfg, err := (Factory{}).NewChromeClient(context.Background(), "example.test", chromeOptions())
	if err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	conn, err := cfg.Client(left)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = badtls.NewReadWaitConn(conn); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("new backend must not match metacubex private layout: %v", err)
	}
}

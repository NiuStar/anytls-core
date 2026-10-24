//go:build !with_utls

package chrometls

import (
	"context"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestMissingUTLSFailsClosed(t *testing.T) {
	cfg, err := (Factory{}).NewChromeClient(context.Background(), "example.test", option.OutboundTLSOptions{})
	if cfg != nil || err == nil || !strings.Contains(err.Error(), "with_utls") {
		t.Fatalf("missing uTLS must fail closed: %v, %v", cfg, err)
	}
}

package tlsdialretry

import (
	"context"
	"crypto/tls"
	"errors"
	"testing"
	"time"

	stls "github.com/sagernet/sing-box/common/tls"
)

// A verifier error can itself wrap a transport-looking cause. Security identity
// takes precedence over a nested reset; never replay a rejected verifier.
func TestRetryRejectsCertificateWrapperAroundReset(t *testing.T) {
	failure := &tls.CertificateVerificationError{Err: reset()}
	d := &countedDialer{fn: func(context.Context, int) (stls.Conn, error) { return nil, failure }}
	_, e := run(context.Background(), d, time.Second)
	if d.calls != 1 || !errors.Is(e, failure) {
		t.Fatalf("certificate error replayed: calls=%d", d.calls)
	}
}

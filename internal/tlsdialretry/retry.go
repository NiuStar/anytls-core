// Package tlsdialretry bounds retries at the AnyTLS TLS-dial boundary only.
package tlsdialretry

import (
	"context"
	stdtls "crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"syscall"
	"time"

	"github.com/sagernet/sing-box/common/tls"
	M "github.com/sagernet/sing/common/metadata"
)

// Factory deliberately receives the original SDK dialer, not a raw TCP address.
// Every attempt retains its interface binding, detour and strict TLS verifier.
type Factory struct{}

func (Factory) DialAnyTLS(ctx context.Context, dialer tls.Dialer, server M.Socksaddr, budget time.Duration) (net.Conn, error) {
	if budget <= 0 {
		budget = 15 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	var failures []error
	for attempt := 0; attempt < 3; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, errors.Join(append(failures, err)...)
		}
		conn, err := dialer.DialTLSContext(ctx, server)
		if err == nil && ctx.Err() == nil && conn != nil {
			return conn, nil
		}
		if err == nil {
			err = ctx.Err()
			if err == nil {
				err = io.ErrUnexpectedEOF
			}
		}
		failures = append(failures, err)
		if conn != nil {
			if closeErr := conn.Close(); closeErr != nil {
				return nil, errors.Join(append(failures, closeErr)...)
			}
		}
		if ctx.Err() != nil {
			return nil, errors.Join(append(failures, ctx.Err())...)
		}
		if attempt == 2 || !resetOnly(err) {
			return nil, errors.Join(failures...)
		}
		timer := time.NewTimer(time.Duration(attempt+1) * 150 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, errors.Join(append(failures, ctx.Err())...)
		case <-timer.C:
		}
	}
	panic("unreachable")
}

// Require an actual net.OpError and the exact reset sentinel at the leaf.
// Reject all multi-cause trees (including reset+security/cancel/permission),
// timeout wrappers, EOF, protocol and same-text errors. No string matching.
func resetOnly(err error) bool {
	var op *net.OpError
	if !errors.Is(err, syscall.ECONNRESET) || !errors.As(err, &op) {
		return false
	}
	for depth := 0; err != nil && depth < 32; depth++ {
		switch err.(type) {
		case *stdtls.CertificateVerificationError, *stdtls.ECHRejectionError,
			stdtls.RecordHeaderError, stdtls.AlertError,
			x509.CertificateInvalidError, x509.HostnameError, x509.UnknownAuthorityError,
			x509.SystemRootsError, x509.InsecureAlgorithmError:
			return false
		}
		if _, joined := err.(interface{ Unwrap() []error }); joined {
			return false
		}
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return false
		}
		if err == syscall.ECONNRESET {
			return true
		}
		next, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = next.Unwrap()
	}
	return false
}

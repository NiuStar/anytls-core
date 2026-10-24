//go:build with_utls

// Package chrometls adapts the pinned upstream Chrome155 backend for AnyTLS.
// It deliberately does not replace the SDK's other TLS implementations.
package chrometls

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/sagernet/sing-box/adapter"
	boxTLS "github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/service/filemanager"
)

// Factory is registered under the SDK hook's exact anonymous interface.
// No global TLS dispatch, init registration, or metacubex replacement is used.
type Factory struct{}

func (Factory) NewChromeClient(ctx context.Context, address string, o option.OutboundTLSOptions) (boxTLS.Config, error) {
	if err := boxTLS.ValidateCertificateSHA256Options(o); err != nil {
		return nil, err
	}
	if !o.Enabled || o.UTLS == nil || !o.UTLS.Enabled || (o.UTLS.Fingerprint != "" && o.UTLS.Fingerprint != "chrome") {
		return nil, errors.New("Chrome155 requires enabled plain Chrome uTLS")
	}
	if (o.Engine != "" && o.Engine != "go") || o.Reality != nil || o.ECH != nil || o.KernelRx || o.KernelTx || o.Fragment || o.RecordFragment || o.FragmentFallbackDelay != 0 || o.Spoof != "" || o.SpoofMethod != "" || o.CipherSuites != nil || o.CurvePreferences != nil || o.ClientCertificate != nil || o.ClientCertificatePath != "" || o.ClientKey != nil || o.ClientKeyPath != "" {
		return nil, errors.New("unsupported Chrome155 TLS option")
	}
	// The fixed browser preset advertises TLS1.2/1.3. Do not silently claim
	// narrower policy from Config fields that a preset may overwrite.
	if (o.MinVersion != "" && o.MinVersion != "1.2") || (o.MaxVersion != "" && o.MaxVersion != "1.3") {
		return nil, errors.New("Chrome155 supports only the TLS1.2-to-1.3 version range")
	}
	name := o.ServerName
	if name == "" {
		name = address
	}
	if name == "" && !o.Insecure && len(o.CertificateSHA256) == 0 {
		return nil, errors.New("missing TLS server name")
	}
	cfg := &utls.Config{Time: ntp.TimeFuncFromContext(ctx), RootCAs: adapter.RootPoolFromContext(ctx), InsecureSkipVerify: o.Insecure, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13}
	if cfg.RootCAs != nil {
		cfg.RootCAs = cfg.RootCAs.Clone()
	}
	if len(o.CertificateSHA256) > 0 {
		pins := make([][]byte, len(o.CertificateSHA256))
		for i, pin := range o.CertificateSHA256 {
			pins[i] = slices.Clone(pin)
		}
		// Pin-only identity; authenticate the entire leaf DER, never SPKI or CA.
		cfg.InsecureSkipVerify = true
		cfg.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("missing peer certificate")
			}
			digest := sha256.Sum256(raw[0])
			matched := 0
			for _, pin := range pins {
				matched |= subtle.ConstantTimeCompare(pin, digest[:])
			}
			if matched != 1 {
				return errors.New("unrecognized remote leaf certificate")
			}
			return nil
		}
	}
	if len(o.CertificatePublicKeySHA256) > 0 {
		if len(o.Certificate) > 0 || o.CertificatePath != "" {
			return nil, errors.New("certificate_public_key_sha256 conflicts with certificate or certificate_path")
		}
		pins := make([][]byte, len(o.CertificatePublicKeySHA256))
		for i, pin := range o.CertificatePublicKeySHA256 {
			if len(pin) != sha256.Size {
				return nil, errors.New("invalid certificate_public_key_sha256 length")
			}
			pins[i] = slices.Clone(pin)
		}
		// Match the SDK's pin-only identity policy, including its deliberate
		// bypass of PKIX/name/expiry checks, rather than inventing PKIX+pin.
		cfg.InsecureSkipVerify = true
		cfg.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("missing peer certificate")
			}
			return boxTLS.VerifyPublicKeySHA256(pins, raw)
		}
	}
	var certificate []byte
	if len(o.Certificate) > 0 {
		certificate = []byte(strings.Join(o.Certificate, "\n"))
	} else if o.CertificatePath != "" {
		var err error
		certificate, err = filemanager.ReadFile(ctx, o.CertificatePath)
		if err != nil {
			return nil, fmt.Errorf("read TLS certificate: %w", err)
		}
	}
	if len(o.Certificate) > 0 || o.CertificatePath != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(certificate) {
			return nil, errors.New("failed to parse TLS certificate")
		}
		cfg.RootCAs = pool
	}
	timeout := C.TCPTimeout
	if o.HandshakeTimeout > 0 {
		timeout = o.HandshakeTimeout.Build()
	}
	c := &clientConfig{config: cfg, disableSNI: o.DisableSNI, verifyServerName: o.DisableSNI && !o.Insecure && len(o.CertificateSHA256) == 0, timeout: timeout}
	c.SetServerName(name)
	c.SetNextProtos(o.ALPN)
	return c, nil
}

type clientConfig struct {
	config           *utls.Config
	serverName       string
	disableSNI       bool
	verifyServerName bool
	timeout          time.Duration
}

var _ boxTLS.Config = (*clientConfig)(nil)
var _ boxTLS.Conn = (*clientConn)(nil)

func (c *clientConfig) ServerName() string { return c.serverName }
func (c *clientConfig) SetServerName(name string) {
	c.serverName = name
	c.config.ServerName = name
	c.config.InsecureServerNameToVerify = ""
	if c.disableSNI {
		c.config.ServerName = ""
		if c.verifyServerName {
			c.config.InsecureServerNameToVerify = name
		}
	}
}
func (c *clientConfig) NextProtos() []string { return slices.Clone(c.config.NextProtos) }
func (c *clientConfig) SetNextProtos(protos []string) {
	c.config.NextProtos = slices.Clone(protos)
	if len(protos) == 1 && protos[0] == "h2" {
		c.config.NextProtos = append(c.config.NextProtos, "http/1.1")
	}
}
func (c *clientConfig) HandshakeTimeout() time.Duration     { return c.timeout }
func (c *clientConfig) SetHandshakeTimeout(d time.Duration) { c.timeout = d }
func (c *clientConfig) STDConfig() (*tls.Config, error) {
	return nil, errors.New("Chrome155 cannot be converted to Go TLS")
}
func (c *clientConfig) Clone() boxTLS.Config {
	clone := *c
	clone.config = c.config.Clone()
	clone.config.NextProtos = slices.Clone(c.config.NextProtos)
	if c.config.RootCAs != nil {
		clone.config.RootCAs = c.config.RootCAs.Clone()
	}
	return &clone
}
func (c *clientConfig) Client(raw net.Conn) (boxTLS.Conn, error) {
	cfg := c.config.Clone()
	cfg.NextProtos = slices.Clone(cfg.NextProtos)
	return &clientConn{UConn: utls.UClient(raw, cfg, utls.HelloChrome_155), protos: slices.Clone(cfg.NextProtos)}, nil
}

type clientConn struct {
	*utls.UConn
	protos []string
}

func (c *clientConn) Upstream() any           { return c.UConn }
func (c *clientConn) ReaderReplaceable() bool { return true }
func (c *clientConn) WriterReplaceable() bool { return true }
func (c *clientConn) HandshakeContext(ctx context.Context) error {
	if len(c.protos) > 0 {
		if err := c.BuildHandshakeState(); err != nil {
			return err
		}
		found := false
		for _, ext := range c.Extensions {
			if alpn, ok := ext.(*utls.ALPNExtension); ok {
				alpn.AlpnProtocols = slices.Clone(c.protos)
				found = true
				break
			}
		}
		if !found {
			return errors.New("Chrome155 preset has no ALPN extension")
		}
		if err := c.BuildHandshakeState(); err != nil {
			return err
		}
	}
	return c.UConn.HandshakeContext(ctx)
}

// Copy every public Go1.27 field. ExportKeyingMaterial's private closure is not
// portable between libraries; callers requiring it must use Upstream directly.
func (c *clientConn) ConnectionState() tls.ConnectionState {
	s := c.UConn.ConnectionState()
	return tls.ConnectionState{
		Version: s.Version, HandshakeComplete: s.HandshakeComplete, DidResume: s.DidResume,
		CipherSuite: s.CipherSuite, CurveID: tls.CurveID(s.CurveID), NegotiatedProtocol: s.NegotiatedProtocol,
		NegotiatedProtocolIsMutual: s.NegotiatedProtocolIsMutual, ServerName: s.ServerName,
		PeerCertificates: s.PeerCertificates, VerifiedChains: s.VerifiedChains,
		SignedCertificateTimestamps: s.SignedCertificateTimestamps, OCSPResponse: s.OCSPResponse,
		TLSUnique: s.TLSUnique, ECHAccepted: s.ECHAccepted, HelloRetryRequest: s.HelloRetryRequest,
		LocalCertificate: s.LocalCertificate,
	}
}

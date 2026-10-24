//go:build with_utls

package chrometls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
	boxTLS "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
)

func chromeOptions() option.OutboundTLSOptions {
	return option.OutboundTLSOptions{Enabled: true, UTLS: &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"}}
}

func TestConfigCloneAndTraits(t *testing.T) {
	o := chromeOptions()
	o.ALPN = []string{"h2"}
	cfg, err := (Factory{}).NewChromeClient(context.Background(), "example.test", o)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg.(boxTLS.WithSessionIDGenerator); ok {
		t.Fatal("must not expose metacubex session mutation")
	}
	if _, err := cfg.STDConfig(); err == nil {
		t.Fatal("must not substitute Go TLS")
	}
	clone := cfg.Clone()
	clone.SetServerName("other.test")
	clone.SetNextProtos([]string{"http/1.1"})
	clone.SetHandshakeTimeout(time.Second)
	if cfg.ServerName() != "example.test" || cfg.NextProtos()[0] != "h2" || len(cfg.NextProtos()) != 2 || cfg.HandshakeTimeout() == time.Second {
		t.Fatal("clone changed original")
	}
	o.ALPN[0] = "changed"
	if cfg.NextProtos()[0] != "h2" {
		t.Fatal("retained caller slice")
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	conn, err := cfg.Client(left)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := conn.(interface{ Upstream() any }).Upstream().(*utls.UConn); !ok {
		t.Fatal("wrong upstream library")
	}
}

func TestRejectUnsupported(t *testing.T) {
	cases := []struct {
		name   string
		change func(*option.OutboundTLSOptions)
	}{
		{"disabled", func(o *option.OutboundTLSOptions) { o.Enabled = false }},
		{"fingerprint", func(o *option.OutboundTLSOptions) { o.UTLS.Fingerprint = "firefox" }},
		{"engine", func(o *option.OutboundTLSOptions) { o.Engine = "apple" }},
		{"reality", func(o *option.OutboundTLSOptions) { o.Reality = &option.OutboundRealityOptions{} }},
		{"ech", func(o *option.OutboundTLSOptions) { o.ECH = &option.OutboundECHOptions{} }},
		{"fragment", func(o *option.OutboundTLSOptions) { o.Fragment = true }},
		{"fragment_delay", func(o *option.OutboundTLSOptions) { o.FragmentFallbackDelay = 1 }},
		{"record_fragment", func(o *option.OutboundTLSOptions) { o.RecordFragment = true }},
		{"spoof", func(o *option.OutboundTLSOptions) { o.Spoof = "x" }},
		{"spoof_method", func(o *option.OutboundTLSOptions) { o.SpoofMethod = "x" }},
		{"ktls_tx", func(o *option.OutboundTLSOptions) { o.KernelTx = true }},
		{"ktls_rx", func(o *option.OutboundTLSOptions) { o.KernelRx = true }},
		{"client_key", func(o *option.OutboundTLSOptions) { o.ClientKeyPath = "x" }},
		{"client_cert", func(o *option.OutboundTLSOptions) { o.ClientCertificatePath = "x" }},
		{"ciphers", func(o *option.OutboundTLSOptions) { o.CipherSuites = []string{"x"} }},
		{"curves", func(o *option.OutboundTLSOptions) { o.CurvePreferences = []option.CurvePreference{29} }},
		{"min13", func(o *option.OutboundTLSOptions) { o.MinVersion = "1.3" }},
		{"max12", func(o *option.OutboundTLSOptions) { o.MaxVersion = "1.2" }},
		{"bad_ca", func(o *option.OutboundTLSOptions) { o.Certificate = []string{"invalid"} }},
		{"bad_pin", func(o *option.OutboundTLSOptions) { o.CertificatePublicKeySHA256 = [][]byte{{1}} }},
		{"pin_ca_conflict", func(o *option.OutboundTLSOptions) {
			o.CertificatePublicKeySHA256 = [][]byte{make([]byte, 32)}
			o.CertificatePath = "x"
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := chromeOptions()
			tc.change(&o)
			if _, err := (Factory{}).NewChromeClient(context.Background(), "example.test", o); err == nil {
				t.Fatal("accepted unsupported option")
			}
		})
	}
	if _, err := (Factory{}).NewChromeClient(context.Background(), "", chromeOptions()); err == nil {
		t.Fatal("accepted missing identity")
	}
}

// Real loopback TLS: a rejected certificate must deliver zero application bytes.
func TestRealTLSIdentity(t *testing.T) {
	now := time.Now()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, caPEM, 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"strict", "path", "wrong_san", "untrusted", "expired", "pin", "bad_pin", "insecure", "disable_sni", "ip"} {
		t.Run(name, func(t *testing.T) {
			leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"example.test"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
			if name == "expired" {
				leaf.NotAfter = now.Add(-time.Minute)
			}
			der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, key)
			if err != nil {
				t.Fatal(err)
			}
			cert := tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: key}
			o := chromeOptions()
			o.ServerName = "example.test"
			o.Certificate = []string{string(caPEM)}
			o.ALPN = []string{"http/1.1"}
			o.MinVersion = "1.2"
			o.MaxVersion = "1.3"
			success := true
			switch name {
			case "path":
				o.Certificate = nil
				o.CertificatePath = path
			case "wrong_san":
				o.ServerName = "wrong.test"
				success = false
			case "untrusted":
				o.Certificate = nil
				success = false
			case "expired":
				success = false
			case "insecure":
				o.Certificate = nil
				o.Insecure = true
			case "disable_sni":
				o.DisableSNI = true
			case "ip":
				o.ServerName = "127.0.0.1"
			case "pin", "bad_pin":
				o.Certificate = nil
				parsed, e := x509.ParseCertificate(der)
				if e != nil {
					t.Fatal(e)
				}
				spki, e := x509.MarshalPKIXPublicKey(parsed.PublicKey)
				if e != nil {
					t.Fatal(e)
				}
				pin := sha256.Sum256(spki)
				if name == "bad_pin" {
					pin[0] ^= 1
					success = false
				}
				o.CertificatePublicKeySHA256 = [][]byte{pin[:]}
			}
			cfg, err := (Factory{}).NewChromeClient(context.Background(), "127.0.0.1", o)
			if err != nil {
				t.Fatal(err)
			}
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			type result struct {
				n   int
				err error
				sni string
			}
			done := make(chan result, 1)
			go func() {
				raw, e := ln.Accept()
				if e != nil {
					done <- result{err: e}
					return
				}
				defer raw.Close()
				raw.SetDeadline(time.Now().Add(3 * time.Second))
				server := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}})
				b := make([]byte, 1)
				n, e := server.Read(b)
				done <- result{n: n, err: e, sni: server.ConnectionState().ServerName}
			}()
			raw, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			raw.SetDeadline(time.Now().Add(3 * time.Second))
			conn, err := cfg.Client(raw)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			err = conn.HandshakeContext(ctx)
			if success {
				if err != nil {
					t.Fatal(err)
				}
				state := conn.ConnectionState()
				if !state.HandshakeComplete || state.NegotiatedProtocol != "http/1.1" || len(state.PeerCertificates) == 0 {
					t.Fatal("lost connection state")
				}
				if _, err = conn.Write([]byte{42}); err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("accepted invalid identity")
			}
			conn.Close()
			r := <-done
			if success {
				if r.n != 1 {
					t.Fatalf("missing app byte: %v", r.err)
				}
				if (name == "disable_sni" || name == "ip") && r.sni != "" {
					t.Fatal("unexpected SNI")
				}
			} else if r.n != 0 || r.err == nil || r.err == io.EOF {
				t.Fatalf("no certificate rejection evidence: %+v", r)
			}
		})
	}
}

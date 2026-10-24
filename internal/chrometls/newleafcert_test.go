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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	boxTLS "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
)

// Decode JSON rather than referencing the new SDK field, so these exact test
// bytes also compile against the historical SDK for a behavioral RED.
func leafOptions(t *testing.T, backend string, pin []byte) option.OutboundTLSOptions {
	t.Helper()
	utlsJSON := ""
	if backend != "golang" {
		utlsJSON = fmt.Sprintf(`,"utls":{"enabled":true,"fingerprint":%q}`, backend)
	}
	var o option.OutboundTLSOptions
	if err := json.Unmarshal([]byte(fmt.Sprintf(`{"enabled":true,"disable_sni":true,"certificate_sha256":[%q]%s}`, base64.StdEncoding.EncodeToString(pin), utlsJSON)), &o); err != nil {
		t.Fatal(err)
	}
	return o
}

func leafClient(backend string, o option.OutboundTLSOptions) (boxTLS.Config, error) {
	if backend == "chrome" {
		return (Factory{}).NewChromeClient(context.Background(), "127.0.0.1", o)
	}
	return boxTLS.NewClient(context.Background(), nil, "127.0.0.1", o)
}

func TestLeafCertificatePinRealTLS(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	// Deliberately expired, no SAN: correct pin must work without PKIX/SNI.
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-2 * time.Hour), NotAfter: now.Add(-time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	other := *leaf
	other.SerialNumber = big.NewInt(3)
	otherDER, err := x509.CreateCertificate(rand.Reader, &other, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, backend := range []string{"chrome", "golang", "firefox"} {
		for _, tc := range []struct {
			name  string
			input []byte
			ok    bool
		}{{"correct", der, true}, {"wrong", []byte("wrong"), false}, {"chain_only", caDER, false}, {"same_key_reissued", otherDER, false}, {"spki_not_der", spki, false}} {
			t.Run(backend+"/"+tc.name, func(t *testing.T) {
				pin := sha256.Sum256(tc.input)
				cfg, err := leafClient(backend, leafOptions(t, backend, pin[:]))
				if err != nil {
					t.Fatal(err)
				}
				cfg = cfg.Clone()
				cfg.SetServerName("untrusted.invalid")
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer ln.Close()
				type result struct {
					n   int
					err error
				}
				done := make(chan result, 1)
				go func() {
					raw, e := ln.Accept()
					if e != nil {
						done <- result{err: e}
						return
					}
					defer raw.Close()
					raw.SetDeadline(time.Now().Add(5 * time.Second))
					server := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der, caDER}, PrivateKey: key}}})
					buf := make([]byte, 1)
					n, e := server.Read(buf)
					done <- result{n, e}
				}()
				raw, err := net.Dial("tcp", ln.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				defer raw.Close()
				raw.SetDeadline(time.Now().Add(5 * time.Second))
				conn, err := cfg.Client(raw)
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				err = conn.HandshakeContext(ctx)
				if tc.ok && err == nil {
					_, err = conn.Write([]byte{42})
				}
				conn.Close()
				r := <-done
				if tc.ok {
					if err != nil || r.n != 1 {
						t.Fatalf("correct leaf rejected or missing byte: client=%v peer=%v n=%d", err, r.err, r.n)
					}
				} else {
					var timeout net.Error
					if err == nil || errors.As(err, &timeout) && timeout.Timeout() {
						t.Fatalf("not a certificate rejection: %v", err)
					}
					if r.n != 0 || r.err == nil || errors.Is(r.err, io.EOF) || errors.As(r.err, &timeout) && timeout.Timeout() {
						t.Fatalf("no peer TLS rejection / leaked payload: n=%d err=%v", r.n, r.err)
					}
				}
			})
		}
	}
}

func TestLeafCertificatePinRejectConflicts(t *testing.T) {
	for _, backend := range []string{"chrome", "golang", "firefox"} {
		for _, conflict := range []string{`"insecure":true`, `"certificate":["bad"]`, `"certificate_path":"absent"`, `"certificate_public_key_sha256":["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="]`, `"engine":"apple"`, `"engine":"windows"`, `"reality":{"enabled":true}`, `"ech":{"enabled":true}`} {
			t.Run(backend+"/"+conflict, func(t *testing.T) {
				o := leafOptions(t, backend, make([]byte, 32))
				if err := json.Unmarshal([]byte("{"+conflict+"}"), &o); err != nil {
					t.Fatal(err)
				}
				if _, err := leafClient(backend, o); err == nil {
					t.Fatal("accepted leaf-pin conflict")
				}
			})
		}
		for _, size := range []int{1, 31, 33} {
			o := leafOptions(t, backend, make([]byte, size))
			if _, err := leafClient(backend, o); err == nil {
				t.Fatalf("%s accepted %d-byte pin", backend, size)
			}
		}
	}
}

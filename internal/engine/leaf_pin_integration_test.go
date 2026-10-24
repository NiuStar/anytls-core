//go:build with_utls

package engine

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"testing"
	"time"
)

// Keep this regression compatible with the pre-pin engine API: runtime JSON,
// existing real-engine/AnyTLS fixtures and no newly added option struct fields.
// The old strict SDK decoder must reject certificate_sha256, not fail to compile.
func TestAnyTLSLeafPin(t *testing.T) {
	for _, fingerprint := range []string{"golang", "chrome", "firefox"} {
		t.Run(fingerprint, func(t *testing.T) {
			for _, network := range []string{"tcp", "udp"} {
				t.Run(network, func(t *testing.T) {
					for _, pinKind := range []string{"leaf", "wrong-leaf", "spki-not-leaf", "issuer-not-leaf"} {
						t.Run(pinKind, func(t *testing.T) {
							f := g13New(t)
							leaf, err := x509.ParseCertificate(f.cert.Certificate[0])
							if err != nil {
								t.Fatal(err)
							}
							leafHash := sha256.Sum256(leaf.Raw)
							pin := leafHash
							switch pinKind {
							case "wrong-leaf":
								pin[0] ^= 1
							case "spki-not-leaf":
								pin = sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
							case "issuer-not-leaf":
								pin = sha256.Sum256(f.cert.Certificate[1])
							}
							if pinKind != "leaf" && pin == leafHash {
								t.Fatal("negative fixture unexpectedly matches the leaf digest")
							}
							config := func(port int, digest [sha256.Size]byte) []byte {
								return f.config(port, func(ob map[string]any) {
									tlsOptions := ob["tls"].(map[string]any)
									delete(tlsOptions, "certificate")
									delete(tlsOptions, "certificate_path")
									// Deliberately untrusted CA AND mismatching hostname:
									// acceptance must be pin-only, not accidental PKIX.
									tlsOptions["server_name"] = "pin-only.fixture.invalid"
									tlsOptions["insecure"] = false
									tlsOptions["certificate_sha256"] = []string{base64.StdEncoding.EncodeToString(digest[:])}
									if fingerprint == "golang" {
										delete(tlsOptions, "utls")
									} else {
										tlsOptions["utls"] = map[string]any{"enabled": true, "fingerprint": fingerprint}
									}
								})
							}
							payload := make([]byte, 48)
							if _, err := rand.Read(payload); err != nil {
								t.Fatal(err)
							}
							target := f.tcp.Addr().String()
							if network == "udp" {
								target = f.udp.LocalAddr().String()
							}
							port := freeLoopbackPort(t)
							client, _ := g13Start(t, config(port, pin), port)
							err = g13Exchange(client, network, target, payload)
							if pinKind != "leaf" {
								if err == nil {
									t.Fatal("non-leaf pin returned authorized echo")
								}
								if network == "tcp" && !g13NonTimeoutClose(err) {
									t.Fatalf("wrong pin lacked non-timeout TCP close: %v", err)
								}
								// UDP has no datagram rejection response; its timeout alone
								// is NOT evidence. Require the actual peer's TLS alert.
								// The fixture returns before svc.NewConnection on this path,
								// so AnyTLS authentication is never entered.
								g13Witness(t, f, "TLS_CERTIFICATE_REJECTED", "", 4*time.Second)
								g13Closed(t, f, 1, 4*time.Second)
								if f.tcpBytes.Load() != 0 || f.udpBytes.Load() != 0 || f.uotStreams.Load() != 0 {
									t.Fatal("wrong pin reached TCP/UDP/UoT business")
								}
								// Same peer, certificate, hostname and password: change
								// ONLY the pin, using a fresh engine after rejection.
								goodPort := freeLoopbackPort(t)
								good, _ := g13Start(t, config(goodPort, leafHash), goodPort)
								if err := g13Exchange(good, network, target, payload); err != nil {
									t.Fatalf("same-fixture correct-leaf recovery: %v", err)
								}
							} else if err != nil {
								t.Fatalf("pin-only authenticated %s echo: %v", network, err)
							}
							if network == "tcp" {
								if f.tcpBytes.Load() != int64(len(payload)) || f.udpBytes.Load() != 0 || f.uotStreams.Load() != 0 {
									t.Fatal("missing exact TCP-only business witness")
								}
							} else if f.udpBytes.Load() != int64(len(payload)) || f.tcpBytes.Load() != 0 || f.uotStreams.Load() != 1 {
								t.Fatal("missing exact UDP payload/UoT business witness")
							}
						})
					}
				})
			}
		})
	}
}

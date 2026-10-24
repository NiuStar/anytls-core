package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/NiuStar/anytls-core/internal/engine"
)

func TestNetworkPrivacyFingerprint(t *testing.T) {
	for _, mode := range []string{"proxy", "tun"} {
		for _, tc := range []struct {
			name, input, want string
		}{
			{"default", "", "chrome"},
			{"chrome", "chrome", "chrome"},
			{"firefox", "firefox", "firefox"},
			{"golang", "golang", ""},
			{"unchanged-case", "Chrome", "Chrome"},
			{"unchanged-whitespace", " chrome ", " chrome "},
			{"unchanged-unknown", "not-a-fingerprint", "not-a-fingerprint"},
		} {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				n := node{Name: "fixture", Type: "anytls", Server: "127.0.0.1", Port: 443, Password: "synthetic-only", SkipVerify: true, Fingerprint: tc.input}
				before := n
				cfg, err := buildNode(n, mode, 11080, true)
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(n, before) {
					t.Fatal("buildNode changed source node")
				}
				// Assert the actual runtime JSON, not an SDK-specific new helper.
				raw, err := json.Marshal(cfg)
				if err != nil {
					t.Fatal(err)
				}
				var runtime map[string]any
				if err := json.Unmarshal(raw, &runtime); err != nil {
					t.Fatal(err)
				}
				tls := runtime["outbounds"].([]any)[0].(map[string]any)["tls"].(map[string]any)
				want := map[string]any{"enabled": true, "insecure": true}
				if tc.want != "" {
					want["utls"] = map[string]any{"enabled": true, "fingerprint": tc.want}
				}
				if !reflect.DeepEqual(tls, want) {
					t.Fatalf("runtime TLS = %#v; want %#v", tls, want)
				}
			})
		}
	}
}

func TestNetworkPrivacyEngineConstruction(t *testing.T) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		t.Fatal("build info unavailable")
	}
	withUTLS := false
	for _, setting := range info.Settings {
		if setting.Key == "-tags" {
			for _, tag := range strings.Split(setting.Value, ",") {
				withUTLS = withUTLS || tag == "with_utls"
			}
		}
	}
	for _, fingerprint := range []string{"", "chrome", "golang"} {
		t.Run(fingerprint, func(t *testing.T) {
			cfg, err := buildNode(node{Name: "fixture", Type: "anytls", Server: "127.0.0.1", Port: 9, Password: "synthetic-only", SkipVerify: true, Fingerprint: fingerprint}, "proxy", 11080, true)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			err = engine.Check(context.Background(), raw)
			if !withUTLS && fingerprint != "golang" {
				if err == nil || !strings.Contains(err.Error(), "uTLS is not included in this build") {
					t.Fatalf("default/Chrome must fail closed without uTLS: %v", err)
				}
			} else if err != nil {
				t.Fatalf("real engine constructor rejected supported TLS: %v", err)
			}
		})
	}
}

func TestNetworkPrivacyTrustUnchanged(t *testing.T) {
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, []byte("fixture-only: buildNode validates file, SDK validates PEM"), 0600); err != nil {
		t.Fatal(err)
	}
	pin := base64.StdEncoding.EncodeToString(make([]byte, 32))
	for _, fingerprint := range []string{"", "chrome", "firefox", "golang"} {
		for _, trust := range []string{"ca", "pin", "insecure"} {
			t.Run(fingerprint+"/"+trust, func(t *testing.T) {
				n := node{Name: "fixture", Type: "anytls", Server: "127.0.0.1", Port: 443, Password: "synthetic-only", SNI: "fixture.invalid", Fingerprint: fingerprint, IdleCheck: 6, IdleTimeout: 7, MinIdle: 2}
				want := map[string]any{"enabled": true, "server_name": "fixture.invalid"}
				switch trust {
				case "ca":
					n.CA = ca
					want["certificate_path"] = ca
				case "pin":
					n.CertificatePublicKeySHA256 = pin
					want["certificate_public_key_sha256"] = []string{pin}
				case "insecure":
					n.SkipVerify = true
					want["insecure"] = true
					if _, err := buildNode(n, "proxy", 11080, false); err == nil {
						t.Fatal("insecure node accepted without consent")
					}
				}
				if fingerprint != "golang" {
					fp := fingerprint
					if fp == "" {
						fp = "chrome"
					}
					want["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
				}
				cfg, err := buildNode(n, "proxy", 11080, true)
				if err != nil {
					t.Fatal(err)
				}
				out := cfg["outbounds"].([]any)[0].(map[string]any)
				if !reflect.DeepEqual(out["tls"], want) {
					t.Fatalf("TLS trust changed: %#v; want %#v", out["tls"], want)
				}
				if out["idle_session_check_interval"] != "6s" || out["idle_session_timeout"] != "7s" || out["min_idle_session"] != 2 || out["password"] != n.Password {
					t.Fatal("non-TLS outbound settings changed")
				}
			})
		}
	}
}

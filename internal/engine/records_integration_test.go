//go:build with_utls

package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cr "github.com/NiuStar/anytls-core/internal/connectionrecords"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/protocol/socks"
)

func TestRecordsCAPinnedStrictTLSBehavior(t *testing.T) {
	for _, name := range []string{"strict", "wrong-sni", "wrong-ca", "wrong-password", "digest-mismatch-original-path"} {
		t.Run(name, func(t *testing.T) {
			f := g13New(t)
			port := freeLoopbackPort(t)
			ca := f.ca
			if name == "wrong-ca" {
				ca, _ = g13Cert(t)
			}
			path := filepath.Join(t.TempDir(), "ca.pem")
			if err := os.WriteFile(path, []byte(ca), 0600); err != nil {
				t.Fatal(err)
			}
			raw := f.config(port, func(ob map[string]any) {
				tls := ob["tls"].(map[string]any)
				delete(tls, "certificate")
				tls["certificate_path"] = path
				if name == "wrong-sni" {
					tls["server_name"] = "wrong.fixture.invalid"
				}
				if name == "wrong-password" {
					ob["password"] = "unauthorized"
				}
			})
			m := recordsTestManifest(t, raw, "secure", "anytls")
			sum := recordsSHA([]byte(ca))
			if name == "digest-mismatch-original-path" {
				sum = strings.Repeat("0", 64)
			}
			m.CapturedSources = append(m.CapturedSources, cr.CapturedSource{Kind: cr.SourceCA, Present: true, SHA256: &sum})
			recordsSeal(t, m)
			sink := &recordsTestSink{}
			client, _ := g13StartWithRecords(t, raw, port, &RecordsInput{Manifest: m, Sink: sink})
			err := g13Exchange(client, "tcp", f.tcp.Addr().String(), []byte("CA continuity business"))
			if name == "strict" || name == "digest-mismatch-original-path" {
				if err != nil {
					t.Fatal("original strict positive changed", err)
				}
			} else {
				if err == nil || !g13NonTimeoutClose(err) {
					t.Fatal("strict rejection changed", err)
				}
				class := "TLS_CERTIFICATE_REJECTED"
				if name == "wrong-password" {
					class = "AUTH_REJECTED"
				}
				g13Witness(t, f, class, "", 4*time.Second)
				if f.tcpBytes.Load() != 0 || f.udpBytes.Load() != 0 {
					t.Fatal("negative reached authorized target")
				}
			}
			rows, status := sink.snapshot()
			if len(rows) == 0 {
				t.Fatal("refused dial still must be ROUTED")
			}
			if name == "digest-mismatch-original-path" && status != cr.ProvenanceUnknown {
				t.Fatal("CA mismatch attribution not UNKNOWN")
			}
		})
	}
}

// Reuse the authenticated AnyTLS/TCP/UDP fixture; no fake router or Match call.
func TestRecordsRealMixedTCPUDPAndUnknownManifest(t *testing.T) {
	for _, altered := range []bool{false, true} {
		t.Run(fmt.Sprint(altered), func(t *testing.T) {
			f := g13New(t)
			port := freeLoopbackPort(t)
			raw := f.config(port, nil)
			m := recordsTestManifest(t, raw, "secure", "anytls")
			if altered {
				m.ManifestID = strings.Repeat("0", 64)
			}
			sink := &recordsTestSink{}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- RunWithRecords(ctx, raw, &RecordsInput{Manifest: m, Sink: sink}) }()
			t.Cleanup(func() {
				cancel()
				if err := awaitRun(t, done); !errors.Is(err, context.Canceled) {
					t.Error(err)
				}
				assertBindable(t, port)
			})
			addr := fmt.Sprintf("127.0.0.1:%d", port)
			deadline := time.Now().Add(5 * time.Second)
			for {
				c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
				if err == nil {
					c.Close()
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("mixed not ready")
				}
				time.Sleep(10 * time.Millisecond)
			}
			client := socks.NewClient(g13Dialer{}, M.ParseSocksaddr(addr), socks.Version5, "", "")
			if err := g13Exchange(client, "tcp", f.tcp.Addr().String(), []byte("records TCP\x00\xff")); err != nil {
				t.Fatal(err)
			}
			if err := g13Exchange(client, "udp", f.udp.LocalAddr().String(), []byte("records UDP\x00\xff")); err != nil {
				t.Fatal(err)
			}
			rows, status := sink.snapshot()
			tcp, udp := false, false
			for _, r := range rows {
				if r.Hook == cr.HookTCP {
					tcp = true
				}
				if r.Hook == cr.HookUDP {
					udp = true
				}
				expected := cr.ProvenanceVerified
				if altered {
					expected = cr.ProvenanceUnknown
				}
				if r.Route.Evidence != expected || r.Route.OutboundTag != "secure" || r.Route.OutboundType != "anytls" {
					t.Fatal("actual route attribution")
				}
				if altered && (r.Route.GroupPath != nil || r.Route.FinalNodeLabel != nil) {
					t.Fatal("unknown manifest leaked claims")
				}
			}
			if !tcp || !udp || f.tcpBytes.Load() == 0 || f.udpBytes.Load() == 0 {
				t.Fatal("missing real mixed TCP/UDP business witness")
			}
			if altered && status != cr.ProvenanceUnknown {
				t.Fatal("initial mismatch status")
			}
		})
	}
}

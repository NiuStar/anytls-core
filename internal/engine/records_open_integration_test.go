//go:build with_utls

package engine

import (
	cr "github.com/NiuStar/anytls-core/internal/connectionrecords"
	"os"
	"path/filepath"
	"testing"
)

func TestRecordsDeferredOpenRealProtocol(t *testing.T) {
	for _, available := range []bool{false, true} {
		t.Run(map[bool]string{false: "unavailable-traffic-continues", true: "CA-pinned-before-New"}[available], func(t *testing.T) {
			f := g13New(t)
			port := freeLoopbackPort(t)
			path := filepath.Join(t.TempDir(), "ca.pem")
			if err := os.WriteFile(path, []byte(f.ca), 0600); err != nil {
				t.Fatal(err)
			}
			raw := f.config(port, func(ob map[string]any) {
				tls := ob["tls"].(map[string]any)
				delete(tls, "certificate")
				tls["certificate_path"] = path
			})
			m := recordsTestManifest(t, raw, "secure", "anytls")
			sum := recordsSHA([]byte(f.ca))
			m.CapturedSources = append(m.CapturedSources, cr.CapturedSource{Kind: cr.SourceCA, Present: true, SHA256: &sum})
			recordsSeal(t, m)
			sink := &recordsTestSink{}
			calls := 0
			client, _ := g13StartWithRecords(t, raw, port, &RecordsInput{Manifest: m, OpenSink: func() cr.Sink {
				calls++
				if err := os.Remove(path); err != nil {
					t.Error(err)
				}
				if available {
					return sink
				}
				return nil
			}})
			if err := g13Exchange(client, "tcp", f.tcp.Addr().String(), []byte("deferred records strict business")); err != nil {
				t.Fatal(err)
			}
			if calls != 1 {
				t.Fatalf("opens=%d", calls)
			}
			if available {
				rows, status := sink.snapshot()
				if len(rows) == 0 || status != cr.ProvenanceVerified {
					t.Fatalf("rows=%d provenance=%s", len(rows), status)
				}
			}
		})
	}
}

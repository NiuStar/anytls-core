//go:build embedded_core && with_utls

package main

import (
	"github.com/miekg/dns"
	"testing"
)

func TestDNSRuntimeCompilerEngineHTTPS(t *testing.T) {
	f := dnsPerfStartMetrics(t, nil, "evidence", true)
	for _, typ := range []uint16{dns.TypeA, dns.TypeAAAA} {
		dnsPerfRun(t, f, f.query("evidence", typ), false)
		dnsPerfRun(t, f, f.query("evidence", typ), false)
	}
	s := f.evidence.Snapshot()
	if s.State != "LOADED" || len(s.Events) != 2 || len(s.Policy.Transports) != 1 || s.Policy.Final != "SUPPORTED" {
		t.Fatalf("same-instance evidence %+v", s)
	}
	for _, e := range s.Events {
		if e.Validation != "MATCHED" || e.Outcome != "NOERROR" || e.Connections.Acquisitions == "0" {
			t.Fatalf("completion %+v", e)
		}
	}
	for _, typ := range []uint16{dns.TypeA, dns.TypeAAAA} {
		if n := f.count(f.query("evidence", typ)); n != 1 {
			t.Fatal("independent server count", n)
		}
	}
	dnsRuntimeUnixHTTP(t, f.evidence)
	f.shutdown()
	if f.evidence.Snapshot().State != "CLOSED" {
		t.Fatal("run not closed")
	}
	t.Log("same compiler policy -> actual engine Start -> authenticated AnyTLS -> strict HTTPS -> A/AAAA completion; repeat server counts=1 each; cache provenance remains NOT_OBSERVED")
}

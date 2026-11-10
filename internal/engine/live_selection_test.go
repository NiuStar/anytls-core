//go:build with_utls

package engine

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	cr "github.com/NiuStar/anytls-core/internal/connectionrecords"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/protocol/socks"
)

func TestLiveSelectionRealAnyTLS(t *testing.T) {
	a, b := g13New(t), g13New(t)
	a.dnsTargets = map[string]string{b.tcp.Addr().String(): a.tcp.Addr().String()}
	port := freeLoopbackPort(t)
	var cfg, other map[string]any
	json.Unmarshal(a.config(port, nil), &cfg)
	json.Unmarshal(b.config(port, nil), &other)
	oa := cfg["outbounds"].([]any)[0].(map[string]any)
	oa["tag"] = "a"
	ob := other["outbounds"].([]any)[0].(map[string]any)
	ob["tag"] = "b"
	cfg["outbounds"] = []any{oa, ob, map[string]any{"type": "anytls-selection", "tag": "live", "outbounds": []string{"a", "b"}, "default": "a"}}
	cfg["route"] = map[string]any{"rules": []any{map[string]any{"port": []uint16{uint16(a.tcp.Addr().(*net.TCPAddr).Port)}, "action": "route", "outbound": "a"}}, "final": "live"}
	raw, _ := json.Marshal(cfg)
	m := recordsTestManifest(t, raw, "a", "anytls")
	second := m.Outbounds[0]
	second.Tag = "b"
	id, label := m.Generation+":node:1", "fixture-B"
	second.NodeID, second.NodeLabel = &id, &label
	m.Outbounds = append(m.Outbounds, second, cr.OutboundOrigin{Tag: "live", Type: LiveSelectionType, TerminalKind: cr.TerminalUnknown})
	m.FinalOrigin.OutboundTag, m.FinalOrigin.OutboundType = "live", LiveSelectionType
	origin := m.FinalOrigin
	index := 0
	source := m.Generation + ":rule:0"
	origin.SourceID, origin.SourceIndex = &source, &index
	origin.Kind = cr.RuleIPCIDR
	origin.Condition = &cr.Condition{Kind: cr.RuleIPCIDR, Value: "127.0.0.1/32"}
	origin.ConfiguredTarget = m.FinalOrigin.ConfiguredTarget
	origin.OutboundTag, origin.OutboundType = "a", "anytls"
	m.Rules = []cr.RuleOrigin{{Type: "default", ActionType: "route", ExpectedOutbound: "a", Synthetic: cr.SyntheticNone, Route: origin}}
	recordsSeal(t, m)
	sink := &recordsTestSink{}
	live := NewLiveSelection()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- RunControlled(ctx, raw, &RecordsInput{Manifest: m, Sink: sink}, live) }()
	t.Cleanup(func() { cancel(); awaitRun(t, done); assertBindable(t, port) })
	deadline := time.Now().Add(5 * time.Second)
	for !live.Snapshot().Ready {
		if time.Now().After(deadline) {
			t.Fatal("not ready")
		}
		time.Sleep(time.Millisecond * 10)
	}
	client := socks.NewClient(g13Dialer{}, M.ParseSocksaddr(net.JoinHostPort("127.0.0.1", strconv.Itoa(port))), socks.Version5, "", "")
	held, e := client.DialContext(ctx, "tcp", M.ParseSocksaddr(b.tcp.Addr().String()))
	if e != nil {
		t.Fatal(e)
	}
	defer held.Close()
	echo := func(c net.Conn) {
		t.Helper()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		if _, e := c.Write([]byte("old")); e != nil {
			t.Fatal(e)
		}
		buf := make([]byte, 3)
		if _, e := io.ReadFull(c, buf); e != nil {
			t.Fatal(e)
		}
	}
	echo(held)
	before := live.Snapshot()
	pid := os.Getpid()
	start := time.Now()
	if e := live.Switch(before.Generation, before.Revision, "b"); e != nil {
		t.Fatal(e)
	}
	if e := g13Exchange(client, "tcp", b.tcp.Addr().String(), []byte("new")); e != nil {
		t.Fatal(e)
	}
	echo(held)
	if e := g13Exchange(client, "tcp", a.tcp.Addr().String(), []byte("fix")); e != nil {
		t.Fatal(e)
	}
	if a.tcpBytes.Load() != 9 || b.tcpBytes.Load() != 3 {
		t.Fatalf("wrong exit counts a=%d b=%d", a.tcpBytes.Load(), b.tcpBytes.Load())
	}
	if pid != os.Getpid() {
		t.Fatal("PID changed")
	}
	if e := live.Switch(before.Generation, before.Revision, "a"); e == nil {
		t.Fatal("stale revision accepted")
	}
	rows, status := sink.snapshot()
	if status != cr.ProvenanceVerified || len(rows) != 3 {
		t.Fatalf("records status=%s rows=%+v", status, rows)
	}
	if rows[0].Route.OutboundTag != "a" || rows[1].Route.OutboundTag != "b" || rows[0].Route.Evidence != cr.ProvenanceVerified || rows[1].Route.FinalNodeLabel == nil || *rows[1].Route.FinalNodeLabel != "fixture-B" {
		t.Fatalf("actual leaf records=%+v", rows)
	}
	if rows[2].Route.OutboundTag != "a" || rows[2].Route.Evidence != cr.ProvenanceVerified {
		t.Fatal("static dedicated route degraded")
	}
	for _, row := range rows {
		if err := cr.Validate(row.Route); err != nil {
			t.Fatal("invalid dynamic record", err)
		}
	}
	t.Logf("real TLS exits a=%d b=%d; held survives; PID=%d listener=%d; switch+new-connect=%s", a.tcpBytes.Load(), b.tcpBytes.Load(), pid, port, time.Since(start))
}

package engine

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	cr "github.com/NiuStar/anytls-core/internal/connectionrecords"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	sdkRule "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type recordsTestSink struct {
	mu     sync.Mutex
	rows   []cr.Observation
	status cr.ProvenanceStatus
}

func (s *recordsTestSink) TryAppend(o cr.Observation) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rows = append(s.rows, o)
	return true
}
func (s *recordsTestSink) SetProvenanceStatus(p cr.ProvenanceStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status = p
}
func (s *recordsTestSink) snapshot() ([]cr.Observation, cr.ProvenanceStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]cr.Observation(nil), s.rows...), s.status
}

func recordsTestManifest(t *testing.T, raw []byte, tag, typ string) *cr.Manifest {
	t.Helper()
	m := &cr.Manifest{SchemaVersion: 1, Binding: cr.Binding{InstanceID: strings.Repeat("a", 32), Generation: strings.Repeat("b", 32)}, SelectionGeneration: strings.Repeat("b", 32), RuntimeSHA256: recordsSHA(raw), Rules: []cr.RuleOrigin{}, Outbounds: []cr.OutboundOrigin{{Tag: tag, Type: typ, TerminalKind: cr.TerminalDirect}}}
	source := recordsSHA([]byte("synthetic-captured-config"))
	m.CapturedSources = []cr.CapturedSource{{Kind: cr.SourceConfig, Present: true, SHA256: &source}, {Kind: cr.SourceSelection}}
	target := "DIRECT"
	m.FinalOrigin = cr.RouteProjection{Evidence: cr.ProvenanceVerified, Kind: cr.RuleDefault, ConfiguredTarget: &target, GroupPath: []cr.GroupEdge{}, TerminalKind: cr.TerminalDirect, OutboundTag: tag, OutboundType: typ, SelectionGeneration: &m.SelectionGeneration}
	if typ == "anytls" {
		label := "fixture"
		id := m.Generation + ":node:0"
		m.FinalOrigin.TerminalKind = cr.TerminalNode
		m.FinalOrigin.FinalNodeID = &id
		m.FinalOrigin.FinalNodeLabel = &label
		m.Outbounds[0].TerminalKind = cr.TerminalNode
		m.Outbounds[0].NodeID = &id
		m.Outbounds[0].NodeLabel = &label
	}
	recordsSeal(t, m)
	return m
}
func recordsSeal(t *testing.T, m *cr.Manifest) {
	t.Helper()
	digest, err := cr.ManifestDigest(*m, recordsManifestBudget(m))
	if err != nil {
		t.Fatal(err)
	}
	m.ManifestID = digest
}
func recordsBox(t *testing.T, raw []byte) *box.Box {
	t.Helper()
	ctx, options, err := decodeOptions(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	instance, err := box.New(box.Options{Options: options, Context: ctx})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := instance.Close(); err != nil {
			t.Error(err)
		}
	})
	return instance
}

func TestRecordsTrackerOriginalObjectsAndFlowNil(t *testing.T) {
	raw := loopbackConfig()
	instance := recordsBox(t, raw)
	sink := &recordsTestSink{}
	tracker := bindRecords(instance, raw, &RecordsInput{Manifest: recordsTestManifest(t, raw, "direct", "direct"), Sink: sink}, true)
	if !tracker.verified {
		t.Fatal("actual Box binding rejected")
	}
	out := instance.Outbound().Default()
	metadata := adapter.InboundContext{Network: N.NetworkTCP, Destination: M.Socksaddr{Addr: netip.MustParseAddr("127.0.0.1"), Port: 1234}, Domain: "safe.invalid", User: "excluded-secret", SniffContext: "excluded-url?password=x"}
	conn, other := net.Pipe()
	defer conn.Close()
	defer other.Close()
	if got := tracker.RoutedConnection(context.Background(), conn, metadata, nil, out); got != conn {
		t.Fatal("TCP identity changed")
	}
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	original := bufio.NewPacketConn(packet)
	metadata.Network = N.NetworkUDP
	if got := tracker.RoutedPacketConnection(context.Background(), original, metadata, nil, out); got != original {
		t.Fatal("packet identity changed")
	}
	if tracker.RoutedFlow(context.Background(), metadata, nil, out) != nil {
		t.Fatal("flow tracker not nil")
	}
	rows, status := sink.snapshot()
	if len(rows) != 3 || status != cr.ProvenanceVerified || rows[0].Hook != cr.HookTCP || rows[1].Hook != cr.HookUDP || rows[2].Hook != cr.HookFlow {
		t.Fatal("hook projection")
	}
	for _, row := range rows {
		if row.Route.Evidence != cr.ProvenanceVerified || row.Destination.Host == nil || *row.Destination.Host != "safe.invalid" {
			t.Fatal("whitelist projection")
		}
	}
}

func TestRecordsTrackerAlteredManifestUnknown(t *testing.T) {
	for _, change := range []string{"digest", "runtime", "count", "type", "outbound", "final"} {
		t.Run(change, func(t *testing.T) {
			raw := loopbackConfig()
			instance := recordsBox(t, raw)
			sink := &recordsTestSink{}
			m := recordsTestManifest(t, raw, "direct", "direct")
			switch change {
			case "digest":
				m.ManifestID = strings.Repeat("0", 64)
			case "runtime":
				m.RuntimeSHA256 = strings.Repeat("0", 64)
				recordsSeal(t, m)
			case "count":
				m.Rules = append(m.Rules, cr.RuleOrigin{Type: "default", ActionType: "sniff", Synthetic: cr.SyntheticSniff, Route: unknownRecordsRoute(cr.ProvenanceUnknown, "", "")})
				recordsSeal(t, m)
			case "type":
				m.Outbounds[0].Type = "anytls"
				recordsSeal(t, m)
			case "outbound":
				m.Outbounds[0].Tag = "foreign"
				recordsSeal(t, m)
			case "final":
				m.FinalOrigin.OutboundTag = "foreign"
				recordsSeal(t, m)
			}
			tracker := bindRecords(instance, raw, &RecordsInput{Manifest: m, Sink: sink}, true)
			if tracker.verified {
				t.Fatal("altered manifest accepted")
			}
			r := tracker.route(nil, instance.Outbound().Default())
			if r.Evidence != cr.ProvenanceUnknown || r.SourceID != nil || r.GroupPath != nil || r.FinalNodeID != nil || r.OutboundTag != "direct" || r.OutboundType != "direct" {
				t.Fatal("unknown leaks attribution/loses actual outbound")
			}
			_, status := sink.snapshot()
			if status != cr.ProvenanceUnknown {
				t.Fatal("empty-generation initial status")
			}
		})
	}
}

type recordsUncomparableRule struct {
	adapter.Rule
	payload []byte
}
type recordsUncomparableOutbound struct {
	adapter.Outbound
	payload []byte
}

func TestRecordsTrackerForeignRuleAndOutboundMismatch(t *testing.T) {
	raw := []byte(`{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct","rules":[{"domain":["safe.invalid"],"action":"route","outbound":"direct"}]}}`)
	a, b := recordsBox(t, raw), recordsBox(t, raw)
	m := recordsTestManifest(t, raw, "direct", "direct")
	index := 0
	id := m.Generation + ":rule:0"
	r := m.FinalOrigin
	r.Kind = cr.RuleDomain
	r.SourceID = &id
	r.SourceIndex = &index
	r.Condition = &cr.Condition{Kind: cr.RuleDomain, Value: "safe.invalid"}
	m.Rules = []cr.RuleOrigin{{Type: "default", ActionType: "route", ExpectedOutbound: "direct", Synthetic: cr.SyntheticNone, Route: r}}
	recordsSeal(t, m)
	sink := &recordsTestSink{}
	tracker := bindRecords(a, raw, &RecordsInput{Manifest: m, Sink: sink}, true)
	if !tracker.verified {
		t.Fatal("actual rule binding")
	}
	if tracker.route(a.Router().Rules()[0], a.Outbound().Default()).Evidence != cr.ProvenanceVerified {
		t.Fatal("actual pointer rejected")
	}
	if tracker.route(b.Router().Rules()[0], a.Outbound().Default()).Evidence != cr.ProvenanceMismatch || tracker.route(nil, b.Outbound().Default()).Evidence != cr.ProvenanceMismatch {
		t.Fatal("foreign objects not rejected")
	}
	if tracker.route(recordsUncomparableRule{Rule: a.Router().Rules()[0]}, a.Outbound().Default()).Evidence != cr.ProvenanceMismatch {
		t.Fatal("noncomparable rule accepted")
	}
	if r := tracker.route(nil, recordsUncomparableOutbound{Outbound: a.Outbound().Default()}); r.Evidence != cr.ProvenanceMismatch || r.OutboundTag != "direct" {
		t.Fatal("noncomparable outbound lost actual tag or accepted")
	}
	m.Rules[0].Route.ConfiguredTarget = new(string)
	if *tracker.route(a.Router().Rules()[0], a.Outbound().Default()).ConfiguredTarget != "DIRECT" {
		t.Fatal("caller mutated bound projection")
	}
	action := a.Router().Rules()[0].Action().(*sdkRule.RuleActionRoute)
	original := action.Outbound
	action.Outbound = "altered"
	if tracker.route(a.Router().Rules()[0], a.Outbound().Default()).Evidence != cr.ProvenanceMismatch {
		t.Fatal("changed actual route action accepted")
	}
	action.Outbound = original
	for _, kind := range []string{"slot-type", "slot-action", "slot-outbound"} {
		fresh := recordsTestManifest(t, raw, "direct", "direct")
		fresh.Rules = append([]cr.RuleOrigin(nil), m.Rules...)
		fresh.Rules[0].Route = r
		switch kind {
		case "slot-type":
			fresh.Rules[0].Type = "logical"
		case "slot-action":
			fresh.Rules[0].ActionType = "reject"
		case "slot-outbound":
			fresh.Rules[0].ExpectedOutbound = "foreign"
		}
		recordsSeal(t, fresh)
		if bindRecords(a, raw, &RecordsInput{Manifest: fresh, Sink: sink}, true).verified {
			t.Fatal("altered SDK slot accepted", kind)
		}
	}
}

func TestRecordsDestinationPrivacy(t *testing.T) {
	bad := []string{"https://safe.invalid/path?secret=x", "safe.invalid?secret=x", "bad\x00host", "a/b", "a b", "-bad.invalid"}
	for _, s := range bad {
		r := recordsDestination(M.Socksaddr{Fqdn: s}, s)
		if r.Host != nil || r.HostSource != cr.HostUnknown {
			t.Fatal("unsafe destination projected")
		}
	}
	r := recordsDestination(M.Socksaddr{Fqdn: "first.invalid", Addr: netip.MustParseAddr("::1"), Port: 443}, "second.invalid")
	if *r.Host != "first.invalid" || r.HostSource != cr.HostDestination || *r.IP != "::1" || *r.Port != 443 {
		t.Fatal("destination precedence")
	}
	if recordsOptionalDestination(M.Socksaddr{}) != nil {
		t.Fatal("absent original invented")
	}
}

func TestRecordsStopAdmissionBeforeIndependentClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	stopped, closed := false, false
	closeErr := errors.New("original-close")
	probe := lifecycleProbe{start: func() error { t.Fatal("canceled start"); return nil }, close: func() error {
		closed = true
		if !stopped {
			t.Error("close before stop admission")
		}
		return closeErr
	}}
	err := executeRecords(ctx, probe, true, func() { stopped = true })
	if !closed || !errors.Is(err, context.Canceled) || !errors.Is(err, closeErr) {
		t.Fatal("telemetry changed lifecycle causes")
	}
}

func TestRecordsCAPinsActualDecodedBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca.pem")
	ca := []byte("capture-only-not-TLS-construction")
	if err := os.WriteFile(path, ca, 0600); err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"outbounds":[{"type":"anytls","tag":"secure","server":"127.0.0.1","server_port":9,"password":"fixture","tls":{"enabled":true,"certificate_path":` + strconv.Quote(path) + `}}]}`)
	_, options, err := decodeOptions(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	m := recordsTestManifest(t, raw, "secure", "anytls")
	sum := recordsSHA(ca)
	m.CapturedSources = append(m.CapturedSources, cr.CapturedSource{Kind: cr.SourceCA, Present: true, SHA256: &sum})
	_, different, err := decodeOptions(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	wrong := *m
	wrong.CapturedSources = append([]cr.CapturedSource(nil), m.CapturedSources...)
	bad := strings.Repeat("0", 64)
	wrong.CapturedSources[len(wrong.CapturedSources)-1].SHA256 = &bad
	if pinRecordsCA(&different, &wrong) {
		t.Fatal("different capture verified")
	}
	if different.Outbounds[0].Options.(option.OutboundTLSOptionsWrapper).TakeOutboundTLSOptions().CertificatePath != path {
		t.Fatal("mismatch changed original SDK path")
	}
	if !pinRecordsCA(&options, m) {
		t.Fatal("same bytes not verified")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	tls := options.Outbounds[0].Options.(option.OutboundTLSOptionsWrapper).TakeOutboundTLSOptions()
	if tls.CertificatePath != "" || len(tls.Certificate) != 1 || tls.Certificate[0] != string(ca) {
		t.Fatal("SDK not consuming same capture")
	}
}

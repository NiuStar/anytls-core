package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"os"
	"reflect"
	"sync/atomic"
	"syscall"

	cr "github.com/NiuStar/anytls-core/internal/connectionrecords"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	sdkRule "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing-tun"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Manifest is immutable after compilation. The sink must implement the bounded,
// nonblocking admission contract; false is counted by the sink, never here.
// StopAdmission, if supplied, runs before the Box's independent Close.
type RecordsInput struct {
	Manifest      *cr.Manifest
	Sink          cr.Sink
	StopAdmission func()
}

type recordsTracker struct {
	sink      cr.Sink
	verified  bool
	rules     map[adapter.Rule]cr.RuleOrigin
	final     cr.RouteProjection
	outbounds map[string]adapter.Outbound
	mismatch  atomic.Bool
}

var _ adapter.ConnectionTracker = (*recordsTracker)(nil)

func recordsSHA(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }

// The legacy JSON keeps certificate_path byte-for-byte. Freeze the *actual*
// bytes passed to New into decoded TLS options and compare to compiler captures.
// On capture error leave the original SDK path behavior untouched and suppress
// attribution. Never turn a telemetry validation failure into a traffic error.
func pinRecordsCA(options *option.Options, m *cr.Manifest) bool {
	if m == nil {
		return false
	}
	var expected []cr.CapturedSource
	for _, s := range m.CapturedSources {
		if s.Kind == cr.SourceCA {
			expected = append(expected, s)
		}
	}
	ordinal := 0
	verified := true
	for i := range options.Outbounds {
		wrapper, ok := options.Outbounds[i].Options.(option.OutboundTLSOptionsWrapper)
		if !ok {
			continue
		}
		tls := wrapper.TakeOutboundTLSOptions()
		if tls == nil || tls.CertificatePath == "" {
			continue
		}
		b, err := captureRecordsCA(tls.CertificatePath)
		if err != nil {
			verified = false
			ordinal++
			continue
		}
		matched := ordinal < len(expected) && expected[ordinal].Ordinal == ordinal && expected[ordinal].SHA256 != nil && recordsSHA(b) == *expected[ordinal].SHA256
		ordinal++
		if !matched {
			verified = false
			continue
		}
		if len(tls.Certificate) != 0 || (tls.Engine != "" && tls.Engine != "go") {
			verified = false
			continue
		}
		// Same interpretation as the SDK: a single certificate string containing the
		// complete PEM bytes. No change to TLS policy, validation or runtime JSON.
		copyTLS := *tls
		copyTLS.CertificatePath = ""
		copyTLS.Certificate = []string{string(b)}
		wrapper.ReplaceOutboundTLSOptions(&copyTLS)
	}
	return verified && ordinal == len(expected)
}

func captureRecordsCA(path string) ([]byte, error) {
	// Keep existing resolved-regular symlink compatibility. O_NONBLOCK prevents a
	// replacement FIFO hanging before fstat. This is not hostile-parent authority.
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	closed := false
	defer func() {
		if !closed {
			f.Close()
		}
	}()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() < 0 || st.Size() > 1<<20 {
		return nil, cr.ErrInvalid
	}
	// The compiler's existing accepted CA bound, not a history quota.
	b, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > 1<<20 {
		return nil, cr.ErrTooLarge
	}
	after, err := f.Stat()
	if err != nil || !os.SameFile(st, after) || st.Size() != after.Size() || int64(len(b)) != after.Size() || st.Mode() != after.Mode() || !st.ModTime().Equal(after.ModTime()) {
		return nil, cr.ErrInvalid
	}
	closed = true
	if err := f.Close(); err != nil {
		return nil, err
	}
	return b, nil
}

func bindRecords(instance *box.Box, raw []byte, input *RecordsInput, caVerified bool) *recordsTracker {
	t := &recordsTracker{sink: input.Sink, rules: make(map[adapter.Rule]cr.RuleOrigin), outbounds: make(map[string]adapter.Outbound)}
	m := input.Manifest
	if m == nil || !caVerified {
		t.report(cr.ProvenanceUnknown)
		return t
	}
	budget := cr.ManifestBudget(m)
	if budget == 0 || m.RuntimeSHA256 != recordsSHA(raw) {
		t.report(cr.ProvenanceUnknown)
		return t
	}
	digest, err := cr.ManifestDigest(*m, budget)
	if err != nil || digest != m.ManifestID {
		t.report(cr.ProvenanceUnknown)
		return t
	}
	// Own a typed immutable snapshot; no caller-owned mutable pointers/slices are
	// retained in callbacks. No runtime metadata/context/SDK objects enter the sink.
	encoded, err := cr.EncodeBounded(*m, budget)
	if err != nil {
		t.report(cr.ProvenanceUnknown)
		return t
	}
	var owned cr.Manifest
	if cr.DecodeStrict(encoded, &owned, budget) != nil {
		t.report(cr.ProvenanceUnknown)
		return t
	}
	m = &owned
	actualOutbounds := instance.Outbound().Outbounds()
	if len(actualOutbounds) != len(m.Outbounds) {
		t.report(cr.ProvenanceUnknown)
		return t
	}
	for i, origin := range m.Outbounds {
		out := actualOutbounds[i]
		if !recordsPointer(out) || out.Tag() != origin.Tag || out.Type() != origin.Type {
			t.report(cr.ProvenanceUnknown)
			return t
		}
		if _, exists := t.outbounds[origin.Tag]; exists {
			t.report(cr.ProvenanceUnknown)
			return t
		}
		t.outbounds[origin.Tag] = out
	}
	actualRules := instance.Router().Rules()
	if len(actualRules) != len(m.Rules) {
		t.report(cr.ProvenanceUnknown)
		return t
	}
	for i, origin := range m.Rules {
		r := actualRules[i]
		if !recordsPointer(r) || r.Type() != origin.Type || r.Action() == nil || r.Action().Type() != origin.ActionType {
			t.report(cr.ProvenanceUnknown)
			return t
		}
		if origin.ActionType == "route" {
			action, ok := r.Action().(*sdkRule.RuleActionRoute)
			if !ok || action.Outbound != origin.ExpectedOutbound || origin.Route.OutboundTag != action.Outbound {
				t.report(cr.ProvenanceUnknown)
				return t
			}
			out := t.outbounds[action.Outbound]
			if out == nil || origin.Route.OutboundType != out.Type() {
				t.report(cr.ProvenanceUnknown)
				return t
			}
		}
		if _, exists := t.rules[r]; exists {
			t.report(cr.ProvenanceUnknown)
			return t
		}
		t.rules[r] = origin
	}
	// Default() is initialized during New, before Start. Explicit final must
	// resolve to the very same registry outbound as nil-rule callbacks.
	finalOut := instance.Outbound().Default()
	expected := t.outbounds[m.FinalOrigin.OutboundTag]
	if !recordsPointer(finalOut) || expected == nil || finalOut != expected || finalOut.Type() != m.FinalOrigin.OutboundType {
		t.report(cr.ProvenanceUnknown)
		return t
	}
	t.final = m.FinalOrigin
	t.verified = true
	t.report(cr.ProvenanceVerified)
	return t
}

func recordsPointer(v any) bool {
	if v == nil {
		return false
	}
	r := reflect.ValueOf(v)
	return r.Kind() == reflect.Pointer && !r.IsNil() && r.Type().Comparable()
}

func (t *recordsTracker) report(status cr.ProvenanceStatus) {
	if r, ok := t.sink.(cr.ProvenanceReporter); ok {
		r.SetProvenanceStatus(status)
	}
}

func unknownRecordsRoute(status cr.ProvenanceStatus, tag, typ string) cr.RouteProjection {
	return cr.RouteProjection{Evidence: status, Kind: cr.RuleUnknown, TerminalKind: cr.TerminalUnknown, OutboundTag: tag, OutboundType: typ}
}

func (t *recordsTracker) route(matched adapter.Rule, out adapter.Outbound) cr.RouteProjection {
	tag, typ := "", ""
	if out != nil {
		value := reflect.ValueOf(out)
		if value.Kind() != reflect.Pointer || !value.IsNil() {
			tag, typ = out.Tag(), out.Type()
		}
	}
	if !t.verified {
		return unknownRecordsRoute(cr.ProvenanceUnknown, tag, typ)
	}
	r := t.final
	valid := true
	if matched != nil {
		if !recordsPointer(matched) {
			valid = false
		} else {
			origin, ok := t.rules[matched]
			valid = ok && origin.ActionType == "route" && matched.Type() == origin.Type && matched.Action() != nil && matched.Action().Type() == origin.ActionType
			if valid {
				action, isRoute := matched.Action().(*sdkRule.RuleActionRoute)
				valid = isRoute && action.Outbound == origin.ExpectedOutbound
				if valid {
					r = origin.Route
				}
			}
		}
	}
	expected := t.outbounds[tag]
	if !valid || !recordsPointer(out) || expected == nil || expected != out || r.OutboundTag != tag || r.OutboundType != typ || r.Evidence != cr.ProvenanceVerified {
		if t.mismatch.CompareAndSwap(false, true) {
			t.report(cr.ProvenanceMismatch)
		}
		return unknownRecordsRoute(cr.ProvenanceMismatch, tag, typ)
	}
	return r
}

func recordsDestination(d M.Socksaddr, domain string) cr.Destination {
	r := cr.Destination{HostSource: cr.HostUnknown}
	if cr.ValidHost(d.Fqdn) {
		host := d.Fqdn
		r.Host = &host
		r.HostSource = cr.HostDestination
	} else if cr.ValidHost(domain) {
		r.Host = &domain
		r.HostSource = cr.HostMetadata
	}
	if d.Addr.IsValid() {
		ip := d.Addr.String()
		r.IP = &ip
	}
	if d.IsValid() {
		port := d.Port
		r.Port = &port
	}
	return r
}

func recordsOptionalDestination(d M.Socksaddr) *cr.Destination {
	if !d.IsValid() {
		return nil
	}
	r := recordsDestination(d, "")
	return &r
}

func (t *recordsTracker) observe(hook cr.Hook, metadata adapter.InboundContext, matched adapter.Rule, out adapter.Outbound) {
	network := cr.NetworkUnknown
	switch metadata.Network {
	case N.NetworkTCP:
		network = cr.NetworkTCP
	case N.NetworkUDP:
		network = cr.NetworkUDP
	}
	t.sink.TryAppend(cr.Observation{Hook: hook, Network: network, Destination: recordsDestination(metadata.Destination, metadata.Domain), OriginDestination: recordsOptionalDestination(metadata.OriginDestination), RouteOriginalDestination: recordsOptionalDestination(metadata.RouteOriginalDestination), Route: t.route(matched, out)})
}
func (t *recordsTracker) RoutedConnection(_ context.Context, conn net.Conn, metadata adapter.InboundContext, matched adapter.Rule, out adapter.Outbound) net.Conn {
	t.observe(cr.HookTCP, metadata, matched, out)
	return conn
}
func (t *recordsTracker) RoutedPacketConnection(_ context.Context, conn N.PacketConn, metadata adapter.InboundContext, matched adapter.Rule, out adapter.Outbound) N.PacketConn {
	t.observe(cr.HookUDP, metadata, matched, out)
	return conn
}
func (t *recordsTracker) RoutedFlow(_ context.Context, metadata adapter.InboundContext, matched adapter.Rule, out adapter.Outbound) tun.FlowTracker {
	t.observe(cr.HookFlow, metadata, matched, out)
	return nil
}

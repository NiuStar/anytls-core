package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	cr "github.com/NiuStar/anytls-core/internal/connectionrecords"
)

// UNIT-SIMULATED UID policy, real Unix EOF/CloseWrite transport. Native kernel
// credentials are independently exercised by TestControlHelperDarwinKernelPeerUID.
func recordsTestPage(identity string) cr.PageResponse {
	return cr.PageResponse{Header: cr.Header{SchemaVersion: 1, ConfigIdentity: identity, Binding: cr.Binding{InstanceID: strings.Repeat("1", 32), Generation: strings.Repeat("2", 32), ManifestID: strings.Repeat("3", 64)}, RuntimeSHA256: strings.Repeat("4", 64), CreatedAt: "2026-10-22T00:00:00Z"}, HistoryKind: cr.LastRecorded, ProvenanceStatus: cr.ProvenanceUnknown, Collection: cr.CollectionUnknown, Freshness: cr.FreshnessUnknown, Timestamp: "2026-10-22T00:00:00Z", HighWaterSeq: "0", NextAfter: "0", Records: []cr.Record{}, Coverage: cr.Coverage{Unobserved: []string{"REJECT", "DNS", "EARLY_ERROR"}, Gap: true, Continuity: cr.ContinuityUnknown}, DNS: cr.DNSStatus{Status: "UNKNOWN"}}
}
func recordsTestServer(t *testing.T) *controlHelperServer {
	t.Helper()
	s := unitControlServer()
	s.recordsRegistration = func() (controlHelperRegistration, error) { return s.registration, nil }
	s.state = func() (bool, bool, error) { t.Error("records called lifecycle state"); return false, false, nil }
	s.preflight = func(context.Context, bool) error { t.Error("records called preflight"); return nil }
	s.start = func(context.Context, bool) error { t.Error("records called start"); return nil }
	s.stop = func(context.Context) error { t.Error("records called stop"); return nil }
	s.recordsRead = func(ctx context.Context, scope cr.Scope, q cr.PageRequest) (cr.PageResponse, error) {
		if scope.UID != 501 {
			t.Error("scope not registration-derived")
		}
		return recordsTestPage(scope.ConfigIdentity), nil
	}
	return s
}
func TestControlRecordsEOFReadOnly(t *testing.T) {
	s := recordsTestServer(t)
	s.mutation.Lock()
	defer s.mutation.Unlock()
	c, _ := unitControlPair(t, s)
	q := cr.PageRequest{SchemaVersion: 1, After: "0", Limit: 100}
	page, err := controlHelperRecordsExchange(context.Background(), c, q, func(net.Conn) (uint32, error) { return 0, nil })
	if err != nil || page.ConfigIdentity == "" || page.Records == nil {
		t.Fatalf("page=%+v error=%v", page, err)
	}
}
func TestControlRecordsLegacyBudgetAndLargePage(t *testing.T) {
	s := recordsTestServer(t)
	identity, _ := controlHelperConfigIdentity(s.registration.Config)
	page := recordsTestPage(identity)
	one := cr.Decimal("1")
	page.HistoryStartSeq = &one
	page.HighWaterSeq = "1"
	page.NextAfter = "1"
	page.Records = []cr.Record{{SchemaVersion: 1, Binding: page.Binding, Seq: "1", ObservationID: "9007199254740993", ObservedAt: page.Timestamp, Event: "ROUTED", Hook: cr.HookTCP, Network: cr.NetworkTCP, Destination: cr.Destination{HostSource: cr.HostUnknown}, Route: cr.RouteProjection{Evidence: cr.ProvenanceUnknown, Kind: cr.RuleUnknown, TerminalKind: cr.TerminalUnknown, OutboundTag: strings.Repeat("untrusted-label", 400), OutboundType: "direct"}, State: "ROUTED"}}
	s.recordsRead = func(context.Context, cr.Scope, cr.PageRequest) (cr.PageResponse, error) { return page, nil }
	c, _ := unitControlPair(t, s)
	got, err := controlHelperRecordsExchange(context.Background(), c, cr.PageRequest{SchemaVersion: 1, Binding: &page.Binding, After: "0", Limit: 100}, func(net.Conn) (uint32, error) { return 0, nil })
	if err != nil || len(got.Records) != 1 {
		t.Fatalf("large page rejected %v", err)
	}
	b, err := cr.EncodeBounded(got, cr.MaxResponseBytes)
	if err != nil || len(b) <= 4096 {
		t.Fatal("not a >4KiB page")
	}
	// Legacy decoding budget is exactly the old 4096, never promoted to 8KiB.
	raw := `{"action":"status","allow_insecure":false}` + strings.Repeat(" ", 4096)
	legacy := unitControlRaw(t, s, raw)
	if legacy.Code != "INVALID_REQUEST" {
		t.Fatal(legacy)
	}
}
func TestControlRecordsStrictFramesNoRead(t *testing.T) {
	s := recordsTestServer(t)
	var calls atomic.Int32
	s.recordsRead = func(context.Context, cr.Scope, cr.PageRequest) (cr.PageResponse, error) {
		calls.Add(1)
		return cr.PageResponse{}, cr.TelemetryUnavailable
	}
	good := `{"action":"records.read","schema_version":1,"instance_id":null,"generation":null,"manifest_id":null,"after":"0","limit":100}`
	for _, raw := range []string{
		good + ` {}`, strings.Replace(good, `"limit":100`, `"limit":null`, 1), strings.Replace(good, `"after":"0"`, `"after":"01"`, 1), strings.Replace(good, `"after":"0"`, `"after":"18446744073709551616"`, 1), strings.Replace(good, `"limit":100`, `"limit":501`, 1), strings.Replace(good, `"limit":100`, `"limit":1,"limit":2`, 1), strings.Replace(good, `"limit":100`, `"limit":1,"path":"/secret"`, 1), strings.Replace(good, `"generation":null`, `"generation":"bad"`, 1), good + "\x00", good + string([]byte{0xff}), good + strings.Repeat(" ", cr.MaxRequestBytes),
	} {
		b := recordsRaw(t, s, []byte(raw))
		var e cr.ErrorResponse
		if cr.DecodeStrict(b, &e, cr.MaxResponseBytes) != nil || e.ErrorCode != cr.InvalidRequest {
			t.Fatalf("bad strict rejection: %s", b)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid input read store")
	}
	// Both request boundaries use bounded data: exact 8KiB valid whitespace frame.
	exact := good + strings.Repeat(" ", cr.MaxRequestBytes-len(good))
	b := recordsRaw(t, s, []byte(exact))
	var e cr.ErrorResponse
	if cr.DecodeStrict(b, &e, cr.MaxResponseBytes) != nil || e.ErrorCode != cr.TelemetryUnavailable || calls.Load() != 1 {
		t.Fatal("exact request budget rejected", string(b))
	}
}
func TestControlRecordsSlotSurvivesTimeout(t *testing.T) {
	s := recordsTestServer(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	finished := make(chan struct{})
	defer func() {
		close(release)
		select {
		case <-finished:
		case <-time.After(time.Second):
			t.Error("read worker did not exit")
		}
	}()
	s.recordsRead = func(context.Context, cr.Scope, cr.PageRequest) (cr.PageResponse, error) {
		close(entered)
		<-release
		close(finished)
		return cr.PageResponse{}, cr.TelemetryUnavailable
	}
	q := cr.PageRequest{SchemaVersion: 1, After: "0", Limit: 100}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan []byte, 1)
	go func() { done <- s.recordsPage(ctx, q) }()
	<-entered
	cancel()
	<-done
	var e cr.ErrorResponse
	if cr.DecodeStrict(s.recordsPage(context.Background(), q), &e, cr.MaxResponseBytes) != nil || e.ErrorCode != cr.Busy {
		t.Fatal("timeout released actual read slot")
	}
	// The telemetry slot never acquires the mutation lock, even during blocked I/O.
	if !s.mutation.TryLock() {
		t.Fatal("telemetry held mutation lock")
	}
	s.mutation.Unlock()
}
func TestControlRecordsUIDAndRegistrationNoRead(t *testing.T) {
	for _, uid := range []uint32{0, 502} {
		s := recordsTestServer(t)
		s.peer = func(net.Conn) (uint32, error) { return uid, nil }
		s.recordsRegistration = func() (controlHelperRegistration, error) {
			t.Error("registration read before peer authorization")
			return s.registration, nil
		}
		c, _ := unitControlPair(t, s)
		var r controlHelperResponse
		if controlHelperReadResponse(c, &r) != nil || r.Code != "FORBIDDEN" {
			t.Fatal("peer accepted")
		}
	}
	s := recordsTestServer(t)
	s.recordsRegistration = func() (controlHelperRegistration, error) { r := s.registration; r.UID++; return r, nil }
	s.recordsRead = func(context.Context, cr.Scope, cr.PageRequest) (cr.PageResponse, error) {
		t.Error("changed registration read store")
		return cr.PageResponse{}, nil
	}
	var e cr.ErrorResponse
	if cr.DecodeStrict(s.recordsPage(context.Background(), cr.PageRequest{SchemaVersion: 1, After: "0", Limit: 100}), &e, cr.MaxResponseBytes) != nil || e.ErrorCode != cr.Forbidden {
		t.Fatal("changed registration accepted")
	}
}
func TestControlRecordsClientRootBeforeWrite(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	_, err := controlHelperRecordsExchange(context.Background(), a, cr.PageRequest{SchemaVersion: 1, After: "0", Limit: 100}, func(net.Conn) (uint32, error) { return 501, nil })
	if err != cr.Forbidden {
		t.Fatal(err)
	}
	b.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	var one [1]byte
	if n, _ := b.Read(one[:]); n != 0 {
		t.Fatal("disclosed action to nonroot")
	}
}
func TestControlRecordsResponseFramesAndOldHelper(t *testing.T) {
	page := recordsTestPage(strings.Repeat("a", 64))
	good, err := cr.EncodeBounded(page, cr.MaxResponseBytes)
	if err != nil {
		t.Fatal(err)
	}
	legacy := controlHelperFailure("INVALID_REQUEST")
	legacy.HelperVersion = "old"
	legacy.HelperSHA256 = strings.Repeat("a", 64)
	old, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		raw  []byte
		want cr.ErrorCode
	}{
		{"positive", good, cr.NoError}, {"exact 1MiB", append(append([]byte(nil), good...), []byte(strings.Repeat(" ", cr.MaxResponseBytes-len(good)))...), cr.NoError}, {"trailing", append(append([]byte(nil), good...), []byte(` {}`)...), cr.TelemetryUnavailable},
		{"duplicate nested", []byte(strings.Replace(string(good), `"complete":false`, `"complete":false,"complete":false`, 1)), cr.TelemetryUnavailable},
		{"unknown nested", []byte(strings.Replace(string(good), `"complete":false`, `"complete":false,"path":"/secret"`, 1)), cr.TelemetryUnavailable},
		{"nul", append(append([]byte(nil), good...), 0), cr.TelemetryUnavailable},
		{"utf8", append(append([]byte(nil), good...), 0xff), cr.TelemetryUnavailable},
		{"oversized", []byte(strings.Repeat(" ", cr.MaxResponseBytes+1)), cr.TelemetryUnavailable},
		{"old helper", old, cr.Unsupported},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, e := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(unitControlSocketDir(t), "r.sock"), Net: "unix"})
			if e != nil {
				t.Fatal(e)
			}
			defer l.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				c, e := l.AcceptUnix()
				if e != nil {
					return
				}
				defer c.Close()
				io.Copy(io.Discard, c)
				c.Write(tc.raw)
			}()
			c, e := net.DialUnix("unix", nil, l.Addr().(*net.UnixAddr))
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			_, e = controlHelperRecordsExchange(context.Background(), c, cr.PageRequest{SchemaVersion: 1, After: "0", Limit: 100}, func(net.Conn) (uint32, error) { return 0, nil })
			if tc.want == cr.NoError && e != nil || tc.want != cr.NoError && e != tc.want {
				t.Fatal("response error", e, "want", tc.want)
			}
			c.Close()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("reply server not joined")
			}
		})
	}
}
func TestControlRecordsCapturedPathNotContents(t *testing.T) {
	s := recordsTestServer(t)
	path := filepath.Join(t.TempDir(), "config.yaml")
	if e := os.WriteFile(path, []byte("before secret"), 0600); e != nil {
		t.Fatal(e)
	}
	s.registration.Config = path
	identity, _ := controlHelperConfigIdentity(path)
	s.recordsRead = func(context.Context, cr.Scope, cr.PageRequest) (cr.PageResponse, error) {
		if e := os.WriteFile(path, []byte("changed current YAML unrelated to history"), 0600); e != nil {
			t.Error(e)
		}
		return recordsTestPage(identity), nil
	}
	b := s.recordsPage(context.Background(), cr.PageRequest{SchemaVersion: 1, After: "0", Limit: 100})
	var p cr.PageResponse
	if cr.DecodeStrict(b, &p, cr.MaxResponseBytes) != nil || p.ConfigIdentity != identity {
		t.Fatal("current contents changed history identity", string(b))
	}
}
func TestControlRecordsBoundIdentityAndPrior(t *testing.T) {
	s := recordsTestServer(t)
	identity, _ := controlHelperConfigIdentity(s.registration.Config)
	page := recordsTestPage(identity)
	prior := cr.Binding{InstanceID: strings.Repeat("5", 32), Generation: strings.Repeat("6", 32), ManifestID: strings.Repeat("7", 64)}
	page.Binding = prior
	page.HistoryKind = cr.Historical
	s.recordsRead = func(_ context.Context, _ cr.Scope, q cr.PageRequest) (cr.PageResponse, error) {
		if q.Binding == nil || *q.Binding != prior {
			return cr.PageResponse{}, cr.StaleGeneration
		}
		return page, nil
	}
	c, _ := unitControlPair(t, s)
	p, err := controlHelperRecordsExchange(context.Background(), c, cr.PageRequest{SchemaVersion: 1, Binding: &prior, After: "0", Limit: 100}, func(net.Conn) (uint32, error) { return 0, nil })
	if err != nil || p.Binding != prior || p.HistoryKind != cr.Historical {
		t.Fatal("prior history not readable", err)
	}
	for _, change := range []func(*cr.Binding){func(b *cr.Binding) { b.InstanceID = strings.Repeat("a", 32) }, func(b *cr.Binding) { b.Generation = strings.Repeat("b", 32) }, func(b *cr.Binding) { b.ManifestID = strings.Repeat("c", 64) }} {
		bad := prior
		change(&bad)
		c, _ := unitControlPair(t, s)
		_, err := controlHelperRecordsExchange(context.Background(), c, cr.PageRequest{SchemaVersion: 1, Binding: &bad, After: "0", Limit: 100}, func(net.Conn) (uint32, error) { return 0, nil })
		if err != cr.StaleGeneration {
			t.Fatal("bound mismatch fell back", err)
		}
	}
}
func TestControlRecordsLargeDecimalCursor(t *testing.T) {
	s := recordsTestServer(t)
	identity, _ := controlHelperConfigIdentity(s.registration.Config)
	page := recordsTestPage(identity)
	one := cr.Decimal("1")
	page.HistoryStartSeq = &one
	page.HighWaterSeq = "9007199254740994"
	page.NextAfter = page.HighWaterSeq
	page.Records = []cr.Record{{SchemaVersion: 1, Binding: page.Binding, Seq: page.HighWaterSeq, ObservationID: "9007199254740994", ObservedAt: page.Timestamp, Event: "ROUTED", Hook: cr.HookTCP, Network: cr.NetworkTCP, Destination: cr.Destination{HostSource: cr.HostUnknown}, Route: cr.RouteProjection{Evidence: cr.ProvenanceUnknown, Kind: cr.RuleUnknown, TerminalKind: cr.TerminalUnknown, OutboundTag: "actual", OutboundType: "direct"}, State: "ROUTED"}}
	s.recordsRead = func(_ context.Context, _ cr.Scope, q cr.PageRequest) (cr.PageResponse, error) {
		if q.After != "9007199254740993" {
			t.Error("cursor precision lost")
		}
		return page, nil
	}
	c, _ := unitControlPair(t, s)
	p, err := controlHelperRecordsExchange(context.Background(), c, cr.PageRequest{SchemaVersion: 1, Binding: &page.Binding, After: "9007199254740993", Limit: 1}, func(net.Conn) (uint32, error) { return 0, nil })
	if err != nil || p.NextAfter != "9007199254740994" || len(p.Records) != 1 {
		t.Fatal("large decimal round trip", err)
	}
}
func recordsRaw(t *testing.T, s *controlHelperServer, raw []byte) []byte {
	t.Helper()
	c, _ := unitControlPair(t, s)
	c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

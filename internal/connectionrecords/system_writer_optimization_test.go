package connectionrecords

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// systemWriterProbe delegates to the real private filesystem store. Only the
// explicitly selected fault is synthetic; successful writes, Syncs and renames
// are real. No production clock seam or replacement worker is needed.
type systemWriterProbe struct {
	armed        atomic.Bool
	mu           sync.Mutex
	events       []string
	states       []State
	livePages    []PageResponse
	readErrors   []error
	readLive     func() (PageResponse, error)
	writer       *Writer
	started      time.Time
	fault        string
	faulted      bool
	statusWrites int
	statusOpens  int
	terminal     bool
	stopAt       int
	stop         func()
	afterFirst   func()
}

func (p *systemWriterProbe) event(event string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.terminal {
		p.events = append(p.events, event)
	}
	if p.fault == event && !p.faulted {
		p.faulted = true
		return true
	}
	return false
}

func (p *systemWriterProbe) store(s recordStore) recordStore {
	write, syncFile, closeFile, rename, openFile := s.write, s.sync, s.close, s.rename, s.openFile
	isTemp := func(f *os.File) bool { return strings.HasPrefix(filepath.Base(f.Name()), ".publish-") }
	s.openFile = func(path string, flags int, mode uint32) (int, error) {
		if p.armed.Load() && strings.HasPrefix(filepath.Base(path), ".publish-") {
			p.mu.Lock()
			p.statusOpens++
			p.mu.Unlock()
		}
		return openFile(path, flags, mode)
	}
	s.write = func(f *os.File, b []byte) (int, error) {
		if p.armed.Load() {
			kind := filepath.Base(f.Name())
			if isTemp(f) {
				var state State
				if err := json.Unmarshal(b, &state); err != nil {
					return 0, err
				}
				p.mu.Lock()
				p.statusWrites++
				// Closing/failed/closed publications belong to teardown, not
				// the completed tick's measured I/O window.
				p.terminal = state.Collection != Recording
				p.mu.Unlock()
				kind = "state"
			}
			if p.event("write:" + kind) {
				return 0, syscall.EIO
			}
		}
		return write(f, b)
	}
	s.sync = func(f *os.File) error {
		if p.armed.Load() {
			kind := filepath.Base(f.Name())
			if isTemp(f) {
				kind = "state"
			} else if info, err := f.Stat(); err == nil && info.IsDir() {
				kind = "directory"
			}
			if p.event("sync:" + kind) {
				return syscall.EIO
			}
		}
		return syncFile(f)
	}
	s.close = func(f *os.File) error {
		err := closeFile(f)
		if p.armed.Load() && isTemp(f) && p.event("close:state") {
			return errors.Join(err, syscall.EIO)
		}
		return err
	}
	s.rename = func(from, to string) error {
		if !p.armed.Load() || filepath.Base(to) != "state.json" {
			return rename(from, to)
		}
		var state State
		b, err := os.ReadFile(from)
		if err != nil {
			return err
		}
		if err = DecodeStrict(b, &state, MaxStateBytes); err != nil {
			return err
		}
		if p.event("rename:state") {
			return syscall.EIO
		}
		if err = rename(from, to); err != nil {
			return err
		}
		p.mu.Lock()
		p.states = append(p.states, state)
		n := 0
		for _, st := range p.states {
			if st.Collection == Recording {
				n++
			}
		}
		p.mu.Unlock()
		if state.Collection == Recording {
			if p.readLive != nil {
				page, readErr := p.readLive()
				p.mu.Lock()
				p.livePages = append(p.livePages, page)
				p.readErrors = append(p.readErrors, readErr)
				p.mu.Unlock()
			}
			if n == 1 && p.afterFirst != nil {
				p.afterFirst()
			}
			if n == p.stopAt {
				// A stop closes the next loop's admission to ordinary work,
				// but cannot interrupt the current ticker case. Thus the old
				// immediate second publish is observed in full, while the
				// next tick can never contaminate this measurement.
				p.stop()
			}
		}
		return nil
	}
	return s
}

func systemWriterStart(t *testing.T, probe *systemWriterProbe) (*Writer, recordStore, Scope, Header) {
	t.Helper()
	clean, scope, h := diskFixture(t)
	w, err := openWriter(probe.store(clean), scope, h)
	if err != nil {
		t.Fatal(err)
	}
	probe.writer = w
	probe.readLive = func() (PageResponse, error) {
		return readPage(context.Background(), clean, scope, diskQuery(h, 0, MaxPageLimit))
	}
	probe.started = time.Now()
	probe.stop = func() {
		w.StopAdmission()
		w.stopOnce.Do(func() { close(w.stop) })
	}
	t.Cleanup(func() {
		probe.stop()
		systemWriterWait(t, w)
	})
	// All closure fields and the initialized writer are published before hooks
	// can run; subsequent event/state access is mutex-protected.
	probe.armed.Store(true)
	return w, clean, scope, h
}

func systemWriterWait(t *testing.T, w *Writer) {
	t.Helper()
	select {
	case <-w.done:
	case <-time.After(4 * time.Second):
		t.Fatal("real writer did not finish within four seconds")
	}
}

func systemWriterTrace(t *testing.T, p *systemWriterProbe) ([]string, []State) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	events := append([]string(nil), p.events...)
	states := append([]State(nil), p.states...)
	t.Logf("window started=%s; completed tick I/O: %v; published states: %+v", p.started.UTC().Format(time.RFC3339Nano), events, states)
	for i, page := range p.livePages {
		if p.readErrors[i] != nil || page.Freshness != Fresh || page.Collection != Recording {
			t.Errorf("live readPage heartbeat %d: err=%v page=%+v", i, p.readErrors[i], page)
		}
	}
	return events, states
}

func systemWriterObservation(h Header, i int) Observation {
	host := fmt.Sprintf("route-%d.example.com", i)
	return Observation{
		Hook: HookTCP, Network: NetworkTCP,
		Destination: Destination{Host: ptr(host), IP: ptr("203.0.113.9"), Port: ptr(uint16(443)), HostSource: HostDestination},
		OriginDestination: &Destination{IP: ptr("198.51.100.7"), Port: ptr(uint16(8443)), HostSource: HostUnknown},
		RouteOriginalDestination: &Destination{Host: ptr("original.example.com"), Port: ptr(uint16(9443)), HostSource: HostMetadata},
		Route: RouteProjection{
			Evidence: ProvenanceVerified, SourceID: ptr(h.Generation + ":rule:7"), SourceIndex: ptr(7),
			Kind: RuleDomainSuffix, Condition: &Condition{Kind: RuleDomainSuffix, Value: "example.com"},
			ConfiguredTarget: ptr("proxy-group"), GroupPath: []GroupEdge{{Group: "proxy-group", Selected: "test-node"}},
			TerminalKind: TerminalNode, FinalNodeID: ptr(h.Generation + ":node:9"), FinalNodeLabel: ptr("Node 中文"),
			OutboundTag: "node-outbound", OutboundType: "anytls", SelectionGeneration: ptr(h.Generation),
		},
	}
}

func systemWriterAppend(t *testing.T, w *Writer, observations []Observation) {
	t.Helper()
	for i, o := range observations {
		if !w.TryAppend(o) {
			t.Fatalf("real callback rejected observation %d", i)
		}
	}
}

func systemWriterReadback(t *testing.T, s recordStore, scope Scope, h Header, observations []Observation, tickets []uint64, started time.Time) {
	t.Helper()
	var state State
	ns, err := s.namespace(scope, false)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(ns, h.InstanceID)
	if _, err = s.readJSON(filepath.Join(dir, "state.json"), &state, MaxStateBytes); err != nil {
		t.Fatal(err)
	}
	dataBytes, _ := state.CommittedDataBytes.Uint64()
	for name, want := range map[string]uint64{"records.bin": dataBytes, "index.bin": uint64(len(observations) * IndexEntryBytes)} {
		info, statErr := os.Stat(filepath.Join(dir, name))
		if statErr != nil {
			t.Fatal(statErr)
		}
		if uint64(info.Size()) != want {
			t.Fatalf("%s physical/committed prefix=%d want=%d", name, info.Size(), want)
		}
	}
	var rows []Record
	for after := uint64(0); ; {
		page, err := readPage(context.Background(), s, scope, diskQuery(h, after, 1))
		if err != nil {
			t.Fatal(err)
		}
		if page.Header.Binding != h.Binding || page.HighWaterSeq != DecimalFromUint64(uint64(len(observations))) || page.Collection != Closed || page.Freshness != FreshnessUnknown || !page.Coverage.Gap || page.Pending != nil || page.Coverage.LostTotal != nil {
			t.Fatalf("terminal page lost conservative prefix/binding: %+v", page)
		}
		rows = append(rows, page.Records...)
		if !page.HasMore {
			break
		}
		after, err = page.NextAfter.Uint64()
		if err != nil || after != uint64(len(rows)) {
			t.Fatalf("page did not advance: %+v", page)
		}
	}
	if len(rows) != len(observations) {
		t.Fatalf("readback rows=%d want=%d", len(rows), len(observations))
	}
	for i, o := range observations {
		at, err := time.Parse(time.RFC3339Nano, rows[i].ObservedAt)
		if err != nil || at.Before(started) || at.After(time.Now()) {
			t.Fatalf("invalid receipt timestamp %q: %v", rows[i].ObservedAt, err)
		}
		// Receipt time is writer-owned, not a business field to fabricate.
		want := Record{SchemaVersion: 1, Binding: h.Binding, Seq: DecimalFromUint64(uint64(i+1)), ObservationID: DecimalFromUint64(tickets[i]), ObservedAt: rows[i].ObservedAt, Event: "ROUTED", Hook: o.Hook, Network: o.Network, Destination: o.Destination, OriginDestination: o.OriginDestination, RouteOriginalDestination: o.RouteOriginalDestination, Route: o.Route, State: "ROUTED"}
		if !reflect.DeepEqual(rows[i], want) {
			t.Errorf("complete record %d differs:\ngot  %+v\nwant %+v", i, rows[i], want)
		}
	}
}

func systemWriterLossState(t *testing.T, state State, high, lost uint64) {
	t.Helper()
	wantReasons := LossReasons{number(0), number(lost), number(0), number(0), number(0), number(0), number(0), number(0)}
	if state.HighWaterSeq != DecimalFromUint64(high) || !reflect.DeepEqual(state.Pending, number(0)) || !reflect.DeepEqual(state.LostTotal, number(lost)) || !reflect.DeepEqual(state.LossEpoch, number(lost)) || !reflect.DeepEqual(state.LossReasons, wantReasons) || state.Gap != (lost != 0) || state.CounterSaturated || state.ProvenanceStatus != ProvenanceVerified {
		t.Fatalf("tick snapshot lost exact prefix/loss/provenance: %+v", state)
	}
}

func TestSystemWriterTickPublishesCommittedBatchOnce(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		t.Run(fmt.Sprintf("mixed_oversize_%t", mixed), func(t *testing.T) {
			probe := &systemWriterProbe{stopAt: 1}
			w, clean, scope, h := systemWriterStart(t, probe)
			w.SetProvenanceStatus(ProvenanceVerified)
			observations := []Observation{systemWriterObservation(h, 1), systemWriterObservation(h, 2)}
			tickets := []uint64{1, 2}
			input := append([]Observation(nil), observations...)
			lost := uint64(0)
			if mixed {
				oversize := systemWriterObservation(h, 3)
				oversize.Route.OutboundTag = strings.Repeat("x", MaxRecordBytes)
				input = []Observation{observations[0], oversize, observations[1]}
				tickets[1], lost = 3, 1
			}
			started := time.Now()
			systemWriterAppend(t, w, input)
			systemWriterWait(t, w)
			events, states := systemWriterTrace(t, probe)
			if len(states) < 1 {
				t.Fatal("no real timer publication")
			}
			systemWriterLossState(t, states[0], 2, lost)
			systemWriterReadback(t, clean, scope, h, observations, tickets, started)
			want := []string{"write:records.bin", "write:records.bin", "write:records.bin", "write:records.bin", "write:index.bin", "sync:records.bin", "sync:index.bin", "write:state", "sync:state", "close:state", "rename:state", "sync:directory"}
			if !reflect.DeepEqual(events, want) {
				renamed := 0
				for _, event := range events {
					if event == "rename:state" {
						renamed++
					}
				}
				t.Errorf("completed single tick state.json renames=%d, want 1; real ordered write/Sync/rename trace differs:\ngot  %v\nwant %v", renamed, events, want)
			}
		})
	}
}

func TestSystemWriterTickAllOversizeStillPublishesLossHeartbeat(t *testing.T) {
	probe := &systemWriterProbe{stopAt: 1}
	w, clean, scope, h := systemWriterStart(t, probe)
	w.SetProvenanceStatus(ProvenanceVerified)
	o := systemWriterObservation(h, 1)
	o.Route.OutboundTag = strings.Repeat("x", MaxRecordBytes)
	systemWriterAppend(t, w, []Observation{o})
	systemWriterWait(t, w)
	events, states := systemWriterTrace(t, probe)
	if len(states) < 1 {
		t.Fatal("accepted==0 suppressed the loss heartbeat")
	}
	systemWriterLossState(t, states[0], 0, 1)
	want := []string{"write:state", "sync:state", "close:state", "rename:state", "sync:directory"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("accepted==0 tick I/O got %v want %v", events, want)
	}
	systemWriterReadback(t, clean, scope, h, nil, nil, time.Now())
}

func TestSystemWriterIdleTicksKeepFreshHeartbeat(t *testing.T) {
	probe := &systemWriterProbe{stopAt: 3}
	w, clean, scope, h := systemWriterStart(t, probe)
	w.SetProvenanceStatus(ProvenanceVerified)
	systemWriterWait(t, w)
	events, states := systemWriterTrace(t, probe)
	var previous time.Time
	var revision uint64
	count := 0
	for _, state := range states {
		if state.Collection != Recording {
			continue
		}
		count++
		systemWriterLossState(t, state, 0, 0)
		at, err := time.Parse(time.RFC3339Nano, state.Timestamp)
		nextRevision, revisionErr := state.Revision.Uint64()
		if err != nil || revisionErr != nil || !at.After(previous) || nextRevision != revision+1 && count > 1 {
			t.Fatalf("heartbeat failed to advance: %+v", state)
		}
		// Exercise the real reader projection at the captured publication time.
		if page := pageFromState(state, h.InstanceID, 0, at); page.Freshness != Fresh || page.Collection != Recording {
			t.Fatalf("idle heartbeat not fresh: %+v", page)
		}
		previous, revision = at, nextRevision
	}
	want := []string{}
	for i := 0; i < 3; i++ {
		want = append(want, "write:state", "sync:state", "close:state", "rename:state", "sync:directory")
	}
	if count != 3 || !reflect.DeepEqual(events, want) {
		t.Fatalf("idle heartbeat count=%d I/O=%v want=%v", count, events, want)
	}
	systemWriterReadback(t, clean, scope, h, nil, nil, time.Now())
}

func TestSystemWriterTickStatusFailureNeverRetriesIO(t *testing.T) {
	for _, fault := range []string{"write:state", "sync:state", "close:state", "rename:state", "sync:directory"} {
		t.Run(fault, func(t *testing.T) {
			probe := &systemWriterProbe{fault: fault}
			w, clean, scope, h := systemWriterStart(t, probe)
			systemWriterAppend(t, w, []Observation{systemWriterObservation(h, 1)})
			systemWriterWait(t, w)
			events, _ := systemWriterTrace(t, probe)
			if !probe.faulted || !w.statusBroken || w.result.Collection != IOFailed || w.result.ErrorCode != TelemetryUnavailable || w.high != 0 || w.offset != 0 || w.pending.Load() != 0 || w.lost.Load() != 1 || w.reasons[lossIO].Load() != 1 || !w.gap.Load() {
				t.Fatalf("status fault did not conservatively latch: faulted=%t result=%+v high=%d lost=%d", probe.faulted, w.result, w.high, w.lost.Load())
			}
			writes, renames := 0, 0
			for _, event := range events {
				if event == "write:state" {
					writes++
				}
				if event == "rename:state" {
					renames++
				}
			}
			if writes != 1 || renames > 1 || probe.statusWrites != 1 || probe.statusOpens != 1 {
				t.Fatalf("uncertain status was retried: status opens=%d writes=%d events=%v", probe.statusOpens, probe.statusWrites, events)
			}
			page, err := readPage(context.Background(), clean, scope, diskQuery(h, 0, 10))
			wantHigh := Decimal("0")
			if fault == "sync:directory" {
				// Rename succeeded before the failed directory Sync. The
				// durable outcome is uncertain, not necessarily unchanged.
				wantHigh = "1"
			}
			if err != nil || page.HighWaterSeq != wantHigh {
				t.Fatalf("uncertain prefix readback: %v %+v", err, page)
			}
		})
	}
}

func TestSystemWriterFullBatchStillCommitsBeforeIdleHeartbeat(t *testing.T) {
	probe := &systemWriterProbe{stopAt: 2}
	w, clean, scope, h := systemWriterStart(t, probe)
	w.SetProvenanceStatus(ProvenanceVerified)
	observations := make([]Observation, BatchRecords)
	tickets := make([]uint64, BatchRecords)
	for i := range observations {
		observations[i] = systemWriterObservation(h, i)
		tickets[i] = uint64(i + 1)
	}
	started := time.Now()
	systemWriterAppend(t, w, observations)
	systemWriterWait(t, w)
	events, states := systemWriterTrace(t, probe)
	var recording []State
	for _, state := range states {
		if state.Collection == Recording {
			recording = append(recording, state)
		}
	}
	if len(recording) != 2 {
		t.Fatalf("full commit plus idle tick publications=%d want=2", len(recording))
	}
	for _, state := range recording {
		systemWriterLossState(t, state, BatchRecords, 0)
	}
	want := make([]string, 0, BatchRecords*2+13)
	for i := 0; i < BatchRecords; i++ {
		want = append(want, "write:records.bin", "write:records.bin")
	}
	want = append(want, "write:index.bin", "sync:records.bin", "sync:index.bin")
	for i := 0; i < 2; i++ {
		want = append(want, "write:state", "sync:state", "close:state", "rename:state", "sync:directory")
	}
	if !reflect.DeepEqual(events, want) {
		t.Errorf("full-batch or following idle I/O changed: got %v want %v", events, want)
	}
	systemWriterReadback(t, clean, scope, h, observations, tickets, started)
}

func TestSystemWriterTickLateCallbackStateVisibleByNextHeartbeat(t *testing.T) {
	probe := &systemWriterProbe{stopAt: 3}
	var unexpectedlyAccepted atomic.Bool
	probe.afterFirst = func() {
		// The first snapshot already exists on disk; exercise the real public
		// callbacks in the publication interval without demanding a second
		// snapshot in that same tick.
		w := probe.writer
		w.SetProvenanceStatus(ProvenanceMismatch)
		w.SetProvenanceStatus(ProvenanceVerified)
		w.StopAdmission()
		unexpectedlyAccepted.Store(w.TryAppend(diskObservation()))
	}
	w, clean, scope, h := systemWriterStart(t, probe)
	w.SetProvenanceStatus(ProvenanceVerified)
	o := systemWriterObservation(h, 1)
	started := time.Now()
	systemWriterAppend(t, w, []Observation{o})
	systemWriterWait(t, w)
	_, states := systemWriterTrace(t, probe)
	if unexpectedlyAccepted.Load() {
		t.Fatal("late callback bypassed stopped admission")
	}
	seen := false
	for _, state := range states {
		if state.Collection != Recording || state.ProvenanceStatus != ProvenanceMismatch {
			continue
		}
		seen = true
		wantReasons := LossReasons{number(0), number(0), number(1), number(0), number(0), number(0), number(0), number(0)}
		if !state.Gap || state.HighWaterSeq != "1" || !reflect.DeepEqual(state.Pending, number(0)) || !reflect.DeepEqual(state.LostTotal, number(1)) || !reflect.DeepEqual(state.LossEpoch, number(1)) || !reflect.DeepEqual(state.LossReasons, wantReasons) {
			t.Fatalf("next heartbeat dropped callback state: %+v", state)
		}
	}
	if !seen {
		t.Fatal("next publication never exposed latched mismatch/admission loss")
	}
	systemWriterReadback(t, clean, scope, h, []Observation{o}, []uint64{1}, started)
}

func TestSystemWriterTickCollectionFailureOnlyPublishesTerminalState(t *testing.T) {
	for _, fault := range []string{"write:records.bin", "write:index.bin", "sync:records.bin", "sync:index.bin"} {
		t.Run(fault, func(t *testing.T) {
			probe := &systemWriterProbe{fault: fault}
			w, clean, scope, h := systemWriterStart(t, probe)
			systemWriterAppend(t, w, []Observation{systemWriterObservation(h, 1)})
			systemWriterWait(t, w)
			_, states := systemWriterTrace(t, probe)
			if !probe.faulted || w.result.Collection != IOFailed || w.pending.Load() != 0 || w.lost.Load() != 1 || w.reasons[lossIO].Load() != 1 || w.high != 0 {
				t.Fatalf("collection failure accounting: %+v lost=%d", w.result, w.lost.Load())
			}
			if len(states) != 1 || states[0].Collection != IOFailed || states[0].HighWaterSeq != "0" || states[0].LostTotal == nil || *states[0].LostTotal != "1" {
				t.Fatalf("failed collection published ordinary tick status: %+v", states)
			}
			page, err := readPage(context.Background(), clean, scope, diskQuery(h, 0, 10))
			if err != nil || len(page.Records) != 0 || page.HighWaterSeq != "0" || page.Collection != IOFailed || !page.Coverage.Gap {
				t.Fatalf("failed collection exposed an uncommitted tail: %v %+v", err, page)
			}
		})
	}
}

package connectionrecords

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func diskFixture(t *testing.T) (recordStore, Scope, Header) {
	t.Helper()
	anchor := t.TempDir()
	if e := os.Chmod(anchor, 0700); e != nil {
		t.Fatal(e)
	}
	s := newRecordStore(filepath.Join(anchor, "records"), anchor, uint32(os.Geteuid()))
	scope := Scope{UID: 501, ConfigIdentity: strings.Repeat("a", 64)}
	h := Header{SchemaVersion: 1, ConfigIdentity: scope.ConfigIdentity, Binding: Binding{strings.Repeat("1", 32), strings.Repeat("2", 32), strings.Repeat("3", 64)}, RuntimeSHA256: strings.Repeat("4", 64), CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	return s, scope, h
}
func diskObservation() Observation {
	return Observation{Hook: HookTCP, Network: NetworkTCP, Destination: Destination{HostSource: HostUnknown}, Route: RouteProjection{Evidence: ProvenanceUnknown, Kind: RuleUnknown, TerminalKind: TerminalUnknown, OutboundTag: "actual", OutboundType: "direct"}}
}
func finishWriter(t *testing.T, w *Writer) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), TelemetryTimeout)
	defer cancel()
	r := w.Shutdown(ctx)
	if r.Cleanup != CleanupVerified || r.Collection != Closed || r.ErrorCode != NoError {
		t.Fatalf("shutdown: %+v", r)
	}
}
func appendBatch(t *testing.T, w *Writer, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if !w.TryAppend(diskObservation()) {
			t.Fatalf("append %d rejected", i)
		}
	}
	// Read committed state rather than touching the worker's non-atomic cursors.
	want := w.tickets.Load()
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		var state State
		_, e := w.store.readJSON(filepath.Join(w.dir, "state.json"), &state, MaxStateBytes)
		if e == nil {
			v, _ := state.HighWaterSeq.Uint64()
			if v >= want {
				return
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("batch was not committed")
}
func diskQuery(h Header, after uint64, limit int) PageRequest {
	return PageRequest{SchemaVersion: 1, Binding: &h.Binding, After: DecimalFromUint64(after), Limit: limit}
}

func TestDiskRecordsDirectSeekPersistenceAndPriorRun(t *testing.T) {
	s, scope, h := diskFixture(t)
	w, e := openWriter(s, scope, h)
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 8; i++ {
		appendBatch(t, w, 100)
	}
	finishWriter(t, w)
	var reads atomic.Int64
	s.readAt = func(f *os.File, b []byte, off int64) (int, error) { reads.Add(1); return f.ReadAt(b, off) }
	p, e := readPage(context.Background(), s, scope, diskQuery(h, 790, 10))
	if e != nil {
		t.Fatal(e)
	}
	if len(p.Records) != 10 || p.Records[0].Seq != "791" || p.NextAfter != "800" || p.HasMore || !p.Coverage.Gap || p.Coverage.Continuity != ContinuityUnknown || p.Freshness != FreshnessUnknown || !p.Closed || p.Collection != Closed {
		t.Fatalf("bad tail page %+v", p)
	}
	if reads.Load() > 32 {
		t.Fatalf("page scanned preceding history: %d reads", reads.Load())
	}
	h2 := h
	h2.InstanceID = strings.Repeat("5", 32)
	h2.Generation = strings.Repeat("6", 32)
	w2, e := openWriter(s, scope, h2)
	if e != nil {
		t.Fatal(e)
	}
	finishWriter(t, w2)
	p, e = readPage(context.Background(), s, scope, PageRequest{SchemaVersion: 1, After: "0", Limit: 100})
	if e != nil {
		t.Fatal(e)
	}
	if p.InstanceID != h2.InstanceID || p.PreviousBinding == nil || *p.PreviousBinding != h.Binding || len(p.Records) != 0 {
		t.Fatal("discovery/prior binding lost")
	}
	p, e = readPage(context.Background(), s, scope, diskQuery(h, 0, 1))
	if e != nil || p.HistoryKind != Historical || p.Records[0].Binding != h.Binding {
		t.Fatalf("old run: %v %+v", e, p)
	}
	other := scope
	other.UID++
	if _, e = readPage(context.Background(), s, other, diskQuery(h, 0, 1)); e != TelemetryUnavailable {
		t.Fatalf("namespace leak: %v", e)
	}
}
func TestDiskRecordsDirectSeekWorkDoesNotGrowWithHistory(t *testing.T) {
	s, scope, h := diskFixture(t)
	w, e := openWriter(s, scope, h)
	if e != nil {
		t.Fatal(e)
	}
	var counts []int64
	for _, batches := range []int{1, 7} {
		for i := 0; i < batches; i++ {
			appendBatch(t, w, 100)
		}
		var state State
		if _, e = s.readJSON(filepath.Join(w.dir, "state.json"), &state, MaxStateBytes); e != nil {
			t.Fatal(e)
		}
		high, _ := state.HighWaterSeq.Uint64()
		var reads int64
		readStore := s
		readStore.readAt = func(f *os.File, b []byte, off int64) (int, error) { reads++; return f.ReadAt(b, off) }
		p, e := readPage(context.Background(), readStore, scope, diskQuery(h, high-10, 10))
		if e != nil || len(p.Records) != 10 {
			t.Fatalf("tail %v", e)
		}
		counts = append(counts, reads)
	}
	finishWriter(t, w)
	if counts[0] != counts[1] || counts[0] > 32 {
		t.Fatalf("page work grew with preceding rows %v", counts)
	}
}

func TestDiskRecordsUncommittedTailInvisibleAndCorruptionRejected(t *testing.T) {
	s, scope, h := diskFixture(t)
	w, e := openWriter(s, scope, h)
	if e != nil {
		t.Fatal(e)
	}
	appendBatch(t, w, 100)
	finishWriter(t, w)
	dataPath := filepath.Join(w.dir, "records.bin")
	indexPath := filepath.Join(w.dir, "index.bin")
	data, e := os.OpenFile(dataPath, os.O_APPEND|os.O_WRONLY, 0)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = data.Write([]byte{0, 0, 1, 0, 99}); e != nil {
		t.Fatal(e)
	}
	if e = data.Close(); e != nil {
		t.Fatal(e)
	}
	idx, e := os.OpenFile(indexPath, os.O_APPEND|os.O_WRONLY, 0)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = idx.Write(make([]byte, 7)); e != nil {
		t.Fatal(e)
	}
	_ = idx.Close()
	p, e := readPage(context.Background(), s, scope, diskQuery(h, 99, 10))
	if e != nil || len(p.Records) != 1 || p.HighWaterSeq != "100" {
		t.Fatalf("tail visible %v %+v", e, p)
	}
	before, _ := os.Stat(dataPath)
	if before.Size() <= int64(w.offset) {
		t.Fatal("uncommitted tail missing")
	}
	idx, e = os.OpenFile(indexPath, os.O_WRONLY, 0)
	if e != nil {
		t.Fatal(e)
	}
	var bad [16]byte
	binary.BigEndian.PutUint64(bad[:8], math.MaxUint64)
	binary.BigEndian.PutUint64(bad[8:], 5)
	_, e = idx.WriteAt(bad[:], 99*16)
	_ = idx.Close()
	if e != nil {
		t.Fatal(e)
	}
	if p, e = readPage(context.Background(), s, scope, diskQuery(h, 99, 10)); e != StoreInvalid || p.Records != nil {
		t.Fatalf("corrupt prefix exposed: %v %+v", e, p)
	}
	after, _ := os.Stat(dataPath)
	if after.Size() != before.Size() {
		t.Fatal("reader repaired/truncated history")
	}
}
func TestDiskRecordsLockAndUnsafeLeaves(t *testing.T) {
	s, scope, h := diskFixture(t)
	w, e := openWriter(s, scope, h)
	if e != nil {
		t.Fatal(e)
	}
	h2 := h
	h2.InstanceID = strings.Repeat("5", 32)
	if _, e = openWriter(s, scope, h2); e != Busy {
		t.Fatalf("writer lock: %v", e)
	}
	finishWriter(t, w)
	target := filepath.Join(w.dir, "records.bin")
	for _, kind := range []string{"mode", "symlink", "hardlink", "fifo", "directory", "owner"} {
		t.Run(kind, func(t *testing.T) {
			backup := target + ".saved"
			if e := os.Rename(target, backup); e != nil {
				t.Fatal(e)
			}
			defer func() { _ = os.Remove(target); _ = os.Rename(backup, target) }()
			switch kind {
			case "mode":
				if e := os.WriteFile(target, []byte("x"), 0644); e != nil {
					t.Fatal(e)
				}
				// Creation permissions are filtered by the caller's umask.
				if e := os.Chmod(target, 0644); e != nil {
					t.Fatal(e)
				}
			case "symlink":
				if e := os.Symlink(backup, target); e != nil {
					t.Fatal(e)
				}
			case "hardlink":
				if e := os.Link(backup, target); e != nil {
					t.Fatal(e)
				}
			case "fifo":
				if e := syscall.Mkfifo(target, 0600); e != nil {
					t.Fatal(e)
				}
			case "directory":
				if e := os.Mkdir(target, 0700); e != nil {
					t.Fatal(e)
				}
			case "owner":
				if e := os.WriteFile(target, []byte("x"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			readStore := s
			if kind == "owner" {
				readStore.uid++
			}
			if p, e := readPage(context.Background(), readStore, scope, diskQuery(h, 0, 1)); e != StoreInvalid || p.Records != nil {
				t.Fatalf("unsafe accepted %v", e)
			}
		})
	}
}
func TestDiskRecordsInitOrphansDoNotReplaceLatest(t *testing.T) {
	s, scope, h := diskFixture(t)
	w, e := openWriter(s, scope, h)
	if e != nil {
		t.Fatal(e)
	}
	finishWriter(t, w)
	original := s.rename
	s.rename = func(from, to string) error {
		if filepath.Base(to) == "latest.json" {
			return syscall.EIO
		}
		return original(from, to)
	}
	h2 := h
	h2.InstanceID = strings.Repeat("5", 32)
	if _, e = openWriter(s, scope, h2); e != TelemetryUnavailable {
		t.Fatalf("init fault %v", e)
	}
	ns, _ := s.namespace(scope, false)
	latest, e := s.latest(ns, scope)
	if e != nil || latest.Binding != h.Binding {
		t.Fatal("valid latest changed on init failure")
	}
	if _, e = os.Stat(filepath.Join(ns, h2.InstanceID)); e != nil {
		t.Fatal("orphan automatically removed")
	}
}
func TestDiskRecordsFaultsLatchAndPreservePrefix(t *testing.T) {
	for _, fault := range []string{"data", "index", "short", "sync", "state-rename", "close", "panic"} {
		t.Run(fault, func(t *testing.T) {
			s, scope, h := diskFixture(t)
			var armed atomic.Bool
			write, syncFile, rename, closeFile := s.write, s.sync, s.rename, s.close
			s.write = func(f *os.File, b []byte) (int, error) {
				if armed.Load() {
					switch fault {
					case "data":
						if filepath.Base(f.Name()) == "records.bin" {
							return 0, syscall.ENOSPC
						}
					case "index":
						if filepath.Base(f.Name()) == "index.bin" {
							return 0, syscall.EIO
						}
					case "short":
						if filepath.Base(f.Name()) == "records.bin" {
							return 0, nil
						}
					case "panic":
						if filepath.Base(f.Name()) == "records.bin" {
							panic("injected worker failure")
						}
					}
				}
				return write(f, b)
			}
			s.sync = func(f *os.File) error {
				if armed.Load() && fault == "sync" && filepath.Base(f.Name()) == "index.bin" {
					return syscall.EIO
				}
				return syncFile(f)
			}
			s.rename = func(a, b string) error {
				if armed.Load() && fault == "state-rename" && filepath.Base(b) == "state.json" {
					return syscall.EIO
				}
				return rename(a, b)
			}
			s.close = func(f *os.File) error {
				e := closeFile(f)
				if armed.Load() && fault == "close" && filepath.Base(f.Name()) == "records.bin" {
					return errors.Join(e, syscall.EIO)
				}
				return e
			}
			w, e := openWriter(s, scope, h)
			if e != nil {
				t.Fatal(e)
			}
			appendBatch(t, w, 100)
			armed.Store(true)
			if fault != "close" {
				for i := 0; i < 100; i++ {
					_ = w.TryAppend(diskObservation())
				}
			}
			r := w.Shutdown(context.Background())
			if r.Collection != IOFailed && r.Collection != WorkerFailed {
				t.Fatalf("failure did not latch: %+v", r)
			}
			clean := newRecordStore(s.root, s.anchor, s.uid)
			p, e := readPage(context.Background(), clean, scope, diskQuery(h, 99, 100))
			if e != nil {
				t.Fatal(e)
			}
			if p.HighWaterSeq != "100" || len(p.Records) != 1 {
				t.Fatal("uncommitted data became visible")
			}
			if fault == "state-rename" {
				if w.high != 100 {
					t.Fatal("uncertain publication adopted in memory")
				}
			} else if !p.Coverage.Gap {
				t.Fatal("failure GAP missing")
			}
		})
	}
}
func TestDiskRecordsBlockedShutdownRetainsHandlesAndLock(t *testing.T) {
	s, scope, h := diskFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	write := s.write
	s.write = func(f *os.File, b []byte) (int, error) {
		if filepath.Base(f.Name()) == "records.bin" {
			once.Do(func() { close(entered); <-release })
		}
		return write(f, b)
	}
	w, e := openWriter(s, scope, h)
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < BatchRecords; i++ {
		if !w.TryAppend(diskObservation()) {
			t.Fatal("unexpected drop")
		}
	}
	// Hold the current commit in file I/O while checking provenance latching.
	w.SetProvenanceStatus(ProvenanceVerified)
	w.SetProvenanceStatus(ProvenanceMismatch)
	w.SetProvenanceStatus(ProvenanceVerified)
	if w.provenance.Load() != 2 {
		t.Fatal("provenance mismatch upgraded")
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("worker did not enter I/O")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	result := w.Shutdown(ctx)
	if result.Cleanup != CleanupUnknown {
		t.Fatalf("blocked cleanup %+v", result)
	}
	if _, e = w.data.Stat(); e != nil {
		t.Fatal("worker-owned data closed on timeout")
	}
	h2 := h
	h2.InstanceID = strings.Repeat("5", 32)
	if _, e = openWriter(s, scope, h2); e != Busy {
		t.Fatal("blocked writer lock released early")
	}
	if next := w.Shutdown(context.Background()); next != result {
		t.Fatal("repeated shutdown changed first deadline/result")
	}
	close(release)
	select {
	case <-w.done:
	case <-time.After(4 * time.Second):
		t.Fatal("worker did not finish")
	}
	w2, e := openWriter(s, scope, h2)
	if e != nil {
		t.Fatal(e)
	}
	finishWriter(t, w2)
}
func TestDiskRecordsQueueOversizeCountersAndIDExhaustion(t *testing.T) {
	s, scope, h := diskFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	write := s.write
	s.write = func(f *os.File, b []byte) (int, error) {
		if filepath.Base(f.Name()) == "records.bin" {
			once.Do(func() { close(entered); <-release })
		}
		return write(f, b)
	}
	w, e := openWriter(s, scope, h)
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 100; i++ {
		_ = w.TryAppend(diskObservation())
	}
	<-entered
	for i := 0; i < QueueCapacity; i++ {
		if !w.TryAppend(diskObservation()) {
			t.Fatal("queue capacity not 256")
		}
	}
	if w.TryAppend(diskObservation()) || w.reasons[lossQueue].Load() != 1 {
		t.Fatal("queue loss not counted exactly once")
	}
	w.StopAdmission()
	if w.TryAppend(diskObservation()) || w.reasons[lossAdmission].Load() != 1 {
		t.Fatal("admission loss not counted")
	}
	stopped := make(chan ShutdownResult, 1)
	go func() { stopped <- w.Shutdown(context.Background()) }()
	<-w.stop
	close(release)
	if r := <-stopped; r.Collection != Closed || r.Cleanup != CleanupVerified {
		t.Fatalf("shutdown %+v", r)
	}
	if w.pending.Load() != 0 || w.reasons[lossShutdown].Load() == 0 {
		t.Fatal("bounded final batch did not account discards")
	}
	s2, scope2, h2 := diskFixture(t)
	w2, e := openWriter(s2, scope2, h2)
	if e != nil {
		t.Fatal(e)
	}
	o := diskObservation()
	o.Route.OutboundTag = strings.Repeat("x", MaxRecordBytes)
	if !w2.TryAppend(o) {
		t.Fatal("callback encoded oversize")
	}
	time.Sleep(1100 * time.Millisecond)
	finishWriter(t, w2)
	if w2.reasons[lossOversize].Load() != 1 || w2.high != 0 {
		t.Fatal("oversize was truncated/committed")
	}
	s3, scope3, h3 := diskFixture(t)
	w3, e := openWriter(s3, scope3, h3)
	if e != nil {
		t.Fatal(e)
	}
	w3.tickets.Store(math.MaxUint64)
	if w3.TryAppend(diskObservation()) {
		t.Fatal("ID wrapped")
	}
	r := w3.Shutdown(context.Background())
	if r.Collection != IDExhausted || !w3.gap.Load() {
		t.Fatal("ID exhaustion not latched")
	}
	w3.lost.Store(math.MaxUint64)
	w3.loss(lossQueue)
	if w3.lost.Load() != math.MaxUint64 || !w3.saturated.Load() {
		t.Fatal("counter wrapped")
	}
}
func TestDiskRecordsFreshnessBindingBudgetAndReplacement(t *testing.T) {
	s, scope, h := diskFixture(t)
	w, e := openWriter(s, scope, h)
	if e != nil {
		t.Fatal(e)
	}
	// Valid but large untrusted labels cause a whole-record page boundary.
	for i := 0; i < 8; i++ {
		o := diskObservation()
		o.Route.OutboundTag = strings.Repeat("x", 180000)
		if !w.TryAppend(o) {
			t.Fatal("append failed")
		}
	}
	time.Sleep(1100 * time.Millisecond)
	finishWriter(t, w)
	p, e := readPage(context.Background(), s, scope, diskQuery(h, 0, 8))
	if e != nil {
		t.Fatal(e)
	}
	encoded, e := EncodeBounded(p, MaxResponseBytes)
	if e != nil || len(encoded) > MaxResponseBytes || len(p.Records) < 1 || len(p.Records) >= 8 || !p.HasMore {
		t.Fatal("whole-record response bound failed")
	}
	bad := h
	bad.Generation = strings.Repeat("9", 32)
	if _, e = readPage(context.Background(), s, scope, diskQuery(bad, 0, 1)); e != StaleGeneration {
		t.Fatal("binding silently fell back")
	}
	if _, e = readPage(context.Background(), s, scope, diskQuery(h, 9, 1)); e != InvalidRequest {
		t.Fatal("future cursor accepted")
	}
	var state State
	if _, e = s.readJSON(filepath.Join(w.dir, "state.json"), &state, MaxStateBytes); e != nil {
		t.Fatal(e)
	}
	state.Collection = Recording
	state.Closed = false
	state.Timestamp = time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
	if e = s.publish(w.dir, "state.json", state, MaxStateBytes, false); e != nil {
		t.Fatal(e)
	}
	p, e = readPage(context.Background(), s, scope, diskQuery(h, 0, 1))
	if e != nil || p.Collection != CollectionUnknown || !p.Coverage.Gap || p.Coverage.LostTotal != nil || p.Pending != nil {
		t.Fatal("future heartbeat did not become unknown")
	}
	read := s.readAt
	var replaced bool
	s.readAt = func(f *os.File, b []byte, off int64) (int, error) {
		n, e := read(f, b, off)
		if !replaced && filepath.Base(f.Name()) == "records.bin" {
			replaced = true
			path := filepath.Join(w.dir, "header.json")
			raw, _ := os.ReadFile(path)
			_ = os.Rename(path, path+".old")
			_ = os.WriteFile(path, raw, 0600)
		}
		return n, e
	}
	if p, e = readPage(context.Background(), s, scope, diskQuery(h, 0, 1)); e != StoreInvalid || p.Records != nil {
		t.Fatal("header replacement accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = readPage(ctx, s, scope, diskQuery(h, 0, 1)); e != TelemetryUnavailable {
		t.Fatal("cancel ignored")
	}
}

func TestDiskRecordsCommittedOffsetOverflowAndMalformedState(t *testing.T) {
	s, scope, h := diskFixture(t)
	w, e := openWriter(s, scope, h)
	if e != nil {
		t.Fatal(e)
	}
	appendBatch(t, w, 100)
	finishWriter(t, w)
	var state State
	if _, e = s.readJSON(filepath.Join(w.dir, "state.json"), &state, MaxStateBytes); e != nil {
		t.Fatal(e)
	}
	state.CommittedDataBytes = DecimalFromUint64(uint64(math.MaxInt64) + 1)
	if e = s.publish(w.dir, "state.json", state, MaxStateBytes, false); e != nil {
		t.Fatal(e)
	}
	if p, e := readPage(context.Background(), s, scope, diskQuery(h, 0, 1)); e != StoreInvalid || p.Records != nil {
		t.Fatal("signed offset overflow accepted")
	}
	path := filepath.Join(w.dir, "state.json")
	if e = os.WriteFile(path, []byte(`{"schema_version":1,"schema_version":1}`), 0600); e != nil {
		t.Fatal(e)
	}
	if p, e := readPage(context.Background(), s, scope, diskQuery(h, 0, 1)); e != StoreInvalid || p.Records != nil {
		t.Fatal("malformed/duplicate state accepted")
	}
}

func TestDiskRecordsWriterPermissionChangeAndEncodingFailure(t *testing.T) {
	for _, kind := range []string{"permission", "encoding"} {
		t.Run(kind, func(t *testing.T) {
			s, scope, h := diskFixture(t)
			w, e := openWriter(s, scope, h)
			if e != nil {
				t.Fatal(e)
			}
			appendBatch(t, w, 100)
			o := diskObservation()
			if kind == "permission" {
				if e = os.Chmod(filepath.Join(w.dir, "records.bin"), 0644); e != nil {
					t.Fatal(e)
				}
			} else {
				o.Hook = Hook("invalid")
			}
			if !w.TryAppend(o) {
				t.Fatal("callback performed worker validation")
			}
			r := w.Shutdown(context.Background())
			want := IOFailed
			if kind == "encoding" {
				want = WorkerFailed
			}
			if r.Collection != want || !w.gap.Load() {
				t.Fatalf("fault not latched %+v", r)
			}
			if w.high != 100 || w.pending.Load() != 0 {
				t.Fatal("failed batch changed committed prefix/pending")
			}
			if kind == "encoding" && w.reasons[lossEncoding].Load() != 1 {
				t.Fatal("encoding loss double-counted")
			}
		})
	}
}

// Use io in the injected read-error test rather than exposing raw errors.
func TestDiskRecordsShortCommittedReadHasNoPartialPage(t *testing.T) {
	s, scope, h := diskFixture(t)
	w, e := openWriter(s, scope, h)
	if e != nil {
		t.Fatal(e)
	}
	appendBatch(t, w, 100)
	finishWriter(t, w)
	original := s.readAt
	var calls int
	s.readAt = func(f *os.File, b []byte, o int64) (int, error) {
		calls++
		if calls == 5 {
			return 0, io.ErrUnexpectedEOF
		}
		return original(f, b, o)
	}
	if p, e := readPage(context.Background(), s, scope, diskQuery(h, 0, 10)); e != StoreInvalid || p.Records != nil {
		t.Fatalf("partial response on read failure: %v", e)
	}
}

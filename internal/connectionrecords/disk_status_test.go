package connectionrecords

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestDiskRecordsDefaultShutdownBudget(t *testing.T) {
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
	defer func() {
		close(release)
		select {
		case <-w.done:
		case <-time.After(3 * time.Second):
			t.Error("worker did not exit after release")
		}
	}()
	for i := 0; i < 100; i++ {
		_ = w.TryAppend(diskObservation())
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("worker did not block")
	}
	start := time.Now()
	result := w.Shutdown(context.Background())
	elapsed := time.Since(start)
	if result.Cleanup != CleanupUnknown || elapsed < TelemetryTimeout-100*time.Millisecond || elapsed > TelemetryTimeout+2*time.Second {
		t.Fatalf("default shutdown budget result=%+v elapsed=%s", result, elapsed)
	}
	if _, e = w.lock.Stat(); e != nil {
		t.Fatal("deadline closed worker lock")
	}
}

func TestDiskRecordsOpenFaultKeepsPriorLatestAndReadersNeverCreate(t *testing.T) {
	s, scope, h := diskFixture(t)
	if _, e := readPage(context.Background(), s, scope, diskQuery(h, 0, 1)); e != TelemetryUnavailable {
		t.Fatal("empty store read should be unavailable")
	}
	if _, e := os.Lstat(s.root); !os.IsNotExist(e) {
		t.Fatal("read provisioned a root")
	}
	w, e := openWriter(s, scope, h)
	if e != nil {
		t.Fatal(e)
	}
	finishWriter(t, w)
	original := s.openFile
	s.openFile = func(path string, flags int, mode uint32) (int, error) {
		if flags&syscall.O_CREAT != 0 && filepath.Base(path) == "records.bin" {
			return -1, syscall.EACCES
		}
		return original(path, flags, mode)
	}
	h2 := h
	h2.InstanceID = strings.Repeat("5", 32)
	if _, e = openWriter(s, scope, h2); e != TelemetryUnavailable {
		t.Fatalf("open fault %v", e)
	}
	ns, _ := s.namespace(scope, false)
	prior, e := s.latest(ns, scope)
	if e != nil || prior.Binding != h.Binding {
		t.Fatal("open fault replaced latest")
	}
	p, e := readPage(context.Background(), s, scope, diskQuery(h, 0, 1))
	if e != nil || p.Binding != h.Binding {
		t.Fatal("old empty history no longer readable")
	}
}

func TestDiskRecordsPublicEntrypointsRequireRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("ordinary UID guard")
	}
	_, scope, h := diskFixture(t)
	if w, e := OpenWriter(scope, h); w != nil || e != TelemetryUnavailable {
		t.Fatal("nonroot public writer opened a store")
	}
	if p, e := ReadPage(context.Background(), scope, diskQuery(h, 0, 1)); e != TelemetryUnavailable || p.Records != nil {
		t.Fatal("nonroot public reader opened a store")
	}
}

func TestDiskRecordsConcurrentCallbacksAndStateCounters(t *testing.T) {
	s, scope, h := diskFixture(t)
	w, e := openWriter(s, scope, h)
	if e != nil {
		t.Fatal(e)
	}
	var callbacks sync.WaitGroup
	for g := 0; g < 8; g++ {
		callbacks.Add(1)
		go func() {
			defer callbacks.Done()
			for i := 0; i < 100; i++ {
				w.TryAppend(diskObservation())
			}
		}()
	}
	callbacks.Wait()
	r := w.Shutdown(context.Background())
	if r.Collection != Closed || r.Cleanup != CleanupVerified {
		t.Fatalf("shutdown %+v", r)
	}
	p, e := readPage(context.Background(), s, scope, diskQuery(h, 0, 1))
	if e != nil {
		t.Fatal(e)
	}
	high, _ := p.HighWaterSeq.Uint64()
	lost, _ := p.Coverage.LostTotal.Uint64()
	if high+lost != 800 || w.pending.Load() != 0 {
		t.Fatalf("accepted/lost mismatch high=%d lost=%d", high, lost)
	}
	var state State
	if _, e = s.readJSON(filepath.Join(w.dir, "state.json"), &state, MaxStateBytes); e != nil {
		t.Fatal(e)
	}
	if state.Pending == nil || *state.Pending != "0" || state.LostTotal == nil || state.LossEpoch == nil {
		t.Fatal("final counters unknown despite quiescence")
	}
	if lost > 0 && !p.Coverage.Gap {
		t.Fatal("loss was hidden")
	}
}
func TestDiskRecordsHeartbeatAndFailedPublicationStale(t *testing.T) {
	s, scope, h := diskFixture(t)
	var deny atomic.Bool
	rename := s.rename
	s.rename = func(a, b string) error {
		if deny.Load() && filepath.Base(b) == "state.json" {
			return syscall.EIO
		}
		return rename(a, b)
	}
	w, e := openWriter(s, scope, h)
	if e != nil {
		t.Fatal(e)
	}
	var initial State
	if _, e = s.readJSON(filepath.Join(w.dir, "state.json"), &initial, MaxStateBytes); e != nil {
		t.Fatal(e)
	}
	deadline := time.Now().Add(3 * time.Second)
	var heartbeat State
	for time.Now().Before(deadline) {
		_, e = s.readJSON(filepath.Join(w.dir, "state.json"), &heartbeat, MaxStateBytes)
		if e == nil && heartbeat.Revision != initial.Revision {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if heartbeat.Revision == initial.Revision || heartbeat.HighWaterSeq != "0" {
		t.Fatal("empty writer did not publish heartbeat")
	}
	deny.Store(true)
	result := w.Shutdown(context.Background())
	if result.Collection != IOFailed {
		t.Fatal("publication failed without latching")
	}
	var last State
	if _, e = s.readJSON(filepath.Join(w.dir, "state.json"), &last, MaxStateBytes); e != nil {
		t.Fatal(e)
	}
	at, e := time.Parse(time.RFC3339Nano, last.Timestamp)
	if e != nil {
		t.Fatal(e)
	}
	// Deterministic clock projection; no six-second test sleep or forged disk row.
	p := pageFromState(last, h.InstanceID, 0, at.Add(TelemetryTimeout+time.Nanosecond))
	if p.Collection != CollectionUnknown || !p.Coverage.Gap || p.Coverage.LostTotal != nil || p.Freshness != Stale {
		t.Fatal("unwritable status stayed recording")
	}
}
func TestDiskRecordsPublicationUncertaintyKeepsValidatedPrefix(t *testing.T) {
	s, scope, h := diskFixture(t)
	var armed atomic.Bool
	syncFile := s.sync
	s.sync = func(f *os.File) error {
		if armed.Load() && filepath.Base(f.Name()) == h.InstanceID {
			return syscall.EIO
		}
		return syncFile(f)
	}
	w, e := openWriter(s, scope, h)
	if e != nil {
		t.Fatal(e)
	}
	appendBatch(t, w, 100)
	// Directory Sync fails after rename. State might already have become visible;
	// don't assert an invented rollback or adopt it in writer memory.
	armed.Store(true)
	r := w.Shutdown(context.Background())
	if r.Collection != IOFailed {
		t.Fatal("uncertain publication reported success")
	}
	clean := newRecordStore(s.root, s.anchor, s.uid)
	p, e := readPage(context.Background(), clean, scope, diskQuery(h, 0, 1))
	if e != nil || p.HighWaterSeq != "100" || len(p.Records) != 1 {
		t.Fatalf("valid prior prefix unreadable %v", e)
	}
	if p.Closed {
		t.Fatal("failed publication claimed orderly completion")
	}
}
func TestDiskRecordsUnsafeNamespaceAndOrphanLatest(t *testing.T) {
	for _, kind := range []string{"ancestor-write", "records-mode", "namespace-mode", "namespace-symlink", "latest-header-missing"} {
		t.Run(kind, func(t *testing.T) {
			s, scope, h := diskFixture(t)
			w, e := openWriter(s, scope, h)
			if e != nil {
				t.Fatal(e)
			}
			finishWriter(t, w)
			ns, e := s.namespace(scope, false)
			if e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "ancestor-write":
				if e = os.Chmod(s.anchor, 0777); e != nil {
					t.Fatal(e)
				}
			case "records-mode":
				if e = os.Chmod(s.root, 0755); e != nil {
					t.Fatal(e)
				}
			case "namespace-mode":
				if e = os.Chmod(ns, 0755); e != nil {
					t.Fatal(e)
				}
			case "namespace-symlink":
				if e = os.Rename(ns, ns+".saved"); e != nil {
					t.Fatal(e)
				}
				if e = os.Symlink(ns+".saved", ns); e != nil {
					t.Fatal(e)
				}
			case "latest-header-missing":
				if e = os.Rename(filepath.Join(w.dir, "header.json"), filepath.Join(w.dir, "header.retained")); e != nil {
					t.Fatal(e)
				}
			}
			if _, e = readPage(context.Background(), s, scope, diskQuery(h, 0, 1)); e != StoreInvalid {
				t.Fatalf("unsafe store accepted %v", e)
			}
			h2 := h
			h2.InstanceID = strings.Repeat("5", 32)
			if _, e = openWriter(s, scope, h2); e == nil {
				t.Fatal("writer repaired/adopted unsafe store")
			}
		})
	}
}

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

// Exercise actual files and the production worker/reader. Only the failure
// return is injected; close, rename and the successful Sync calls are real.
func TestDiskRecordsTerminalFailureCannotCertifyClosed(t *testing.T) {
	for _, mode := range []string{"lock-close", "closed-directory-sync"} {
		for _, denyRecovery := range []bool{false, true} {
			name := mode
			if denyRecovery {
				name += "-no-failure-publication"
			}
			t.Run(name, func(t *testing.T) {
				s, scope, h := diskFixture(t)
				var armed, failed atomic.Bool
				var lockCloses atomic.Int64
				var closedRenamed atomic.Bool
				closeFile, rename, syncFile, openFile := s.close, s.rename, s.sync, s.openFile
				s.close = func(f *os.File) error {
					if filepath.Base(f.Name()) == "writer.lock" {
						lockCloses.Add(1)
						e := closeFile(f)
						if armed.Load() && mode == "lock-close" {
							failed.Store(true)
							return syscall.EIO
						}
						return e
					}
					return closeFile(f)
				}
				s.rename = func(a, b string) error {
					if failed.Load() && denyRecovery {
						return syscall.EIO
					}
					if e := rename(a, b); e != nil {
						return e
					}
					if armed.Load() && filepath.Base(b) == "state.json" {
						var state State
						clean := newRecordStore(s.root, s.anchor, s.uid)
						if _, e := clean.readJSON(b, &state, MaxStateBytes); e == nil && state.Closed {
							closedRenamed.Store(true)
						}
					}
					return nil
				}
				s.sync = func(f *os.File) error {
					if armed.Load() && mode == "closed-directory-sync" && filepath.Base(f.Name()) == h.InstanceID && closedRenamed.Load() {
						failed.Store(true)
						return syscall.EIO
					}
					if failed.Load() && denyRecovery {
						return syscall.EIO
					}
					return syncFile(f)
				}
				s.openFile = func(path string, flags int, mode uint32) (int, error) {
					if failed.Load() && denyRecovery && flags&(syscall.O_WRONLY|syscall.O_RDWR|syscall.O_CREAT) != 0 {
						return -1, syscall.EIO
					}
					return openFile(path, flags, mode)
				}
				w, e := openWriter(s, scope, h)
				if e != nil {
					t.Fatal(e)
				}
				appendBatch(t, w, 100)
				before, e := os.ReadDir(w.dir)
				if e != nil {
					t.Fatal(e)
				}
				armed.Store(true)
				r := w.Shutdown(context.Background())
				<-w.done
				if !failed.Load() || r.Collection != IOFailed || r.Cleanup != CleanupUnknown || r.ErrorCode != TelemetryUnavailable {
					t.Fatalf("terminal fault not reached/reported: failed=%v result=%+v", failed.Load(), r)
				}
				if lockCloses.Load() != 1 {
					t.Errorf("lock close attempted %d times", lockCloses.Load())
				}
				for _, f := range []*os.File{w.data, w.index, w.lock} {
					if _, e := f.Stat(); e == nil {
						t.Error("actual owned handle remains open")
					}
				}
				for _, entry := range before {
					if _, e := os.Lstat(filepath.Join(w.dir, entry.Name())); e != nil {
						t.Errorf("history auto-deleted %s: %v", entry.Name(), e)
					}
				}
				clean := newRecordStore(s.root, s.anchor, s.uid)
				p, e := readPage(context.Background(), clean, scope, diskQuery(h, 99, 1))
				if e != nil || p.HighWaterSeq != "100" || len(p.Records) != 1 || p.Records[0].Seq != "100" {
					t.Fatalf("prior committed prefix unavailable: %v %+v", e, p)
				}
				var state State
				if _, e := clean.readJSON(filepath.Join(w.dir, "state.json"), &state, MaxStateBytes); e != nil {
					t.Fatal(e)
				}
				at, e := time.Parse(time.RFC3339Nano, state.Timestamp)
				if e != nil {
					t.Fatal(e)
				}
				future := pageFromState(state, h.InstanceID, 99, at.Add(24*time.Hour))
				if p.Closed || p.Coverage.Continuity == ContinuityClosed || !p.Coverage.Gap {
					t.Errorf("known terminal failure certified CLOSED/FRESH/no-GAP: closed=%v collection=%s freshness=%s gap=%v continuity=%s", p.Closed, p.Collection, p.Freshness, p.Coverage.Gap, p.Coverage.Continuity)
				}
				if future.Closed && future.Freshness == Fresh && !future.Coverage.Gap {
					t.Error("failed CLOSED remains trusted indefinitely after 24h")
				}
			})
		}
	}
}

func TestDiskRecordsTerminalLockLifetimeAndSuccessfulClosed(t *testing.T) {
	s, scope, h := diskFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	var closes atomic.Int64
	closeFile := s.close
	s.close = func(f *os.File) error {
		if filepath.Base(f.Name()) == "writer.lock" {
			closes.Add(1)
			once.Do(func() { close(entered); <-release })
		}
		return closeFile(f)
	}
	w, e := openWriter(s, scope, h)
	if e != nil {
		t.Fatal(e)
	}
	appendBatch(t, w, 100)
	result := make(chan ShutdownResult, 1)
	go func() { result <- w.Shutdown(context.Background()) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("did not reach actual lock close")
	}
	clean := newRecordStore(s.root, s.anchor, s.uid)
	h2 := h
	h2.InstanceID = strings.Repeat("5", 32)
	_, openErr := openWriter(clean, scope, h2)
	select {
	case <-w.done:
		t.Error("worker done before actual lock close returned")
	default:
	}
	close(release)
	r := <-result
	if openErr != Busy || closes.Load() != 1 || r.Collection != Closed || r.Cleanup != CleanupVerified || r.ErrorCode != NoError {
		t.Fatalf("lock lifetime/success: open=%v closes=%d result=%+v", openErr, closes.Load(), r)
	}
	p, e := readPage(context.Background(), clean, scope, diskQuery(h, 99, 1))
	if e != nil || !p.Closed || p.Collection != Closed || p.Coverage.Gap || p.Coverage.Continuity != ContinuityClosed {
		t.Fatalf("ordinary successful CLOSED weakened: %v %+v", e, p)
	}
}

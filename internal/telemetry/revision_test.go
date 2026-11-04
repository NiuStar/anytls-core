package telemetry

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

func flushStore(t *testing.T, s *Store) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestR2SlowPersistenceDoesNotBlockSnapshotSamplerOrClose(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), "history.json"))
	entered := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	s.syncFile = func(f *os.File) error { close(entered); <-release; return f.Sync() }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.run(ctx, time.Hour, func(context.Context) error { return nil }) }()
	<-entered
	read := make(chan Snapshot, 1)
	go func() { read <- s.Snapshot(time.Now()) }()
	select {
	case g := <-read:
		if g.Network.Attempts != 1 {
			t.Fatal(g.Network)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("read held by filesystem")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("sampler held by filesystem")
	}
	stop, c := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer c()
	if err := s.Close(stop); err != context.DeadlineExceeded {
		t.Fatalf("unjoined IO not reported: %v", err)
	}
	if s.Snapshot(time.Now()).Network.HistoryStatus != "STOP_TIMEOUT" {
		t.Fatal("missing timeout status")
	}
}

func TestR2ParentTrustBoundary(t *testing.T) {
	for _, mode := range []os.FileMode{0777, 0770} {
		t.Run(mode.String(), func(t *testing.T) {
			d := t.TempDir()
			if err := os.Chmod(d, mode); err != nil {
				t.Fatal(err)
			}
			s := New(filepath.Join(d, "history.json"))
			now := time.Now()
			s.Record(now.Add(-time.Millisecond), now, nil)
			if s.Snapshot(now).Network.HistoryStatus != "UNAVAILABLE" {
				t.Fatal("unsafe writable parent accepted")
			}
		})
	}
	d := t.TempDir()
	outside := t.TempDir()
	link := filepath.Join(d, "config")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	s := New(filepath.Join(link, "history.json"))
	now := time.Now()
	s.Record(now.Add(-time.Millisecond), now, nil)
	if s.Snapshot(now).Network.HistoryStatus != "UNAVAILABLE" {
		t.Fatal("symlink parent accepted")
	}
	if _, err := os.Stat(filepath.Join(outside, "history.json")); !os.IsNotExist(err) {
		t.Fatal("escaped directory", err)
	}
	// Validate the real metadata owner predicate without chown or privilege use.
	info, err := os.Stat(d)
	if err != nil {
		t.Fatal(err)
	}
	st := *info.Sys().(*syscall.Stat_t)
	st.Uid = uint32(os.Geteuid() + 1)
	if trustedDirectory(ownerInfo{info, &st}) {
		t.Fatal("foreign owner accepted")
	}
}

type ownerInfo struct {
	os.FileInfo
	st *syscall.Stat_t
}

func (i ownerInfo) Sys() any { return i.st }

func TestR2ClockStepAndRestart(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skip("time.Time fixture uses 64-bit layout")
	}
	for _, delta := range []int64{-1, 1} {
		t.Run(time.Duration(delta).String(), func(t *testing.T) {
			start := time.Now().Add(-2 * time.Second)
			end := start.Add(10 * time.Millisecond)
			*(*uint64)(unsafe.Pointer(&end)) += uint64(delta) * (uint64(1) << 30)
			if end.Sub(start) != 10*time.Millisecond {
				t.Fatal("fixture monotonic invalid")
			}
			s := New(filepath.Join(t.TempDir(), "history.json"))
			s.Record(start, end, nil)
			g := s.Snapshot(start.Add(2 * time.Second))
			if g.Network.LatencyMS == nil || *g.Network.LatencyMS != 10 || g.Network.ObservedProbeSeconds != 0 || g.Network.ClockStatus != "DISCONTINUITY" {
				t.Fatalf("clock step misreported %+v", g.Network)
			}
			flushStore(t, s)
			g = New(s.path).Snapshot(start.Add(2 * time.Second))
			if g.Network.Attempts != 1 || g.Network.LatencyMS == nil || *g.Network.LatencyMS != 10 || g.Network.ClockStatus != "DISCONTINUITY" {
				t.Fatal("restart changed clock semantics", g.Network)
			}
		})
	}
}

func TestR2RollbackBetweenProbesKeepsFailures(t *testing.T) {
	start := time.Now().Add(-3 * time.Second)
	s := New("")
	s.Record(start, start.Add(10*time.Millisecond), nil)
	next := start.Add(time.Second)
	end := next.Add(10 * time.Millisecond)
	*(*uint64)(unsafe.Pointer(&next)) -= uint64(2) << 30
	*(*uint64)(unsafe.Pointer(&end)) -= uint64(2) << 30
	s.Record(next, end, context.DeadlineExceeded)
	g := s.Snapshot(start.Add(2 * time.Second))
	if g.Network.Attempts != 2 || g.Network.Succeeded != 1 || g.Network.LatestError == nil || *g.Network.LatestError != "TIMEOUT" || g.Network.ClockStatus != "DISCONTINUITY" || g.Network.ObservedProbeSeconds != .01 {
		t.Fatal(g.Network)
	}
}

func TestR2LegacyHistoryMigrationAndV2Validation(t *testing.T) {
	now := time.Now().UTC()
	p := filepath.Join(t.TempDir(), "history.json")
	b, _ := json.Marshal(history{1, Endpoint, []sample{{Start: now.Add(-time.Second), End: now, Outcome: "OK"}}})
	if err := os.WriteFile(p, b, 0600); err != nil {
		t.Fatal(err)
	}
	s := New(p)
	if g := s.Snapshot(now); g.Network.LatencyMS == nil || *g.Network.LatencyMS != 1000 {
		t.Fatal("v1 migration", g.Network)
	}
	flushStore(t, s)
	for _, row := range []sample{{Start: now.Add(-time.Second), End: now, Outcome: "OK", ElapsedNS: -1}, {Start: now.Add(-time.Second), End: now, Outcome: "OK", ElapsedNS: int64(time.Millisecond)}} {
		b, _ := json.Marshal(history{2, Endpoint, []sample{row}})
		os.WriteFile(p, b, 0600)
		s = New(p)
		if s.Snapshot(now).Network.HistoryStatus != "UNAVAILABLE" {
			t.Fatal("invalid v2 elapsed accepted")
		}
		flushStore(t, s)
	}
}

func TestR2DirectoryFDRemainsPinned(t *testing.T) {
	root := t.TempDir()
	d := filepath.Join(root, "config")
	if err := os.Mkdir(d, 0700); err != nil {
		t.Fatal(err)
	}
	s := New(filepath.Join(d, "history.json"))
	moved := filepath.Join(root, "original")
	if err := os.Rename(d, moved); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, d); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	s.Record(now.Add(-time.Millisecond), now, nil)
	flushStore(t, s)
	if _, err := os.Stat(filepath.Join(outside, "history.json")); !os.IsNotExist(err) {
		t.Fatal("replacement redirected write", err)
	}
	if _, err := os.Stat(filepath.Join(moved, "history.json")); err != nil {
		t.Fatal("pinned directory not used", err)
	}
}

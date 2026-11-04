package connectionrecords

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestTrafficLeasePersistenceAndSafePaths(t *testing.T) {
	s, scope, h := diskFixture(t)
	w, e := openWriter(s, scope, h)
	if e != nil {
		t.Fatal(e)
	}
	defer finishWriter(t, w)
	lease, e := w.OpenTrafficLease()
	if e != nil {
		t.Fatal(e)
	}
	defer lease.Close()
	payload := struct {
		Bytes Decimal `json:"bytes"`
	}{"9007199254740993"}
	if e = w.PublishTraffic(payload, 1024); e != nil {
		t.Fatal(e)
	}
	var out struct {
		Bytes Decimal `json:"bytes"`
	}
	if got, e := readTraffic(context.Background(), s, scope, &out, 1024); e != nil || !trafficSameHeader(got, w.TrafficHeader()) || out.Bytes != payload.Bytes {
		t.Fatal(got, out, e)
	}
	for _, p := range []string{filepath.Join(w.dir, "traffic.json"), lease.Name()} {
		info, e := os.Stat(p)
		if e != nil || info.Mode().Perm() != 0600 {
			t.Fatal(info, e)
		}
	}
	if _, e = w.OpenTrafficLease(); e == nil {
		t.Fatal("duplicate lease accepted")
	}
	lease.Close()
	if _, e = readTraffic(context.Background(), s, scope, &out, 1024); e == nil {
		t.Fatal("dead reporter observed")
	}
	if e = os.Chmod(filepath.Join(w.dir, "traffic.json"), 0644); e != nil {
		t.Fatal(e)
	}
	if e = w.PublishTraffic(payload, 1024); e == nil {
		t.Fatal("unsafe target published")
	}
	if e = os.Chmod(filepath.Join(w.dir, "traffic.json"), 0600); e != nil {
		t.Fatal(e)
	}
}

func TestTrafficOldInstanceNotRevivedByNewNamespaceWriter(t *testing.T) {
	s, scope, h := diskFixture(t)
	w, e := openWriter(s, scope, h)
	if e != nil {
		t.Fatal(e)
	}
	lease, e := w.OpenTrafficLease()
	if e != nil {
		t.Fatal(e)
	}
	payload := struct {
		Bytes Decimal `json:"bytes"`
	}{"9"}
	if e = w.PublishTraffic(payload, 1024); e != nil {
		t.Fatal(e)
	}
	// Simulate old process exit while latest and fresh RUNNING state remain.
	var state State
	if _, e = s.readJSON(filepath.Join(w.dir, "state.json"), &state, MaxStateBytes); e != nil {
		t.Fatal(e)
	}
	lease.Close()
	finishWriter(t, w)
	if e = s.publish(w.dir, "state.json", state, MaxStateBytes, false); e != nil {
		t.Fatal(e)
	}
	// New instance holds namespace authority before it has replaced latest.
	lock, e := s.open(filepath.Join(filepath.Dir(w.dir), "writer.lock"), syscall.O_RDWR)
	if e != nil {
		t.Fatal(e)
	}
	defer lock.Close()
	if e = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		t.Fatal(e)
	}
	var out struct {
		Bytes Decimal `json:"bytes"`
	}
	if _, e = readTraffic(context.Background(), s, scope, &out, 1024); e == nil {
		t.Fatal("adopted old run")
	}
}

func TestTrafficStoppedWriterCannotOpenLease(t *testing.T) {
	s, scope, h := diskFixture(t)
	w, e := openWriter(s, scope, h)
	if e != nil {
		t.Fatal(e)
	}
	w.StopAdmission()
	defer finishWriter(t, w)
	lease, e := w.OpenTrafficLease()
	if e == nil {
		lease.Close()
		t.Fatal("stopped writer opened live lease")
	}
}

func TestTrafficNamespaceLockReplacementRejected(t *testing.T) {
	s, scope, h := diskFixture(t)
	w, e := openWriter(s, scope, h)
	if e != nil {
		t.Fatal(e)
	}
	defer finishWriter(t, w)
	lease, e := w.OpenTrafficLease()
	if e != nil {
		t.Fatal(e)
	}
	defer lease.Close()
	payload := struct {
		Bytes Decimal `json:"bytes"`
	}{"9"}
	if e = w.PublishTraffic(payload, 1024); e != nil {
		t.Fatal(e)
	}
	original := s.openFile
	s.openFile = func(path string, flags int, mode uint32) (int, error) {
		fd, e := original(path, flags, mode)
		if e == nil && strings.HasSuffix(path, "writer.lock") {
			if e = os.Rename(path, path+".old"); e != nil {
				t.Fatal(e)
			}
			f, e := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
			if e != nil {
				t.Fatal(e)
			}
			f.Close()
		}
		return fd, e
	}
	var out struct {
		Bytes Decimal `json:"bytes"`
	}
	if _, e = readTraffic(context.Background(), s, scope, &out, 1024); e == nil {
		t.Fatal("replaced namespace lock accepted")
	}
	if e = os.Rename(w.lock.Name()+".old", w.lock.Name()); e != nil {
		t.Fatal(e)
	}
}

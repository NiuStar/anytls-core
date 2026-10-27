package connectionrecords

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestDiskRecordsStickyAncestorRejections(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode os.FileMode
	}{
		{"world-writable", 0777 | os.ModeSticky},
		{"group-writable", 0775 | os.ModeSticky},
		{"setuid", 0755 | os.ModeSticky | os.ModeSetuid},
		{"setgid", 0755 | os.ModeSticky | os.ModeSetgid},
		{"wrong-owner", 0755 | os.ModeSticky},
		{"symlink", 0755 | os.ModeSticky},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, scope, h := diskFixture(t)
			ancestor := filepath.Join(s.anchor, "ancestor")
			if e := os.Mkdir(ancestor, 0700); e != nil {
				t.Fatal(e)
			}
			if e := os.Chmod(ancestor, tc.mode); e != nil {
				t.Fatal(e)
			}
			info, e := os.Lstat(ancestor)
			if e != nil || info.Mode() != os.ModeDir|tc.mode {
				t.Fatalf("unsafe fixture mode: %v %v", info, e)
			}
			if tc.name == "wrong-owner" {
				wrong := s
				wrong.uid++ // No chown privilege or system directory changes.
				if wrong.safe(info, true, false) {
					t.Fatal("wrong owner accepted")
				}
				s.uid++
			}
			if tc.name == "symlink" {
				link := ancestor + "-link"
				if e := os.Symlink(ancestor, link); e != nil {
					t.Fatal(e)
				}
				ancestor = link
			}
			s.root = filepath.Join(ancestor, "records")
			if e := s.directory(ancestor, false); e != StoreInvalid {
				t.Fatalf("unsafe ancestor directory accepted: %v", e)
			}
			if w, e := openWriter(s, scope, h); e != TelemetryUnavailable {
				if w != nil {
					finishWriter(t, w)
				}
				t.Fatalf("unsafe ancestor writer accepted: %v", e)
			}
			if _, e := os.Lstat(s.root); !errors.Is(e, os.ErrNotExist) {
				t.Fatalf("unsafe ancestor created records root: %v", e)
			}
		})
	}
}

func TestDiskRecordsStickyPrivatePathsRejected(t *testing.T) {
	s, scope, h := diskFixture(t)
	w, e := openWriter(s, scope, h)
	if e != nil {
		t.Fatal(e)
	}
	appendBatch(t, w, 1)
	finishWriter(t, w)
	for _, path := range []string{s.root, filepath.Dir(w.dir), w.dir, filepath.Join(w.dir, "records.bin")} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			info, e := os.Lstat(path)
			if e != nil {
				t.Fatal(e)
			}
			defer func() {
				if e := os.Chmod(path, info.Mode()); e != nil {
					t.Error(e)
				}
			}()
			if e := os.Chmod(path, info.Mode()|os.ModeSticky); e != nil {
				t.Fatal(e)
			}
			sticky, e := os.Lstat(path)
			if e != nil || sticky.Mode() != info.Mode()|os.ModeSticky {
				t.Fatalf("private sticky fixture mode: %v %v", sticky, e)
			}
			if s.safe(sticky, info.IsDir(), true) || !info.IsDir() && s.safe(sticky, false, false) {
				t.Fatal("sticky private directory or file accepted")
			}
			if info.IsDir() && s.syncDir(path) != StoreInvalid {
				t.Fatal("syncDir bypassed strict private directory check")
			}
			if p, e := readPage(context.Background(), s, scope, diskQuery(h, 0, 1)); e != StoreInvalid || p.Records != nil {
				t.Fatalf("sticky private path read accepted: %v %+v", e, p)
			}
		})
	}
}

func TestDiskRecordsStickyAncestorLifecycle(t *testing.T) {
	s, scope, h := diskFixture(t)
	ancestor := filepath.Join(s.anchor, "PrivilegedHelperTools")
	if e := os.Mkdir(ancestor, 0755); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(ancestor, 0755|os.ModeSticky); e != nil {
		t.Fatal(e)
	}
	info, e := os.Lstat(ancestor)
	if e != nil || info.Mode() != os.ModeDir|os.ModeSticky|0755 {
		t.Fatalf("sticky fixture mode: %v %v", info, e)
	}
	s.root = filepath.Join(ancestor, "records")
	// A live state publication replaces its inode. Keep this ancestor-policy
	// fixture's page read outside that legitimate rename window; the reader's
	// fail-closed identity checks must not be weakened to stabilize a test.
	var publication sync.Mutex
	s.rename = func(from, to string) error {
		publication.Lock()
		defer publication.Unlock()
		return os.Rename(from, to)
	}
	w, e := openWriter(s, scope, h)
	if e != nil {
		_, rootErr := os.Lstat(s.root)
		t.Fatalf("safe sticky ancestor rejected: openWriter=%v recordsRootMissing=%v", e, errors.Is(rootErr, os.ErrNotExist))
	}
	t.Cleanup(func() { finishWriter(t, w) })
	var nonce [16]byte
	if _, e := rand.Read(nonce[:]); e != nil {
		t.Fatal(e)
	}
	host := hex.EncodeToString(nonce[:]) + ".example"
	observation := diskObservation()
	observation.Destination.Host = &host
	observation.Destination.HostSource = HostDestination
	if !w.TryAppend(observation) {
		t.Fatal("nonce observation rejected")
	}
	appendBatch(t, w, 1) // Wait for both tickets to become committed.
	publication.Lock()
	p, e := readPage(context.Background(), s, scope, diskQuery(h, 0, 2))
	publication.Unlock()
	if e != nil || len(p.Records) != 2 || p.HighWaterSeq != "2" || p.Records[0].Binding != h.Binding || p.Records[0].Destination.Host == nil || *p.Records[0].Destination.Host != host {
		t.Fatalf("live sticky ancestor page: %v %+v", e, p)
	}
	finishWriter(t, w)
	p, e = readPage(context.Background(), s, scope, diskQuery(h, 0, 2))
	if e != nil || len(p.Records) != 2 || p.HighWaterSeq != "2" || !p.Closed || p.Freshness != FreshnessUnknown || p.Coverage.Continuity != ContinuityUnknown || !p.Coverage.Gap {
		t.Fatalf("closed sticky ancestor page: %v %+v", e, p)
	}
	if info, e := os.Lstat(s.root); e != nil || info.Mode() != os.ModeDir|0700 {
		t.Fatalf("private root permissions changed: %v %v", info, e)
	}
}

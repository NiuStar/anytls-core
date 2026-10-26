package connectionrecords

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const recordsRoot = "/Library/PrivilegedHelperTools/com.nousresearch.anytls-control/records"

// Private per-operation seams never expose a caller-selected path in the API.
type recordStore struct {
	root, anchor string
	uid          uint32
	write        func(*os.File, []byte) (int, error)
	sync         func(*os.File) error
	close        func(*os.File) error
	rename       func(string, string) error
	readAt       func(*os.File, []byte, int64) (int, error)
	openFile     func(string, int, uint32) (int, error)
}

func defaultStore() recordStore { return newRecordStore(recordsRoot, "/", 0) }
func newRecordStore(root, anchor string, uid uint32) recordStore {
	return recordStore{root: root, anchor: anchor, uid: uid, write: func(f *os.File, b []byte) (int, error) { return f.Write(b) }, sync: func(f *os.File) error { return f.Sync() }, close: func(f *os.File) error { return f.Close() }, rename: os.Rename, readAt: func(f *os.File, b []byte, o int64) (int, error) { return f.ReadAt(b, o) }, openFile: syscall.Open}
}
func (s recordStore) safe(info os.FileInfo, dir, private bool) bool {
	if info == nil || info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid) != 0 {
		return false
	}
	// Sticky is harmless on trusted ancestors, never on private storage or files.
	if info.Mode()&os.ModeSticky != 0 && (!dir || private) {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != s.uid {
		return false
	}
	if dir {
		return info.IsDir() && info.Mode().Perm()&0022 == 0 && (!private || info.Mode().Perm() == 0700)
	}
	return info.Mode().IsRegular() && info.Mode().Perm() == 0600 && st.Nlink == 1
}
func (s recordStore) directory(path string, private bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !(path == s.anchor || strings.HasPrefix(path, s.anchor+"/") || s.anchor == "/") {
		return StoreInvalid
	}
	for p := path; ; p = filepath.Dir(p) {
		info, e := os.Lstat(p)
		if e != nil {
			return e
		}
		strict := private && p == path || p == s.root || strings.HasPrefix(p, s.root+"/")
		if !s.safe(info, true, strict) {
			return StoreInvalid
		}
		if p == s.anchor {
			break
		}
		if p == "/" {
			return StoreInvalid
		}
	}
	return nil
}
func (s recordStore) mkdir(path string) error {
	if e := s.directory(filepath.Dir(path), false); e != nil {
		return e
	}
	if e := os.Mkdir(path, 0700); e != nil {
		if !errors.Is(e, os.ErrExist) {
			return e
		}
	} else if e = s.syncDir(filepath.Dir(path)); e != nil {
		return e
	}
	return s.directory(path, true)
}
func (s recordStore) open(path string, flags int) (*os.File, error) {
	if e := s.directory(filepath.Dir(path), true); e != nil {
		return nil, e
	}
	fd, e := s.openFile(path, flags|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0600)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), path)
	info, e := f.Stat()
	if e == nil && !s.safe(info, false, true) {
		e = StoreInvalid
	}
	if e == nil {
		e = s.recheck(path, info)
	}
	if e != nil {
		_ = s.close(f)
		return nil, e
	}
	return f, nil
}
func (s recordStore) recheck(path string, old os.FileInfo) error {
	if e := s.directory(filepath.Dir(path), true); e != nil {
		return e
	}
	now, e := os.Lstat(path)
	if e != nil {
		return e
	}
	if !s.safe(now, false, true) || !os.SameFile(old, now) {
		return StoreInvalid
	}
	return nil
}
func (s recordStore) syncDir(path string) error {
	if e := s.directory(path, false); e != nil {
		return e
	}
	fd, e := s.openFile(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if e != nil {
		return e
	}
	f := os.NewFile(uintptr(fd), path)
	info, e := f.Stat()
	if e == nil && !s.safe(info, true, false) {
		e = StoreInvalid
	}
	if e == nil {
		e = s.sync(f)
	}
	return errors.Join(e, s.close(f))
}
func (s recordStore) writeAll(f *os.File, b []byte) error {
	n, e := s.write(f, b)
	if e == nil && n != len(b) {
		e = io.ErrShortWrite
	}
	return e
}
func (s recordStore) publish(dir, name string, value any, budget int, exclusive bool) error {
	b, e := EncodeBounded(value, budget)
	if e != nil {
		return e
	}
	target := filepath.Join(dir, name)
	old, e := os.Lstat(target)
	if e == nil {
		if exclusive || !s.safe(old, false, true) {
			return StoreInvalid
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	var token [16]byte
	if _, e = rand.Read(token[:]); e != nil {
		return e
	}
	tmp := filepath.Join(dir, ".publish-"+hex.EncodeToString(token[:]))
	f, e := s.open(tmp, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL)
	if e != nil {
		return e
	}
	e = s.writeAll(f, b)
	if e == nil {
		e = s.sync(f)
	}
	e = errors.Join(e, s.close(f))
	if e != nil {
		return e
	}
	// Recheck the existing target before publication. Failed/orphan files remain.
	if old != nil {
		if e = s.recheck(target, old); e != nil {
			return e
		}
	} else if _, e = os.Lstat(target); !errors.Is(e, os.ErrNotExist) {
		return StoreInvalid
	}
	if e = s.rename(tmp, target); e != nil {
		return e
	}
	return s.syncDir(dir)
}
func (s recordStore) readJSON(path string, out any, budget int) (info os.FileInfo, result error) {
	f, e := s.open(path, syscall.O_RDONLY)
	if e != nil {
		return nil, e
	}
	defer func() { result = errors.Join(result, s.close(f)) }()
	info, e = f.Stat()
	if e != nil {
		return nil, e
	}
	if info.Size() < 1 || info.Size() > int64(budget) {
		return nil, StoreInvalid
	}
	if e = ReadStrict(f, out, budget); e != nil {
		return nil, e
	}
	end, e := f.Stat()
	if e != nil || end.Size() != info.Size() || !end.ModTime().Equal(info.ModTime()) {
		return nil, StoreInvalid
	}
	if e := s.recheck(path, info); e != nil {
		return nil, e
	}
	return info, nil
}
func (s recordStore) namespace(scope Scope, create bool) (string, error) {
	digest, e := NamespaceDigest(scope)
	if e != nil {
		return "", InvalidRequest
	}
	if create {
		if e = s.mkdir(s.root); e != nil {
			return "", e
		}
	} else if e = s.directory(s.root, true); e != nil {
		return "", e
	}
	path := filepath.Join(s.root, digest)
	if create {
		e = s.mkdir(path)
	} else {
		e = s.directory(path, true)
	}
	return path, e
}
func (s recordStore) latest(ns string, scope Scope) (Header, error) {
	var latest Latest
	var h Header
	if _, e := s.readJSON(filepath.Join(ns, "latest.json"), &latest, MaxHeaderBytes); e != nil {
		return h, e
	}
	dir := filepath.Join(ns, latest.InstanceID)
	if e := s.directory(dir, true); e != nil {
		return h, StoreInvalid
	}
	if _, e := s.readJSON(filepath.Join(dir, "header.json"), &h, MaxHeaderBytes); e != nil {
		return h, StoreInvalid
	}
	if h.InstanceID != latest.InstanceID || h.ConfigIdentity != scope.ConfigIdentity {
		return Header{}, StoreInvalid
	}
	return h, nil
}

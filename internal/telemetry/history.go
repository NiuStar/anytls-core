package telemetry

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const maxHistoryBytes = 512 << 10

type history struct {
	SchemaVersion int      `json:"schema_version"`
	Target        string   `json:"target"`
	Samples       []sample `json:"samples"`
}

func privateRegular(st os.FileInfo) bool {
	owner, ok := st.Sys().(*syscall.Stat_t)
	return ok && owner.Uid == uint32(os.Geteuid()) && st.Mode().IsRegular() && st.Mode().Perm()&0077 == 0
}
func trustedDirectory(st os.FileInfo) bool {
	owner, ok := st.Sys().(*syscall.Stat_t)
	return ok && owner.Uid == uint32(os.Geteuid()) && st.IsDir() && st.Mode().Perm()&0022 == 0
}

// Pin every path component without following symlinks. Ancestors are a named
// trust boundary: root/current-user owned, non-writable, except sticky shared
// directories (e.g. /tmp); the application directory must be current-user owned
// and not group/other writable. No chmod/chown of existing directories.
func openHistoryDirectory(path string) (*os.File, error) {
	abs, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	dir := os.NewFile(uintptr(fd), "/")
	parts := strings.Split(strings.TrimPrefix(abs, "/"), "/")
	for _, part := range parts {
		if part == "" {
			continue
		}
		next, err := openAt(int(dir.Fd()), part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		dir.Close()
		if err != nil {
			return nil, err
		}
		dir = os.NewFile(uintptr(next), part)
		st, err := dir.Stat()
		if err != nil {
			dir.Close()
			return nil, err
		}
		owner, ok := st.Sys().(*syscall.Stat_t)
		if !ok || (owner.Uid != 0 && owner.Uid != uint32(os.Geteuid())) || st.Mode().Perm()&0022 != 0 && st.Mode()&os.ModeSticky == 0 {
			dir.Close()
			return nil, errors.New("untrusted history ancestor")
		}
	}
	st, err := dir.Stat()
	if err != nil || !trustedDirectory(st) {
		dir.Close()
		return nil, errors.New("untrusted history directory")
	}
	return dir, nil
}
func (s *Store) load() {
	s.historyStatus = "UNAVAILABLE"
	dir, err := openHistoryDirectory(s.path)
	if err != nil {
		return
	}
	s.dir = dir
	s.leaf = filepath.Base(s.path)
	fd, err := openAt(int(dir.Fd()), s.leaf, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if errors.Is(err, os.ErrNotExist) {
		s.historyStatus = "OK"
		return
	}
	if err != nil {
		return
	}
	f := os.NewFile(uintptr(fd), s.leaf)
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !privateRegular(st) || st.Size() > maxHistoryBytes {
		return
	}
	b, err := io.ReadAll(io.LimitReader(f, maxHistoryBytes+1))
	if err != nil || len(b) > maxHistoryBytes {
		return
	}
	var h history
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&h) != nil || (h.SchemaVersion != 1 && h.SchemaVersion != 2) || h.Target != Endpoint || len(h.Samples) > MaxSamples {
		return
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return
	}
	var prev time.Time
	now := time.Now().UTC()
	for i := range h.Samples {
		row := &h.Samples[i]
		wall := row.End.Sub(row.Start)
		if row.Start.IsZero() || row.End.After(now) || (row.Outcome != "OK" && row.Outcome != "HTTPS_FAILED" && row.Outcome != "TIMEOUT") {
			return
		}
		if h.SchemaVersion == 1 {
			if row.ClockUnknown || row.ElapsedNS != 0 || wall < 0 || wall > 2*Timeout || row.Start.Before(prev) {
				return
			}
			row.ElapsedNS = int64(wall)
		} else {
			if row.ElapsedNS < 0 || time.Duration(row.ElapsedNS) > 2*Timeout {
				return
			}
			if !row.ClockUnknown && (wall != time.Duration(row.ElapsedNS) || row.Start.Before(prev)) {
				return
			}
		}
		prev = row.End
	}
	s.rows = h.Samples
	s.historyStatus = "OK"
}

func (s *Store) save(rows []sample) error {
	// The fd pins the validated directory even if the pathname is replaced.
	st, err := s.dir.Stat()
	if err != nil || !trustedDirectory(st) {
		return errors.New("history directory permissions changed")
	}
	fd, err := openAt(int(s.dir.Fd()), s.leaf, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err == nil {
		f := os.NewFile(uintptr(fd), s.leaf)
		st, e := f.Stat()
		f.Close()
		if e != nil || !privateRegular(st) {
			return errors.New("unsafe history leaf")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	b, err := json.Marshal(history{2, Endpoint, rows})
	if err != nil {
		return err
	}
	if len(b) > maxHistoryBytes {
		return errors.New("history too large")
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return err
	}
	name := ".webui-metrics-" + hex.EncodeToString(nonce[:])
	fd, err = openAt(int(s.dir.Fd()), name, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	defer unlinkAt(int(s.dir.Fd()), name)
	if _, err = f.Write(b); err != nil {
		return err
	}
	if s.syncFile != nil {
		err = s.syncFile(f)
	} else {
		err = f.Sync()
	}
	if err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = renameAt(int(s.dir.Fd()), name, s.leaf); err != nil {
		return err
	}
	return s.dir.Sync()
}

// One writer, one coalesced wakeup and at most two bounded immutable copies.
// OS IO is not interruptible; Close reports a timeout without claiming it joined.
func (s *Store) writer() {
	defer close(s.writerDone)
	defer s.dir.Close()
	for range s.wake {
		s.mu.Lock()
		rows := append([]sample(nil), s.rows...)
		version := s.persistVersion
		saved := s.savedVersion
		closing := s.closing
		s.mu.Unlock()
		var err error
		if version > saved {
			err = s.save(rows)
		}
		s.mu.Lock()
		s.savedVersion = version
		if err != nil {
			s.historyStatus = "UNAVAILABLE"
		} else if version > 0 && version == s.persistVersion && s.historyStatus != "STOP_TIMEOUT" && s.historyStatus != "UNAVAILABLE" {
			s.historyStatus = "OK"
		}
		closing = closing || s.closing
		more := version != s.persistVersion
		s.mu.Unlock()
		if more {
			select {
			case s.wake <- struct{}{}:
			default:
			}
		}
		if closing && !more {
			return
		}
	}
}

func (s *Store) Close(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	s.closing = true
	done := s.writerDone
	if done != nil {
		select {
		case s.wake <- struct{}{}:
		default:
		}
	}
	s.mu.Unlock()
	if done == nil {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		s.mu.Lock()
		s.historyStatus = "STOP_TIMEOUT"
		s.mu.Unlock()
		return ctx.Err()
	}
}

package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	snapshotAppLimit       = 128 << 20
	snapshotConfigLimit    = 32 << 20
	snapshotSelectedLimit  = 64 << 10
	snapshotRuleLimit      = 32 << 20
	snapshotCALimit        = 1 << 20
	snapshotReferenceLimit = 128
	snapshotRuleTotalLimit = 128 << 20
	snapshotCATotalLimit   = 16 << 20
)

// A bounded regular handle pins one inode, NOT an atomic filesystem version.
// Metadata checks detect ordinary in-place changes, not adversarial writes that
// evade metadata observation. Final symlinks are allowed only for rules and CA,
// preserving their public loader policy. Ancestors are not authenticated.
func readSnapshotSource(path string, limit int64, follow bool) ([]byte, error) {
	flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK
	if !follow {
		flags |= unix.O_NOFOLLOW
	}
	fd, err := unix.Open(path, flags, 0)
	if err != nil {
		return nil, lifecycleFailure("snapshot source cannot be opened", err)
	}
	return readSnapshotOpened(os.NewFile(uintptr(fd), "snapshot source"), limit)
}

// Always closes the handle, including rejection and failed reads.
func readSnapshotOpened(f *os.File, limit int64) (b []byte, result error) {
	defer func() {
		if err := f.Close(); err != nil {
			result = errors.Join(result, errors.New("snapshot source close failed"))
		}
	}()
	before, err := f.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() < 0 || before.Size() > limit {
		return nil, errors.New("snapshot source must be regular and within byte limit")
	}
	return readSnapshotVersion(f, before, limit)
}

func readSnapshotVersion(f *os.File, before os.FileInfo, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, errors.New("snapshot source read failed or exceeds byte limit")
	}
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || int64(len(b)) != after.Size() || before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) || !snapshotChangeTimeEqual(before, after) {
		return nil, errors.New("snapshot source changed during acquisition")
	}
	return b, nil
}

func snapshotChangeTimeEqual(a, b os.FileInfo) bool {
	av, bv := reflect.ValueOf(a.Sys()).Elem(), reflect.ValueOf(b.Sys()).Elem()
	for _, field := range []string{"Ctim", "Ctimespec"} {
		x, y := av.FieldByName(field), bv.FieldByName(field)
		if x.IsValid() && y.IsValid() {
			return reflect.DeepEqual(x.Interface(), y.Interface())
		}
	}
	return false
}

// Exclusive publication, complete write/close, then bounded nofollow SHA readback.
func writeSnapshotLeaf(path string, b []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return errors.New("snapshot leaf already exists or cannot be created")
	}
	n, writeErr := f.Write(b)
	closeErr := f.Close()
	if writeErr != nil || n != len(b) || closeErr != nil {
		return errors.New("snapshot leaf write or close failed")
	}
	got, err := readSnapshotSource(path, int64(len(b)), false)
	if err != nil || shaHex(got) != shaHex(b) {
		return errors.New("snapshot leaf readback mismatch")
	}
	return nil
}

// Rewrites only an already-private regular config. Use a fresh exclusive leaf
// and rename, never truncate/follow an existing destination.
func replaceSnapshotConfig(root string, b []byte) error {
	path := filepath.Join(root, "config.yaml")
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() {
		return errors.New("snapshot config replacement unavailable")
	}
	temp := filepath.Join(root, "config.yaml.next")
	if err := writeSnapshotLeaf(temp, b, 0600); err != nil {
		return err
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) {
		return errors.New("snapshot config replacement identity changed")
	}
	if err := os.Rename(temp, path); err != nil {
		return errors.New("snapshot config replacement failed")
	}
	got, err := readSnapshotSource(path, int64(len(b)), false)
	if err != nil || shaHex(got) != shaHex(b) {
		return errors.New("snapshot config replacement readback mismatch")
	}
	return nil
}

type snapshotRootIdentity struct {
	path string
	info os.FileInfo
}

func snapshotRootAt(path string) (*snapshotRootIdentity, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("snapshot root identity unavailable")
	}
	return &snapshotRootIdentity{path, info}, nil
}
func (r *snapshotRootIdentity) check() error {
	if r == nil || r.info == nil {
		return errors.New("snapshot root ownership unavailable; retained")
	}
	now, err := os.Lstat(r.path)
	if err != nil || !now.IsDir() || !os.SameFile(r.info, now) {
		return errors.New("snapshot root identity changed; retained")
	}
	return nil
}
func (r *snapshotRootIdentity) remove(remove func(string) error) error {
	if err := r.check(); err != nil {
		return err
	}
	return remove(r.path)
}

// Preserve failed recovery evidence without occupying the next active snapshot.
// Like remove, this pins the leaf identity; it is not hostile-parent protection.
func (d serviceLifecycle) archiveSnapshot(r *serviceDiagnostic) error {
	check := func() error {
		if err := d.owned.check(); err != nil {
			return err
		}
		info, err := os.Lstat(d.root)
		if err != nil {
			return err
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || int(owner.Uid) != os.Geteuid() || info.Mode().Perm() != 0700 || info.Mode()&os.ModeSymlink != 0 || !os.SameFile(d.owned.info, info) {
			return errors.New("unsafe snapshot ownership; retained")
		}
		return nil
	}
	if err := check(); err != nil {
		return err
	}
	loaded, running, err := d.traceState("JOB_INITIAL")
	if err != nil {
		return lifecycleFailure("archive job state unavailable; retained", err)
	}
	if loaded || running {
		return errors.New("archive job may be loaded; retained")
	}
	archive, err := os.MkdirTemp(filepath.Dir(d.root), ".service-recovery-*")
	if err != nil {
		return err
	}
	// Never delete evidence after the move, even if publishing its receipt fails.
	moved := false
	defer func() {
		if !moved {
			_ = os.Remove(filepath.Join(archive, "previous-service-diagnostic.json"))
			_ = os.Remove(archive)
		}
	}()
	previous := filepath.Join(filepath.Dir(d.root), "service-diagnostic.json")
	if _, err := os.Lstat(previous); err == nil {
		raw, err := readSnapshotSource(previous, diagnosticLimit, false)
		if err != nil {
			return err
		}
		if err := writeSnapshotLeaf(filepath.Join(archive, "previous-service-diagnostic.json"), raw, 0600); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := check(); err != nil {
		return err
	}
	destination := filepath.Join(archive, "snapshot")
	if err := os.Rename(d.root, destination); err != nil {
		return err
	}
	moved = true
	r.Snapshot = "ARCHIVED"
	copy := *r
	copy.Outcome = "SUCCEEDED"
	if r.Operation != "STOP" {
		copy.Outcome = "FAILED"
	}
	if err := copy.write(destination); err != nil {
		return lifecycleFailure("snapshot archived; recovery receipt write failed", err)
	}
	return nil
}

// Ownership survives staging errors so lifecycle cleanup cannot adopt a foreign
// replacement root. The caller must NOT fall back to path-only cleanup.
type snapshotStageError struct {
	cause error
	owned *snapshotRootIdentity
}

func (e *snapshotStageError) Error() string { return e.cause.Error() }
func (e *snapshotStageError) Unwrap() error { return e.cause }

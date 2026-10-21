//go:build darwin && embedded_core

package main

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"context"
	"encoding/json"
	"github.com/NiuStar/anytls-core/internal/engine"
	"golang.org/x/sys/unix"
)

func controlHelperEnginePreflight(ctx context.Context, cfg map[string]any) error {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return engine.Check(ctx, raw)
}
func controlHelperSupported() bool { return true }
func controlHelperRootOwned(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0
}
func controlHelperPeerUID(conn net.Conn) (uint32, error) {
	c, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, errors.New("not a Unix peer")
	}
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid uint32
	var peerErr error
	err = raw.Control(func(fd uintptr) {
		cred, e := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if e != nil {
			peerErr = e
			return
		}
		// XUCRED_VERSION in Darwin <sys/ucred.h> is 0 (not exported by x/sys).
		if cred.Version != 0 {
			peerErr = errors.New("unknown peer credential version")
			return
		}
		uid = cred.Uid
	})
	if err != nil {
		return 0, err
	}
	return uid, peerErr
}

// Keep the socket beneath the same protected root as the helper executable.
// Some Macs have group-writable /private/var/run; never relax ancestry checks.
func controlHelperCanonicalSocketDir() (string, error) {
	if err := controlHelperTrustedPath(controlHelperRoot, true); err != nil {
		return "", err
	}
	return controlHelperSocketDir, nil
}
func controlHelperValidateSocket() error {
	dir, err := controlHelperCanonicalSocketDir()
	if err != nil {
		return err
	}
	if err = controlHelperTrustedPath(dir, true); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil || info.Mode().Perm() != 0711 {
		return errors.New("unsafe socket directory")
	}
	info, err = os.Lstat(filepath.Join(dir, "control.sock"))
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0600 {
		return errors.New("unsafe control socket")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Uid == 0 {
		return errors.New("control socket belongs to another user")
	}
	return nil
}
func controlHelperPrepareSocket(uid uint32) error {
	dir, err := controlHelperCanonicalSocketDir()
	if err != nil {
		return err
	}
	if err = os.Mkdir(dir, 0711); err != nil && !errors.Is(err, os.ErrExist) {
		return errors.New("socket directory unavailable")
	}
	if err = controlHelperTrustedPath(dir, true); err != nil {
		return err
	}
	if err = os.Chmod(dir, 0711); err != nil {
		return errors.New("socket directory permissions failed")
	}
	path := filepath.Join(dir, "control.sock")
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0600 {
		return errors.New("unsafe existing control socket")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uid {
		return errors.New("unexpected control socket owner")
	}
	c, dialErr := net.DialTimeout("unix", path, time.Second)
	if dialErr == nil {
		c.Close()
		return errors.New("control helper already running")
	}
	// Only a demonstrably stale socket can be removed; permission/timeouts fail
	// closed. No caller-controlled path is accepted here.
	if !errors.Is(dialErr, syscall.ECONNREFUSED) {
		return errors.New("existing control socket state unknown")
	}
	return os.Remove(path)
}

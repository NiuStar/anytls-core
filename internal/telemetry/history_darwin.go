//go:build darwin

package telemetry

import "golang.org/x/sys/unix"

func openAt(fd int, name string, flags int, mode uint32) (int, error) {
	return unix.Openat(fd, name, flags, mode)
}
func renameAt(fd int, old, new string) error { return unix.Renameat(fd, old, fd, new) }
func unlinkAt(fd int, name string) error     { return unix.Unlinkat(fd, name, 0) }

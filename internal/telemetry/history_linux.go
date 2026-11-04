//go:build linux

package telemetry

import "syscall"

func openAt(fd int, name string, flags int, mode uint32) (int, error) {
	return syscall.Openat(fd, name, flags, mode)
}
func renameAt(fd int, old, new string) error { return syscall.Renameat(fd, old, fd, new) }
func unlinkAt(fd int, name string) error     { return syscall.Unlinkat(fd, name) }

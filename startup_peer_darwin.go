//go:build darwin && embedded_core

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	st "github.com/NiuStar/anytls-core/internal/startuptimeline"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func startupKernelIdentity(pid int) (startupProcessIdentity, error) {
	k, e := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if e != nil {
		return startupProcessIdentity{}, e
	}
	if k.Proc.P_pid != int32(pid) {
		return startupProcessIdentity{}, errors.New("process unavailable")
	}
	return startupProcessIdentity{PID: pid, UID: k.Eproc.Ucred.Uid, Sec: k.Proc.P_starttime.Sec, Usec: int64(k.Proc.P_starttime.Usec)}, nil
}
func startupPeerPID(c net.Conn) (int, error) {
	u, ok := c.(*net.UnixConn)
	if !ok {
		return 0, errors.New("not Unix")
	}
	raw, e := u.SyscallConn()
	if e != nil {
		return 0, e
	}
	var pid int
	var inner error
	e = raw.Control(func(fd uintptr) { pid, inner = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID) })
	if e != nil {
		return 0, e
	}
	return pid, inner
}

// KERN_PROCARGS2 starts with argc, executable NUL padding, then argc separate
// NUL-terminated arguments. Spaces inside an argument must never be split.
func startupParseArgs(raw []byte) (string, []string, error) {
	if len(raw) < 5 {
		return "", nil, errors.New("argv unavailable")
	}
	argc := int(binary.LittleEndian.Uint32(raw[:4]))
	if argc < 1 || argc > 128 {
		return "", nil, errors.New("argv unavailable")
	}
	raw = raw[4:]
	i := bytes.IndexByte(raw, 0)
	if i < 1 {
		return "", nil, errors.New("argv unavailable")
	}
	exe := string(raw[:i])
	raw = bytes.TrimLeft(raw[i+1:], "\x00")
	args := make([]string, 0, argc)
	for n := 0; n < argc; n++ {
		i = bytes.IndexByte(raw, 0)
		if i < 0 {
			return "", nil, errors.New("argv unavailable")
		}
		args = append(args, string(raw[:i]))
		raw = raw[i+1:]
	}
	return exe, args, nil
}
func startupLabelPID() (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	out, e := runTool(ctx, "/bin/launchctl", "print", "system/"+serviceLabel)
	if e != nil || !strings.Contains(out, "system/"+serviceLabel+" = {") {
		return 0, errors.New("job unavailable")
	}
	pid := 0
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "pid = ") {
			if pid != 0 {
				return 0, errors.New("ambiguous job")
			}
			pid, e = strconv.Atoi(strings.TrimPrefix(line, "pid = "))
			if e != nil {
				return 0, e
			}
		}
	}
	if pid <= 0 {
		return 0, errors.New("job PID unavailable")
	}
	return pid, nil
}
func startupAuthenticatePush(c net.Conn, b *startupBinding) bool {
	return startupAuthenticatePushWith(c, b, startupPeerObservations{startupLabelPID, startupKernelIdentity, startupPeerPID, controlHelperPeerUID, startupNativeArgs})
}
func startupNativeArgs(pid int) ([]byte, error) { return unix.SysctlRaw("kern.procargs2", pid) }

type startupPeerObservations struct {
	label   func() (int, error)
	kernel  func(int) (startupProcessIdentity, error)
	peerPID func(net.Conn) (int, error)
	peerUID func(net.Conn) (uint32, error)
	args    func(int) ([]byte, error)
}

func startupAuthenticatePushWith(c net.Conn, b *startupBinding, d startupPeerObservations) bool {
	if !b.check() {
		return false
	}
	expectedPID, e := d.label()
	if e != nil {
		return false
	}
	expected, e := d.kernel(expectedPID)
	if e != nil || expected.UID != 0 {
		return false
	}
	if b.process != nil && *b.process != expected {
		return false
	}
	pid, e := d.peerPID(c)
	if e != nil || pid != expected.PID {
		return false
	}
	uid, e := d.peerUID(c)
	if e != nil || uid != 0 {
		return false
	}
	before, e := d.kernel(pid)
	if e != nil || before != expected {
		return false
	}
	raw, e := d.args(pid)
	if e != nil {
		return false
	}
	exe, args, e := startupParseArgs(raw)
	if e != nil || exe != b.executable || len(args) != len(b.args) {
		return false
	}
	for i := range args {
		if args[i] != b.args[i] {
			return false
		}
	}
	after, e := d.kernel(pid)
	if e != nil || after != before {
		return false
	}
	again, e := d.label()
	if e != nil || again != pid || !b.check() {
		return false
	}
	b.process = &expected
	return true
}
func startupReporterSocket() error {
	reg, e := controlHelperReadRegistration()
	if e != nil || reg.UID == 0 {
		return st.Unavailable
	}
	if e = controlHelperTrustedPath(controlHelperSocketDir, true); e != nil {
		return e
	}
	info, e := os.Lstat(controlHelperSocketPath)
	if e != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0600 {
		return st.Unavailable
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != reg.UID {
		return st.Unavailable
	}
	return nil
}
func startupLaunchReporter(r *startupReporter) {
	if r == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		send := func() bool {
			stream := r.recorder.Snapshot()
			result := "IN_PROGRESS"
			complete := stream.Terminal != nil
			if complete {
				result = stream.Terminal.Result
			}
			for _, e := range stream.Events {
				if e.Stage == "CORE_WAIT" {
					complete = true
					result = "SUCCEEDED"
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			if startupReporterSocket() != nil {
				return complete
			}
			c, e := (&net.Dialer{}).DialContext(ctx, "unix", controlHelperSocketPath)
			if e != nil {
				return complete
			}
			defer c.Close()
			q := st.PushRequest{TimelineSchema: 1, Action: "startup.push", HelperEpoch: r.epoch, OperationID: r.operation, Snapshot: st.CoreSnapshot{Stream: stream, StartupResult: result, Complete: complete}}
			var ack st.PushAck
			_ = startupExchange(ctx, c, q, &ack, 500*time.Millisecond, controlHelperPeerUID)
			return complete
		}
		for {
			select {
			case <-r.ctx.Done():
				send()
				return
			case <-r.done:
				send()
				return
			case <-ticker.C:
				if send() {
					return
				}
			case <-r.recorder.Notifications():
				if send() {
					return
				}
			}
		}
	}()
}

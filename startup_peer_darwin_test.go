//go:build darwin && embedded_core

package main

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func startupArgsFixture(exe string, args []string) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(len(args)))
	b = append(b, []byte(exe)...)
	b = append(b, 0, 0, 0)
	for _, a := range args {
		b = append(b, []byte(a)...)
		b = append(b, 0)
	}
	return append(b, []byte("ENV=not-an-argument\x00")...)
}
func TestStartupCompositeIdentityFixtures(t *testing.T) {
	// UNIT-SIMULATED root/label/kernel observations; real private snapshot inodes.
	// This is not an installed root-helper or launchd acceptance test.
	for _, mode := range []string{"valid", "wrong_pid", "wrong_birth", "root_uid_only", "argv_spaces", "extra_argv", "changed_label", "replaced_snapshot", "kernel_failure"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			exe, config := filepath.Join(root, "app with spaces"), filepath.Join(root, "config with spaces.yaml")
			for _, p := range []string{exe, config} {
				if e := os.WriteFile(p, []byte("fixture"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			b := &startupBinding{root: root, executable: exe, config: config, args: []string{exe, "-config", config, "-startup-operation", "0123456789abcdef0123456789abcdef", "run"}}
			b.rootInfo, _ = os.Lstat(root)
			b.executableInfo, _ = os.Lstat(exe)
			b.configInfo, _ = os.Lstat(config)
			identity := startupProcessIdentity{PID: 123, UID: 0, Sec: 456, Usec: 789}
			labelCalls, kernelCalls := 0, 0
			deps := startupPeerObservations{label: func() (int, error) {
				labelCalls++
				if mode == "changed_label" && labelCalls == 2 {
					return 124, nil
				}
				return 123, nil
			}, kernel: func(int) (startupProcessIdentity, error) {
				kernelCalls++
				v := identity
				if mode == "wrong_birth" && kernelCalls == 3 {
					v.Usec++
				}
				if mode == "kernel_failure" {
					return v, context.Canceled
				}
				return v, nil
			}, peerPID: func(net.Conn) (int, error) {
				if mode == "wrong_pid" {
					return 124, nil
				}
				return 123, nil
			}, peerUID: func(net.Conn) (uint32, error) {
				if mode == "root_uid_only" {
					return 501, nil
				}
				return 0, nil
			}, args: func(int) ([]byte, error) {
				args := append([]string(nil), b.args...)
				if mode == "argv_spaces" {
					args[2] = filepath.Join(root, "config", "with", "spaces.yaml")
				}
				if mode == "extra_argv" {
					args = append(args, "-allow-insecure")
				}
				if mode == "replaced_snapshot" {
					if e := os.Rename(config, config+".old"); e != nil {
						t.Fatal(e)
					}
					os.WriteFile(config, []byte("fixture"), 0600)
				}
				return startupArgsFixture(exe, args), nil
			}}
			good := startupAuthenticatePushWith(nil, b, deps)
			if good != (mode == "valid") {
				t.Fatalf("mode=%s authenticated=%v", mode, good)
			}
		})
	}
}
func TestStartupNativeOrdinaryUIDArgvShape(t *testing.T) {
	// Actual kernel API/argv on this ordinary-UID test process only. Root label
	// ownership remains fixture coverage, never claimed from this primitive.
	if os.Getuid() == 0 {
		t.Skip("ordinary UID primitive only")
	}
	pid := os.Getpid()
	before, e := startupKernelIdentity(pid)
	if e != nil {
		t.Fatal(e)
	}
	if before.UID != uint32(os.Geteuid()) || before.PID != pid || before.Sec <= 0 {
		t.Fatal("invalid native PID/birth")
	}
	raw, e := startupNativeArgs(pid)
	if e != nil {
		t.Fatal(e)
	}
	exe, args, e := startupParseArgs(raw)
	if e != nil {
		t.Fatal(e)
	}
	if exe == "" || !reflect.DeepEqual(args, os.Args) {
		t.Fatal("KERN_PROCARGS2 failed exact argv preservation")
	}
	after, e := startupKernelIdentity(pid)
	if e != nil || after != before {
		t.Fatal("process birth drift")
	}
	s := unitControlServer()
	c, _ := unitControlPair(t, s)
	observed, e := startupPeerPID(c)
	if e != nil || observed != pid {
		t.Fatal("actual socket peer PID mismatch", observed, e)
	}
}

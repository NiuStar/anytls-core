//go:build darwin && embedded_core

package main

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestControlHelperDarwinProtectedSocketLocation(t *testing.T) {
	if filepath.Dir(controlHelperSocketDir) != controlHelperRoot {
		t.Fatal("socket not under protected helper root")
	}
	if len(controlHelperSocketPath) >= 104 {
		t.Fatal("socket path exceeds Darwin limit")
	}
	if strings.HasPrefix(controlHelperSocketPath, "/var/") {
		t.Fatal("depends on mutable system runtime ancestry")
	}
}

func TestControlHelperDarwinKernelPeerUID(t *testing.T) {
	path := filepath.Join(unitControlSocketDir(t), "p.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.DialUnix("unix", nil, listener.Addr().(*net.UnixAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	for _, conn := range []*net.UnixConn{server, client} {
		uid, err := controlHelperPeerUID(conn)
		if err != nil || uid != uint32(os.Getuid()) {
			t.Fatalf("kernel UID %d expected %d: %v", uid, os.Getuid(), err)
		}
	}
}
func TestControlHelperDarwinNativePlistLint(t *testing.T) {
	b, err := controlInstallPlistBytes("/Users/test/.anytls/config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "helper.plist")
	if err := os.WriteFile(p, b, 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("/usr/bin/plutil", "-lint", p).CombinedOutput(); err != nil {
		t.Fatalf("native plist lint failed: %v %s", err, out)
	}
}

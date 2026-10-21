package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestGeneratedServicePlistParsesOnMac(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS plutil required")
	}
	for _, insecure := range []bool{false, true} {
		core := "/Users/example/.anytls/service/sing-box"
		if snapshotEmbedded(t) {
			core = "unused&invalid-core"
		}
		p, err := servicePlist("/Users/example/.anytls/service/anytls-macos", "/Users/example/.anytls/service/config.yaml", core, "/Users/example/.anytls/service/anytls.log", insecure)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "anytls.plist")
		if err := os.WriteFile(path, []byte(p), 0600); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command("/usr/bin/plutil", "-lint", path).CombinedOutput()
		if err != nil {
			t.Fatalf("plutil rejected plist: %s: %v", out, err)
		}
		t.Logf("native plutil insecure=%v: %s", insecure, out)
	}
}

func TestServicePlistContainsExactPaths(t *testing.T) {
	p, err := servicePlist("/opt/anytls/anytls-macos", "/opt/anytls/config.yaml", "/opt/anytls/sing-box", "/var/run/anytls-macos/log.txt", true)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"<string>com.nousresearch.anytls-macos</string>", "<string>/opt/anytls/config.yaml</string>", "<string>-network</string>", "<string>tun</string>", "<string>-allow-insecure</string>", "<false/>"} {
		if !strings.Contains(p, s) {
			t.Fatalf("missing %q: %s", s, p)
		}
	}
	if _, err := servicePlist("/tmp/a&b", "/tmp/config", "/tmp/core", "/tmp/log", false); err == nil {
		t.Fatal("unsafe XML path accepted")
	}
}

func TestServiceConfigRejectsInsecureWithoutNodeSetting(t *testing.T) {
	n := node{Name: "secure", Type: "anytls", Server: "203.0.113.2", Port: 443, Password: "test", SkipVerify: false}
	if _, err := buildNode(n, "tun", 0, true); err == nil {
		t.Fatal("allowed skip verify without node consent")
	}
}

func TestStatusDoesNotAcceptUnrelatedPID(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte("proxies: []\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := isServiceActive("com.nousresearch.anytls-macos", "Could not find service \"com.nousresearch.anytls-macos\" in domain for system"); got {
		t.Fatal("absent job accepted")
	}
	if !isServiceActive("com.nousresearch.anytls-macos", "system/com.nousresearch.anytls-macos = {\n state = running\n pid = 1234\n}") {
		t.Fatal("live job not recognized")
	}
}

//go:build !embedded_core

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestExternalRuntimeExclusivePrivateAndCleanup(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("native Mac stat permission witness")
	}
	d := t.TempDir()
	p := filepath.Join(d, "runtime.json")
	config := filepath.Join(d, "config.yaml")
	core := filepath.Join(d, "core")
	// This is a subprocess invocation/permission witness, not an engine validator.
	runtimeWrite(t, core, []byte("#!/bin/sh\n[ \"$1\" = check ] || exit 92\n[ \"$(/usr/bin/stat -f %Lp \"$3\")\" = 600 ] || exit 93\n/bin/cp \"$3\" '"+filepath.Join(d, "seen.json")+"'\n"), 0700)
	if err := dispatchEngine("check", []byte(`{"synthetic":true}`), config, core); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("runtime not removed")
	}
	b, err := os.ReadFile(filepath.Join(d, "seen.json"))
	if err != nil || string(b) != `{"synthetic":true}` {
		t.Fatal("external input changed")
	}
	runtimeWrite(t, p, []byte("owned by another instance"), 0600)
	if err := dispatchEngine("check", []byte("new"), config, core); err == nil || !strings.Contains(err.Error(), "runtime config already exists") {
		t.Fatalf("exclusive create not retained: %v", err)
	}
	b, err = os.ReadFile(p)
	if err != nil || string(b) != "owned by another instance" {
		t.Fatal("foreign runtime overwritten or removed")
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := dispatchEngine("check", []byte("new"), config, "/nonexistent/core"); err == nil {
		t.Fatal("missing external core accepted")
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("runtime not removed after error")
	}
}

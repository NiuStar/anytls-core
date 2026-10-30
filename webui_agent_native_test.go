package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// Test executable only: native acceptance replaces the network installer seam
// with two wrapper-built images. Ordinary tests retain the standard runner.
// No test hook is present in the shipped executable.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && (os.Args[1] == "webui" || os.Args[1] == "version" || os.Args[1] == "update") {
		switch os.Args[1] {
		case "webui":
			if err := webuiCommand(os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			os.Exit(0)
		case "version":
			fmt.Println(currentVersion())
			os.Exit(0)
		case "update":
			binary, _, _, err := servicePaths()
			if err != nil {
				os.Exit(1)
			}
			if len(os.Args) == 3 && os.Args[2] == "--check" {
				json.NewEncoder(os.Stdout).Encode(map[string]any{"current_version": currentVersion(), "latest_version": "v1.0.1", "update_available": currentVersion() != "v1.0.1", "source_only": false})
				os.Exit(0)
			}
			if len(os.Args) != 4 || os.Args[2] != "--version" || os.Args[3] != "v1.0.1" {
				os.Exit(1)
			}
			if _, err := os.Stat(filepath.Join(filepath.Dir(binary), "fail-install")); err == nil {
				os.Exit(1)
			}
			next, err := os.ReadFile(filepath.Join(filepath.Dir(binary), "next"))
			if err != nil {
				os.Exit(1)
			}
			f, err := os.CreateTemp(filepath.Dir(binary), ".acceptance-image-")
			if err != nil {
				os.Exit(1)
			}
			name := f.Name()
			if _, err = f.Write(next); err != nil {
				os.Exit(1)
			}
			if f.Chmod(0700) != nil || f.Sync() != nil || f.Close() != nil {
				os.Exit(1)
			}
			if os.Rename(name, binary) != nil {
				os.Exit(1)
			}
			os.Exit(0)
		}
	}
	os.Exit(m.Run())
}

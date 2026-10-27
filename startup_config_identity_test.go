package main

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestStartupConfigIdentityMetadataOnly(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "config.yaml")
	for _, size := range []int64{0, (1 << 20) + 1, snapshotConfigLimit, snapshotConfigLimit + 1} {
		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Truncate(size); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		got := startupConfigIdentity(path)
		if (got != nil) != (size <= snapshotConfigLimit) {
			t.Fatalf("metadata size=%d accepted=%v", size, got != nil)
		}
		if got != nil && got.Size() != size {
			t.Fatal("wrong metadata identity")
		}
	}
	if err := os.Truncate(path, 1); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"symlink", "directory", "fifo", "absent"} {
		t.Run(kind, func(t *testing.T) {
			p := filepath.Join(root, kind)
			switch kind {
			case "symlink":
				if err := os.Symlink(path, p); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(p, 0700); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := unix.Mkfifo(p, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if startupConfigIdentity(p) != nil {
				t.Fatal("unsafe metadata object accepted")
			}
		})
	}
}

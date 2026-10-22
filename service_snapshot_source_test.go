package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Additional handle/helper coverage added after the native business RED.
func TestSnapshotSourcePinnedHandle(t *testing.T) {
	for _, kind := range []string{"regular", "fifo", "directory", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			d := t.TempDir()
			path := filepath.Join(d, "source")
			original := []byte(`{"version":3,"rules":[{"domain":["original.invalid"]}]}`)
			runtimeWrite(t, path, original, 0600)
			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(path, path+".old"); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "regular":
				runtimeWrite(t, path, []byte("replacement"), 0600)
			case "fifo":
				if err := unix.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(path+".old", path); err != nil {
					t.Fatal(err)
				}
			}
			got, err := readSnapshotOpened(f, snapshotRuleLimit)
			if err != nil || !bytes.Equal(got, original) {
				t.Fatalf("opened inode not pinned: %v", err)
			}
			spec := fileRuleSet{Path: path, SHA256: shaHex(original)}
			if _, err := validateRuleSetBytes("a", spec, got); err != nil {
				t.Fatal(err)
			}
			spec.SHA256 = strings.Repeat("0", 64)
			if _, err := validateRuleSetBytes("a", spec, got); err == nil {
				t.Fatal("wrong SHA accepted")
			}
		})
	}
}

func TestSnapshotSourceMutationAndBounds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	runtimeWrite(t, path, []byte("before"), 0600)
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	runtimeWrite(t, path, []byte("changed-and-longer"), 0600)
	if _, err := readSnapshotVersion(f, before, 64); err == nil {
		t.Fatal("in-place size mutation accepted")
	}
	for _, limit := range []int64{snapshotAppLimit, snapshotConfigLimit, snapshotSelectedLimit, snapshotRuleLimit, snapshotCALimit} {
		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Truncate(limit + 1); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := readSnapshotSource(path, limit, false); err == nil {
			t.Fatal("oversize accepted")
		}
	}
}

func TestSnapshotSourceTypePolicy(t *testing.T) {
	for _, leaf := range []string{"app", "config", "selected"} {
		for _, kind := range []string{"fifo", "directory", "symlink"} {
			t.Run(leaf+"/"+kind, func(t *testing.T) {
				binary, config, core, root := caSnapshotFixture(t, "")
				path := map[string]string{"app": binary, "config": config, "selected": selectedPath(config)}[leaf]
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				switch kind {
				case "fifo":
					if err := unix.Mkfifo(path, 0600); err != nil {
						t.Fatal(err)
					}
				case "directory":
					if err := os.Mkdir(path, 0700); err != nil {
						t.Fatal(err)
					}
				case "symlink":
					target := path + ".target"
					runtimeWrite(t, target, []byte("bytes"), 0600)
					if err := os.Symlink(target, path); err != nil {
						t.Fatal(err)
					}
				}
				start := time.Now()
				err := stagePrivateRun(binary, config, core, root)
				if err == nil {
					t.Fatal("unsafe source accepted")
				}
				if time.Since(start) > time.Second {
					t.Fatal("unsafe source rejection blocked")
				}
				if strings.Contains(err.Error(), path) {
					t.Fatal("source path leaked")
				}
			})
		}
	}
}

func TestSnapshotSourceCASymlink(t *testing.T) {
	ca, _ := runtimeCertificate(t)
	d := t.TempDir()
	target := filepath.Join(d, "target")
	link := filepath.Join(d, "link")
	runtimeWrite(t, target, ca, 0600)
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	binary, config, core, root := caSnapshotFixture(t, link)
	if err := stagePrivateRun(binary, config, core, root); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(root, "certs"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("CA count: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(root, "certs", entries[0].Name()))
	if err != nil || !bytes.Equal(got, ca) || entries[0].Name() != shaHex(ca)+".pem" {
		t.Fatalf("CA bytes/SHA differ: %v", err)
	}
}

func TestSnapshotRootReplacementCleanupRefuses(t *testing.T) {
	d := t.TempDir()
	root := filepath.Join(d, "snapshot")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	owned, err := snapshotRootAt(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(root, root+".moved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(root, "foreign")
	runtimeWrite(t, marker, []byte("preserve"), 0600)
	called := false
	if err := owned.remove(func(p string) error { called = true; return os.RemoveAll(p) }); err == nil || called {
		t.Fatal("foreign cleanup attempted")
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("foreign replacement deleted")
	}
	if _, err := os.Stat(root + ".moved"); err != nil {
		t.Fatal("owned renamed root deleted")
	}
}

func TestSnapshotSourceExclusiveLeaves(t *testing.T) {
	d := t.TempDir()
	target := filepath.Join(d, "target")
	runtimeWrite(t, target, []byte("retain"), 0600)
	for _, kind := range []string{"regular", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(d, kind)
			if kind == "regular" {
				runtimeWrite(t, path, []byte("retain"), 0600)
			} else if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
			if err := writeSnapshotLeaf(path, []byte("changed"), 0600); err == nil {
				t.Fatal("existing leaf overwritten")
			}
		})
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != "retain" {
		t.Fatal("symlink target overwritten")
	}
}

// These business regressions compile against the frozen 67-file predecessor.
func TestSnapshotBoundedConfig(t *testing.T) {
	binary, config, core, root := caSnapshotFixture(t, "")
	data := append([]byte("proxies: []\n#"), bytes.Repeat([]byte("x"), snapshotConfigLimit)...)
	runtimeWrite(t, config, data, 0600)
	if err := stagePrivateRun(binary, config, core, root); err == nil {
		t.Fatal("snapshot accepted config above documented 32MiB bound")
	}
}

func TestSnapshotOneConfigVersionRewrite(t *testing.T) {
	d := t.TempDir()
	config, root := filepath.Join(d, "config.yaml"), filepath.Join(d, "snapshot")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	rule := []byte(`{"version":3,"rules":[{"domain_suffix":["original.invalid"]}]}`)
	runtimeWrite(t, filepath.Join(d, "original.json"), rule, 0600)
	captured := []byte("unknown: 00123\nrule-sets:\n 123: {path: original.json, sha256: " + shaHex(rule) + "}\n")
	runtimeWrite(t, filepath.Join(root, "config.yaml"), captured, 0600)
	// Atomic replacement of the public source after capture must not affect rewrite.
	replacement := filepath.Join(d, "next.yaml")
	runtimeWrite(t, replacement, []byte("unknown: changed\nrule-sets: {}\n"), 0600)
	if err := os.Rename(replacement, config); err != nil {
		t.Fatal(err)
	}
	// Relative rules MUST still resolve at ORIGINAL config dir, not private root.
	runtimeWrite(t, filepath.Join(root, "original.json"), []byte("decoy"), 0600)
	if err := stageRuleSets(config, root); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Sets map[string]fileRuleSet `yaml:"rule-sets"`
	}
	if err := readYAML(filepath.Join(root, "config.yaml"), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Sets["123"].Path != "rules/123.json" {
		t.Fatal("rewrite did not use the one captured config version")
	}
	got, err := os.ReadFile(filepath.Join(root, "rules", "123.json"))
	if err != nil || !bytes.Equal(got, rule) {
		t.Fatalf("original rule bytes not frozen: %v", err)
	}
}

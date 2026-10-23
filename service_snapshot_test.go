package main

import (
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func snapshotEmbedded(t *testing.T) bool {
	t.Helper()
	fs := flag.NewFlagSet("snapshot-mode", flag.ContinueOnError)
	fs.String("core", "", "")
	if err := fs.Parse([]string{"-core=unused"}); err != nil {
		t.Fatal(err)
	}
	return validateCoreFlag(fs) != nil
}

func TestServiceSnapshotBuildMode(t *testing.T) {
	embedded := snapshotEmbedded(t)
	for _, coreKind := range []string{"regular", "missing", "directory", "symlink"} {
		t.Run(coreKind, func(t *testing.T) {
			dir := t.TempDir()
			source := filepath.Join(dir, "source")
			if err := os.Mkdir(source, 0700); err != nil {
				t.Fatal(err)
			}
			binary, config, core := filepath.Join(source, "app"), filepath.Join(source, "config.yaml"), filepath.Join(source, "sing-box")
			rules := []byte(`{"version":3,"rules":[{"domain_suffix":["example.org"]}]}`)
			data := "proxies: []\nrule-sets:\n  domains: {path: source.json, sha256: " + shaHex(rules) + "}\n"
			for name, b := range map[string][]byte{binary: []byte("same application bytes"), config: []byte(data), selectedPath(config): []byte("fixture-node"), filepath.Join(source, "source.json"): rules} {
				if err := os.WriteFile(name, b, 0644); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Chmod(config, 0644); err != nil {
				t.Fatal(err)
			}
			switch coreKind {
			case "regular":
				if err := os.WriteFile(core, []byte("external core bytes"), 0644); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(core, 0700); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(binary, core); err != nil {
					t.Fatal(err)
				}
			}
			dest := filepath.Join(dir, "snapshot")
			err := stagePrivateRun(binary, config, core, dest)
			if !embedded && coreKind != "regular" {
				if err == nil {
					t.Fatal("external snapshot accepted unsafe/missing core")
				}
				return
			}
			if err != nil {
				t.Fatalf("snapshot must not require core in embedded mode: %v", err)
			}
			want := []string{"anytls-macos", "config.yaml", "config.yaml.selected", "rules"}
			if !embedded {
				want = append(want, "sing-box")
			}
			entries, err := os.ReadDir(dest)
			if err != nil {
				t.Fatal(err)
			}
			var names []string
			for _, e := range entries {
				names = append(names, e.Name())
			}
			if !slices.Equal(names, want) {
				t.Fatalf("snapshot files: %v, want %v", names, want)
			}
			for name, mode := range map[string]os.FileMode{".": 0700, "anytls-macos": 0700, "config.yaml": 0600, "config.yaml.selected": 0600, "rules": 0700, "rules/domains.json": 0600} {
				st, err := os.Stat(filepath.Join(dest, name))
				if err != nil {
					t.Fatal(err)
				}
				if st.Mode().Perm() != mode {
					t.Fatalf("%s mode %o, want %o", name, st.Mode().Perm(), mode)
				}
			}
			for name, wantBytes := range map[string]string{"anytls-macos": "same application bytes", "config.yaml.selected": "fixture-node"} {
				b, err := os.ReadFile(filepath.Join(dest, name))
				if err != nil || string(b) != wantBytes {
					t.Fatalf("copied %s mismatch: %v", name, err)
				}
			}
			if !embedded {
				st, err := os.Stat(filepath.Join(dest, "sing-box"))
				if err != nil || st.Mode().Perm() != 0700 {
					t.Fatalf("external core mode: %v", err)
				}
				b, err := os.ReadFile(filepath.Join(dest, "sing-box"))
				if err != nil || string(b) != "external core bytes" {
					t.Fatalf("external core copy: %v", err)
				}
			}
			if err := os.RemoveAll(source); err != nil {
				t.Fatal(err)
			}
			var doc struct {
				Sets map[string]fileRuleSet `yaml:"rule-sets"`
			}
			stagedConfig := filepath.Join(dest, "config.yaml")
			if err := readYAML(stagedConfig, &doc); err != nil {
				t.Fatal(err)
			}
			spec := doc.Sets["domains"]
			if spec.Path != "rules/domains.json" || spec.SHA256 != shaHex(rules) {
				t.Fatal("rule path/SHA not frozen")
			}
			if _, err := loadRuleSet(stagedConfig, "domains", spec); err != nil {
				t.Fatalf("snapshot depends on source: %v", err)
			}
			if err := os.WriteFile(filepath.Join(dest, spec.Path), []byte("tampered"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadRuleSet(stagedConfig, "domains", spec); err == nil {
				t.Fatal("tampered snapshot rule accepted")
			}
		})
	}
}

func TestServicePlistBuildMode(t *testing.T) {
	embedded := snapshotEmbedded(t)
	for _, insecure := range []bool{false, true} {
		p, err := servicePlist("/opt/anytls/anytls-macos", "/opt/anytls/config.yaml", "/opt/anytls/sing-box", "/opt/anytls/log", insecure)
		if err != nil {
			t.Fatal(err)
		}
		args := []string{"/opt/anytls/anytls-macos", "-config", "/opt/anytls/config.yaml"}
		if !embedded {
			args = append(args, "-core", "/opt/anytls/sing-box")
		}
		args = append(args, "-network", "tun")
		if embedded {
			args = append(args, "-record-service")
		}
		if insecure {
			args = append(args, "-allow-insecure")
		}
		args = append(args, "run")
		want := "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n<key>Label</key><string>com.nousresearch.anytls-macos</string>\n<key>ProgramArguments</key><array>\n"
		for _, arg := range args {
			want += "<string>" + arg + "</string>\n"
		}
		want += "</array>\n<key>RunAtLoad</key><true/>\n<key>KeepAlive</key><false/>\n<key>StandardOutPath</key><string>/opt/anytls/log</string>\n<key>StandardErrorPath</key><string>/opt/anytls/log</string>\n</dict></plist>\n"
		if p != want {
			t.Fatal("plist bytes differ from build-mode contract")
		}
		if strings.Count(p, "<key>ProgramArguments</key>") != 1 || strings.Count(p, "<string>/opt/anytls/anytls-macos</string>") != 1 {
			t.Fatal("expected exactly one application ProgramArguments")
		}
	}
	for _, core := range []string{"", "relative", "/bad&core", "/bad\x00core"} {
		_, err := servicePlist("/app", "/config", core, "/log", false)
		if (err == nil) != embedded {
			t.Fatalf("core validation mismatch for %q: %v", core, err)
		}
	}
	for i := range 3 {
		paths := []string{"/app", "/config", "/log"}
		paths[i] = "relative"
		if _, err := servicePlist(paths[0], paths[1], "/core", paths[2], false); err == nil {
			t.Fatal("non-core path validation removed")
		}
	}
}

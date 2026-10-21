package main

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestControlInstallPlist(t *testing.T) {
	config := "/Users/test/a & b/config.yaml"
	b, err := controlInstallPlistBytes(config)
	if err != nil {
		t.Fatal(err)
	}
	decoder := xml.NewDecoder(bytes.NewReader(b))
	for {
		_, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, want := range []string{controlInstallLabel, controlInstallRoot + "/anytls-control", "<string>helper-serve</string>", "<key>KeepAlive</key><true/>", "<integer>10</integer>", "<string>/Users/test/a &amp; b</string>", "control.log"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(string(b), serviceLabel+"</string>") || strings.Contains(string(b), "sudo") {
		t.Fatal("VPN or sudo in helper plist")
	}
	for _, invalid := range []string{"relative/config.yaml", "/Users/x/../y/config.yaml", "/Users/x\n/config.yaml"} {
		if _, err := controlInstallPlistBytes(invalid); err == nil {
			t.Errorf("accepted %q", invalid)
		}
	}
}

func TestControlInstallUserPaths(t *testing.T) {
	// Resolve the fixture's platform temp alias, never relax production guards.
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(home, "app", "anytls")
	if err := os.Mkdir(filepath.Dir(binary), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binary, []byte("image"), 0755); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(filepath.Dir(binary), "config.yaml")
	if err := os.WriteFile(config, []byte("nodes: []"), 0600); err != nil {
		t.Fatal(err)
	}
	uid := os.Getuid()
	if uid == 0 {
		t.Skip("ordinary-user home guard requires uid > 0")
	}
	if err := controlInstallUserPaths(uid, home, binary); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		uid          int
		home, binary string
	}{{0, home, binary}, {uid, home + "/..", binary}, {uid, home, filepath.Join(filepath.Dir(home), "elsewhere")}, {uid + 1, home, binary}} {
		if controlInstallUserPaths(tc.uid, tc.home, tc.binary) == nil {
			t.Errorf("accepted invalid source %+v", tc)
		}
	}
	if err := os.Remove(config); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(binary, config); err != nil {
		t.Fatal(err)
	}
	if controlInstallUserPaths(uid, home, binary) == nil {
		t.Fatal("accepted config symlink")
	}
	if controlInstallWithin(home, home+"-escape/app") {
		t.Fatal("prefix escape")
	}
}

func TestControlInstallPathGuard(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if controlInstallGuardAncestors("relative", 0) == nil {
		t.Fatal("relative ancestor accepted")
	}
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatal(err)
	}
	if controlInstallGuardAncestors(dir, uint32(os.Geteuid())) == nil {
		t.Fatal("writable ancestor accepted")
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(dir, alias); err != nil {
		t.Fatal(err)
	}
	if controlInstallGuardAncestors(alias, uint32(os.Geteuid())) == nil {
		t.Fatal("symlink ancestor accepted")
	}
}

func TestControlInstallAtomic(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "helper")
	if err := controlInstallAtomic(target, []byte("first"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := controlInstallAtomic(target, []byte("next"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != "next" {
		t.Fatal(string(got), err)
	}
	st, err := os.Stat(target)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatal(st, err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "alias")); err != nil {
		t.Fatal(err)
	}
	if controlInstallAtomic(filepath.Join(dir, "alias"), []byte("bad"), 0600) == nil {
		t.Fatal("symlink overwritten")
	}
	if err := os.Mkdir(filepath.Join(dir, "directory"), 0700); err != nil {
		t.Fatal(err)
	}
	if controlInstallAtomic(filepath.Join(dir, "directory"), nil, 0600) == nil {
		t.Fatal("directory overwritten")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".anytls-install-") {
			t.Fatal("temporary file leaked")
		}
	}
}

func TestControlInstallTransactionFailure(t *testing.T) {
	for _, existing := range []bool{false, true} {
		for _, failure := range []string{"write", "bootstrap", "verify", "ready"} {
			name := failure
			if existing {
				name += "-upgrade"
			}
			t.Run(name, func(t *testing.T) {
				dir := t.TempDir()
				unrelated := filepath.Join(dir, "unrelated")
				if err := os.WriteFile(unrelated, []byte("keep"), 0600); err != nil {
					t.Fatal(err)
				}
				files := []controlInstallFile{{filepath.Join(dir, "helper"), []byte("new-helper"), 0755}, {filepath.Join(dir, "registration.json"), []byte("new-registration"), 0600}, {filepath.Join(dir, "helper.plist"), []byte("new-plist"), 0644}}
				if existing {
					for _, f := range files {
						if err := os.WriteFile(f.path, []byte("old-"+filepath.Base(f.path)), f.mode); err != nil {
							t.Fatal(err)
						}
					}
				}
				injected := errors.New("injected install failure")
				writes := 0
				bootstraps := 0
				loaded := existing
				write := func(path string, b []byte, mode os.FileMode) error {
					if failure == "ready" && bootstraps > 0 && loaded && !strings.HasSuffix(path, ".backup") {
						t.Fatal("rollback writes before candidate bootout")
					}
					if !strings.HasSuffix(path, ".backup") {
						writes++
					}
					// Simulate the rename having happened before its directory fsync fails.
					if err := controlInstallAtomic(path, b, mode); err != nil {
						return err
					}
					if failure == "write" && writes == 2 {
						return injected
					}
					return nil
				}
				var calls []string
				tool := func(args ...string) error {
					calls = append(calls, strings.Join(args, " "))
					switch args[0] {
					case "print":
						if failure == "verify" && bootstraps == 1 {
							return injected
						}
						if !loaded {
							return os.ErrNotExist
						}
					case "bootout":
						if failure == "ready" && bootstraps == 1 {
							for _, f := range files {
								b, err := os.ReadFile(f.path)
								if err != nil || !bytes.Equal(b, f.data) {
									t.Fatal("candidate files changed before unload", f.path, err)
								}
							}
						}
						loaded = false
					case "bootstrap":
						bootstraps++
						if failure == "bootstrap" && bootstraps == 1 {
							return injected
						}
						loaded = true
					default:
						t.Fatal(args)
					}
					return nil
				}
				readyCalls := 0
				err := controlInstallTransaction(files, write, tool, func() error {
					readyCalls++
					if bootstraps != 1 || !loaded {
						t.Fatal("readiness must follow candidate bootstrap")
					}
					// launchctl print succeeded, but the job is waiting/exited;
					// no authenticated socket readiness can be established.
					waiting := "system/" + controlInstallLabel + " = {\n state = waiting\n last exit code = 1\n}"
					if isServiceActive(controlInstallLabel, waiting) {
						t.Fatal("registered but non-running candidate accepted")
					}
					return injected
				})
				if failure == "ready" && readyCalls != 1 {
					t.Fatal("authenticated readiness callback not called", readyCalls)
				}
				if !errors.Is(err, injected) {
					t.Fatalf("lost primary error: %v", err)
				}
				for _, f := range files {
					b, err := os.ReadFile(f.path)
					if existing {
						if err != nil || string(b) != "old-"+filepath.Base(f.path) {
							t.Fatalf("not restored: %s %q %v", f.path, b, err)
						}
					} else if !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("new target left: %s %v", f.path, err)
					}
				}
				if existing {
					b, err := os.ReadFile(files[0].path + ".backup")
					if err != nil || string(b) != "old-helper" {
						t.Fatal("missing backup", err)
					}
					if !loaded {
						t.Fatal("old helper not bootstrapped")
					}
				}
				if b, err := os.ReadFile(unrelated); err != nil || string(b) != "keep" {
					t.Fatal("rollback touched unrelated file", err)
				}
				if !existing && loaded {
					t.Fatal("candidate left loaded after initial-install rollback")
				}
				for _, call := range calls {
					if strings.Contains(call, serviceLabel) {
						t.Fatal("VPN label touched")
					}
				}
			})
		}
	}
}

func TestControlInstallRejectsUnknownLaunchState(t *testing.T) {
	dir := t.TempDir()
	files := []controlInstallFile{{filepath.Join(dir, "helper"), nil, 0755}, {filepath.Join(dir, "reg"), nil, 0600}, {filepath.Join(dir, "plist"), nil, 0644}}
	failure := errors.New("launchctl permission denied")
	writes := 0
	err := controlInstallTransaction(files, func(string, []byte, os.FileMode) error { writes++; return nil }, func(...string) error { return failure })
	if !errors.Is(err, failure) || writes != 0 {
		t.Fatal(err, writes)
	}
}

func TestControlInstallTransactionSuccess(t *testing.T) {
	dir := t.TempDir()
	files := []controlInstallFile{{filepath.Join(dir, "helper"), []byte("image"), 0755}, {filepath.Join(dir, "registration.json"), []byte("record"), 0600}, {filepath.Join(dir, "helper.plist"), []byte("plist"), 0644}}
	loaded := false
	tool := func(args ...string) error {
		switch args[0] {
		case "print":
			if !loaded {
				return os.ErrNotExist
			}
		case "bootstrap":
			loaded = true
		default:
			t.Fatalf("unexpected tool %v", args)
		}
		return nil
	}
	readyCalled := false
	if err := controlInstallTransaction(files, controlInstallAtomic, tool, func() error {
		if !loaded {
			t.Fatal("readiness before bootstrap")
		}
		readyCalled = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !readyCalled {
		t.Fatal("readiness gate skipped")
	}
	for _, f := range files {
		b, err := os.ReadFile(f.path)
		if err != nil || !bytes.Equal(b, f.data) {
			t.Fatal(f.path, err)
		}
		st, err := os.Stat(f.path)
		if err != nil || st.Mode().Perm() != f.mode {
			t.Fatal(f.path, err)
		}
	}
	if !loaded {
		t.Fatal("not bootstrapped")
	}
}

func TestControlInstallReadyCommandAndResponse(t *testing.T) {
	cmd := controlInstallStatusCommand(context.Background(), 501, 20, "/Users/test")
	for _, out := range []string{
		"system/" + controlInstallLabel + " = {\n state = waiting\n}",
		"system/" + controlInstallLabel + " = {\n state = running\n}",
		"system/other = {\n state = running\n pid = 42\n}",
	} {
		if isServiceActive(controlInstallLabel, out) {
			t.Fatal("non-running or wrong-label print accepted", out)
		}
	}
	if !isServiceActive(controlInstallLabel, "system/"+controlInstallLabel+" = {\n state = running\n pid = 42\n}") {
		t.Fatal("running helper rejected")
	}
	if cmd.Path != controlInstallRoot+"/anytls-control" || strings.Join(cmd.Args[1:], " ") != "helper status" || cmd.Dir != "/" {
		t.Fatal("readiness must only execute fixed protected status", cmd)
	}
	cred := cmd.SysProcAttr.Credential
	if cred.Uid != 501 || cred.Gid != 20 || len(cred.Groups) != 1 || cred.Groups[0] != 20 || cred.NoSetGroups {
		t.Fatal("readiness must drop UID/GID and supplementary groups", cred)
	}
	if strings.Join(cmd.Env, "|") != "HOME=/Users/test|PATH=/usr/bin:/bin" {
		t.Fatal("inherited child environment", cmd.Env)
	}
	sha := strings.Repeat("a", 64)
	if err := controlInstallReadyResponse([]byte(`{"ok":true,"helper_sha256":"`+sha+`"}`), sha); err != nil {
		t.Fatal(err)
	}
	for _, data := range []string{
		`{"ok":false,"helper_sha256":"` + sha + `"}`,
		`{"ok":true,"helper_sha256":"wrong"}`,
		`{"ok":true}`, `null`, `not json`,
		`{"ok":true,"helper_sha256":"` + sha + `"} {}`,
	} {
		if controlInstallReadyResponse([]byte(data), sha) == nil {
			t.Fatal("invalid readiness accepted", data)
		}
	}
	if controlInstallVerifyReady(0, 0, "/", sha) == nil {
		t.Fatal("root client allowed")
	}
}

func TestControlInstallReadyUnloadFailureBlocksRestore(t *testing.T) {
	dir := t.TempDir()
	files := []controlInstallFile{{filepath.Join(dir, "helper"), []byte("new-helper"), 0755}, {filepath.Join(dir, "reg"), []byte("new-reg"), 0600}, {filepath.Join(dir, "plist"), []byte("new-plist"), 0644}}
	for _, f := range files {
		if err := os.WriteFile(f.path, []byte("old"), f.mode); err != nil {
			t.Fatal(err)
		}
	}
	readyErr, stopErr := errors.New("socket unavailable"), errors.New("candidate bootout denied")
	bootstraps := 0
	tool := func(args ...string) error {
		if args[0] == "bootstrap" {
			bootstraps++
		}
		if args[0] == "bootout" && bootstraps == 1 {
			return stopErr
		}
		return nil
	}
	err := controlInstallTransaction(files, controlInstallAtomic, tool, func() error { return readyErr })
	if !errors.Is(err, readyErr) || !errors.Is(err, stopErr) || bootstraps != 1 {
		t.Fatal("unload failure lost or old job bootstrapped", err, bootstraps)
	}
	for _, f := range files {
		b, err := os.ReadFile(f.path)
		if err != nil || !bytes.Equal(b, f.data) {
			t.Fatal("rewrote files under unknown candidate", f.path, err)
		}
	}
	b, err := os.ReadFile(files[0].path + ".backup")
	if err != nil || string(b) != "old" {
		t.Fatal("old backup lost", err)
	}
}

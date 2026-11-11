package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func migrationDiagnosticObserver(t *testing.T, m *desktopMigration, codes *[]string) {
	t.Helper()
	m.recoveryDiagnostic = func(code string) { *codes = append(*codes, code); t.Log("RECOVERY_REJECTION", code) }
}
func TestDesktopMigrationRecoveryDiagnosticVersion(t *testing.T) {
	for _, tc := range []struct{ name, script, want string }{
		{"success", "#!/bin/sh\nprintf 'v2026-11-07-03\\n'\n", ""},
		{"child-exit", "#!/bin/sh\nprintf 'PRIVATE_DIAGNOSTIC_VALUE' >&2\nexit 17\n", "START_OR_WAIT"},
		{"timeout", "#!/bin/sh\nexec sleep 5\n", "TIMEOUT"},
		{"overflow", "#!/bin/sh\ni=0; while [ $i -lt 300 ]; do printf x; i=$((i+1)); done\n", "OUTPUT_OVERFLOW"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, _, _ := migrationIncumbentFixture(t)
			var codes []string
			migrationDiagnosticObserver(t, &m, &codes)
			image := []byte(tc.script)
			version, err := m.recoveryImageVersion(image, desktopSum(image))
			if tc.want == "" {
				if err != nil || version != "v2026-11-07-03" || len(codes) != 0 {
					t.Fatal("success changed", err, codes)
				}
			} else {
				if err != migrationRecoveryHold || !errors.Is(err, migrationRecoveryHold) || version != "" || !reflect.DeepEqual(codes, []string{tc.want}) {
					t.Fatal("fixed rejection contract", err, codes)
				}
				m.recoveryDiagnostic = nil
				v, e := m.recoveryImageVersion(image, desktopSum(image))
				if v != version || e != err {
					t.Fatal("nil observer changed verdict")
				}
			}
			entries, e := filepath.Glob(filepath.Join(m.home, ".anytls", ".migration-version-*"))
			if e != nil || len(entries) != 0 {
				t.Fatal("probe retained")
			}
		})
	}
}
func TestDesktopMigrationRecoveryDiagnosticHistory(t *testing.T) {
	for _, kind := range []string{"success", "invalid-version", "lineage", "held-callback"} {
		t.Run(kind, func(t *testing.T) {
			script := "#!/bin/sh\nprintf 'v2026-11-07-03\\n'\n"
			if kind == "invalid-version" {
				script = "#!/bin/sh\nprintf 'PRIVATE_DIAGNOSTIC_VALUE\\n'\n"
			}
			m, c := completedPublishedScript(t, script)
			var codes []string
			migrationDiagnosticObserver(t, &m, &codes)
			if kind == "lineage" {
				completedEditIntent(t, m, "authorization", func(v map[string]any) { v["sha"] = strings.Repeat("a", 64) })
			}
			if kind == "held-callback" {
				original := m.status
				m.status = func(ctx context.Context) (controlHelperResponse, error) {
					h, e := original(ctx)
					h.Running = true
					return h, e
				}
			}
			// Compare exact public error and metadata with nil observer on unchanged input.
			before := map[string][]byte{}
			filepath.Walk(m.home, func(p string, i os.FileInfo, e error) error {
				if e != nil {
					t.Fatal(e)
				}
				if i.Mode().IsRegular() {
					before[p], e = os.ReadFile(p)
					if e != nil {
						t.Fatal(e)
					}
				}
				return nil
			})
			p, e := m.inspect()
			if kind == "success" {
				if e != nil || len(codes) != 0 {
					t.Fatal("false rejection", e, codes)
				}
			} else if e == nil || len(codes) == 0 {
				t.Fatal("missing rejection", e, codes)
			}
			m.recoveryDiagnostic = nil
			q, f := m.inspect()
			if !reflect.DeepEqual(p, q) || (e == nil) != (f == nil) || e != nil && (e.Error() != f.Error() || errors.Is(e, migrationRecoveryHold) != errors.Is(f, migrationRecoveryHold)) {
				t.Fatal("observer changed public outcome")
			}
			if *c != 1 {
				t.Fatal("STOP replay")
			}
			filepath.Walk(m.home, func(p string, i os.FileInfo, e error) error {
				if e != nil {
					t.Fatal(e)
				}
				if i.Mode().IsRegular() {
					b, e := os.ReadFile(p)
					if e != nil || !bytes.Equal(b, before[p]) {
						t.Fatal("inspection wrote state")
					}
				}
				return nil
			})
			for _, code := range codes {
				if strings.Contains(code, "PRIVATE") || strings.ContainsAny(code, "/\\\n ") {
					t.Fatal("unsafe code")
				}
			}
		})
	}
}

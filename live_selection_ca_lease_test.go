package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLiveHelperCASourceLease(t *testing.T) {
	for _, mode := range []string{"unchanged", "same_bytes_inode", "changed_contents", "missing_pins", "post_same_bytes_inode", "post_changed_contents"} {
		t.Run(mode, func(t *testing.T) {
			f := newLiveEntryFixture(t)
			root := filepath.Join(filepath.Dir(f.s.registration.Config), "service")
			raw, e := os.ReadFile(filepath.Join(root, liveSourceName))
			if e != nil {
				t.Fatal(e)
			}
			s, e := decodeLiveSource(raw)
			if e != nil {
				t.Fatal(e)
			}
			var path string
			for p := range s.CAPins {
				path = p
			}
			if path == "" {
				t.Fatal("positive CA seam missing")
			}
			ca, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			mutate := func() {
				switch strings.TrimPrefix(mode, "post_") {
				case "same_bytes_inode":
					if e := os.Rename(path, path+".old"); e != nil {
						t.Error(e)
					}
					if e := os.WriteFile(path, ca, 0600); e != nil {
						t.Error(e)
					}
				case "changed_contents":
					next, _ := runtimeCertificate(t)
					if e := os.WriteFile(path, next, 0600); e != nil {
						t.Error(e)
					}
				case "missing_pins":
					s.CAPins = map[string]liveFilePin{}
					raw, e := json.Marshal(s)
					if e != nil {
						t.Error(e)
					}
					if e = os.WriteFile(filepath.Join(root, liveSourceName), raw, 0600); e != nil {
						t.Error(e)
					}
				}
			}
			late := strings.HasPrefix(mode, "post_")
			if late {
				f.onRead = func(n int32, _ *liveResponse) string {
					if n == 2 {
						mutate()
					}
					return ""
				}
			} else if mode != "unchanged" {
				mutate()
			}
			r := f.call("select")
			if mode == "unchanged" {
				if !r.OK || f.switches.Load() != 1 {
					t.Fatalf("positive %+v", r)
				}
				return
			}
			want, count := "RELOAD_REQUIRED", int32(0)
			if late {
				want, count = "SWITCH_UNKNOWN", 1
			}
			if r.OK || r.Code != want || f.switches.Load() != count {
				t.Fatalf("%s %+v switches=%d", mode, r, f.switches.Load())
			}
		})
	}
}

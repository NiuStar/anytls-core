//go:build darwin && embedded_core

package main

import (
	"context"
	"encoding/xml"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	st "github.com/NiuStar/anytls-core/internal/startuptimeline"
)

// Actual staging/capture/startupPlist and private filesystem identities. Only
// root/launchd/kernel observations are UNIT-SIMULATED; no installed helper/TUN.
func TestStartupLargeConfigPlistBinding(t *testing.T) {
	for _, size := range []int{(1 << 20) + 1, snapshotConfigLimit} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			d, binary, config, core, _, _ := lifecycleFixture(t)
			raw, err := os.ReadFile(config)
			if err != nil {
				t.Fatal(err)
			}
			raw = append(raw, []byte("#"+strings.Repeat("x", size-len(raw)-2)+"\n")...)
			if len(raw) != size {
				t.Fatal("fixture size")
			}
			if err := os.WriteFile(config, raw, 0600); err != nil {
				t.Fatal(err)
			}
			// The real compiler accepts the YAML, not merely a codec fixture.
			if _, _, err := serviceOutbounds(config, true); err != nil {
				t.Fatal(err)
			}
			owned := &snapshotRootIdentity{}
			if err := stagePrivateRunOwned(binary, config, core, d.root, owned); err != nil {
				t.Fatal(err)
			}
			receipt := newDiagnostic("START")
			receipt.capture(d.root)
			if receipt.Identity.Config != "UNAVAILABLE" {
				t.Fatal("optional config hash budget changed")
			}
			s := unitControlServer()
			identity, err := controlHelperConfigIdentity(config)
			if err != nil {
				t.Fatal(err)
			}
			op := s.startupBegin(strings.Repeat("a", 32), "start", identity, "MANUAL_START")
			ctx := context.WithValue(context.Background(), startupOperationKey{}, op)
			d = d.withStartup(ctx, s)
			d.owned, d.receipt = owned, receipt
			plist, err := d.startupPlist(true)
			if err != nil {
				t.Fatal(err)
			}
			want := serviceArgs(filepath.Join(d.root, "anytls-macos"), filepath.Join(d.root, "config.yaml"), filepath.Join(d.root, "sing-box"), true, op.trace.OperationID, *op.trace.HelperEpoch)
			var parsed struct {
				Dict struct {
					Args []string `xml:"array>string"`
				} `xml:"dict"`
			}
			if err := xml.Unmarshal([]byte(plist), &parsed); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(parsed.Dict.Args, want) || !strings.Contains(plist, "-startup-operation") || !strings.Contains(plist, "-startup-epoch") || op.binding == nil {
				t.Fatal("legal large staged config lost startup correlation flags/binding")
			}
			b := op.binding
			if !b.check() || !reflect.DeepEqual(b.args, parsed.Dict.Args) {
				t.Fatal("actual plist binding mismatch")
			}
			// Exact argv and root PID/UID/birth gate, with unchanged production
			// composite authenticator. Root authority itself is simulated here.
			process := startupProcessIdentity{PID: 123, UID: 0, Sec: 456, Usec: 789}
			deps := startupPeerObservations{
				label:   func() (int, error) { return 123, nil },
				kernel:  func(int) (startupProcessIdentity, error) { return process, nil },
				peerPID: func(net.Conn) (int, error) { return 123, nil },
				peerUID: func(net.Conn) (uint32, error) { return 0, nil },
				args:    func(int) ([]byte, error) { return startupArgsFixture(b.executable, parsed.Dict.Args), nil },
			}
			if !startupAuthenticatePushWith(nil, b, deps) {
				t.Fatal("large config core push ineligible")
			}
			// All core CLI predicates except real euid are checked from emitted
			// args. Ordinary UID must still be refused by the actual root gate.
			o := runtimeOptions{Command: "run", Config: b.config, Mode: "tun", RecordService: true}
			if startupCoreFlags(op.trace.OperationID, *op.trace.HelperEpoch, o) != (os.Geteuid() == 0) {
				t.Fatal("core eligibility/root gate changed")
			}
			r, err := st.NewRecorder("CORE", startupProvenance(""))
			if err != nil {
				t.Fatal(err)
			}
			r.Observe("START", "CORE_ENTER", "OK", st.Fields{})
			if code := op.acceptCore(st.CoreSnapshot{Stream: r.Snapshot(), StartupResult: "IN_PROGRESS"}); code != "OK" {
				t.Fatal(code)
			}
			for _, drift := range []string{"mode", "mtime", "inode"} {
				t.Run(drift, func(t *testing.T) {
					before, err := os.Lstat(b.config)
					if err != nil {
						t.Fatal(err)
					}
					switch drift {
					case "mode":
						if err := os.Chmod(b.config, 0640); err != nil {
							t.Fatal(err)
						}
						defer os.Chmod(b.config, before.Mode())
					case "mtime":
						if err := os.Chtimes(b.config, before.ModTime(), before.ModTime().Add(time.Second)); err != nil {
							t.Fatal(err)
						}
						defer os.Chtimes(b.config, before.ModTime(), before.ModTime())
					case "inode":
						if err := os.Rename(b.config, b.config+".old"); err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(b.config, raw, before.Mode()); err != nil {
							t.Fatal(err)
						}
						if err := os.Chtimes(b.config, before.ModTime(), before.ModTime()); err != nil {
							t.Fatal(err)
						}
					}
					if b.check() || startupAuthenticatePushWith(nil, b, deps) {
						t.Fatal("bound config drift accepted")
					}
				})
			}
		})
	}
}

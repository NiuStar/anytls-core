package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	st "github.com/NiuStar/anytls-core/internal/startuptimeline"
)

// Real STOP producer and encoders; only OS tools/network are fixture-owned.
func TestLifecycleStoppedAbsentSnapshotDiagnostics(t *testing.T) {
	d, _, config, _, _, calls := lifecycleFixture(t)
	stateReads := 0
	d.state = func() (bool, bool, error) { stateReads++; return false, false, nil }
	d.dns = func() ([]string, error) { t.Fatal("no-baseline STOP probed DNS"); return nil, nil }
	d.pause = func() { t.Fatal("already-stopped STOP paused") }
	s := unitControlServer()
	s.state = d.state
	s.stop = func(ctx context.Context) error { return d.withStartup(ctx, s).stop() }
	var reply controlHelperResponse
	output, err := lifecycleOutput(t, func() error {
		reply = s.executeContext(context.Background(), controlHelperWireRequest{"stop", false})
		return nil
	})
	if err != nil || !reply.OK || reply.Loaded || reply.Running || output != "AnyTLS TUN stopped\n" {
		t.Fatalf("stopped STOP result: ok=%v loaded=%v running=%v output=%q err=%v", reply.OK, reply.Loaded, reply.Running, output, err)
	}
	if stateReads != 2 || len(*calls) != 0 {
		t.Fatalf("STOP dispatch/probe count changed: state=%d tools/routes=%v", stateReads, *calls)
	}
	legacy, _ := readDiagnostic(t, d.root)
	if legacy["restoration"] != "UNAVAILABLE_NO_BASELINE" || legacy["stopped"] != "VERIFIED" || legacy["snapshot"] != "ABSENT" || legacy["restore"] != nil && legacy["restore"].(map[string]any)["dns"] != "NOT_EXECUTED" {
		t.Fatal("legacy receipt claimed restoration", legacy)
	}
	want := *newStartDiagnostics("STOP")
	want.Restoration, want.Cleanup, want.Receipt, want.Job = "NOT_ATTEMPTED", "VERIFIED", "WRITTEN", "UNLOADED"
	if reply.Diagnostics == nil || *reply.Diagnostics != want {
		t.Fatalf("STOP diagnostics=%+v want=%+v", reply.Diagnostics, want)
	}
	if !reply.Diagnostics.valid(true) {
		t.Fatal("producer diagnostics invalid")
	}
	raw, err := json.Marshal(reply)
	var decoded controlHelperResponse
	if err != nil || controlHelperReadResponse(bytes.NewReader(raw), &decoded) != nil || decoded.Diagnostics == nil || *decoded.Diagnostics != want {
		t.Fatal("legacy helper response round-trip rejected producer diagnostics", err)
	}
	identity, err := controlHelperConfigIdentity(config)
	if err != nil {
		t.Fatal(err)
	}
	modern := st.MutationResponse{TimelineSchema: 1, OK: reply.OK, TimelineAvailability: "UNAVAILABLE", ConfigIdentity: identity, Loaded: reply.Loaded, Running: reply.Running, Diagnostics: startupDiagnostics(reply.Diagnostics)}
	raw, err = st.Encode(modern)
	var roundTrip st.MutationResponse
	if err != nil || st.Decode(bytes.NewReader(raw), &roundTrip) != nil || roundTrip.Diagnostics == nil || *roundTrip.Diagnostics != *modern.Diagnostics {
		t.Fatal("modern helper response round-trip rejected producer diagnostics", err)
	}
}

func TestLifecycleStopUncertainSnapshotDiagnostics(t *testing.T) {
	for _, mode := range []string{"loaded_no_snapshot", "loaded_missing_baseline", "stopped_bad_baseline", "baseline_permission", "snapshot_permission", "snapshot_alias", "failed_bootout"} {
		t.Run(mode, func(t *testing.T) {
			d, _, _, _, loaded, _ := lifecycleFixture(t)
			wantErr := false
			switch mode {
			case "loaded_no_snapshot", "failed_bootout":
				*loaded, wantErr = true, true
				if mode == "failed_bootout" {
					d.tool = func(context.Context, string, ...string) (string, error) {
						return "", errors.New("fixture bootout failure")
					}
				}
			case "snapshot_alias":
				wantErr = true
				if err := os.Symlink(filepath.Join(t.TempDir(), "absent"), d.root); err != nil {
					t.Fatal(err)
				}
			case "snapshot_permission":
				wantErr = true
				parent := filepath.Join(filepath.Dir(d.root), "unreadable")
				if err := os.Mkdir(parent, 0700); err != nil {
					t.Fatal(err)
				}
				d.root = filepath.Join(parent, "snapshot")
				if err := os.Chmod(parent, 0000); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(parent, 0700) })
				if _, err := os.Lstat(d.root); !errors.Is(err, os.ErrPermission) {
					t.Fatalf("permission fixture not established: %v", err)
				}
			default:
				if err := os.Mkdir(d.root, 0700); err != nil {
					t.Fatal(err)
				}
				if mode == "loaded_missing_baseline" {
					*loaded = true
				} else {
					baseline := filepath.Join(d.root, serviceBaselineName)
					if err := os.WriteFile(baseline, []byte("invalid baseline"), 0600); err != nil {
						t.Fatal(err)
					}
					if mode == "baseline_permission" {
						if err := os.Chmod(baseline, 0000); err != nil {
							t.Fatal(err)
						}
						if _, err := os.ReadFile(baseline); !errors.Is(err, os.ErrPermission) {
							t.Fatalf("baseline permission fixture not established: %v", err)
						}
					}
				}
			}
			d.route = func(string) (string, error) { t.Fatal("uncertain baseline probed routes"); return "", nil }
			d.dns = func() ([]string, error) { t.Fatal("uncertain baseline probed DNS"); return nil, nil }
			var diagnostic *startDiagnostics
			ctx := context.WithValue(context.Background(), lifecycleDiagnosticsKey{}, &diagnostic)
			_, err := lifecycleOutput(t, func() error { return d.withStartup(ctx, nil).stop() })
			if (err != nil) != wantErr || diagnostic == nil || diagnostic.Restoration != "UNKNOWN" || !diagnostic.valid(err == nil) {
				t.Fatalf("uncertainty changed: diagnostics=%+v err=%v wantErr=%v", diagnostic, err, wantErr)
			}
		})
	}
}

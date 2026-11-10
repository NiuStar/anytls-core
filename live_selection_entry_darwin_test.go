//go:build darwin && embedded_core

package main

import (
	"net"
	"strings"
	"sync/atomic"
	"testing"
)

func TestLiveHelperEntryCompositeIdentity(t *testing.T) {
	// Actual executeContext + UDS + production composite verifier; only native
	// OS observations/root filesystem ownership are fixtures. No sudo/launchd.
	for _, mode := range []string{"positive", "wrong_pid", "wrong_birth", "wrong_uid", "wrong_argv", "label_replaced", "process_replaced_during_read", "process_replaced_after_dispatch"} {
		t.Run(mode, func(t *testing.T) {
			f := newLiveEntryFixture(t)
			b := f.s.dns.binding
			b.args = []string{b.executable, "-config", b.config, "run"}
			identity := *b.process
			var labels atomic.Int32
			var replacement atomic.Bool
			if mode == "process_replaced_during_read" {
				f.onRead = func(n int32, _ *liveResponse) string {
					if n == 1 {
						replacement.Store(true)
					}
					return ""
				}
			}
			if mode == "process_replaced_after_dispatch" {
				f.onSwitch = func(liveRequest) string { replacement.Store(true); return "" }
			}
			f.s.livePeer = func(c net.Conn, b *startupBinding) bool {
				return startupAuthenticatePushWith(c, b, startupPeerObservations{
					label: func() (int, error) {
						if mode == "label_replaced" && labels.Add(1) > 1 {
							return 78, nil
						}
						return 77, nil
					},
					kernel: func(int) (startupProcessIdentity, error) {
						v := identity
						if mode == "wrong_birth" || replacement.Load() {
							v.Usec++
						}
						return v, nil
					},
					peerPID: func(net.Conn) (int, error) {
						if mode == "wrong_pid" {
							return 78, nil
						}
						return 77, nil
					},
					peerUID: func(net.Conn) (uint32, error) {
						if mode == "wrong_uid" {
							return 501, nil
						}
						return 0, nil
					},
					args: func(int) ([]byte, error) {
						args := append([]string(nil), b.args...)
						if mode == "wrong_argv" {
							args = append(args, "-allow-insecure")
						}
						return startupArgsFixture(b.executable, args), nil
					},
				})
			}
			r := f.call("select")
			if mode == "positive" {
				if !r.OK || f.switches.Load() != 1 || r.SelectionOperation.Generation != strings.Repeat("a", 32) {
					t.Fatalf("positive did not reach mutation: %+v", r)
				}
				return
			}
			count := int32(0)
			want := "RELOAD_REQUIRED"
			if mode == "process_replaced_after_dispatch" {
				count = 1
				want = "SWITCH_UNKNOWN"
			}
			if r.OK || r.Code != want || f.switches.Load() != count {
				t.Fatalf("identity accepted: %+v switches=%d", r, f.switches.Load())
			}
		})
	}
}

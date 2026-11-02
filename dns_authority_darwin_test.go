//go:build darwin && embedded_core

package main

import (
	"context"
	de "github.com/NiuStar/anytls-core/internal/dnsevidence"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestDNSRootCompositeRejectThenLegitimatePush(t *testing.T) {
	// UNIT-SIMULATED label/kernel/UID/argv; actual independent snapshot files,
	// exact composite verifier, and actual private Unix helper dispatch.
	for _, fault := range []string{"pid", "start", "argv"} {
		t.Run(fault, func(t *testing.T) {
			w, _ := webFixture(t)
			id, _ := controlHelperConfigIdentity(w.configPath)
			root := t.TempDir()
			exe, config := filepath.Join(root, "app"), filepath.Join(root, "config.yaml")
			for _, p := range []string{exe, config} {
				if e := os.WriteFile(p, []byte("fixture"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			b := &startupBinding{root: root, executable: exe, config: config, args: []string{exe, "-config", config, "run"}}
			b.rootInfo, _ = os.Lstat(root)
			b.executableInfo, _ = os.Lstat(exe)
			b.configInfo, _ = os.Lstat(config)
			identity := startupProcessIdentity{PID: 123, UID: 0, Sec: 456, Usec: 789}
			b.process = &identity
			var wrong atomic.Bool
			s := &controlHelperServer{registration: controlHelperRegistration{UID: 501, Config: w.configPath}, peer: func(net.Conn) (uint32, error) { return 0, nil }}
			s.startupRegistration = func() (controlHelperRegistration, error) { return s.registration, nil }
			s.startupAuthenticate = func(c net.Conn, b *startupBinding) bool {
				return startupAuthenticatePushWith(c, b, startupPeerObservations{
					label: func() (int, error) { return 123, nil },
					kernel: func(int) (startupProcessIdentity, error) {
						v := identity
						if wrong.Load() && fault == "start" {
							v.Usec++
						}
						return v, nil
					},
					peerPID: func(net.Conn) (int, error) {
						if wrong.Load() && fault == "pid" {
							return 124, nil
						}
						return 123, nil
					},
					peerUID: func(net.Conn) (uint32, error) { return 0, nil },
					args: func(int) ([]byte, error) {
						args := append([]string{}, b.args...)
						if wrong.Load() && fault == "argv" {
							args = append(args, "-allow-insecure")
						}
						return startupArgsFixture(exe, args), nil
					},
				})
			}
			epoch, op := strings.Repeat("e", 32), strings.Repeat("f", 32)
			s.dnsBind(b, epoch, op, id)
			collector := de.New(de.Binding{InstanceID: strings.Repeat("a", 32), Generation: strings.Repeat("b", 32), ManifestID: strings.Repeat("c", 64), RuntimeSHA256: strings.Repeat("d", 64)})
			collector.Loaded()
			push := func() de.Ack {
				c, _ := unitControlPair(t, s)
				defer c.Close()
				q := de.Push{DNSSchema: 1, Action: "dns.push", HelperEpoch: epoch, OperationID: op, ConfigIdentity: id, Binding: collector.Binding(), Snapshot: collector.Snapshot()}
				var ack de.Ack
				if wrong.Load() {
					raw := make([]byte, 1024)
					n, e := c.Read(raw)
					if e != nil || de.Decode(raw[:n], &ack) != nil {
						t.Fatal("reject", e)
					}
					return ack
				}
				if e := dnsExchange(context.Background(), c, q, &ack, func(net.Conn) (uint32, error) { return 0, nil }); e != nil {
					t.Fatal(e)
				}
				return ack
			}
			if a := push(); a.Code != "OK" {
				t.Fatal("initial", a)
			}
			wrong.Store(true)
			if a := push(); a.Code != "FORBIDDEN" {
				t.Fatal("untrusted", a)
			}
			wrong.Store(false)
			if a := push(); a.Code != "OK" {
				t.Fatal("legitimate after stranger", a)
			}
		})
	}
}

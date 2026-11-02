package main

import (
	"context"
	"errors"
	de "github.com/NiuStar/anytls-core/internal/dnsevidence"
	"net"
	"strings"
	"testing"
)

func TestDNSLifecycleFailureFences(t *testing.T) {
	for _, mode := range []string{"before_registration", "after_registration", "after_peer", "publication"} {
		t.Run(mode, func(t *testing.T) {
			// UNIT-SIMULATED authority, real Unix framing/dispatch. A callback barrier
			// replaces A exactly within A's in-flight validation, not a timing sleep.
			w, _ := webFixture(t)
			id, _ := controlHelperConfigIdentity(w.configPath)
			s := &controlHelperServer{registration: controlHelperRegistration{UID: 501, Config: w.configPath}, peer: func(net.Conn) (uint32, error) { return 0, nil }}
			epochA, opA := strings.Repeat("a", 32), strings.Repeat("b", 32)
			epochB, opB := strings.Repeat("c", 32), strings.Repeat("d", 32)
			s.dnsBind(&startupBinding{}, epochA, opA, id)
			var targetB *startupBinding
			replace := func() {
				s.dnsBind(&startupBinding{}, epochB, opB, id)
				s.dns.mu.Lock()
				targetB = s.dns.binding
				s.dns.mu.Unlock()
			}
			reads, auths := 0, 0
			s.startupRegistration = func() (controlHelperRegistration, error) {
				reads++
				if mode == "before_registration" && reads == 1 || mode == "after_registration" && reads == 2 {
					replace()
					return controlHelperRegistration{}, errors.New("old A observation unavailable")
				}
				return s.registration, nil
			}
			s.startupAuthenticate = func(net.Conn, *startupBinding) bool {
				auths++
				if auths == 2 && (mode == "after_peer" || mode == "publication") {
					replace()
					return mode == "publication"
				}
				return true
			}
			collector := de.New(de.Binding{InstanceID: strings.Repeat("e", 32), Generation: strings.Repeat("f", 32), ManifestID: strings.Repeat("1", 64), RuntimeSHA256: strings.Repeat("2", 64)})
			collector.Loaded()
			exchange := func(epoch, op string, readOnly bool) de.Ack {
				c, _ := unitControlPair(t, s)
				defer c.Close()
				var ack de.Ack
				if readOnly {
					raw := make([]byte, 1024)
					n, e := c.Read(raw)
					if e != nil || de.Decode(raw[:n], &ack) != nil {
						t.Fatal(e)
					}
					return ack
				}
				q := de.Push{DNSSchema: 1, Action: "dns.push", HelperEpoch: epoch, OperationID: op, ConfigIdentity: id, Binding: collector.Binding(), Snapshot: collector.Snapshot()}
				if e := dnsExchange(context.Background(), c, q, &ack, func(net.Conn) (uint32, error) { return 0, nil }); e != nil {
					t.Fatal(e)
				}
				return ack
			}
			a := exchange(epochA, opA, mode == "before_registration")
			if a.Code == "OK" {
				t.Fatal("old A published after replacement")
			}
			s.dns.mu.Lock()
			alive := targetB != nil && s.dns.binding == targetB
			s.dns.mu.Unlock()
			if !alive {
				t.Fatal("old A erased B", mode)
			}
			collector = de.New(collector.Binding())
			collector.Loaded()
			if b := exchange(epochB, opB, false); b.Code != "OK" {
				t.Fatal("B lost authority", b)
			}
		})
	}
}

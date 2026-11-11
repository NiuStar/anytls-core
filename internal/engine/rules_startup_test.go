package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
)

type heldStartupRule struct {
	adapter.Rule
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	starts  atomic.Int32
	fail    error
}

func (r *heldStartupRule) Start() error {
	r.starts.Add(1)
	r.once.Do(func() { close(r.entered) })
	<-r.release
	if r.fail != nil {
		return r.fail
	}
	return r.Rule.Start()
}

// Hold the actual rule initialization boundary. A listening socket is already
// admission: mixed can accept and route before Box.Start returns.
func TestRuleSetStartupBeforeInboundAdmission(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprintf("start_failure_%t", fail), func(t *testing.T) {
			port := freeLoopbackPort(t)
			raw := []byte(fmt.Sprintf(`{"log":{"disabled":true},"inbounds":[{"type":"mixed","listen":"127.0.0.1","listen_port":%d}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"rules":[{"rule_set":["loop"],"action":"route","outbound":"direct"}],"rule_set":[{"type":"inline","tag":"loop","rules":[{"ip_cidr":["127.0.0.0/8"]}]}]}}`, port))
			ctx, options, err := decodeOptions(context.Background(), raw)
			if err != nil {
				t.Fatal(err)
			}
			instance, err := box.New(box.Options{Options: options, Context: ctx})
			if err != nil {
				t.Fatal(err)
			}
			sentinel := errors.New("held rule startup failure")
			held := &heldStartupRule{Rule: instance.Router().Rules()[0], entered: make(chan struct{}), release: make(chan struct{})}
			if fail {
				held.fail = sentinel
			}
			instance.Router().Rules()[0] = held
			done := make(chan error, 1)
			var release sync.Once
			unblock := func() { release.Do(func() { close(held.release) }) }
			go func() { done <- instance.Start() }()
			t.Cleanup(func() {
				unblock()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Error("startup did not join")
				}
				if err := instance.Close(); err != nil {
					t.Error(err)
				}
			})
			select {
			case <-held.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("actual rule startup seam not reached")
			}
			c, dialErr := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
			if c != nil {
				c.Close()
			}
			if dialErr == nil {
				t.Error("inbound admitted connection before rule-set initialization completed")
			}
			unblock()
			select {
			case err = <-done:
				done <- err // retain the joined result for cleanup
			case <-time.After(5 * time.Second):
				t.Fatal("startup did not complete after release")
			}
			if fail {
				if !errors.Is(err, sentinel) {
					t.Fatalf("startup failure lost: %v", err)
				}
				assertBindable(t, port)
			} else {
				if err != nil {
					t.Fatal(err)
				}
				c, err = net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
				if err != nil {
					t.Fatalf("ready inbound unavailable: %v", err)
				}
				c.Close()
			}
			if held.starts.Load() != 1 {
				t.Fatalf("rule initialized %d times", held.starts.Load())
			}
		})
	}
}

package main

import (
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"
)

// Exercise the actual owner entry used by runLiveCore, including an engine
// failure while an authorized peer has stalled in request framing.
func TestLiveWorkerRunFailureJoins(t *testing.T) {
	for _, cancelRun := range []bool{false, true} {
		t.Run(map[bool]string{false: "run_failure", true: "cancel"}[cancelRun], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "s")
			l, e := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
			if e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			accepted := make(chan struct{})
			release := make(chan struct{})
			done := make(chan error, 1)
			sentinel := errors.New("engine start failure")
			closing := make(chan struct{})
			allowReturn := make(chan struct{})
			go func() {
				done <- runLiveWorker(ctx, l, func(c *net.UnixConn) { close(accepted); io.ReadAll(c); close(closing); <-allowReturn }, func() error { <-release; return sentinel })
			}()
			c, e := net.Dial("unix", path)
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			<-accepted
			if cancelRun {
				cancel()
			}
			close(release)
			select {
			case <-closing:
			case <-time.After(time.Second):
				t.Fatal("active conn not closed")
			}
			select {
			case <-done:
				close(allowReturn)
				t.Fatal("returned before worker joined")
			case <-time.After(20 * time.Millisecond):
			}
			close(allowReturn)
			select {
			case e = <-done:
				if !errors.Is(e, sentinel) {
					t.Fatal(e)
				}
			case <-time.After(time.Second):
				t.Fatal("worker not joined before return")
			}
			c.SetReadDeadline(time.Now().Add(time.Second))
			_, e = c.Read(make([]byte, 1))
			if e == nil {
				t.Fatal("accepted connection left open")
			}
			if n, ok := e.(net.Error); ok && n.Timeout() {
				t.Fatal("timeout is not closure")
			}
			rebound, e := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
			if e != nil {
				t.Fatal(e)
			}
			rebound.Close()
		})
	}
}

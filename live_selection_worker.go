package main

import (
	"context"
	"net"
	"sync"
)

// runLiveWorker owns the listener, the accepted connection, and the worker.
// All three are closed/joined before returning even when Run fails early.
func runLiveWorker(ctx context.Context, listener *net.UnixListener, handle func(*net.UnixConn), run func() error) error {
	var mu sync.Mutex
	var active *net.UnixConn
	closing := false
	closeOwned := func() {
		mu.Lock()
		closing = true
		listener.Close()
		if active != nil {
			active.Close()
		}
		mu.Unlock()
	}
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		for {
			c, e := listener.AcceptUnix()
			if e != nil {
				return
			}
			mu.Lock()
			if closing {
				mu.Unlock()
				c.Close()
				return
			}
			active = c
			mu.Unlock()
			handle(c)
			c.Close()
			mu.Lock()
			active = nil
			mu.Unlock()
		}
	}()
	stop := context.AfterFunc(ctx, closeOwned)
	defer func() { stop(); closeOwned(); <-joined }()
	return run()
}

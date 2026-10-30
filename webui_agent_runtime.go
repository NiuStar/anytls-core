package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// Admission closes before drain. A timeout leaves the listener AND old process
// running, with mutation admission disabled; it never abandons an active child.
type webAgentDrain struct {
	mu       sync.Mutex
	active   int
	draining bool
	idle     chan struct{}
	handler  http.Handler
}

func (d *webAgentDrain) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	if d.draining {
		d.mu.Unlock()
		webError(rw, 409, "RESTART_PENDING")
		return
	}
	d.active++
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		d.active--
		if d.draining && d.active == 0 {
			close(d.idle)
		}
		d.mu.Unlock()
	}()
	d.handler.ServeHTTP(rw, r)
}
func (d *webAgentDrain) drain(ctx context.Context) bool {
	d.mu.Lock()
	if !d.draining {
		d.draining = true
		d.idle = make(chan struct{})
		if d.active == 0 {
			close(d.idle)
		}
	}
	idle := d.idle
	d.mu.Unlock()
	select {
	case <-idle:
		return true
	case <-ctx.Done():
		return false
	}
}
func webAgentServe(server *http.Server, listener net.Listener, w *webConsole, managed bool) error {
	d := &webAgentDrain{handler: w}
	server.Handler = d
	requests := make(chan struct{}, 1)
	if managed {
		w.restartRequest = func() {
			select {
			case requests <- struct{}{}:
			default:
			}
		}
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, os.Interrupt)
	defer signal.Stop(signals)
	finished := make(chan error, 1)
	go func() { finished <- server.Serve(listener) }()
	for {
		select {
		case err := <-finished:
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		case <-requests:
		case <-signals:
		}
		// Do not return while the handler still owns an installer or native action.
		// Bounded attempts continue without closing the listener on a drain timeout.
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			idle := d.drain(ctx)
			cancel()
			if idle {
				break
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := server.Shutdown(ctx)
		cancel()
		if err != nil { // Active handlers are already zero; retry until server quiesces.
			continue
		}
		err = <-finished
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

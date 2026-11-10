//go:build darwin && embedded_core

package main

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/NiuStar/anytls-core/internal/engine"
	"net"
	"os"
	"path/filepath"
	"time"
)

func runLiveCore(ctx context.Context, compiled compiledRuntime, config string, input *engine.RecordsInput) error {
	root := filepath.Dir(config)
	if livePrivateRoot(root) != nil || !liveSnapshotEnabled(config) {
		return engine.RunWithRecords(ctx, compiled.JSON, input)
	}
	plan := compiled.livePlan
	if plan == nil {
		return engine.RunWithRecords(ctx, compiled.JSON, input)
	}
	var e error
	live := engine.NewLiveSelection()
	if live == nil {
		return errors.New("selection entropy unavailable")
	}
	path := filepath.Join(root, liveSocketName)
	// Fresh service snapshot: refuse every pre-existing entry, never unlink it.
	if _, e = os.Lstat(path); !errors.Is(e, os.ErrNotExist) {
		return errors.New("selection socket already exists")
	}
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if e != nil {
		return e
	}
	defer listener.Close()
	if e = os.Chmod(path, 0600); e != nil {
		return e
	}
	return runLiveWorker(ctx, listener, func(c *net.UnixConn) {
		defer c.Close()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		uid, e := controlHelperPeerUID(c)
		if e != nil || uid != 0 {
			return
		}
		q, e := readLiveRequest(c)
		r := liveResponse{Code: "INVALID_REQUEST", PID: os.Getpid()}
		if e == nil {
			snapshot := live.Snapshot()
			r.Generation, r.Revision = snapshot.Generation, snapshot.Revision
			for name, tag := range plan.Nodes {
				if tag == snapshot.Selected {
					r.Node = name
				}
			}
			if q.Action == "read" {
				r.Code = "NOT_READY"
				if snapshot.Ready {
					r.Code = "READY"
				}
			} else if tag, ok := plan.Nodes[q.Node]; ok {
				if e = live.Switch(q.Generation, q.Revision, tag); e == nil {
					r.Code = "APPLIED"
					snapshot = live.Snapshot()
					r.Revision = snapshot.Revision
					r.Node = q.Node
				} else {
					r.Code = "STALE"
				}
			}
		}
		json.NewEncoder(c).Encode(r)
	}, func() error { return engine.RunControlled(ctx, compiled.JSON, input, live) })
}

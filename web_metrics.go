package main

import (
	"context"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"github.com/NiuStar/anytls-core/internal/telemetry"
)

// Owned by one WebUI lifetime. A console constructor or GET never starts probes.
// Binding is the WebUI instance, not the privileged VPN instance; the response
// explicitly never claims VPN bytes or connectivity through the selected node.
type webMetricsController struct {
	store    *telemetry.Store
	cancel   context.CancelFunc
	done     chan struct{}
	stopOnce sync.Once
	stopErr  error
}

func startWebMetrics(parent context.Context, configPath string) *webMetricsController {
	c := &webMetricsController{store: telemetry.New(filepath.Join(filepath.Dir(configPath), "webui-metrics.json")), done: make(chan struct{})}
	ctx, cancel := context.WithCancel(parent)
	c.cancel = cancel
	go func() { defer close(c.done); c.store.Run(ctx) }()
	return c
}
func (c *webMetricsController) Stop() error {
	if c == nil {
		return nil
	}
	c.stopOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if c.cancel != nil {
			c.cancel()
		}
		if c.done != nil {
			select {
			case <-c.done:
			case <-ctx.Done():
				c.stopErr = ctx.Err()
			}
		}
		if err := c.store.Close(ctx); err != nil {
			c.stopErr = err
		}
	})
	return c.stopErr
}

// Called only after the existing ServeHTTP session and Host checks. Empty c
// produces an honest NOT_OBSERVED snapshot, never an on-demand network request.
func (c *webMetricsController) get(w *webConsole, rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		webError(rw, 405, "METHOD_NOT_ALLOWED")
		return
	}
	app, site := r.Header.Values("X-AnyTLS-Origin"), r.Header.Values("Sec-Fetch-Site")
	siteOK := len(site) == 1 && site[0] == "same-origin" || len(site) == 0 && w.networkListen()
	if len(app) != 1 || app[0] != "http://"+r.Host || !siteOK || len(r.Header.Values("Origin")) > 0 && !w.originOK(r) {
		webError(rw, 403, "INVALID_ORIGIN")
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		webError(rw, 400, "INVALID_INPUT")
		return
	}
	var s *telemetry.Store
	if c != nil {
		s = c.store
	}
	now := time.Now()
	if w.now != nil {
		now = w.now()
	}
	rw.Header().Set("Cache-Control", "no-store")
	webJSON(rw, 200, s.Snapshot(now))
}

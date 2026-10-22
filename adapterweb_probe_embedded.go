//go:build embedded_core

package main

import (
	"context"
	"encoding/json"

	"github.com/NiuStar/anytls-core/internal/engine"
)

func webEmbeddedNodeProbe(ctx context.Context, n node) (float64, error) {
	cfg, err := buildNode(n, "proxy", 11080, true)
	if err != nil {
		return 0, err
	}
	delete(cfg, "inbounds")
	cfg["log"] = map[string]any{"disabled": true}
	// No interface monitor/routing manipulation is needed for a chosen outbound.
	delete(cfg, "route")
	b, err := json.Marshal(cfg)
	if err != nil {
		return 0, err
	}
	return engine.Probe(ctx, b)
}

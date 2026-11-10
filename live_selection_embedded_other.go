//go:build !darwin && embedded_core

package main

import (
	"context"
	"github.com/NiuStar/anytls-core/internal/engine"
)

func runLiveCore(ctx context.Context, c compiledRuntime, _ string, input *engine.RecordsInput) error {
	return engine.RunWithRecords(ctx, c.JSON, input)
}

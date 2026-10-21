//go:build embedded_core

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/NiuStar/anytls-core/internal/engine"
)

func externalCoreRequired() bool { return false }

func validateCoreFlag(fs *flag.FlagSet) error {
	var explicit bool
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "core" {
			explicit = true
		}
	})
	if explicit {
		return errors.New("-core is not supported by embedded_core; no external engine fallback")
	}
	return nil
}

// Signals belong to the executable, never the engine library. Preserve every
// Run error, including cancellation joined with a cleanup failure (exit 1).
func dispatchEngine(command string, b []byte, _, _ string) error {
	if err := engine.Check(context.Background(), b); err != nil {
		return err
	}
	if command == "check" {
		fmt.Println("embedded configuration valid")
		return nil
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return engine.Run(ctx, b)
}

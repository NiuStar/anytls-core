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

	cr "github.com/NiuStar/anytls-core/internal/connectionrecords"

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
func dispatchEngine(command string, b []byte, config, core string) error {
	return dispatchCompiledEngine(command, compiledRuntime{JSON: b}, config, core, false)
}

func dispatchCompiledEngine(command string, compiled compiledRuntime, config, _ string, recordService bool) error {
	b := compiled.JSON
	if err := engine.Check(context.Background(), b); err != nil {
		return err
	}
	if command == "check" {
		fmt.Println("embedded configuration valid")
		return nil
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var input *engine.RecordsInput
	if recordService && command == "run" {
		writer, err := openRunRecords(config, compiled)
		if err == nil && writer != nil {
			input = &engine.RecordsInput{Manifest: compiled.Manifest, Sink: writer, StopAdmission: writer.StopAdmission}
			defer func() {
				writer.StopAdmission()
				cleanup, cancel := context.WithTimeout(context.Background(), cr.TelemetryTimeout)
				defer cancel()
				writer.Shutdown(cleanup)
			}()
		} else {
			fmt.Fprintln(os.Stderr, "connection recording unavailable")
		}
	}
	return engine.RunWithRecords(ctx, b, input)
}

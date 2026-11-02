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
	fp "github.com/NiuStar/anytls-core/internal/familypolicy"
	st "github.com/NiuStar/anytls-core/internal/startuptimeline"

	de "github.com/NiuStar/anytls-core/internal/dnsevidence"
	"github.com/NiuStar/anytls-core/internal/engine"
	"net"
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
	if command == "check" {
		if err := engine.Check(context.Background(), b); err != nil {
			return err
		}
		fmt.Println("embedded configuration valid")
		return nil
	}
	parent := compiled.startupContext
	if parent == nil {
		parent = context.Background()
	}
	ctx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx = fp.WithSnapshot(ctx, compiled.familyPolicy)
	if _, enabled := ctx.Value(dnsObservationKey{}).(dnsObservation); enabled && compiled.Manifest != nil && command == "run" {
		m := compiled.Manifest
		collector := de.New(de.Binding{InstanceID: m.InstanceID, Generation: m.Generation, ManifestID: m.ManifestID, RuntimeSHA256: m.RuntimeSHA256})
		if collector != nil {
			ctx = engine.WithDNSEvidence(ctx, collector)
			defer launchDNSReporter(ctx, collector, config, func(work context.Context, q de.Push) error {
				if e := startupReporterSocket(); e != nil {
					return e
				}
				c, e := (&net.Dialer{}).DialContext(work, "unix", controlHelperSocketPath)
				if e != nil {
					return e
				}
				defer c.Close()
				var ack de.Ack
				return dnsExchange(work, c, q, &ack, controlHelperPeerUID)
			})()
		}
	}
	if command == "run" && dnsMetricsEnabled(ctx) {
		metrics := new(engine.DNSMetrics)
		ctx = engine.WithDNSMetrics(ctx, metrics)
		defer func() {
			if err := writeDNSMetricsFinal(os.Stderr, metrics.Snapshot()); err != nil {
				fmt.Fprintln(os.Stderr, "dns metrics summary unavailable")
			}
		}()
	}
	dispatchSpan := st.FromContext(ctx).Begin("START", "CORE_DISPATCH", st.Fields{})
	var input *engine.RecordsInput
	if recordService && command == "run" {
		var writer *cr.Writer
		input = &engine.RecordsInput{Manifest: compiled.Manifest, OpenSink: func() cr.Sink {
			var err error
			writer, err = openRunRecords(config, compiled)
			if err != nil || writer == nil {
				fmt.Fprintln(os.Stderr, "connection recording unavailable")
				return nil
			}
			return writer
		}, StopAdmission: func() {
			if writer != nil {
				writer.StopAdmission()
			}
		}}
		defer func() {
			if writer != nil {
				span := st.FromContext(ctx).Begin("FINALIZE", "CORE_RECORDS_SHUTDOWN", st.Fields{})
				writer.StopAdmission()
				cleanup, cancel := context.WithTimeout(context.Background(), cr.TelemetryTimeout)
				defer cancel()
				writer.Shutdown(cleanup)
				st.FromContext(ctx).End(span, "UNKNOWN", st.Fields{})
			}
		}()
	}
	st.FromContext(ctx).End(dispatchSpan, "OK", st.Fields{})
	return engine.RunWithRecords(ctx, b, input)
}

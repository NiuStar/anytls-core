package main

import (
	"context"
	"errors"
	"testing"
)

func TestStartDiagnosticsPrimaryAndRecovery(t *testing.T) {
	for _, mode := range []string{"cancel", "certificate", "typedproxy", "plaintextproxy"} {
		t.Run(mode, func(t *testing.T) {
			d, b, c, k, _, _ := lifecycleFixture(t)
			tool := d.tool
			secondary := errors.New("rollback private marker")
			primary := error(context.Canceled)
			want := "CANCELLED"
			switch mode {
			case "typedproxy":
				d.proxy = func() error { return &systemProxyActiveError{} }
				want = "SYSTEM_PROXY_ACTIVE"
			case "plaintextproxy":
				d.proxy = func() error { return errors.New((&systemProxyActiveError{}).Error()) }
				want = "PROXY_STATE_UNAVAILABLE"
			case "certificate":
				primary = diagnosticCurlExit(60)
				want = "HTTPS_CERTIFICATE_FAILED"
			}
			d.tool = func(ctx context.Context, name string, args ...string) (string, error) {
				if name == "/usr/bin/curl" {
					return "", primary
				}
				if name == "/bin/launchctl" && args[0] == "bootout" {
					return "", secondary
				}
				return tool(ctx, name, args...)
			}
			err := d.start(b, c, k, true)
			if err == nil {
				t.Fatal("expected failure")
			}
			var e *startDiagnosticError
			if !errors.As(err, &e) || e.diagnostic.Reason != want {
				t.Fatal("primary changed", err)
			}
			if mode == "cancel" || mode == "certificate" {
				if !errors.Is(err, primary) || !errors.Is(err, secondary) || e.diagnostic.Rollback != "FAILED" {
					t.Fatal("causes/recovery lost", err)
				}
			}
		})
	}
}

type diagnosticCurlExit int

func (e diagnosticCurlExit) Error() string { return "private curl marker" }
func (e diagnosticCurlExit) ExitCode() int { return int(e) }

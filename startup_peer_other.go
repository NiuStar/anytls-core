//go:build !darwin || !embedded_core

package main

import (
	"errors"
	"net"
)

func startupReporterSocket() error { return errors.New("DNS reporter unavailable") }

func startupAuthenticatePush(net.Conn, *startupBinding) bool { return false }
func startupLaunchReporter(r *startupReporter)               {}

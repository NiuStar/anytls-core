//go:build !darwin || !embedded_core

package main

import "net"

func startupAuthenticatePush(net.Conn, *startupBinding) bool { return false }
func startupLaunchReporter(r *startupReporter)               {}

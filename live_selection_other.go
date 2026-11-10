//go:build !darwin || !embedded_core

package main

import "net"

func liveAuthenticateCore(net.Conn, string) bool { return false }

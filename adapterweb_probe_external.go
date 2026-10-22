//go:build !embedded_core

package main

import "context"

// External builds never launch a child CLI or borrow a running SOCKS proxy.
func webEmbeddedNodeProbe(context.Context, node) (float64, error) {
	return 0, errNodeProbeUnsupported
}

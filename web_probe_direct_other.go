//go:build !darwin

package main

import "context"

// No unbound default-route substitute on unsupported platforms.
func webDirectNodeProbe(context.Context, node) (float64, error) {
	return 0, errNodeProbeDirectUnavailable
}

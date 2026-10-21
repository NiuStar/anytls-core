//go:build !darwin || !embedded_core

package main

import (
	"context"
	"errors"
	"net"
	"os"
)

func controlHelperEnginePreflight(context.Context, map[string]any) error {
	return errors.New("control helper requires macOS")
}
func controlHelperSupported() bool            { return false }
func controlHelperRootOwned(os.FileInfo) bool { return false }
func controlHelperPeerUID(net.Conn) (uint32, error) {
	return 0, errors.New("control helper peer authentication requires macOS")
}
func controlHelperValidateSocket() error      { return errors.New("control helper requires macOS") }
func controlHelperPrepareSocket(uint32) error { return errors.New("control helper requires macOS") }

package main

import (
	_ "embed"
	"strings"
)

// Version is captured at build time; publishing a release must update VERSION.
//
//go:embed VERSION
var Version string

func currentVersion() string { return strings.TrimSpace(Version) }

package main

import (
	_ "embed"
	"errors"
	"regexp"
	"strings"
	"time"
)

// Version is captured at build time; publishing a release must update VERSION.
//
//go:embed VERSION
var Version string

func currentVersion() string { return strings.TrimSpace(Version) }

var buildCandidate = regexp.MustCompile(`^v([0-9]{4}-[0-9]{2}-[0-9]{2})-unified-r[1-9][0-9]*-candidate$`)

// Build identity is broader than the stable asset channel, never a download tag.
func validateBuildVersion(version string) error {
	if validateUpdateVersion(version) == nil {
		return nil
	}
	if match := buildCandidate.FindStringSubmatch(version); match != nil && match[1][:4] != "0000" {
		if _, err := time.Parse("2006-01-02", match[1]); err == nil {
			return nil
		}
	}
	return errors.New("version must be a stable release or vYYYY-MM-DD-unified-rN-candidate build")
}

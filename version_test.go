package main

import (
	"os"
	"strings"
	"testing"
)

func TestCurrentVersionMatchesSource(t *testing.T) {
	data, err := os.ReadFile("VERSION")
	if err != nil {
		t.Fatal(err)
	}
	if currentVersion() != strings.TrimSpace(string(data)) {
		t.Fatal("version must match embedded VERSION")
	}
	if err := validateUpdateVersion(currentVersion()); err != nil {
		t.Fatal(err)
	}
}

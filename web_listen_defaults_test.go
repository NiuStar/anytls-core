package main

import (
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestWebUIHelpDefaultListen(t *testing.T) {
	output, err := os.Create(filepath.Join(t.TempDir(), "help.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	// Exercise the real CLI flag registration without opening a listener.
	err = func() error {
		previous := os.Stderr
		os.Stderr = output
		defer func() { os.Stderr = previous }()
		return webuiCommand([]string{"--help"})
	}()
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("help error = %v, want flag.ErrHelp", err)
	}
	if _, err := output.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	help, err := io.ReadAll(output)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(help), "-listen string") || !strings.Contains(string(help), `(default "0.0.0.0")`) {
		t.Fatalf("help must advertise the wildcard listen default:\n%s", help)
	}
	if !strings.Contains(string(help), "HTTP has no TLS") {
		t.Fatalf("help lost the HTTP transport warning:\n%s", help)
	}
}

func TestWebUIUsageDefaultListen(t *testing.T) {
	err := webuiCommand([]string{"unexpected"})
	if err == nil || !strings.Contains(err.Error(), "[--listen 0.0.0.0]") {
		t.Fatalf("usage error = %v, want wildcard listen default", err)
	}
}

func TestWebAgentListenDefaultsAndOverrides(t *testing.T) {
	for _, action := range []string{"install-agent", "agent-status"} {
		t.Run(action, func(t *testing.T) {
			for _, tc := range []struct {
				name string
				args []string
				host string
			}{
				{"default", nil, "0.0.0.0"},
				{"explicit-wildcard", []string{"--listen", "0.0.0.0"}, "0.0.0.0"},
				{"explicit-loopback", []string{"--listen", "127.0.0.1"}, "127.0.0.1"},
				{"explicit-ipv4", []string{"--listen", "192.168.5.2"}, "192.168.5.2"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					flags := newWebAgentFlags(action)
					if err := flags.fs.Parse(tc.args); err != nil {
						t.Fatal(err)
					}
					if *flags.host != tc.host || *flags.port != 18089 {
						t.Fatalf("parsed listen/port = %s:%d, want %s:18089", *flags.host, *flags.port, tc.host)
					}
					s := webAgentSpec{Binary: "/Users/example/app/anytls", Config: "/Users/example/app/config.yaml", Home: "/Users/example", Host: *flags.host, Port: *flags.port, UID: 501}
					want := []string{s.Binary, "webui", "--listen", tc.host, "--port", "18089", "--managed-agent", s.label()}
					if got := s.argv(); !reflect.DeepEqual(got, want) {
						t.Fatalf("managed argv = %q, want %q", got, want)
					}
				})
			}
		})
	}
}

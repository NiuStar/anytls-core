package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	cr "github.com/NiuStar/anytls-core/internal/connectionrecords"
)

// runtimeOptions is the shared CLI compiler input. Menus return a nil config.
type runtimeOptions struct {
	Command, Config, NodeName, Mode string
	Server, SNI, CA, PasswordFile   string
	LocalPort                       int
	AllowInsecure                   bool
	RecordService                   bool
}

// prepareRuntime preserves YAML selection/routing and the legacy secure flags.
// It does not locate an engine, write runtime JSON, or start a process.
func prepareRuntimeMap(o *runtimeOptions, manifest *cr.Manifest) (map[string]any, error) {
	if o.Config == "" && o.Server == "" {
		exe, err := os.Executable()
		if err != nil {
			return nil, err
		}
		exe, err = filepath.EvalSymlinks(exe)
		if err != nil {
			return nil, err
		}
		candidate := filepath.Join(filepath.Dir(exe), "config.yaml")
		if _, err := os.Stat(candidate); err == nil {
			o.Config = candidate
		}
	}
	var cfg map[string]any
	if o.Config != "" {
		// Keep menu reads/behavior unchanged; Run/Check capture each source once.
		var configBytes, selectionBytes []byte
		selectionPresent := false
		var nodes []node
		var err error
		if o.Command == "list" || o.Command == "select" {
			nodes, err = loadNodes(o.Config)
		} else {
			var st os.FileInfo
			st, err = os.Stat(o.Config)
			if err == nil && !st.Mode().IsRegular() {
				err = errors.New("config.yaml must be a regular file")
			}
			if err == nil {
				configBytes, err = readSnapshotSource(o.Config, snapshotConfigLimit, true)
			}
			if err == nil {
				nodes, err = loadNodesBytes(configBytes)
			}
		}
		if err != nil {
			return nil, err
		}
		current := ""
		if o.Command == "list" || o.Command == "select" {
			current, err = selectedNode(o.Config, nodes)
		} else {
			selectionBytes, err = readSnapshotSource(selectedPath(o.Config), snapshotSelectedLimit, true)
			if errors.Is(err, os.ErrNotExist) {
				err = nil
			} else if err == nil {
				selectionPresent = true
				current, err = selectedBytes(selectionBytes, nodes)
			}
			addCapturedSource(manifest, cr.SourceConfig, configBytes, true)
			addCapturedSource(manifest, cr.SourceSelection, selectionBytes, selectionPresent)
		}
		if err != nil {
			return nil, err
		}
		if o.Command == "list" {
			printNodes(os.Stdout, nodes, current)
			groups, err := groupChoices(o.Config)
			if err != nil {
				return nil, err
			}
			for _, g := range groups {
				fmt.Printf("策略组 %s → %s\n", g.Name, g.Selected)
			}
			return nil, nil
		}
		if o.Command == "select" {
			groups, err := groupChoices(o.Config)
			if err != nil {
				return nil, err
			}
			if len(groups) > 0 {
				return nil, selectGroupMenu(o.Config, nodes, groups, os.Stdin, os.Stdout)
			}
			return nil, selectMenu(o.Config, nodes, current, os.Stdin, os.Stdout)
		}
		if o.NodeName == "" {
			o.NodeName = current
		}
		if o.NodeName == "" {
			return nil, errors.New("no node selected; use select or -node")
		}
		n, err := choose(nodes, o.NodeName)
		if err != nil {
			return nil, err
		}
		cfg, err = buildNode(n, o.Mode, o.LocalPort, o.AllowInsecure)
		if err != nil {
			return nil, err
		}
		if err := applyRoutingRecords(o.Config, configBytes, nodes, n, cfg, o.AllowInsecure, manifest); err != nil {
			return nil, err
		}
		if n.EgressIP != "" {
			fmt.Fprintln(os.Stderr, "note: egress-ip is server-side policy, not an AnyTLS client setting; verify observed exit IP")
		}
	} else {
		if o.Command == "list" || o.Command == "select" {
			return nil, errors.New("-config is required for list/select")
		}
		if o.PasswordFile == "" {
			return nil, errors.New("password-file is required")
		}
		st, err := os.Stat(o.PasswordFile)
		if err != nil {
			return nil, err
		}
		if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
			return nil, errors.New("password-file must be regular and private (chmod 600)")
		}
		pass, err := os.ReadFile(o.PasswordFile)
		if err != nil {
			return nil, err
		}
		password := strings.TrimSuffix(strings.TrimSuffix(string(pass), "\n"), "\r")
		if strings.ContainsAny(password, "\r\n") {
			return nil, errors.New("password-file must contain one line")
		}
		cfg, err = build(options{o.Server, o.SNI, password, o.CA})
		if err != nil {
			return nil, err
		}
	}
	return cfg, nil
}

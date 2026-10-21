package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// stageCAs runs AFTER stageRuleSets, using the copied selection and rewritten
// rules. Only outbounds actually built by the existing compiler need CA bytes.
// Relative CA paths deliberately retain buildNode's caller-CWD resolution.
func stageCAs(root string) error {
	config := filepath.Join(root, "config.yaml")
	nodes, err := loadNodes(config)
	if err != nil {
		return err
	}
	hasCA := false
	for _, n := range nodes {
		hasCA = hasCA || (n.Type == "anytls" && n.CA != "")
	}
	if !hasCA {
		return nil
	}
	selected, err := selectedServiceNode(config)
	if err != nil {
		return err
	}
	cfg, err := buildNode(selected, "tun", 0, true)
	if err != nil {
		return err
	}
	if err := applyRouting(config, nodes, selected, cfg, true); err != nil {
		return err
	}
	paths := map[string]bool{}
	for _, entry := range cfg["outbounds"].([]any) {
		out := entry.(map[string]any)
		if out["type"] == "anytls" {
			if path, ok := out["tls"].(map[string]any)["certificate_path"].(string); ok {
				paths[path] = true
			}
		}
	}
	if len(paths) == 0 {
		return nil
	}
	var routing struct {
		Rules  []string     `yaml:"rules"`
		Groups []proxyGroup `yaml:"proxy-groups"`
	}
	if err := readYAML(config, &routing); err != nil {
		return err
	}
	required := map[string]bool{selected.Name: true}
	// applyRouting above has already validated grammar and targets. Resolve the
	// same rule targets to node names; don't validate/build unused group members.
	for _, raw := range routing.Rules {
		parts := strings.Split(raw, ",")
		target := parts[1]
		if strings.TrimSpace(parts[0]) != "MATCH" {
			target = parts[2]
		}
		name, err := resolveGroup(strings.TrimSpace(target), nodes, routing.Groups)
		if err != nil {
			return err
		}
		required[name] = true
	}
	replacements := map[string]string{}
	copied := map[string]string{}
	digests := map[string]bool{}
	total := 0
	references := 0
	for _, n := range nodes {
		if required[n.Name] && n.Type == "anytls" && n.CA != "" {
			references++
		}
	}
	if references > snapshotReferenceLimit {
		return errors.New("snapshot has too many CA references")
	}
	for _, n := range nodes {
		if !required[n.Name] || n.Type != "anytls" || n.CA == "" {
			continue
		}
		path, err := filepath.Abs(n.CA)
		if err != nil {
			return err
		}
		if !paths[path] {
			return errors.New("snapshot CA not in compiled outbounds")
		}
		dest, ok := copied[path]
		if !ok {
			b, err := readSnapshotCA(path)
			if err != nil {
				return err
			}
			dir, err := filepath.Abs(filepath.Join(root, "certs"))
			if err != nil {
				return err
			}
			if len(copied) == 0 {
				if err := os.Mkdir(dir, 0700); err != nil {
					return err
				}
			}
			dest = filepath.Join(dir, shaHex(b)+".pem")
			// Equal source bytes deliberately share the same private destination.
			total += len(b)
			if total > snapshotCATotalLimit {
				return errors.New("snapshot aggregate CA bytes exceeded")
			}
			if !digests[dest] {
				if err := writeSnapshotLeaf(dest, b, 0600); err != nil {
					return err
				}
				digests[dest] = true
			}
			copied[path] = dest
		}
		replacements[n.Name] = dest
	}
	var doc yaml.Node
	if err := readYAML(config, &doc); err != nil {
		return err
	}
	if err := snapshotYAMLPlain(&doc); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, key := range []string{"proxies", "nodes"} {
		entries := snapshotYAMLField(doc.Content[0], key)
		if entries == nil {
			continue
		}
		if entries.Kind != yaml.SequenceNode {
			return errors.New("snapshot nodes must be a sequence")
		}
		for _, entry := range entries.Content {
			var n node
			if err := entry.Decode(&n); err != nil {
				return err
			}
			if dest, ok := replacements[n.Name]; ok {
				if err := snapshotYAMLSetPath(entry, "ca", dest); err != nil {
					return err
				}
				seen[n.Name] = true
			}
		}
	}
	if len(seen) != len(replacements) {
		return errors.New("snapshot CA replacement missing")
	}
	b, err := yaml.Marshal(&doc)
	if err != nil {
		return err
	}
	return replaceSnapshotConfig(root, b)
}

// Follow source symlinks, like buildNode's os.Stat; validate/read the SAME open
// regular file. This is not a nofollow/immutable-parent or startup-integrity gate.
func readSnapshotCA(path string) ([]byte, error) {
	b, err := readSnapshotSource(path, snapshotCALimit, true)
	if err != nil {
		return nil, err
	}
	return validateSnapshotCABytes(b)
}

func validateSnapshotCABytes(b []byte) ([]byte, error) {
	count := 0
	for rest := bytes.TrimSpace(b); len(rest) > 0; rest = bytes.TrimSpace(rest) {
		// pem.Decode searches past malformed input. Bound it to exactly one
		// complete block so it cannot silently skip a prefix or damaged block.
		const begin = "-----BEGIN CERTIFICATE-----"
		const end = "-----END CERTIFICATE-----"
		if !bytes.HasPrefix(rest, []byte(begin)) {
			return nil, errors.New("snapshot CA contains non-certificate or malformed PEM")
		}
		endAt := bytes.Index(rest, []byte(end))
		if endAt < 0 {
			return nil, errors.New("snapshot CA contains incomplete PEM")
		}
		endAt += len(end)
		if newline := bytes.IndexByte(rest[endAt:], '\n'); newline >= 0 {
			endAt += newline + 1
		} else {
			endAt = len(rest)
		}
		chunk := rest[:endAt]
		if bytes.Count(chunk, []byte("-----BEGIN ")) != 1 {
			return nil, errors.New("snapshot CA contains malformed PEM")
		}
		block, next := pem.Decode(chunk)
		if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(next)) != 0 {
			return nil, errors.New("snapshot CA requires complete certificate PEM")
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return nil, errors.New("snapshot CA contains invalid certificate DER")
		}
		count++
		rest = rest[endAt:]
	}
	if count == 0 {
		return nil, errors.New("snapshot CA requires valid PEM certificate")
	}
	return b, nil
}

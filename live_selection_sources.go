package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"

	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"
)

type liveFilePin struct {
	Path     string `json:"path"`
	SHA      string `json:"sha256"`
	Identity string `json:"identity"`
}

func (p *liveFilePin) UnmarshalJSON(raw []byte) error {
	return controlHelperDecode(bytes.NewReader(raw), map[string]any{"path": &p.Path, "sha256": &p.SHA, "identity": &p.Identity})
}
func liveFileIdentity(i os.FileInfo) string {
	v := reflect.ValueOf(i.Sys()).Elem()
	s := fmt.Sprint(i.Mode(), ":", i.Size(), ":", i.ModTime().UnixNano())
	for _, k := range []string{"Dev", "Ino", "Uid", "Gid", "Nlink", "Ctim", "Ctimespec"} {
		f := v.FieldByName(k)
		if f.IsValid() {
			s += fmt.Sprint(":", k, "=", f.Interface())
		}
	}
	return s
}

// Digest and identity come from the exact bounded handle, not separate reads.
func captureLiveFile(path string, limit int64) (p liveFilePin, raw []byte, err error) {
	path, err = filepath.Abs(path)
	if err != nil {
		return
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return p, nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer func() { err = errors.Join(err, f.Close()) }()
	before, err := f.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() > limit {
		return p, nil, errors.New("invalid selection source file")
	}
	raw, err = readSnapshotVersion(f, before, limit)
	if err != nil {
		return
	}
	current, err := os.Stat(path)
	if err != nil || !os.SameFile(before, current) || liveFileIdentity(before) != liveFileIdentity(current) {
		return p, nil, errors.New("selection source replaced")
	}
	p = liveFilePin{path, shaHex(raw), liveFileIdentity(before)}
	return
}
func (p liveFilePin) check(limit int64) bool {
	next, _, e := captureLiveFile(p.Path, limit)
	return e == nil && next == p
}
func liveSourceFiles(config string, raw []byte) (map[string]liveFilePin, map[string]liveFilePin, error) {
	var d struct {
		Sets map[string]fileRuleSet `yaml:"rule-sets"`
	}
	if e := yaml.Unmarshal(raw, &d); e != nil {
		return nil, nil, e
	}
	rules, cas := map[string]liveFilePin{}, map[string]liveFilePin{}
	if len(d.Sets) > snapshotReferenceLimit {
		return nil, nil, errors.New("too many rule sources")
	}
	for name, spec := range d.Sets {
		path := spec.Path
		if !filepath.IsAbs(path) {
			path = filepath.Join(filepath.Dir(config), path)
		}
		pin, b, e := captureLiveFile(path, snapshotRuleLimit)
		if e != nil {
			return nil, nil, e
		}
		if _, e = validateRuleSetBytes(name, spec, b); e != nil {
			return nil, nil, e
		}
		rules[name] = pin
	}
	nodes, e := loadNodesBytes(raw)
	if e != nil {
		return nil, nil, e
	}
	for _, n := range nodes {
		if n.CA != "" {
			pin, b, e := captureLiveFile(n.CA, snapshotCALimit)
			if e != nil {
				return nil, nil, e
			}
			if _, e = validateSnapshotCABytes(b); e != nil {
				return nil, nil, e
			}
			cas[n.CA] = pin
		}
	}
	return rules, cas, nil
}
func (s liveSource) stagedCheck(root string) bool {
	config := filepath.Join(root, "config.yaml")
	pin, ok := s.Staged[config]
	if !ok || pin.Path != config || !pin.check(snapshotConfigLimit) {
		return false
	}
	raw, e := readSnapshotSource(config, snapshotConfigLimit, false)
	if e != nil {
		return false
	}
	var d struct {
		Sets map[string]fileRuleSet `yaml:"rule-sets"`
	}
	if yaml.Unmarshal(raw, &d) != nil || len(d.Sets) != len(s.Rules) {
		return false
	}
	expected := map[string]bool{config: true}
	for name, spec := range d.Sets {
		original, ok := s.Rules[name]
		path := filepath.Join(root, "rules", name+".json")
		p, exists := s.Staged[path]
		if !ok || !exists || p.Path != path || p.SHA != original.SHA || spec.Path != "rules/"+name+".json" || spec.SHA256 != original.SHA {
			return false
		}
		expected[path] = true
	}
	nodes, e := loadNodesBytes(raw)
	if e != nil {
		return false
	}
	for _, n := range nodes {
		if n.CA != "" {
			path, e := filepath.Abs(n.CA)
			if e != nil {
				return false
			}
			p, ok := s.Staged[path]
			if !ok || p.Path != path {
				return false
			}
			expected[path] = true
		}
	}
	if len(expected) != len(s.Staged) {
		return false
	}
	for path := range expected {
		if !s.Staged[path].check(snapshotRuleLimit) {
			return false
		}
	}
	return true
}

func (s liveSource) filesCheck() bool {
	if s.Rules == nil || s.CAPins == nil || s.CAs == nil || s.Staged == nil || !filepath.IsAbs(s.Origin) {
		return false
	}
	for _, p := range s.Staged {
		if !p.check(snapshotRuleLimit) {
			return false
		}
	}
	rules, cas, e := liveSourceFiles(s.Origin, s.Config)
	if e != nil || !reflect.DeepEqual(rules, s.Rules) || !reflect.DeepEqual(cas, s.CAPins) || len(cas) != len(s.CAs) {
		return false
	}
	for path, p := range cas {
		if s.CAs[path] != p.SHA {
			return false
		}
	}
	for _, p := range s.Rules {
		if !p.check(snapshotRuleLimit) {
			return false
		}
	}
	for _, p := range s.CAPins {
		if !p.check(snapshotCALimit) {
			return false
		}
	}
	return true
}

// Exact top-level schema, duplicates and aliases rejected; config is larger than IPC.
func decodeLiveSource(raw []byte) (s liveSource, err error) {
	if e := liveSourceUniqueJSON(json.NewDecoder(bytes.NewReader(raw)), 0); e != nil {
		return s, e
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	tok, e := d.Token()
	if e != nil || tok != json.Delim('{') {
		return s, errors.New("invalid source")
	}
	fields := map[string]any{"config": &s.Config, "selected": &s.Selected, "cas": &s.CAs, "rules": &s.Rules, "ca_pins": &s.CAPins, "origin": &s.Origin, "staged": &s.Staged}
	seen := map[string]bool{}
	for d.More() {
		tok, e = d.Token()
		key, ok := tok.(string)
		dst, known := fields[key]
		if e != nil || !ok || !known || seen[key] {
			return s, errors.New("invalid source field")
		}
		seen[key] = true
		if e = d.Decode(dst); e != nil {
			return s, e
		}
	}
	if _, e = d.Token(); e != nil {
		return s, e
	}
	if _, e = d.Token(); e != io.EOF {
		return s, errors.New("source trailing input")
	}
	if len(seen) != len(fields) || !s.filesCheck() {
		return s, errors.New("missing or changed source pins")
	}
	return s, nil
}

func liveSourceUniqueJSON(d *json.Decoder, depth int) error {
	if depth > 8 {
		return errors.New("source JSON too deep")
	}
	tok, e := d.Token()
	if e != nil {
		return e
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	if delim == '{' {
		seen := map[string]bool{}
		for d.More() {
			key, e := d.Token()
			s, ok := key.(string)
			if e != nil || !ok || seen[s] {
				return errors.New("duplicate source key")
			}
			seen[s] = true
			if e = liveSourceUniqueJSON(d, depth+1); e != nil {
				return e
			}
		}
	} else if delim == '[' {
		for d.More() {
			if e = liveSourceUniqueJSON(d, depth+1); e != nil {
				return e
			}
		}
	} else {
		return errors.New("invalid source JSON")
	}
	_, e = d.Token()
	return e
}

// Called after the real rule/CA staging rewrites. Verify the staged audited
// bytes against original pins; never trust a newly self-reported digest.
func finalizeLiveSource(root string) error {
	path := filepath.Join(root, liveSourceName)
	if _, e := os.Lstat(path); os.IsNotExist(e) {
		return nil
	}
	raw, e := readSnapshotSource(path, 48<<20, false)
	if e != nil {
		return e
	}
	s, e := decodeLiveSource(raw)
	if e != nil {
		return e
	}
	staged, e := readSnapshotSource(filepath.Join(root, "config.yaml"), snapshotConfigLimit, false)
	if e != nil {
		return e
	}
	var doc struct {
		Sets map[string]fileRuleSet `yaml:"rule-sets"`
	}
	if e = yaml.Unmarshal(staged, &doc); e != nil {
		return e
	}
	if len(doc.Sets) != len(s.Rules) {
		return errors.New("staged rule source set changed")
	}
	for name, spec := range doc.Sets {
		p, ok := s.Rules[name]
		if !ok {
			return errors.New("unstaged rule source")
		}
		_, b, e := loadRuleSetCaptured(filepath.Join(root, "config.yaml"), name, spec)
		if e != nil || shaHex(b) != p.SHA {
			return errors.New("staged rule bytes differ from captured source")
		}
	}
	nodes, e := loadNodesBytes(staged)
	if e != nil {
		return e
	}
	original, e := loadNodesBytes(s.Config)
	if e != nil {
		return e
	}
	expected := map[string]string{}
	for _, n := range original {
		if p, ok := s.CAPins[n.CA]; ok {
			expected[n.Name] = p.SHA
		}
	}
	for _, n := range nodes {
		if digest, ok := expected[n.Name]; ok {
			b, e := readSnapshotCA(n.CA)
			if e != nil || shaHex(b) != digest {
				return errors.New("staged CA differs from captured source")
			}
		}
	}
	s.Staged = map[string]liveFilePin{}
	paths := []string{filepath.Join(root, "config.yaml")}
	for name := range doc.Sets {
		paths = append(paths, filepath.Join(root, "rules", name+".json"))
	}
	for _, n := range nodes {
		if n.CA != "" {
			paths = append(paths, n.CA)
		}
	}
	for _, p := range paths {
		pin, _, e := captureLiveFile(p, snapshotRuleLimit)
		if e != nil {
			return e
		}
		s.Staged[pin.Path] = pin
	}
	next, e := json.Marshal(s)
	if e != nil {
		return e
	}
	temp := filepath.Join(root, liveSourceName+".next")
	if e = writeSnapshotLeaf(temp, next, 0600); e != nil {
		return e
	}
	return os.Rename(temp, path)
}

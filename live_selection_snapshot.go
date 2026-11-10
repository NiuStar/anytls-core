package main

import (
	"fmt"
	cr "github.com/NiuStar/anytls-core/internal/connectionrecords"
	"os"
	"path/filepath"
)

// Private root marker is written only by staging, before baseline compilation.
// Ordinary CLI/check and user configuration never opt in through a YAML flag.
func liveSnapshotEnabled(path string) bool {
	if externalCoreRequired() || os.Geteuid() != 0 {
		return false
	}
	marker := filepath.Join(filepath.Dir(path), liveSourceName)
	info, e := os.Lstat(marker)
	return e == nil && info.Mode().IsRegular() && info.Mode().Perm() == 0600 && controlHelperRootOwned(info) && livePrivateRoot(filepath.Dir(path)) == nil
}
func addWarmCandidates(raw []byte, nodes []node, selected node, cfg map[string]any, allow bool, m *cr.Manifest) {
	if !liveSourceEligible(raw) {
		return
	}
	group, _, e := defaultSelectionGroup(raw)
	if e != nil {
		return
	}
	members := make([]string, 0, len(nodes))
	for _, n := range nodes {
		members = append(members, n.Name)
	}
	if group != nil && group.Type == "select" {
		members = group.Proxies
	}
	if len(members) > 256 {
		return
	}
	in := cfg["inbounds"].([]any)[0].(map[string]any)
	if in["type"] != "tun" {
		return
	}
	outs := cfg["outbounds"].([]any)
	excluded := in["route_exclude_address"].([]string)
	for i, name := range members {
		n, e := choose(nodes, name)
		if e != nil || !selectable(n) || n.SkipVerify {
			continue
		}
		built, e := buildNode(n, "tun", 0, allow)
		if e != nil {
			continue
		}
		out := built["outbounds"].([]any)[0].(map[string]any)
		tag := fmt.Sprintf("warm-%d", i)
		out["tag"] = tag
		outs = append(outs, out)
		excluded = append(excluded, built["inbounds"].([]any)[0].(map[string]any)["route_exclude_address"].([]string)...)
		if m != nil {
			m.Outbounds = append(m.Outbounds, nodeOrigin(m, nodes, name, tag))
		}
	}
	cfg["outbounds"] = outs
	in["route_exclude_address"] = excluded
}

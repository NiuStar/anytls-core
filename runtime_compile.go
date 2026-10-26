package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"strconv"

	cr "github.com/NiuStar/anytls-core/internal/connectionrecords"
)

type compiledRuntime struct {
	JSON     []byte
	Manifest *cr.Manifest
}

// The map compiler and encoder are shared with legacy callers. Provenance is a
// parallel result and never adds fields to the SDK JSON.
func prepareRuntime(o *runtimeOptions) (map[string]any, error) {
	return prepareRuntimeMap(o, nil)
}

func prepareRuntimeWithRecords(o *runtimeOptions) (compiledRuntime, error) {
	m := &cr.Manifest{SchemaVersion: cr.SchemaVersion, Rules: []cr.RuleOrigin{}, Outbounds: []cr.OutboundOrigin{}}
	var ids [32]byte
	if _, err := rand.Read(ids[:]); err != nil {
		m = nil
	} else {
		m.InstanceID = hex.EncodeToString(ids[:16])
		m.Generation = hex.EncodeToString(ids[16:])
		m.SelectionGeneration = m.Generation
	}
	cfg, err := prepareRuntimeMap(o, m)
	if err != nil || cfg == nil {
		return compiledRuntime{}, err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return compiledRuntime{}, err
	}
	if m != nil {
		m.RuntimeSHA256 = shaHex(b)
		// Legacy flags have no config source/selection identity; no eligible store.
		if len(m.CapturedSources) < 2 {
			m = nil
		} else {
			// CA bytes are pinned again into decoded SDK options before New, compared
			// to these captures. Runtime JSON remains exactly certificate_path based.
			caOrdinal := 0
			for _, raw := range cfg["outbounds"].([]any) {
				out := raw.(map[string]any)
				tls, _ := out["tls"].(map[string]any)
				path, _ := tls["certificate_path"].(string)
				if path == "" {
					continue
				}
				ca, captureErr := readSnapshotSource(path, snapshotCALimit, true)
				if captureErr != nil {
					m = nil
					break
				}
				addCapturedSource(m, cr.SourceCA, caOrdinal, ca, true)
				caOrdinal++
			}
			if m != nil {
				digest, digestErr := cr.ManifestDigest(*m, cr.ManifestBudget(m))
				if digestErr != nil {
					m = nil
				} else {
					m.ManifestID = digest
				}
			}
		}
	}
	return compiledRuntime{JSON: b, Manifest: m}, nil
}

func addCapturedSource(m *cr.Manifest, kind cr.SourceKind, ordinal int, b []byte, present bool) {
	if m == nil {
		return
	}
	s := cr.CapturedSource{Kind: kind, Ordinal: ordinal, Present: present}
	if present {
		sum := shaHex(b)
		s.SHA256 = &sum
	}
	m.CapturedSources = append(m.CapturedSources, s)
}

func nodeOrigin(m *cr.Manifest, nodes []node, terminal, tag string) cr.OutboundOrigin {
	o := cr.OutboundOrigin{Tag: tag, Type: "direct", TerminalKind: cr.TerminalDirect}
	if terminal == "DIRECT" && tag == "direct" {
		return o
	}
	o.Type, o.TerminalKind = "anytls", cr.TerminalNode
	for i, n := range nodes {
		if n.Name == terminal {
			id := m.Generation + ":node:" + strconv.Itoa(i)
			label := n.Name
			o.NodeID, o.NodeLabel = &id, &label
			break
		}
	}
	return o
}

func routeOrigin(m *cr.Manifest, nodes []node, index int, kind, value, target, terminal, tag string, edges []cr.GroupEdge) cr.RouteProjection {
	if terminal == "REJECT" && tag == "" {
		return unknownCompileRoute("", "")
	}
	o := nodeOrigin(m, nodes, terminal, tag)
	r := cr.RouteProjection{Evidence: cr.ProvenanceVerified, Kind: cr.RuleKind(kind), ConfiguredTarget: &target, GroupPath: edges, TerminalKind: o.TerminalKind, FinalNodeID: o.NodeID, FinalNodeLabel: o.NodeLabel, OutboundTag: tag, OutboundType: o.Type, SelectionGeneration: &m.SelectionGeneration}
	if index >= 0 {
		id := m.Generation + ":rule:" + strconv.Itoa(index)
		r.SourceID, r.SourceIndex = &id, &index
	}
	if kind != string(cr.RuleMatch) && kind != string(cr.RuleDefault) {
		r.Condition = &cr.Condition{Kind: cr.RuleKind(kind), Value: value}
		// Routing accepts values the strict records codec cannot represent.
		// Lose only this rule's attribution, never the whole run's records.
		if cr.Validate(*r.Condition) != nil {
			return unknownCompileRoute(tag, o.Type)
		}
	}
	return r
}

func unknownCompileRoute(tag, typ string) cr.RouteProjection {
	return cr.RouteProjection{Evidence: cr.ProvenanceUnknown, Kind: cr.RuleUnknown, TerminalKind: cr.TerminalUnknown, OutboundTag: tag, OutboundType: typ}
}

func syntheticOrigin(action string, kind cr.SyntheticKind) cr.RuleOrigin {
	return cr.RuleOrigin{Type: "default", ActionType: action, Synthetic: kind, Route: unknownCompileRoute("", "")}
}

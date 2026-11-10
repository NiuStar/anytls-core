package main

import cr "github.com/NiuStar/anytls-core/internal/connectionrecords"

// Transform before the sole runtime encoding; every consumer gets these same
// final bytes. Warm leaves preserve the already-established TUN bypass scope.
func finalizeLiveSelection(raw []byte, nodes []node, selected node, cfg map[string]any, allow bool, m *cr.Manifest) {
	if !liveSourceEligible(raw) {
		return
	}
	addWarmCandidates(raw, nodes, selected, cfg, allow, m)
	plan, err := compileLiveSelection(raw, nodes, selected, cfg, allow)
	if err != nil {
		return
	}
	if m == nil {
		return
	}
	// Warm candidates and immutable live leaves are both constructed SDK objects.
	for _, item := range cfg["outbounds"].([]any) {
		out := item.(map[string]any)
		tag := out["tag"].(string)
		found := false
		for _, origin := range m.Outbounds {
			if origin.Tag == tag {
				found = true
			}
		}
		if found {
			continue
		}
		if tag == "live" {
			m.Outbounds = append(m.Outbounds, cr.OutboundOrigin{Tag: tag, Type: "anytls-selection", TerminalKind: cr.TerminalUnknown})
			continue
		}
		for name, leaf := range plan.Nodes {
			if leaf == tag {
				m.Outbounds = append(m.Outbounds, nodeOrigin(m, nodes, name, tag))
				break
			}
		}
	}
	route := cfg["route"].(map[string]any)
	rules, _ := route["rules"].([]any)
	for i, item := range rules {
		r := item.(map[string]any)
		if r["outbound"] == "live" && i < len(m.Rules) {
			m.Rules[i].ExpectedOutbound = "live"
			m.Rules[i].Route.OutboundTag = "live"
			m.Rules[i].Route.OutboundType = "anytls-selection"
		}
	}
	if route["final"] == "live" {
		m.FinalOrigin.OutboundTag = "live"
		m.FinalOrigin.OutboundType = "anytls-selection"
	}
}

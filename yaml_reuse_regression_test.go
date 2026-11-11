package main

import (
	"errors"
	"reflect"
	"testing"
)

func TestLiveSourceEligibleStageParity(t *testing.T) {
	valid := `proxies:
  - {name: A, type: anytls, server: 192.0.2.1, port: 443, password: p}
`
	for _, tc := range []struct {
		name, raw string
		want      bool
	}{
		{"empty", "", true},
		{"null", "null\n", true},
		{"valid hot", valid, true},
		{"duplicate key", "proxies: []\nproxies: []\n", false},
		{"alias", "proxies: &nodes [{name: A, type: anytls}]\nnodes: *nodes\n", false},
		{"merge", "defaults: &defaults {name: A, type: anytls}\nproxies: [{<<: *defaults, server: 192.0.2.1, port: 443, password: p}]\n", true},
		{"multidoc first valid", valid + "---\nrule-providers: {remote: {}}\n", true},
		{"multidoc first invalid", "rule-providers: {remote: {}}\n---\n" + valid, false},
		{"typed provider", "rule-providers: [remote]\n" + valid, false},
		{"typed node", "proxies: {name: A}\n", false},
		{"typed ipv6", "ipv6: nonsense\n" + valid, false},
		{"skip verify", "proxies: [{name: A, type: anytls, skip-cert-verify: true}]\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old, got := liveSourceEligible([]byte(tc.raw)), liveSourceEligibleStage([]byte(tc.raw))
			if got != old || got != tc.want {
				t.Fatalf("old=%v stage=%v want=%v", old, got, tc.want)
			}
		})
	}
}

// Preserve the pre-reuse selection order independently of selectedAndNodes.
func selectedSeparateDecode(captured serviceConfigBytes) (node, error) {
	nodes, err := loadNodesBytes(captured.config)
	if err != nil {
		return node{}, err
	}
	if captured.selection == nil {
		return node{}, errors.New("select a node first with 'anytls config'")
	}
	current, err := selectedBytes(captured.selection, nodes)
	if err != nil {
		return node{}, err
	}
	if current == "" {
		return node{}, errors.New("select a node first with 'anytls config'")
	}
	n, err := choose(nodes, current)
	if err != nil {
		return node{}, err
	}
	if _, err := buildNode(n, "tun", 0, n.SkipVerify); err != nil {
		return node{}, err
	}
	return n, nil
}

// The pre-reuse compile sequence is kept here as a small independent oracle.
func compileSeparateDecodes(captured serviceConfigBytes, allowInsecure bool) (map[string]any, error) {
	n, err := selectedSeparateDecode(captured)
	if err != nil {
		return nil, lifecycleFailure("service selection unavailable", err)
	}
	nodes, err := loadNodesBytes(captured.config)
	if err != nil {
		return nil, lifecycleFailure("service config unavailable", err)
	}
	cfg, err := buildNode(n, "tun", 0, allowInsecure)
	if err != nil {
		return nil, lifecycleFailure("service config rejected", err)
	}
	if err := applyRoutingBytes(captured.path, captured.config, nodes, n, cfg, allowInsecure); err != nil {
		return nil, lifecycleFailure("service routing rejected", err)
	}
	return cfg, nil
}

func TestServiceCompileReuseParity(t *testing.T) {
	_, _, path, _, _, _ := lifecycleFixture(t)
	base, err := captureServiceConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name           string
		config, choice []byte
		allow          bool
	}{
		{name: "valid", config: base.config, choice: base.selection, allow: true},
		{name: "malformed yaml", config: []byte("proxies: ["), choice: nil},
		{name: "duplicate node", config: []byte("proxies: [{name: primary, type: anytls}, {name: primary, type: anytls}]\n"), choice: base.selection},
		{name: "missing selection", config: base.config, choice: nil},
		{name: "unknown selection", config: base.config, choice: []byte("unknown")},
		{name: "invalid node", config: []byte("proxies: [{name: primary, type: direct}]\n"), choice: base.selection},
		{name: "insecure refused", config: base.config, choice: base.selection, allow: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			captured := serviceConfigBytes{path: path, config: tc.config, selection: tc.choice}
			oldSelected, oldErr := selectedSeparateDecode(captured)
			newSelected, nodes, newErr := captured.selectedAndNodes()
			if !reflect.DeepEqual(oldSelected, newSelected) || errorText(oldErr) != errorText(newErr) {
				t.Fatalf("selection old=%+v/%v new=%+v/%v", oldSelected, oldErr, newSelected, newErr)
			}
			if newErr == nil {
				separate, err := loadNodesBytes(tc.config)
				if err != nil || !reflect.DeepEqual(nodes, separate) {
					t.Fatalf("selected nodes differ from separate decode: %v", err)
				}
			}
			oldCfg, oldErr := compileSeparateDecodes(captured, tc.allow)
			newCfg, newErr := captured.compile(tc.allow)
			if (tc.name == "valid") != (oldErr == nil) {
				t.Fatalf("fixture %q did not reach expected compile outcome: %v", tc.name, oldErr)
			}
			if errorText(oldErr) != errorText(newErr) || errorText(errors.Unwrap(oldErr)) != errorText(errors.Unwrap(newErr)) || !reflect.DeepEqual(oldCfg, newCfg) {
				t.Fatalf("compile old=%v/%v new=%v/%v", oldCfg, oldErr, newCfg, newErr)
			}
		})
	}
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

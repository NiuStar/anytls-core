package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type node struct {
	Name        string `yaml:"name"`
	Type        string `yaml:"type"`
	Server      string `yaml:"server"`
	Port        int    `yaml:"port"`
	Password    string `yaml:"password"`
	UDP         *bool  `yaml:"udp"`
	Fingerprint string `yaml:"client-fingerprint"`
	IdleCheck   int    `yaml:"idle-session-check-interval"`
	IdleTimeout int    `yaml:"idle-session-timeout"`
	MinIdle     int    `yaml:"min-idle-session"`
	SkipVerify  bool   `yaml:"skip-cert-verify"`
	EgressIP    string `yaml:"egress-ip"`
	SNI         string `yaml:"sni"`
	DisableSNI  bool   `yaml:"disable-sni,omitempty"`
	CA          string `yaml:"ca"`

	CertificatePublicKeySHA256 string `yaml:"certificate-public-key-sha256,omitempty"`
	CertificateSHA256          string `yaml:"fingerprint,omitempty"`
	TLSMinVersion              string `yaml:"tls-min-version,omitempty"`
}

// Inspect the source tag/presence before decoding strings: YAML null and empty
// values must never erase an explicitly requested leaf trust mode.
func (n *node) UnmarshalYAML(value *yaml.Node) error {
	type plain node
	var decoded plain
	var fields map[string]yaml.Node
	if err := value.Decode(&fields); err != nil {
		return err
	}
	if flag, present := fields["disable-sni"]; present {
		// Node decoding retains aliases; inspect the resolved scalar, not the
		// bool zero value (which would silently accept explicit YAML null).
		p := &flag
		seen := map[*yaml.Node]bool{}
		for p != nil && p.Kind == yaml.AliasNode && !seen[p] {
			seen[p] = true
			p = p.Alias
		}
		if p == nil || p.Kind != yaml.ScalarNode || p.Tag != "!!bool" {
			return errors.New("invalid disable-sni: expected bool")
		}
	}
	if pin, present := fields["fingerprint"]; present {
		if pin.Kind != yaml.ScalarNode || pin.Tag != "!!str" || pin.Value == "" {
			return errors.New("invalid fingerprint")
		}
		if _, mixed := fields["certificate-public-key-sha256"]; mixed {
			return errors.New("fingerprint conflicts with certificate-public-key-sha256")
		}
		if err := validateNodeLeafTrust(node{CertificateSHA256: pin.Value}); err != nil {
			return err
		}
	}
	if err := value.Decode(&decoded); err != nil {
		return err
	}
	if err := validateNodeLeafTrust(node(decoded)); err != nil {
		return err
	}
	decoded.CertificateSHA256 = strings.ToLower(decoded.CertificateSHA256)
	*n = node(decoded)
	return nil
}

// fingerprint is SHA-256 of the complete leaf certificate DER, not SPKI or a
// ClientHello profile. Hex is only the YAML spelling; the SDK consumes base64.
func validateNodeLeafTrust(n node) error {
	if n.CertificateSHA256 == "" {
		return nil
	}
	pin, err := hex.DecodeString(n.CertificateSHA256)
	if err != nil || len(pin) != sha256.Size {
		return errors.New("invalid fingerprint")
	}
	if n.CertificatePublicKeySHA256 != "" || n.CA != "" || n.SkipVerify {
		return errors.New("fingerprint conflicts with certificate-public-key-sha256, ca or skip-cert-verify")
	}
	return nil
}

func validateNodeTLSMinVersion(n node) error {
	if n.TLSMinVersion != "" && n.TLSMinVersion != "1.2" && n.TLSMinVersion != "1.3" {
		return errors.New("invalid tls-min-version")
	}
	// uTLS profiles can override the configured floor in their ClientHello.
	if n.TLSMinVersion == "1.3" && n.Fingerprint != "golang" {
		return errors.New("tls-min-version 1.3 requires client-fingerprint golang")
	}
	return nil
}

// A pin authenticates the SPKI only, not a PKIX chain or hostname. Keep its
// spelling canonical and reject mixed trust before either SDK or CA handling.
func validateNodeSPKITrust(n node) error {
	if n.CertificatePublicKeySHA256 == "" {
		return nil
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(n.CertificatePublicKeySHA256)
	if err != nil || len(decoded) != sha256.Size || base64.StdEncoding.EncodeToString(decoded) != n.CertificatePublicKeySHA256 {
		return errors.New("invalid certificate-public-key-sha256")
	}
	if n.CA != "" || n.SkipVerify {
		return errors.New("certificate-public-key-sha256 conflicts with ca or skip-cert-verify")
	}
	return nil
}

func loadNodes(path string) ([]node, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("config.yaml must be a regular file")
	}
	b, err := readSnapshotSource(path, snapshotConfigLimit, true)
	if err != nil {
		return nil, err
	}
	return loadNodesBytes(b)
}

func loadNodesBytes(b []byte) ([]node, error) {
	var doc struct {
		Proxies []node `yaml:"proxies"`
		Nodes   []node `yaml:"nodes"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	nodes := append(doc.Proxies, doc.Nodes...)
	seen := map[string]bool{}
	for _, n := range nodes {
		if n.Name == "" || seen[n.Name] {
			return nil, errors.New("node names must be nonempty and unique")
		}
		seen[n.Name] = true
	}
	return nodes, nil
}

func choose(nodes []node, name string) (node, error) {
	for _, n := range nodes {
		if n.Name == name {
			if n.Type != "anytls" {
				return node{}, fmt.Errorf("node %q is not AnyTLS", name)
			}
			return n, nil
		}
	}
	return node{}, fmt.Errorf("node %q not found", name)
}

func buildNode(n node, mode string, port int, allowInsecure bool) (map[string]any, error) {
	return buildNodeWithListen(n, mode, port, allowInsecure, "0.0.0.0")
}

func validateProxyListen(listen string) error {
	addr, err := netip.ParseAddr(listen)
	if err != nil || !addr.Is4() || addr.String() != listen {
		return errors.New("invalid local-listen: expected a canonical IPv4 address")
	}
	return nil
}

func buildNodeWithListen(n node, mode string, port int, allowInsecure bool, listen string) (map[string]any, error) {
	if n.Type != "anytls" {
		return nil, errors.New("only AnyTLS is supported")
	}
	if strings.TrimSpace(n.Server) == "" || strings.ContainsAny(n.Server, " /	\n") || strings.Contains(n.Server, "%") {
		return nil, errors.New("invalid server address")
	}
	if mode == "tun" && net.ParseIP(n.Server) == nil {
		return nil, errors.New("TUN server must be a fixed IP to avoid DNS loop")
	}
	if n.Port < 1 || n.Port > 65535 || n.Password == "" {
		return nil, errors.New("invalid port or missing password")
	}
	if n.IdleCheck < 0 || n.IdleTimeout < 0 || n.MinIdle < 0 {
		return nil, errors.New("invalid idle session option")
	}
	if n.UDP != nil && !*n.UDP {
		return nil, errors.New("udp: false is not supported by this client")
	}
	if n.EgressIP != "" && net.ParseIP(n.EgressIP) == nil {
		return nil, errors.New("invalid egress-ip")
	}
	if err := validateNodeTLSMinVersion(n); err != nil {
		return nil, err
	}
	if err := validateNodeSPKITrust(n); err != nil {
		return nil, err
	}
	if err := validateNodeLeafTrust(n); err != nil {
		return nil, err
	}
	minVersion := n.TLSMinVersion
	if minVersion == "" {
		minVersion = "1.2"
	}
	tls := map[string]any{"enabled": true, "min_version": minVersion}
	if n.SNI != "" {
		tls["server_name"] = n.SNI
	}
	if n.DisableSNI {
		// Keep server_name as the CA hostname reference. The TLS backend
		// suppresses only its ClientHello extension, not identity validation.
		tls["disable_sni"] = true
	}
	if n.CertificateSHA256 != "" {
		pin, _ := hex.DecodeString(n.CertificateSHA256) // validated above
		tls["certificate_sha256"] = []string{base64.StdEncoding.EncodeToString(pin)}
	} else if n.CertificatePublicKeySHA256 != "" {
		tls["certificate_public_key_sha256"] = []string{n.CertificatePublicKeySHA256}
	} else if n.CA != "" {
		st, err := os.Stat(n.CA)
		if err != nil || !st.Mode().IsRegular() || st.Size() == 0 {
			return nil, errors.New("invalid CA PEM file")
		}
		abs, err := filepath.Abs(n.CA)
		if err != nil {
			return nil, err
		}
		tls["certificate_path"] = abs
	} else if n.SkipVerify && allowInsecure {
		tls["insecure"] = true
	} else {
		return nil, errors.New("TLS requires ca or explicit -allow-insecure for skip-cert-verify node")
	}
	fingerprint := n.Fingerprint
	if fingerprint == "" {
		fingerprint = "chrome"
	}
	if fingerprint != "golang" {
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": fingerprint}
	}
	out := map[string]any{"type": "anytls", "tag": "anytls-out", "server": n.Server, "server_port": n.Port, "password": n.Password, "tls": tls}
	if n.IdleCheck > 0 {
		out["idle_session_check_interval"] = fmt.Sprintf("%ds", n.IdleCheck)
	}
	if n.IdleTimeout > 0 {
		out["idle_session_timeout"] = fmt.Sprintf("%ds", n.IdleTimeout)
	}
	if n.MinIdle > 0 {
		out["min_idle_session"] = n.MinIdle
	}
	cfg := map[string]any{"log": map[string]any{"level": "info"}, "outbounds": []any{out}, "route": map[string]any{"final": "anytls-out", "auto_detect_interface": true}}
	switch mode {
	case "proxy":
		if port < 1 || port > 65535 {
			return nil, errors.New("invalid local port")
		}
		if err := validateProxyListen(listen); err != nil {
			return nil, err
		}
		cfg["inbounds"] = []any{map[string]any{"type": "mixed", "tag": "local-proxy", "listen": listen, "listen_port": port}}
	case "tun":
		prefix := "/32"
		if net.ParseIP(n.Server).To4() == nil {
			prefix = "/128"
		}
		cfg["inbounds"] = []any{map[string]any{"type": "tun", "tag": "tun-in", "address": []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"}, "mtu": 1500, "auto_route": true, "route_exclude_address": []string{n.Server + prefix}, "dns_mode": "hijack", "stack": "mixed"}}
		cfg["dns"] = unifiedTUNDNS()
		cfg["route"].(map[string]any)["rules"] = unifiedTUNDNSRules()
	default:
		return nil, errors.New("mode must be proxy or tun")
	}
	return cfg, nil
}

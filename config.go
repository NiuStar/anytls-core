package main

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
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
	CA          string `yaml:"ca"`

	CertificatePublicKeySHA256 string `yaml:"certificate-public-key-sha256,omitempty"`
	TLSMinVersion              string `yaml:"tls-min-version,omitempty"`
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
	minVersion := n.TLSMinVersion
	if minVersion == "" {
		minVersion = "1.2"
	}
	tls := map[string]any{"enabled": true, "min_version": minVersion}
	if n.SNI != "" {
		tls["server_name"] = n.SNI
	}
	if n.CertificatePublicKeySHA256 != "" {
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
		cfg["inbounds"] = []any{map[string]any{"type": "mixed", "tag": "local-proxy", "listen": "127.0.0.1", "listen_port": port}}
	case "tun":
		prefix := "/32"
		if net.ParseIP(n.Server).To4() == nil {
			prefix = "/128"
		}
		cfg["inbounds"] = []any{map[string]any{"type": "tun", "tag": "tun-in", "address": []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"}, "mtu": 1500, "auto_route": true, "route_exclude_address": []string{n.Server + prefix}, "dns_mode": "hijack", "stack": "mixed"}}
		cfg["dns"] = map[string]any{"servers": []any{map[string]any{"type": "https", "tag": "secure-dns", "server": "1.1.1.1", "tls": map[string]any{"server_name": "cloudflare-dns.com"}, "detour": "anytls-out"}}, "final": "secure-dns"}
	default:
		return nil, errors.New("mode must be proxy or tun")
	}
	return cfg, nil
}

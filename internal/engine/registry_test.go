package engine

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
)

func TestContextPreservesParent(t *testing.T) {
	type key struct{}
	parent, cancel := context.WithCancel(context.WithValue(context.Background(), key{}, "parent"))
	defer cancel()
	ctx := Context(parent)
	if ctx.Value(key{}) != "parent" {
		t.Fatal("registry context lost parent value")
	}
	cancel()
	if ctx.Err() != context.Canceled {
		t.Fatalf("registry context lost cancellation: %v", ctx.Err())
	}
}

func TestContextDecodesRequiredTypes(t *testing.T) {
	options, err := json.UnmarshalExtendedContext[option.Options](Context(context.Background()), []byte(`{
		"inbounds": [
			{"type":"tun","tag":"tun-in","address":["172.19.0.1/30"],"stack":"gvisor"},
			{"type":"mixed","tag":"mixed-in","listen":"127.0.0.1","listen_port":1080}
		],
		"outbounds": [
			{"type":"anytls","tag":"proxy","server":"example.com","server_port":443,"password":"test-only","tls":{"enabled":true,"utls":{"enabled":true,"fingerprint":"chrome"}}},
			{"type":"direct","tag":"direct"}
		],
		"dns":{"servers":[{"type":"https","tag":"doh","server":"1.1.1.1","path":"/dns-query"}]}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(options.Inbounds) != 2 || len(options.Outbounds) != 2 || options.DNS == nil || len(options.DNS.Servers) != 1 {
		t.Fatal("required options missing after decoding")
	}
	tun, ok := options.Inbounds[0].Options.(*option.TunInboundOptions)
	if !ok || tun.Stack != "gvisor" || len(tun.Address) != 1 {
		t.Fatalf("TUN decoded incorrectly: %#v", options.Inbounds[0].Options)
	}
	mixed, ok := options.Inbounds[1].Options.(*option.HTTPMixedInboundOptions)
	if !ok || mixed.ListenPort != 1080 {
		t.Fatalf("mixed decoded incorrectly: %#v", options.Inbounds[1].Options)
	}
	anytls, ok := options.Outbounds[0].Options.(*option.AnyTLSOutboundOptions)
	if !ok || anytls.Server != "example.com" || anytls.Password != "test-only" || anytls.TLS == nil || anytls.TLS.UTLS == nil || !anytls.TLS.UTLS.Enabled {
		t.Fatalf("AnyTLS decoded incorrectly: %#v", options.Outbounds[0].Options)
	}
	if _, ok := options.Outbounds[1].Options.(*option.DirectOutboundOptions); !ok {
		t.Fatalf("direct decoded as %T", options.Outbounds[1].Options)
	}
	https, ok := options.DNS.Servers[0].Options.(*option.RemoteHTTPSDNSServerOptions)
	if !ok || https.Server != "1.1.1.1" || https.Path != "/dns-query" {
		t.Fatalf("HTTPS DNS decoded incorrectly: %#v", options.DNS.Servers[0].Options)
	}
}

// Both option decoding and runtime construction need all six registry interfaces.
func TestContextHasExactRegistries(t *testing.T) {
	ctx := Context(context.Background())
	for name, registry := range map[string]any{
		"inbound":     service.FromContext[adapter.InboundRegistry](ctx),
		"outbound":    service.FromContext[adapter.OutboundRegistry](ctx),
		"endpoint":    service.FromContext[adapter.EndpointRegistry](ctx),
		"DNS":         service.FromContext[adapter.DNSTransportRegistry](ctx),
		"service":     service.FromContext[adapter.ServiceRegistry](ctx),
		"certificate": service.FromContext[adapter.CertificateProviderRegistry](ctx),
	} {
		if registry == nil {
			t.Errorf("missing %s runtime registry", name)
		}
	}
	for name, tt := range map[string]struct {
		registry interface{ OptionTypes() []string }
		want     []string
	}{
		"inbound":     {service.FromContext[option.InboundOptionsRegistry](ctx), []string{"mixed", "tun"}},
		"outbound":    {service.FromContext[option.OutboundOptionsRegistry](ctx), []string{"anytls", "direct"}},
		"endpoint":    {service.FromContext[option.EndpointOptionsRegistry](ctx), nil},
		"DNS":         {service.FromContext[option.DNSTransportOptionsRegistry](ctx), []string{"https", "local"}},
		"service":     {service.FromContext[option.ServiceOptionsRegistry](ctx), nil},
		"certificate": {service.FromContext[option.CertificateProviderOptionsRegistry](ctx), nil},
	} {
		t.Run(name, func(t *testing.T) {
			if tt.registry == nil {
				t.Fatal("missing options registry")
			}
			got := slices.Clone(tt.registry.OptionTypes())
			slices.Sort(got)
			if !slices.Equal(got, tt.want) {
				t.Fatalf("registered types = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestContextDecodesLocalDNS(t *testing.T) {
	options, err := json.UnmarshalExtendedContext[option.Options](Context(context.Background()), []byte(`{"dns":{"servers":[{"type":"local","tag":"system","prefer_go":true,"neighbor_domain":["fixture.invalid"]}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if options.DNS == nil || len(options.DNS.Servers) != 1 || options.DNS.Servers[0].Type != "local" || options.DNS.Servers[0].Tag != "system" {
		t.Fatal("local DNS entry missing after decoding")
	}
	local, ok := options.DNS.Servers[0].Options.(*option.LocalDNSServerOptions)
	if !ok || !local.PreferGo || !slices.Equal([]string(local.NeighborDomain), []string{"fixture.invalid"}) {
		t.Fatalf("local DNS decoded incorrectly: %T", options.DNS.Servers[0].Options)
	}
}

func TestContextRejectsUnsupportedTypes(t *testing.T) {
	for _, tt := range []struct {
		field       string
		types       []string
		errorPrefix string
	}{
		{"inbounds", []string{"anytls", "direct", "socks", "http", "shadowsocks", "vless", "vmess", "trojan", "hysteria2", "tuic", "not-a-type"}, "unknown inbound type: "},
		{"outbounds", []string{"mixed", "socks", "http", "block", "selector", "urltest", "shadowsocks", "vless", "vmess", "trojan", "hysteria2", "tuic", "wireguard", "not-a-type"}, "unknown outbound type: "},
		{"endpoints", []string{"wireguard", "tailscale", "openconnect", "openvpn", "not-a-type"}, "unknown endpoint type: "},
		// Upstream v1.14.3 labels service decode errors as inbound errors.
		{"services", []string{"api", "resolved", "ssm-api", "derp", "not-a-type"}, "unknown inbound type: "},
		{"certificate_providers", []string{"acme", "tailscale", "origin_ca", "not-a-type"}, "unknown certificate provider type: "},
		{"dns", []string{"udp", "tcp", "tls", "quic", "h3", "hosts", "fakeip", "resolved", "dhcp", "not-a-type"}, "unknown transport type: "},
	} {
		for _, typ := range tt.types {
			t.Run(tt.field+"/"+typ, func(t *testing.T) {
				entry := map[string]any{"type": typ}
				var value any = []any{entry}
				if tt.field == "dns" {
					value = map[string]any{"servers": value}
				}
				content, err := json.Marshal(map[string]any{tt.field: value})
				if err != nil {
					t.Fatal(err)
				}
				_, err = json.UnmarshalExtendedContext[option.Options](Context(context.Background()), content)
				if err == nil || !strings.Contains(err.Error(), tt.errorPrefix+typ) {
					t.Fatalf("unsupported type must fail at registry lookup, got %v", err)
				}
			})
		}
	}
}

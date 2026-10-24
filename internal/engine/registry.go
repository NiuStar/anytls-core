// Package engine provides the explicitly supported embedded sing-box registries.
package engine

import (
	"context"

	"github.com/NiuStar/anytls-core/internal/chrometls"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	singService "github.com/sagernet/sing/service"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/protocol/anytls"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/mixed"
	"github.com/sagernet/sing-box/protocol/tun"
)

// chromeClientFactory is an alias, not a defined interface: the SDK hook uses
// this exact anonymous interface as the service-registry key.
type chromeClientFactory = interface {
	NewChromeClient(context.Context, string, option.OutboundTLSOptions) (tls.Config, error)
}

// Context adds the minimal embedded registries to ctx using box.Context.
// Like box.Context, it REUSES an installed sing service registry (and its types)
// and can mutate it. This helper is not a sanitization or ownership boundary.
// Check/Run install a fresh owned service registry before calling Context.
// Endpoint, service and certificate-provider registries are deliberately empty.
func Context(ctx context.Context) context.Context {
	inbounds := inbound.NewRegistry()
	tun.RegisterInbound(inbounds)
	mixed.RegisterInbound(inbounds)

	outbounds := outbound.NewRegistry()
	anytls.RegisterOutbound(outbounds)
	direct.RegisterOutbound(outbounds)

	dnsTransports := dns.NewTransportRegistry()
	transport.RegisterHTTPS(dnsTransports)
	// Upstream Start requires local fallback when the unchanged config has no DNS.
	local.RegisterTransport(dnsTransports)

	ctx = box.Context(ctx, inbounds, outbounds, endpoint.NewRegistry(), dnsTransports, service.NewRegistry(), certificate.NewRegistry())
	return singService.ContextWith[chromeClientFactory](ctx, chrometls.Factory{})
}

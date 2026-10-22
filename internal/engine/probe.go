package engine

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

const probeEndpoint = "https://www.gstatic.com/generate_204"
const probeTimeout = 8 * time.Second

// Probe measures one HTTPS 204 exchange over the selected real AnyTLS outbound.
// It creates no inbound/listener, TUN, rule sets, system DNS or external process.
// No caller-controlled target is exposed. This is latency, not bandwidth.
// Timing includes construction/start, response and synchronous cleanup. The
// context bounds network work; synchronous SDK construction/Close are not an
// OS-level eight-second guarantee. Cancellation/cleanup failure never means OK.
func Probe(ctx context.Context, runtimeJSON []byte) (float64, error) {
	return probeHTTPS(ctx, runtimeJSON, probeEndpoint, nil)
}

// The endpoint/TLS override is package-private, only for isolated HTTPS fixtures.
// Production always uses the fixed endpoint and the standard HTTPS trust store;
// the endpoint certificate is independent of the AnyTLS node's TLS policy.
func probeHTTPS(ctx context.Context, runtimeJSON []byte, endpoint string, endpointTLS *tls.Config) (ms float64, err error) {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Host == "" {
		return 0, errors.New("invalid probe endpoint")
	}
	start := time.Now()
	ctx, options, err := decodeOptions(ctx, runtimeJSON)
	if err != nil {
		return 0, err
	}
	if len(options.Outbounds) != 1 || options.Outbounds[0].Tag != "anytls-out" || options.Outbounds[0].Type != "anytls" {
		return 0, errors.New("probe requires one AnyTLS outbound")
	}
	// Retain ONLY the chosen outbound + disabled logging: even an accidental
	// full VPN configuration cannot open its inbounds or mutate system settings.
	outbounds, logOptions := options.Outbounds, options.Log
	options = option.Options{Outbounds: outbounds, Log: logOptions}
	instance, err := box.New(box.Options{Options: options, Context: ctx})
	if err != nil {
		return 0, lifecycleError("probe construct", err)
	}
	defer func() {
		err = errors.Join(err, lifecycleError("probe close", instance.Close()), ctx.Err())
		if err != nil {
			ms = 0
		} else {
			ms = float64(time.Since(start)) / float64(time.Millisecond)
		}
	}()
	if err := instance.Start(); err != nil {
		return 0, errors.Join(ctx.Err(), lifecycleError("probe start", err))
	}
	outbound, ok := instance.Outbound().Outbound("anytls-out")
	if !ok {
		return 0, errors.New("probe outbound unavailable")
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	target := net.JoinHostPort(u.Hostname(), port)
	transport := &http.Transport{
		Proxy:                  nil,
		DisableKeepAlives:      true,
		TLSClientConfig:        endpointTLS,
		TLSHandshakeTimeout:    probeTimeout,
		ResponseHeaderTimeout:  probeTimeout,
		MaxResponseHeaderBytes: 16 << 10,
		DialContext: func(dialCtx context.Context, network, address string) (net.Conn, error) {
			if address != target || network != "tcp" {
				return nil, errors.New("probe destination rejected")
			}
			return outbound.DialContext(dialCtx, "tcp", M.ParseSocksaddr(target))
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: probeTimeout, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("probe redirect rejected")
	}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, lifecycleError("probe request", err)
	}
	response, err := client.Do(req)
	if err != nil {
		return 0, errors.Join(ctx.Err(), lifecycleError("probe HTTPS", err))
	}
	_, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	closeErr := response.Body.Close()
	if err := errors.Join(readErr, closeErr, ctx.Err()); err != nil {
		return 0, lifecycleError("probe response", err)
	}
	if response.StatusCode != http.StatusNoContent {
		return 0, errors.New("probe unexpected HTTP status")
	}
	return float64(time.Since(start)) / float64(time.Millisecond), nil
}

package telemetry

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// Run is owned by the WebUI process, not an HTTP request. There is one serial
// probe, no backfill, retries, node selection, service start or route mutation.
func (s *Store) Run(ctx context.Context) {
	s.run(ctx, Interval, func(c context.Context) error { return probeHTTPS(c, Endpoint, nil) })
}

func (s *Store) run(ctx context.Context, interval time.Duration, probe func(context.Context) error) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		start := time.Now()
		c, cancel := context.WithTimeout(ctx, Timeout)
		err := probe(c)
		if c.Err() != nil {
			err = c.Err()
		}
		cancel()
		if ctx.Err() != nil {
			return
		} // shutdown is not a completed connectivity failure
		s.Record(start, time.Now(), err)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// The endpoint/trust override is private for real loopback fixtures. Production
// can only use Endpoint and platform CA validation; no request-controlled URL.
func probeHTTPS(parent context.Context, endpoint string, trust *tls.Config) error {
	ctx, cancel := context.WithTimeout(parent, Timeout)
	defer cancel()
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return errors.New("invalid probe endpoint")
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	target := net.JoinHostPort(u.Hostname(), port)
	if trust == nil {
		trust = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, DisableCompression: true,
		TLSClientConfig: trust, TLSHandshakeTimeout: Timeout, ResponseHeaderTimeout: Timeout, MaxResponseHeaderBytes: 16 << 10,
		DialContext: func(c context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != target {
				return nil, errors.New("probe destination rejected")
			}
			return (&net.Dialer{}).DialContext(c, network, address)
		}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("probe redirect rejected") }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(req)
	if err != nil {
		return err
	}
	_, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	closeErr := response.Body.Close()
	if err = errors.Join(readErr, closeErr, ctx.Err()); err != nil {
		return err
	}
	if response.StatusCode != http.StatusNoContent {
		return errors.New("probe unexpected HTTP status")
	}
	return nil
}

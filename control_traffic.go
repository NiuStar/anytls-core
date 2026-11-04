package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"time"

	cr "github.com/NiuStar/anytls-core/internal/connectionrecords"
	ts "github.com/NiuStar/anytls-core/internal/trafficstats"
)

func trafficFrame(b []byte) bool {
	d := json.NewDecoder(bytes.NewReader(b))
	if t, e := d.Token(); e != nil || t != json.Delim('{') {
		return false
	}
	for d.More() {
		k, e := d.Token()
		if e != nil {
			return false
		}
		if k == "traffic_schema" {
			return true
		}
		var raw json.RawMessage
		if d.Decode(&raw) != nil {
			return false
		}
		if k == "action" {
			var a string
			_ = json.Unmarshal(raw, &a)
			if a == "traffic.read" {
				return true
			}
		}
	}
	return false
}
func (s *controlHelperServer) trafficRead(ctx context.Context) ts.Response {
	if !s.recordsSlot.TryLock() {
		return ts.Unavailable()
	}
	done := make(chan ts.Response, 1)
	go func() {
		r := s.trafficReadWork(ctx)
		s.recordsSlot.Unlock()
		done <- r
	}()
	select {
	case r := <-done:
		return r
	case <-ctx.Done():
		return ts.Unavailable()
	}
}
func (s *controlHelperServer) trafficReadWork(ctx context.Context) ts.Response {
	registration := s.recordsRegistration
	if registration == nil {
		registration = controlHelperReadRegistration
	}
	reg, e := registration()
	if e != nil || reg != s.registration || reg.UID == 0 {
		return ts.Unavailable()
	}
	identity, e := controlHelperConfigIdentity(reg.Config)
	if e != nil {
		return ts.Unavailable()
	}
	read := s.trafficStoreRead
	if read == nil {
		read = cr.ReadTraffic
	}
	var snap ts.Snapshot
	h, e := read(ctx, cr.Scope{UID: reg.UID, ConfigIdentity: identity}, &snap, ts.MaxBytes)
	if e != nil || cr.Validate(h) != nil || ts.Validate(snap) != nil || !trafficHeadersEqual(snap.Header, h) || snap.Header.ConfigIdentity != identity || snap.State != "RUNNING" || snap.Saturated {
		return ts.Unavailable()
	}
	sampled, e := time.Parse(time.RFC3339Nano, snap.SampledAt)
	if e != nil || time.Since(sampled) < 0 || time.Since(sampled) > ts.FreshFor {
		return ts.Unavailable()
	}
	again, e := registration()
	if e != nil || again != reg {
		return ts.Unavailable()
	}
	id, e := controlHelperConfigIdentity(reg.Config)
	if e != nil || id != identity || ctx.Err() != nil {
		return ts.Unavailable()
	}
	return ts.Response{TrafficSchema: 1, Availability: "OBSERVED", Snapshot: &snap}
}
func trafficHeadersEqual(a, b cr.Header) bool {
	if a.SchemaVersion != b.SchemaVersion || a.Binding != b.Binding || a.ConfigIdentity != b.ConfigIdentity || a.RuntimeSHA256 != b.RuntimeSHA256 || a.CreatedAt != b.CreatedAt {
		return false
	}
	if a.PreviousBinding == nil || b.PreviousBinding == nil {
		return a.PreviousBinding == nil && b.PreviousBinding == nil
	}
	return *a.PreviousBinding == *b.PreviousBinding
}
func trafficExchange(ctx context.Context, c net.Conn, peer func(net.Conn) (uint32, error)) (ts.Response, error) {
	r := ts.Unavailable()
	deadline := time.Now().Add(cr.TelemetryTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if c.SetDeadline(deadline) != nil {
		return r, cr.TelemetryUnavailable
	}
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	uid, e := peer(c)
	if e != nil || uid != 0 {
		return r, cr.Forbidden
	}
	b, e := ts.Encode(ts.Request())
	if e != nil {
		return r, e
	}
	if n, e := c.Write(b); e != nil || n != len(b) {
		return r, cr.TelemetryUnavailable
	}
	half, ok := c.(interface{ CloseWrite() error })
	if !ok || half.CloseWrite() != nil {
		return r, cr.TelemetryUnavailable
	}
	b, e = io.ReadAll(io.LimitReader(c, ts.MaxBytes+1))
	if e != nil || ts.Decode(b, &r) != nil || ctx.Err() != nil {
		return ts.Unavailable(), cr.TelemetryUnavailable
	}
	uid, e = peer(c)
	if e != nil || uid != 0 {
		return ts.Unavailable(), cr.Forbidden
	}
	return r, nil
}
func controlHelperTrafficRequest(ctx context.Context) (ts.Response, error) {
	if !controlHelperSupported() || controlHelperValidateSocket() != nil {
		return ts.Unavailable(), cr.TelemetryUnavailable
	}
	c, e := (&net.Dialer{}).DialContext(ctx, "unix", controlHelperSocketPath)
	if e != nil {
		return ts.Unavailable(), cr.TelemetryUnavailable
	}
	defer c.Close()
	return trafficExchange(ctx, c, controlHelperPeerUID)
}

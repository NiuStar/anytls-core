package main

import (
	"bytes"
	"context"
	"encoding/json"
	de "github.com/NiuStar/anytls-core/internal/dnsevidence"
	"io"
	"net"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"
)

// This object owns its binding; it never borrows a finished startupOperation.
type dnsRuntimeCache struct {
	mu                         sync.Mutex
	slot                       sync.Mutex
	binding                    *startupBinding
	epoch, operation, identity string
	run                        *de.Binding
	snapshot                   *de.Snapshot
	received                   time.Time
}

func (s *controlHelperServer) dnsInvalidate() {
	s.dns.mu.Lock()
	defer s.dns.mu.Unlock()
	s.dns.binding = nil
	s.dns.run = nil
	s.dns.snapshot = nil
}
func (s *controlHelperServer) dnsBind(b *startupBinding, epoch, operation, identity string) {
	copy := *b
	copy.args = append([]string{}, b.args...)
	copy.process = nil
	s.dns.mu.Lock()
	defer s.dns.mu.Unlock()
	s.dns.binding = &copy
	s.dns.epoch = epoch
	s.dns.operation = operation
	s.dns.identity = identity
	s.dns.run = nil
	s.dns.snapshot = nil
}
func dnsFrame(b []byte) bool {
	d := json.NewDecoder(bytes.NewReader(b))
	if t, e := d.Token(); e != nil || t != json.Delim('{') {
		return false
	}
	for d.More() {
		k, e := d.Token()
		if e != nil {
			return false
		}
		if k == "dns_schema" {
			return true
		}
		var v json.RawMessage
		if d.Decode(&v) != nil {
			return false
		}
		if k == "action" {
			var s string
			_ = json.Unmarshal(v, &s)
			if strings.HasPrefix(s, "dns.") {
				return true
			}
		}
	}
	return false
}
func dnsWrite(c net.Conn, v any) {
	if b, e := de.Encode(v); e == nil {
		_, _ = c.Write(b)
	}
}
func (s *controlHelperServer) dnsRootHandle(c net.Conn) {
	if !s.dns.slot.TryLock() {
		return
	}
	defer s.dns.slot.Unlock()
	s.dns.mu.Lock()
	b := s.dns.binding
	epoch, operation, identity := s.dns.epoch, s.dns.operation, s.dns.identity
	if b != nil {
		owned := *b
		owned.args = append([]string{}, b.args...)
		if b.process != nil {
			p := *b.process
			owned.process = &p
		}
		b = &owned
	}
	target := s.dns.binding
	s.dns.mu.Unlock()
	reject := func() { dnsWrite(c, de.Ack{DNSSchema: 1, Code: "FORBIDDEN"}) }
	if b == nil {
		reject()
		return
	}
	registration := s.startupRegistration
	if registration == nil {
		registration = controlHelperReadRegistration
	}
	auth := s.startupAuthenticate
	if auth == nil {
		auth = startupAuthenticatePush
	}
	valid := func() bool {
		reg, e := registration()
		if e != nil || reg != s.registration {
			return false
		}
		id, e := controlHelperConfigIdentity(reg.Config)
		return e == nil && id == identity && auth(c, b)
	}
	if !valid() {
		s.dnsInvalidate()
		reject()
		return
	}
	_ = c.SetDeadline(time.Now().Add(500 * time.Millisecond))
	raw, e := io.ReadAll(io.LimitReader(c, de.PushBytes+1))
	var q de.Push
	if e == nil && !dnsFrame(raw) {
		s.startupRootHandleRaw(c, raw)
		return
	}
	if e != nil || de.Decode(raw, &q) != nil {
		dnsWrite(c, de.Ack{DNSSchema: 1, Code: "INVALID_REQUEST"})
		return
	}
	if !valid() {
		s.dnsInvalidate()
		reject()
		return
	}
	s.dns.mu.Lock()
	code := "IDENTITY_MISMATCH"
	if s.dns.binding == target && q.HelperEpoch == epoch && q.OperationID == operation && q.ConfigIdentity == identity {
		target.process = b.process
		if s.dns.run == nil {
			v := q.Binding
			s.dns.run = &v
			snap := de.Clone(q.Snapshot)
			s.dns.snapshot = &snap
			s.dns.received = time.Now()
			code = "OK"
		} else if *s.dns.run == q.Binding {
			old := s.dns.snapshot
			n, _ := strconv.ParseUint(q.Snapshot.Revision, 10, 64)
			prev, _ := strconv.ParseUint(old.Revision, 10, 64)
			if n > prev && dnsSnapshotProgress(*old, q.Snapshot) && reflect.DeepEqual(old.Policy, q.Snapshot.Policy) && !(old.State == "CLOSED" && q.Snapshot.State != "CLOSED") && !(old.State == "LOADED" && q.Snapshot.State == "STARTING") {
				snap := de.Clone(q.Snapshot)
				s.dns.snapshot = &snap
				s.dns.received = time.Now()
				code = "OK"
			}
		}
	}
	s.dns.mu.Unlock()
	dnsWrite(c, de.Ack{DNSSchema: 1, Code: code})
}
func dnsSnapshotProgress(a, b de.Snapshot) bool {
	dec := func(s string) uint64 { n, _ := strconv.ParseUint(s, 10, 64); return n }
	if dec(b.ElapsedNS) < dec(a.ElapsedNS) || dec(b.Coverage.Dropped) < dec(a.Coverage.Dropped) || a.Coverage.Gap && !b.Coverage.Gap || a.Coverage.Saturated && !b.Coverage.Saturated {
		return false
	}
	if len(a.Events) > 0 {
		if len(b.Events) == 0 {
			return false
		}
		if dec(b.Events[len(b.Events)-1].Seq) < dec(a.Events[len(a.Events)-1].Seq) {
			return false
		}
	}
	for _, old := range a.Events {
		for _, next := range b.Events {
			if old.Seq == next.Seq && !reflect.DeepEqual(old, next) {
				return false
			}
		}
	}
	return true
}

// Reads are cached memory only: no action mutex, path stat, launchctl or adoption.
func (s *controlHelperServer) dnsRead(q de.Read) de.Response {
	s.dns.mu.Lock()
	defer s.dns.mu.Unlock()
	r := de.Response{DNSSchema: 1, Code: "UNAVAILABLE", Availability: "UNAVAILABLE"}
	if s.dns.binding == nil {
		return r
	}
	epoch, identity := s.dns.epoch, s.dns.identity
	r.HelperEpoch = &epoch
	r.ConfigIdentity = &identity
	if s.dns.run == nil {
		return r
	}
	b := *s.dns.run
	r.Binding = &b
	if q.InstanceID == nil {
		r.Code = "OK"
		return r
	}
	if !de.Matches(q, b) {
		r.Code = "STALE_GENERATION"
		return r
	}
	snap := de.Clone(*s.dns.snapshot)
	r.Snapshot = &snap
	r.Code = "OK"
	r.Availability = "OBSERVED"
	age := time.Since(s.dns.received)
	if age < 0 {
		age = 0
	}
	a := strconv.FormatInt(int64(age), 10)
	at := s.dns.received.UTC().Format(time.RFC3339Nano)
	r.AgeNS = &a
	r.ReceivedAt = &at
	if age > 2500*time.Millisecond || snap.State == "CLOSED" {
		r.Availability = "STALE"
	}
	return r
}
func dnsExchange(ctx context.Context, c net.Conn, q, v any, peer func(net.Conn) (uint32, error)) error {
	deadline := time.Now().Add(500 * time.Millisecond)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if c.SetDeadline(deadline) != nil {
		return de.Invalid
	}
	uid, e := peer(c)
	if e != nil || uid != 0 {
		return de.Invalid
	}
	b, e := de.Encode(q)
	if e != nil {
		return e
	}
	if _, e = c.Write(b); e != nil {
		return e
	}
	if u, ok := c.(*net.UnixConn); !ok || u.CloseWrite() != nil {
		return de.Invalid
	}
	raw, e := io.ReadAll(io.LimitReader(c, de.PushBytes+1))
	if e != nil {
		return e
	}
	if e = de.Decode(raw, v); e != nil {
		return e
	}
	uid, e = peer(c)
	if e != nil || uid != 0 {
		return de.Invalid
	}
	return nil
}
func controlHelperDNSRequest(ctx context.Context, q de.Read) (de.Response, error) {
	var r de.Response
	if de.Validate(q) != nil {
		return r, de.Invalid
	}
	if e := controlHelperTrustedPath(controlHelperSocketDir, true); e != nil {
		return r, e
	}
	c, e := (&net.Dialer{}).DialContext(ctx, "unix", controlHelperSocketPath)
	if e != nil {
		return r, e
	}
	defer c.Close()
	e = dnsExchange(ctx, c, q, &r, controlHelperPeerUID)
	return r, e
}

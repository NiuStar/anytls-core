package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"unicode/utf8"

	cr "github.com/NiuStar/anytls-core/internal/connectionrecords"
)

// This is only a dispatch discriminator, never an authorization/validation codec.
// Every branch must subsequently pass its own strict codec before executing.
func controlHelperRecordsFrame(b []byte) bool {
	d := json.NewDecoder(bytes.NewReader(b))
	if t, e := d.Token(); e != nil || t != json.Delim('{') {
		return false
	}
	for d.More() {
		key, e := d.Token()
		if e != nil {
			return false
		}
		if key == "schema_version" {
			return true
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return false
		}
		if key == "action" {
			var action string
			_ = json.Unmarshal(value, &action)
			if action == "records.read" {
				return true
			}
		}
	}
	return false
}
func recordsErrorCode(err error) cr.ErrorCode {
	var code cr.ErrorCode
	if errors.As(err, &code) && code != cr.NoError && cr.Validate(code) == nil {
		return code
	}
	return cr.TelemetryUnavailable
}
func recordsErrorBytes(code cr.ErrorCode) []byte {
	b, _ := cr.EncodeBounded(cr.ErrorResponse{SchemaVersion: 1, ErrorCode: code}, cr.MaxResponseBytes)
	return b
}
func recordsPageMatches(p cr.PageResponse, q cr.PageRequest) bool {
	if cr.Validate(p) != nil {
		return false
	}
	after, err := q.After.Uint64()
	if err != nil {
		return false
	}
	high, err := p.HighWaterSeq.Uint64()
	if err != nil || after > high {
		return false
	}
	for _, r := range p.Records {
		if _, e := cr.EncodeBounded(r, cr.MaxRecordBytes); e != nil {
			return false
		}
	}
	if q.Binding == nil {
		return len(p.Records) == 0 && p.NextAfter == q.After
	}
	if p.Binding != *q.Binding || len(p.Records) > q.Limit {
		return false
	}
	if len(p.Records) == 0 {
		return p.NextAfter == q.After && p.HighWaterSeq == q.After
	}
	first, err := p.Records[0].Seq.Uint64()
	return err == nil && after != ^uint64(0) && first == after+1
}

// Own exactly one actual read, not one waiter. Timeout/caller disconnect cannot
// transfer ownership or release the slot while kernel file I/O is still running.
// The worker has no connection/HTTP/lifecycle handle and releases file work before
// publishing its independently owned bounded response bytes.
func (s *controlHelperServer) recordsPage(ctx context.Context, q cr.PageRequest) []byte {
	if !s.recordsSlot.TryLock() {
		return recordsErrorBytes(cr.Busy)
	}
	done := make(chan []byte, 1)
	go func() {
		b := s.recordsPageWork(ctx, q)
		s.recordsSlot.Unlock()
		done <- b
	}()
	select {
	case b := <-done:
		return b
	case <-ctx.Done():
		return recordsErrorBytes(cr.TelemetryUnavailable)
	}
}
func (s *controlHelperServer) recordsPageWork(ctx context.Context, q cr.PageRequest) []byte {
	registration := s.recordsRegistration
	if registration == nil {
		registration = controlHelperReadRegistration
	}
	reg, err := registration()
	if err != nil || reg != s.registration || reg.UID == 0 {
		return recordsErrorBytes(cr.Forbidden)
	}
	identity, err := controlHelperConfigIdentity(reg.Config)
	if err != nil {
		return recordsErrorBytes(cr.TelemetryUnavailable)
	}
	scope := cr.Scope{UID: reg.UID, ConfigIdentity: identity}
	read := s.recordsRead
	if read == nil {
		read = cr.ReadPage
	}
	if ctx.Err() != nil {
		return recordsErrorBytes(cr.TelemetryUnavailable)
	}
	p, err := read(ctx, scope, q)
	if err != nil {
		return recordsErrorBytes(recordsErrorCode(err))
	}
	// Registration is authority; today's configuration contents never supply old
	// route/group/node attribution. Recheck the same registration after file work.
	again, err := registration()
	if err != nil || again != reg {
		return recordsErrorBytes(cr.Forbidden)
	}
	current, err := controlHelperConfigIdentity(reg.Config)
	if err != nil || current != identity || p.ConfigIdentity != identity || !recordsPageMatches(p, q) {
		return recordsErrorBytes(cr.StoreInvalid)
	}
	if ctx.Err() != nil {
		return recordsErrorBytes(cr.TelemetryUnavailable)
	}
	b, err := cr.EncodeBounded(p, cr.MaxResponseBytes)
	if err != nil {
		return recordsErrorBytes(cr.StoreInvalid)
	}
	return b
}

func controlHelperRecordsRequest(ctx context.Context, q cr.PageRequest) (cr.PageResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, cr.TelemetryTimeout)
	defer cancel()
	if cr.ValidatePageRequest(q) != nil {
		return cr.PageResponse{}, cr.InvalidRequest
	}
	if !controlHelperSupported() || controlHelperValidateSocket() != nil {
		return cr.PageResponse{}, cr.TelemetryUnavailable
	}
	c, err := (&net.Dialer{}).DialContext(ctx, "unix", controlHelperSocketPath)
	if err != nil {
		return cr.PageResponse{}, cr.TelemetryUnavailable
	}
	defer c.Close()
	return controlHelperRecordsExchange(ctx, c, q, controlHelperPeerUID)
}
func controlHelperRecordsExchange(ctx context.Context, c net.Conn, q cr.PageRequest, peer func(net.Conn) (uint32, error)) (cr.PageResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, cr.TelemetryTimeout)
	defer cancel()
	b, err := cr.EncodeRequest(q)
	if err != nil {
		return cr.PageResponse{}, cr.InvalidRequest
	}
	deadline, _ := ctx.Deadline()
	_ = c.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	uid, err := peer(c)
	if err != nil || uid != 0 {
		return cr.PageResponse{}, cr.Forbidden
	}
	if ctx.Err() != nil {
		return cr.PageResponse{}, cr.TelemetryUnavailable
	}
	if n, e := c.Write(b); e != nil || n != len(b) {
		return cr.PageResponse{}, cr.TelemetryUnavailable
	}
	half, ok := c.(interface{ CloseWrite() error })
	if !ok || half.CloseWrite() != nil {
		return cr.PageResponse{}, cr.TelemetryUnavailable
	}
	b, err = io.ReadAll(io.LimitReader(c, cr.MaxResponseBytes+1))
	if err != nil || len(b) > cr.MaxResponseBytes || !utf8.Valid(b) || bytes.IndexByte(b, 0) >= 0 || ctx.Err() != nil {
		return cr.PageResponse{}, cr.TelemetryUnavailable
	}
	var p cr.PageResponse
	if cr.DecodeStrict(b, &p, cr.MaxResponseBytes) == nil {
		if !recordsPageMatches(p, q) {
			return cr.PageResponse{}, cr.StoreInvalid
		}
		if ctx.Err() != nil {
			return cr.PageResponse{}, cr.TelemetryUnavailable
		}
		return p, nil
	}
	var failure cr.ErrorResponse
	if cr.DecodeStrict(b, &failure, cr.MaxResponseBytes) == nil {
		return cr.PageResponse{}, failure.ErrorCode
	}
	// Only exact legacy error schema can identify an old helper; never reflect its
	// message or recommend an installation/control operation from a history read.
	var old controlHelperResponse
	if controlHelperReadResponse(bytes.NewReader(b), &old) == nil && !old.OK {
		if old.Code == "FORBIDDEN" {
			return cr.PageResponse{}, cr.Forbidden
		}
		if old.Code == "INVALID_REQUEST" {
			return cr.PageResponse{}, cr.Unsupported
		}
	}
	return cr.PageResponse{}, cr.TelemetryUnavailable
}

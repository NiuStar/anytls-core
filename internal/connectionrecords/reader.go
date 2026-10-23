package connectionrecords

import (
	"context"
	"encoding/binary"
	"errors"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"time"
)

func ReadPage(ctx context.Context, scope Scope, q PageRequest) (PageResponse, error) {
	if os.Geteuid() != 0 {
		return PageResponse{}, TelemetryUnavailable
	}
	return readPage(ctx, defaultStore(), scope, q)
}
func readPage(ctx context.Context, s recordStore, scope Scope, q PageRequest) (page PageResponse, result error) {
	// Error paths never expose partially accumulated rows or raw filesystem errors.
	defer func() {
		if result != nil {
			page = PageResponse{}
			var code ErrorCode
			if !errors.As(result, &code) {
				result = StoreInvalid
			}
		}
	}()
	if ValidatePageRequest(q) != nil {
		return page, InvalidRequest
	}
	if ctx.Err() != nil {
		return page, TelemetryUnavailable
	}
	ns, e := s.namespace(scope, false)
	if e != nil {
		if errors.Is(e, os.ErrNotExist) {
			return page, TelemetryUnavailable
		}
		return page, StoreInvalid
	}
	nsInfo, e := os.Lstat(ns)
	if e != nil {
		return page, StoreInvalid
	}
	latest, e := s.latest(ns, scope)
	if e != nil {
		if errors.Is(e, os.ErrNotExist) {
			return page, TelemetryUnavailable
		}
		return page, StoreInvalid
	}
	binding := latest.Binding
	if q.Binding != nil {
		binding = *q.Binding
	}
	dir := filepath.Join(ns, binding.InstanceID)
	if e = s.directory(dir, true); e != nil {
		if errors.Is(e, os.ErrNotExist) && q.Binding != nil {
			return page, StaleGeneration
		}
		return page, StoreInvalid
	}
	dirInfo, e := os.Lstat(dir)
	if e != nil {
		return page, StoreInvalid
	}
	var header Header
	headerInfo, e := s.readJSON(filepath.Join(dir, "header.json"), &header, MaxHeaderBytes)
	if e != nil {
		return page, StoreInvalid
	}
	if header.Binding != binding {
		return page, StaleGeneration
	}
	if header.ConfigIdentity != scope.ConfigIdentity {
		return page, StoreInvalid
	}
	var state State
	if _, e = s.readJSON(filepath.Join(dir, "state.json"), &state, MaxStateBytes); e != nil {
		return page, StoreInvalid
	}
	if !reflect.DeepEqual(state.Header, header) {
		return page, StoreInvalid
	}
	data, e := s.open(filepath.Join(dir, "records.bin"), syscall.O_RDONLY)
	if e != nil {
		return page, StoreInvalid
	}
	defer func() {
		if e := s.close(data); e != nil {
			result = StoreInvalid
		}
	}()
	index, e := s.open(filepath.Join(dir, "index.bin"), syscall.O_RDONLY)
	if e != nil {
		return page, StoreInvalid
	}
	defer func() {
		if e := s.close(index); e != nil {
			result = StoreInvalid
		}
	}()
	di, e := data.Stat()
	if e != nil {
		return page, StoreInvalid
	}
	ii, e := index.Stat()
	if e != nil {
		return page, StoreInvalid
	}
	high, _ := state.HighWaterSeq.Uint64()
	dataBytes, _ := state.CommittedDataBytes.Uint64()
	indexBytes, _ := state.CommittedIndexBytes.Uint64()
	after, _ := q.After.Uint64()
	if after > high {
		return page, InvalidRequest
	}
	if high > math.MaxInt64/IndexEntryBytes || dataBytes > math.MaxInt64 || indexBytes > math.MaxInt64 || uint64(di.Size()) < dataBytes || uint64(ii.Size()) < indexBytes {
		return page, StoreInvalid
	}
	entry := func(seq uint64) (uint64, uint64, error) {
		if ctx.Err() != nil {
			return 0, 0, TelemetryUnavailable
		}
		if seq == 0 || seq > high {
			return 0, 0, StoreInvalid
		}
		var b [16]byte
		n, e := s.readAt(index, b[:], int64((seq-1)*IndexEntryBytes))
		if e != nil || n != len(b) {
			return 0, 0, StoreInvalid
		}
		offset, length := binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(b[8:])
		if length < 5 || length > MaxRecordBytes+4 || offset > dataBytes || length > dataBytes-offset || seq == 1 && offset != 0 {
			return 0, 0, StoreInvalid
		}
		return offset, length, nil
	}
	// Constant extra reads authenticate both committed prefix endpoint and the
	// immediate preceding boundary; never scan older rows or rebuild an index.
	if high > 0 {
		offset, length, e := entry(high)
		if e != nil {
			return page, e
		}
		if offset+length != dataBytes {
			return page, StoreInvalid
		}
	}
	expected := uint64(0)
	if after > 0 {
		offset, length, e := entry(after)
		if e != nil {
			return page, e
		}
		expected = offset + length
	}
	page = pageFromState(state, latest.InstanceID, after, time.Now())
	encodedRows := 0
	if q.Binding != nil {
		for seq := after + 1; seq <= high && len(page.Records) < q.Limit; seq++ {
			offset, length, e := entry(seq)
			if e != nil {
				return page, e
			}
			if offset != expected {
				return page, StoreInvalid
			}
			var prefix [4]byte
			n, e := s.readAt(data, prefix[:], int64(offset))
			if e != nil || n != 4 {
				return page, StoreInvalid
			}
			size := uint64(binary.BigEndian.Uint32(prefix[:]))
			if size == 0 || size > MaxRecordBytes || size+4 != length {
				return page, StoreInvalid
			}
			b := make([]byte, int(size))
			n, e = s.readAt(data, b, int64(offset+4))
			if e != nil || n != len(b) {
				return page, StoreInvalid
			}
			var r Record
			if e = DecodeStrict(b, &r, MaxRecordBytes); e != nil || r.Binding != binding || r.Seq != DecimalFromUint64(seq) {
				return page, StoreInvalid
			}
			// Canonical row lengths plus a small separately encoded envelope give an
			// exact response budget without repeatedly serializing the entire page.
			row, e := EncodeBounded(r, MaxRecordBytes)
			if e != nil {
				return page, StoreInvalid
			}
			view := page
			view.NextAfter = DecimalFromUint64(seq)
			view.HasMore = seq < high
			view.Records = []Record{}
			envelope, e := EncodeBounded(view, MaxResponseBytes)
			if e != nil {
				return page, StoreInvalid
			}
			commas := len(page.Records)
			if len(envelope)+encodedRows+len(row)+commas > MaxResponseBytes {
				if len(page.Records) == 0 {
					return page, StoreInvalid
				}
				break
			}
			page.Records = append(page.Records, r)
			encodedRows += len(row)
			page.NextAfter = view.NextAfter
			page.HasMore = view.HasMore
			expected = offset + length
		}
	}
	if ctx.Err() != nil {
		return page, TelemetryUnavailable
	}
	if e = s.recheck(filepath.Join(dir, "records.bin"), di); e != nil {
		return page, StoreInvalid
	}
	if e = s.recheck(filepath.Join(dir, "index.bin"), ii); e != nil {
		return page, StoreInvalid
	}
	// Appending is permitted; shrinking below the captured committed prefix is
	// not. Recheck the same handles without requiring an unchanged tail size.
	finalData, e := data.Stat()
	if e != nil || finalData.Size() < int64(dataBytes) {
		return page, StoreInvalid
	}
	finalIndex, e := index.Stat()
	if e != nil || finalIndex.Size() < int64(indexBytes) {
		return page, StoreInvalid
	}
	if e = s.recheck(filepath.Join(dir, "header.json"), headerInfo); e != nil {
		return page, StoreInvalid
	}
	var finalHeader Header
	finalInfo, e := s.readJSON(filepath.Join(dir, "header.json"), &finalHeader, MaxHeaderBytes)
	if e != nil || !os.SameFile(headerInfo, finalInfo) || finalInfo.Size() != headerInfo.Size() || !finalInfo.ModTime().Equal(headerInfo.ModTime()) || !reflect.DeepEqual(header, finalHeader) {
		return page, StoreInvalid
	}
	nowDir, e := os.Lstat(dir)
	if e != nil || !os.SameFile(dirInfo, nowDir) {
		return page, StoreInvalid
	}
	nowNS, e := os.Lstat(ns)
	if e != nil || !os.SameFile(nsInfo, nowNS) {
		return page, StoreInvalid
	}
	if _, e = EncodeBounded(page, MaxResponseBytes); e != nil {
		return page, StoreInvalid
	}
	return page, nil
}
func pageFromState(s State, latest string, after uint64, now time.Time) PageResponse {
	high, _ := s.HighWaterSeq.Uint64()
	p := PageResponse{Header: s.Header, HistoryKind: Historical, ProvenanceStatus: s.ProvenanceStatus, Collection: s.Collection, Freshness: Fresh, Timestamp: s.Timestamp, Closed: s.Closed, HighWaterSeq: s.HighWaterSeq, NextAfter: DecimalFromUint64(after), HasMore: after < high, Records: []Record{}, Pending: s.Pending, Coverage: Coverage{Unobserved: []string{"REJECT", "DNS", "EARLY_ERROR"}, Gap: s.Gap, LostTotal: s.LostTotal, LossEpoch: s.LossEpoch, LossReasons: s.LossReasons, CounterSaturated: s.CounterSaturated, Continuity: ContinuityUnknown}, DNS: DNSStatus{Status: "UNKNOWN"}}
	if s.InstanceID == latest {
		p.HistoryKind = LastRecorded
	}
	if high > 0 {
		p.HistoryStartSeq = number(1)
	}
	at, e := time.Parse(time.RFC3339Nano, s.Timestamp)
	age := now.Sub(at)
	if !s.Closed && (e != nil || age < 0 || age > TelemetryTimeout) {
		p.Freshness = Stale
		p.Collection = CollectionUnknown
		p.ProvenanceStatus = ProvenanceUnknown
		p.Coverage.Gap = true
		p.Pending = nil
		p.Coverage.LostTotal = nil
		p.Coverage.LossEpoch = nil
		p.Coverage.LossReasons = LossReasons{}
	}
	if s.Closed {
		// Persisted CLOSED is only the last saved stopped-recording state.
		// Final directory Sync/lock Close may fail after that publication,
		// with no subsequent write possible. It cannot certify completion.
		p.Freshness = FreshnessUnknown
		p.Coverage.Gap = true
		p.Pending = nil
		p.Coverage.LostTotal = nil
		p.Coverage.LossEpoch = nil
		p.Coverage.LossReasons = LossReasons{}
	}
	if s.Collection == IOFailed || s.Collection == InitFailed || s.Collection == WorkerFailed || s.Collection == IDExhausted {
		p.Coverage.Gap = true
	}
	return p
}

package connectionrecords

import (
	"context"
	"encoding/binary"
	"errors"
	"math"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const admissionStopped uint64 = 1 << 63
const (
	lossQueue = iota
	lossOversize
	lossAdmission
	lossEncoding
	lossIO
	lossWorker
	lossID
	lossShutdown
)

type queuedObservation struct {
	observation Observation
	ticket      uint64
	at          time.Time
}

// Writer owns a fixed queue and one disk worker, never an in-memory history.
// The worker exclusively owns all file handles until its actual exit.
type Writer struct {
	store                         recordStore
	header                        Header
	dir                           string
	lock, data, index             *os.File
	queue                         chan queuedObservation
	stop, done                    chan struct{}
	admission                     atomic.Uint64
	tickets, pending, lost, epoch atomic.Uint64
	reasons                       [8]atomic.Uint64
	saturated, gap                atomic.Bool
	lossWriters, lossRevision     atomic.Uint64
	collection                    atomic.Uint32
	provenance                    atomic.Uint32
	stopOnce, shutdownOnce        sync.Once
	shutdownDone                  chan struct{}
	shutdownResult                ShutdownResult
	result                        ShutdownResult // published by closing done
	high, offset, revision        uint64         // worker only
	statusBroken                  bool
	shutdownDeadline              atomic.Int64
	shutdownExpired               atomic.Bool
}

func collectionValue(v uint32) Collection {
	switch v {
	case 0:
		return Recording
	case 1:
		return Closing
	case 2:
		return Closed
	case 3:
		return IOFailed
	case 4:
		return WorkerFailed
	case 5:
		return IDExhausted
	}
	return WorkerFailed
}
func (w *Writer) fail(v uint32) {
	w.gap.Store(true)
	for {
		old := w.collection.Load()
		if old >= 3 {
			return
		}
		if w.collection.CompareAndSwap(old, v) {
			return
		}
	}
}
func (w *Writer) increment(a *atomic.Uint64) uint64 {
	for {
		n := a.Load()
		if n == math.MaxUint64 {
			w.saturated.Store(true)
			w.gap.Store(true)
			return n
		}
		if a.CompareAndSwap(n, n+1) {
			return n + 1
		}
	}
}
func (w *Writer) loss(reason int) {
	w.lossWriters.Add(1)
	w.gap.Store(true)
	w.increment(&w.lost)
	w.increment(&w.epoch)
	w.increment(&w.reasons[reason])
	w.increment(&w.lossRevision)
	w.lossWriters.Add(^uint64(0))
}
func (w *Writer) takeTicket() (uint64, bool) {
	for {
		n := w.tickets.Load()
		if n == math.MaxUint64 {
			w.fail(5)
			return 0, false
		}
		if w.tickets.CompareAndSwap(n, n+1) {
			return n + 1, true
		}
	}
}
func OpenWriter(scope Scope, header Header) (*Writer, error) {
	if os.Geteuid() != 0 {
		return nil, TelemetryUnavailable
	}
	return openWriter(defaultStore(), scope, header)
}
func openWriter(s recordStore, scope Scope, header Header) (w *Writer, result error) {
	if Validate(header) != nil || header.ConfigIdentity != scope.ConfigIdentity || header.PreviousBinding != nil {
		return nil, InvalidRequest
	}
	ns, e := s.namespace(scope, true)
	if e != nil {
		return nil, TelemetryUnavailable
	}
	lock, e := s.open(filepath.Join(ns, "writer.lock"), syscall.O_RDWR|syscall.O_CREAT)
	if e != nil {
		return nil, TelemetryUnavailable
	}
	if e = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		_ = s.close(lock)
		return nil, Busy
	}
	var data, index *os.File
	success := false
	defer func() {
		if !success {
			if data != nil {
				_ = s.close(data)
			}
			if index != nil {
				_ = s.close(index)
			}
			_ = s.close(lock)
		}
	}()
	prior, e := s.latest(ns, scope)
	if e == nil {
		b := prior.Binding
		header.PreviousBinding = &b
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, StoreInvalid
	}
	dir := filepath.Join(ns, header.InstanceID)
	if e = os.Mkdir(dir, 0700); e != nil {
		return nil, TelemetryUnavailable
	}
	if e = s.directory(dir, true); e != nil {
		return nil, StoreInvalid
	}
	if e = s.syncDir(ns); e != nil {
		return nil, TelemetryUnavailable
	}
	if e = s.publish(dir, "header.json", header, MaxHeaderBytes, true); e != nil {
		return nil, TelemetryUnavailable
	}
	data, e = s.open(filepath.Join(dir, "records.bin"), syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL)
	if e != nil {
		return nil, TelemetryUnavailable
	}
	index, e = s.open(filepath.Join(dir, "index.bin"), syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL)
	if e != nil {
		return nil, TelemetryUnavailable
	}
	if e = errors.Join(s.sync(data), s.sync(index)); e != nil {
		return nil, TelemetryUnavailable
	}
	w = &Writer{store: s, header: header, dir: dir, lock: lock, data: data, index: index, queue: make(chan queuedObservation, QueueCapacity), stop: make(chan struct{}), done: make(chan struct{}), shutdownDone: make(chan struct{})}
	if e = w.publish(); e != nil {
		return nil, TelemetryUnavailable
	}
	if e = s.publish(ns, "latest.json", Latest{SchemaVersion: 1, InstanceID: header.InstanceID}, MaxHeaderBytes, false); e != nil {
		return nil, TelemetryUnavailable
	}
	success = true
	go w.run()
	return w, nil
}

// No lock, filesystem operation, serialization, copy of strings or goroutine
// occurs in a callback. Inflight admission counts prevent close/send races.
func (w *Writer) TryAppend(o Observation) bool {
	for {
		a := w.admission.Load()
		if a&admissionStopped != 0 {
			w.loss(lossAdmission)
			return false
		}
		if w.admission.CompareAndSwap(a, a+1) {
			break
		}
	}
	defer w.admission.Add(^uint64(0))
	if w.collection.Load() >= 2 {
		w.loss(lossAdmission)
		return false
	}
	ticket, ok := w.takeTicket()
	if !ok {
		w.loss(lossID)
		return false
	}
	q := queuedObservation{o, ticket, time.Now().UTC()}
	w.pending.Add(1)
	select {
	case w.queue <- q:
		return true
	default:
		w.pending.Add(^uint64(0))
		w.loss(lossQueue)
		return false
	}
}
func (w *Writer) StopAdmission() {
	for {
		a := w.admission.Load()
		if a&admissionStopped != 0 {
			return
		}
		if w.admission.CompareAndSwap(a, a|admissionStopped) {
			return
		}
	}
}
func (w *Writer) SetProvenanceStatus(p ProvenanceStatus) {
	var n uint32
	switch p {
	case ProvenanceVerified:
		n = 1
	case ProvenanceMismatch:
		n = 2
	case ProvenanceUnknown:
		n = 0
	default:
		return
	}
	// Mismatch is latched and cannot be upgraded by a later normal callback.
	for {
		old := w.provenance.Load()
		if old == 2 {
			return
		}
		if n == 1 && old != 0 {
			return
		}
		if w.provenance.CompareAndSwap(old, n) {
			return
		}
	}
}
func number(n uint64) *Decimal { d := DecimalFromUint64(n); return &d }
func (w *Writer) snapshot() State {
	var p ProvenanceStatus = ProvenanceUnknown
	switch w.provenance.Load() {
	case 1:
		p = ProvenanceVerified
	case 2:
		p = ProvenanceMismatch
	}
	revision := w.lossRevision.Load()
	active := w.lossWriters.Load()
	r := LossReasons{number(w.reasons[0].Load()), number(w.reasons[1].Load()), number(w.reasons[2].Load()), number(w.reasons[3].Load()), number(w.reasons[4].Load()), number(w.reasons[5].Load()), number(w.reasons[6].Load()), number(w.reasons[7].Load())}
	lost, epoch := w.lost.Load(), w.epoch.Load()
	total, epochValue := number(lost), number(epoch)
	uncertain := active != 0 || w.lossWriters.Load() != 0 || w.lossRevision.Load() != revision || revision == math.MaxUint64
	if uncertain {
		r = LossReasons{}
		total = nil
		epochValue = nil
		w.gap.Store(true)
	}
	c := w.collection.Load()
	return State{Header: w.header, Revision: DecimalFromUint64(w.revision), HighWaterSeq: DecimalFromUint64(w.high), CommittedDataBytes: DecimalFromUint64(w.offset), CommittedIndexBytes: DecimalFromUint64(w.high * IndexEntryBytes), Collection: collectionValue(c), ProvenanceStatus: p, Pending: number(w.pending.Load()), LostTotal: total, LossEpoch: epochValue, LossReasons: r, CounterSaturated: w.saturated.Load(), Gap: w.gap.Load() || lost != 0 || uncertain || c >= 3, Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Closed: c == 2}
}
func (w *Writer) publish() error {
	if w.statusBroken {
		return StoreInvalid
	}
	info, err := w.lock.Stat()
	if err == nil {
		err = w.store.recheck(w.lock.Name(), info)
	}
	if err != nil {
		w.statusBroken = true
		w.fail(3)
		return err
	}
	if w.revision == math.MaxUint64 {
		w.fail(5)
		w.statusBroken = true
		return StoreInvalid
	}
	w.revision++
	e := w.store.publish(w.dir, "state.json", w.snapshot(), MaxStateBytes, false)
	if e != nil {
		w.statusBroken = true
		w.fail(3)
	}
	return e
}
func (w *Writer) freeze(q queuedObservation, seq uint64) Record {
	o := q.observation
	return Record{SchemaVersion: 1, Binding: w.header.Binding, Seq: DecimalFromUint64(seq), ObservationID: DecimalFromUint64(q.ticket), ObservedAt: q.at.Format(time.RFC3339Nano), Event: "ROUTED", Hook: o.Hook, Network: o.Network, Destination: o.Destination, OriginDestination: o.OriginDestination, RouteOriginalDestination: o.RouteOriginalDestination, Route: o.Route, State: "ROUTED"}
}
func (w *Writer) discard(reason int) {
	for {
		select {
		case <-w.queue:
			w.pending.Add(^uint64(0))
			w.loss(reason)
		default:
			return
		}
	}
}
func (w *Writer) run() {
	batch := make([]queuedObservation, 0, BatchRecords)
	// A panic is a recording failure only; disk ownership still ends here.
	defer func() {
		if recover() != nil {
			w.fail(4)
			batch = nil
		}
		w.StopAdmission()
		// Existing callbacks only do atomics/select. Never close their channel.
		for w.admission.Load()&^admissionStopped != 0 {
			time.Sleep(time.Millisecond)
		}
		reason := lossShutdown
		if w.collection.Load() == 4 {
			reason = lossWorker
		} else if w.collection.Load() == 5 {
			reason = lossID
		} else if w.collection.Load() >= 3 {
			reason = lossIO
		}
		w.discard(reason)
		// A panic can leave the worker's bounded batch unresolved. The queue is now
		// empty and admission quiescent, so this remainder is known, not crash guesswork.
		for n := w.pending.Swap(0); n > 0; n-- {
			w.loss(reason)
		}
		closeErr := errors.Join(w.store.close(w.data), w.store.close(w.index))
		if closeErr != nil {
			w.fail(3)
		}
		if w.collection.Load() < 2 {
			w.collection.Store(2)
		}
		if e := w.publish(); e != nil {
			w.fail(3)
			closeErr = errors.Join(closeErr, e)
		}
		cleanup := CleanupVerified
		code := NoError
		if w.collection.Load() >= 3 {
			code = TelemetryUnavailable
		}
		if closeErr != nil {
			cleanup = CleanupUnknown
		}
		// No handle is used after its one close attempt, including error outcomes.
		if e := w.store.close(w.lock); e != nil {
			cleanup = CleanupUnknown
			code = TelemetryUnavailable
			w.fail(3)
		}
		// Release the bounded queue/batch references after actual worker exit; no
		// event metadata is retained as an accidental post-shutdown memory history.
		clear(batch)
		w.result = ShutdownResult{collectionValue(w.collection.Load()), cleanup, code}
		close(w.done)
	}()
	ticker := time.NewTicker(StatusInterval)
	defer ticker.Stop()
	finalBatch := func() {
		if w.collection.Load() < 2 {
			w.collection.CompareAndSwap(0, 1)
			if e := w.publish(); e != nil {
				return
			}
			for len(batch) < BatchRecords {
				select {
				case q := <-w.queue:
					batch = append(batch, q)
				default:
					goto finalCommit
				}
			}
		}
	finalCommit:
		if len(batch) > 0 {
			w.commit(batch)
			clear(batch)
			batch = batch[:0]
		}
	}
	for {
		// Once shutdown is requested, do not start another ordinary batch even if
		// both the queue and stop signal are ready in the same scheduler turn.
		select {
		case <-w.stop:
			finalBatch()
			return
		default:
		}
		select {
		case <-w.stop:
			finalBatch()
			return
		case q := <-w.queue:
			if w.collection.Load() >= 3 {
				w.pending.Add(^uint64(0))
				w.loss(lossAdmission)
				return
			}
			batch = append(batch, q)
			if len(batch) == BatchRecords {
				w.commit(batch)
				clear(batch)
				batch = batch[:0]
				if w.collection.Load() >= 3 {
					return
				}
			}
		case <-ticker.C:
			revision := w.revision
			if len(batch) > 0 {
				w.commit(batch)
				clear(batch)
				batch = batch[:0]
			}
			if w.collection.Load() >= 3 {
				return
			}
			// A successful commit already published this tick's state. Keep
			// the heartbeat when idle or when every queued record was rejected.
			if w.revision != revision {
				continue
			}
			if e := w.publish(); e != nil {
				return
			}
		}
	}
}
func (w *Writer) commit(batch []queuedObservation) {
	if w.collection.Load() >= 3 {
		reason := lossIO
		if w.collection.Load() == 4 {
			reason = lossWorker
		} else if w.collection.Load() == 5 {
			reason = lossID
		}
		for range batch {
			w.pending.Add(^uint64(0))
			w.loss(reason)
		}
		return
	}
	for _, f := range []*os.File{w.data, w.index} {
		info, e := f.Stat()
		if e == nil {
			e = w.store.recheck(f.Name(), info)
		}
		if e != nil {
			w.fail(3)
			for range batch {
				w.pending.Add(^uint64(0))
				w.loss(lossIO)
			}
			return
		}
	}
	high, offset := w.high, w.offset
	if high > uint64(math.MaxInt64/IndexEntryBytes) || offset > math.MaxInt64 {
		w.fail(5)
		for range batch {
			w.pending.Add(^uint64(0))
			w.loss(lossID)
		}
		return
	}
	if di, e := w.data.Stat(); e != nil || di.Size() != int64(offset) {
		w.fail(3)
		for range batch {
			w.pending.Add(^uint64(0))
			w.loss(lossIO)
		}
		return
	}
	if ii, e := w.index.Stat(); e != nil || ii.Size() != int64(high*IndexEntryBytes) {
		w.fail(3)
		for range batch {
			w.pending.Add(^uint64(0))
			w.loss(lossIO)
		}
		return
	}
	accepted := 0
	var entries [BatchRecords * IndexEntryBytes]byte
	discard := func(n, reason int) {
		for i := 0; i < n; i++ {
			w.pending.Add(^uint64(0))
			w.loss(reason)
		}
	}
	for i, q := range batch {
		if deadline := w.shutdownDeadline.Load(); w.shutdownExpired.Load() || deadline != 0 && time.Now().UnixNano() >= deadline {
			w.gap.Store(true)
			discard(len(batch)-i, lossShutdown)
			break
		}
		if high >= uint64(math.MaxInt64/IndexEntryBytes) || high == math.MaxUint64 {
			w.fail(5)
			discard(len(batch)-i, lossID)
			break
		}
		b, e := EncodeBounded(w.freeze(q, high+1), MaxRecordBytes)
		if errors.Is(e, ErrTooLarge) {
			discard(1, lossOversize)
			continue
		}
		if e != nil {
			w.fail(4)
			discard(len(batch)-i, lossEncoding)
			break
		}
		length := uint64(len(b) + 4)
		if offset > math.MaxInt64-length {
			w.fail(5)
			discard(len(batch)-i, lossID)
			break
		}
		var prefix [4]byte
		binary.BigEndian.PutUint32(prefix[:], uint32(len(b)))
		e = w.store.writeAll(w.data, prefix[:])
		if e == nil {
			e = w.store.writeAll(w.data, b)
		}
		if e != nil {
			w.fail(3)
			discard(len(batch)-i, lossIO)
			break
		}
		entry := entries[accepted*IndexEntryBytes : (accepted+1)*IndexEntryBytes]
		binary.BigEndian.PutUint64(entry[:8], offset)
		binary.BigEndian.PutUint64(entry[8:], length)
		high++
		offset += length
		accepted++
	}
	if accepted == 0 {
		return
	}
	if w.collection.Load() >= 3 {
		reason := lossIO
		if w.collection.Load() == 4 {
			reason = lossEncoding
		} else if w.collection.Load() == 5 {
			reason = lossID
		}
		discard(accepted, reason)
		return
	}
	// All complete data frames precede all complete disk-index entries.
	e := w.store.writeAll(w.index, entries[:accepted*IndexEntryBytes])
	if e == nil {
		e = errors.Join(w.store.sync(w.data), w.store.sync(w.index))
	}
	if e != nil {
		w.fail(3)
		discard(accepted, lossIO)
		return
	}
	// Never retry an uncertain state publication, or expose its tail via a later
	// status revision. Disk readers independently validate whatever became visible.
	oldHigh, oldOffset := w.high, w.offset
	w.high, w.offset = high, offset
	for i := 0; i < accepted; i++ {
		w.pending.Add(^uint64(0))
	}
	if e = w.publish(); e != nil {
		w.high, w.offset = oldHigh, oldOffset
		for i := 0; i < accepted; i++ {
			w.loss(lossIO)
		}
	}
}
func (w *Writer) Shutdown(ctx context.Context) ShutdownResult {
	w.shutdownOnce.Do(func() {
		budget, cancel := context.WithTimeout(ctx, TelemetryTimeout)
		deadline, _ := budget.Deadline()
		w.shutdownDeadline.Store(deadline.UnixNano())
		w.StopAdmission()
		w.stopOnce.Do(func() { close(w.stop) })
		go func() {
			defer cancel()
			defer close(w.shutdownDone)
			select {
			case <-w.done:
				w.shutdownResult = w.result
			case <-budget.Done():
				w.shutdownExpired.Store(true)
				select {
				case <-w.done:
					w.shutdownResult = w.result
				default:
					w.gap.Store(true)
					w.shutdownResult = ShutdownResult{collectionValue(w.collection.Load()), CleanupUnknown, TelemetryUnavailable}
				}
			}
		}()
	})
	<-w.shutdownDone
	return w.shutdownResult
}

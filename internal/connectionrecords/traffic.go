package connectionrecords

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// PublishTraffic reuses the already-open records writer authority and safe fixed
// directory; the caller owns serialization frequency, never the data callbacks.
// Call only from one reporter; stop it before shutting down Writer.
func (w *Writer) PublishTraffic(value any, budget int) error {
	if w == nil || w.admission.Load()&admissionStopped != 0 {
		return TelemetryUnavailable
	}
	info, e := w.lock.Stat()
	if e != nil {
		return e
	}
	if e = w.store.recheck(w.lock.Name(), info); e != nil {
		return e
	}
	return w.store.publish(w.dir, "traffic.json", value, budget, false)
}

// ReadTraffic does not treat latest.json as liveness: a live root writer must
// hold the namespace lock, state must be current/not closed, and both header
// reads must name exactly the same immutable run. Never adopts an old run.
// OpenTrafficLease binds liveness to this exact instance, not merely a newer
// namespace writer which may be in the middle of replacing latest.json.
func (w *Writer) OpenTrafficLease() (*os.File, error) {
	if w == nil || w.admission.Load()&admissionStopped != 0 || w.collection.Load() != 0 {
		return nil, TelemetryUnavailable
	}
	info, e := w.lock.Stat()
	if e != nil {
		return nil, e
	}
	if e = w.store.recheck(w.lock.Name(), info); e != nil {
		return nil, e
	}
	f, e := w.store.open(filepath.Join(w.dir, "traffic.lock"), syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL)
	if e != nil {
		return nil, e
	}
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		f.Close()
		return nil, e
	}
	return f, nil
}
func (w *Writer) TrafficHeader() Header { return w.header }
func trafficSameHeader(a, b Header) bool {
	if a.SchemaVersion != b.SchemaVersion || a.ConfigIdentity != b.ConfigIdentity || a.Binding != b.Binding || a.RuntimeSHA256 != b.RuntimeSHA256 || a.CreatedAt != b.CreatedAt {
		return false
	}
	if a.PreviousBinding == nil || b.PreviousBinding == nil {
		return a.PreviousBinding == nil && b.PreviousBinding == nil
	}
	return *a.PreviousBinding == *b.PreviousBinding
}
func ReadTraffic(ctx context.Context, scope Scope, out any, budget int) (Header, error) {
	if os.Geteuid() != 0 {
		return Header{}, TelemetryUnavailable
	}
	return readTraffic(ctx, defaultStore(), scope, out, budget)
}
func readTraffic(ctx context.Context, s recordStore, scope Scope, out any, budget int) (Header, error) {
	var empty Header
	if ctx.Err() != nil {
		return empty, TelemetryUnavailable
	}
	ns, e := s.namespace(scope, false)
	if e != nil {
		return empty, e
	}
	lock, e := s.open(filepath.Join(ns, "writer.lock"), syscall.O_RDONLY)
	if e != nil {
		return empty, e
	}
	defer lock.Close()
	alive := func() bool {
		info, e := lock.Stat()
		if e != nil || s.recheck(lock.Name(), info) != nil {
			return false
		}
		e = syscall.Flock(int(lock.Fd()), syscall.LOCK_SH|syscall.LOCK_NB)
		if e == nil {
			syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
			return false
		}
		return errors.Is(e, syscall.EWOULDBLOCK) || errors.Is(e, syscall.EAGAIN)
	}
	if !alive() {
		return empty, TelemetryUnavailable
	}
	header, e := s.latest(ns, scope)
	if e != nil {
		return empty, e
	}
	dir := filepath.Join(ns, header.InstanceID)
	lease, e := s.open(filepath.Join(dir, "traffic.lock"), syscall.O_RDONLY)
	if e != nil {
		return empty, e
	}
	defer lease.Close()
	leaseAlive := func() bool {
		info, e := lease.Stat()
		if e != nil || s.recheck(lease.Name(), info) != nil {
			return false
		}
		e = syscall.Flock(int(lease.Fd()), syscall.LOCK_SH|syscall.LOCK_NB)
		if e == nil {
			syscall.Flock(int(lease.Fd()), syscall.LOCK_UN)
			return false
		}
		return errors.Is(e, syscall.EWOULDBLOCK) || errors.Is(e, syscall.EAGAIN)
	}
	if !leaseAlive() {
		return empty, TelemetryUnavailable
	}
	var state State
	if _, e = s.readJSON(filepath.Join(dir, "state.json"), &state, MaxStateBytes); e != nil {
		return empty, e
	}
	at, e := time.Parse(time.RFC3339Nano, state.Timestamp)
	if e != nil || time.Since(at) < 0 || time.Since(at) > 15*time.Second || state.Closed || state.Collection != Recording || !trafficSameHeader(state.Header, header) {
		return empty, TelemetryUnavailable
	}
	if _, e = s.readJSON(filepath.Join(dir, "traffic.json"), out, budget); e != nil {
		return empty, e
	}
	again, e := s.latest(ns, scope)
	if e != nil || !trafficSameHeader(again, header) || !alive() || !leaseAlive() || ctx.Err() != nil {
		return empty, TelemetryUnavailable
	}
	return header, nil
}

package telemetry

import (
	"context"
	"errors"
	"os"
	"sort"
	"sync"
	"time"
)

const Endpoint = "https://www.gstatic.com/generate_204"
const Interval = time.Minute
const Timeout = 8 * time.Second
const MaxSamples = 1441

type sample struct {
	Start        time.Time `json:"start"`
	End          time.Time `json:"end"`
	Outcome      string    `json:"outcome"`
	ElapsedNS    int64     `json:"elapsed_ns,omitempty"`
	ClockUnknown bool      `json:"clock_unknown,omitempty"`
}

type Traffic struct {
	Quality               string   `json:"quality"`
	Scope                 string   `json:"scope"`
	DownloadBPS           *float64 `json:"download_bps"`
	UploadBPS             *float64 `json:"upload_bps"`
	RecordedDownloadBytes *string  `json:"recorded_download_bytes"`
	RecordedUploadBytes   *string  `json:"recorded_upload_bytes"`
	RecordedSeconds       float64  `json:"recorded_seconds"`
}
type Network struct {
	Scope                string     `json:"scope"`
	Target               string     `json:"target"`
	IntervalSeconds      int        `json:"interval_seconds"`
	TimeoutSeconds       int        `json:"timeout_seconds"`
	Quality              string     `json:"quality"`
	State                string     `json:"state"`
	LatestCheckedAt      *time.Time `json:"latest_checked_at"`
	LatencyMS            *float64   `json:"latency_ms"`
	LatestError          *string    `json:"latest_error"`
	Attempts             int        `json:"attempts"`
	Succeeded            int        `json:"succeeded"`
	SampleSuccessRatio   *float64   `json:"sample_success_ratio"`
	Availability24h      *float64   `json:"availability_24h"`
	ObservedProbeSeconds float64    `json:"observed_probe_seconds"`
	HistoryStatus        string     `json:"history_status"`
	ClockStatus          string     `json:"clock_status"`
}
type Window struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}
type Bin struct {
	Start                time.Time `json:"start"`
	End                  time.Time `json:"end"`
	Attempts             int       `json:"attempts"`
	Succeeded            int       `json:"succeeded"`
	ObservedProbeSeconds float64   `json:"observed_probe_seconds"`
	DownloadBytes        *string   `json:"download_bytes"`
	UploadBytes          *string   `json:"upload_bytes"`
	TrafficQuality       string    `json:"traffic_quality"`
}
type Snapshot struct {
	SchemaVersion int       `json:"schema_version"`
	GeneratedAt   time.Time `json:"generated_at"`
	Traffic       Traffic   `json:"traffic"`
	Network       Network   `json:"network"`
	Window        Window    `json:"window"`
	Bins          []Bin     `json:"bins"`
}

// Store retains fixed-target probe completions, not VPN counters. Record is
// called by one serial sampler. The mutex protects memory only; one coalescing
// writer owns filesystem IO. Clock steps retain outcomes but mark wall coverage unknown.
type Store struct {
	mu             sync.Mutex
	rows           []sample
	path           string
	historyStatus  string
	dir            *os.File
	leaf           string
	wake           chan struct{}
	writerDone     chan struct{}
	closing        bool
	persistVersion uint64
	savedVersion   uint64
	lastEnd        time.Time
	// Test-only injection is assigned before the first Record; production uses File.Sync.
	syncFile func(*os.File) error
}

func New(path string) *Store {
	s := &Store{path: path, historyStatus: "MEMORY_ONLY"}
	if path != "" {
		s.load()
	}
	if s.dir != nil {
		s.wake = make(chan struct{}, 1)
		s.writerDone = make(chan struct{})
		go s.writer()
	}
	return s
}
func (s *Store) Record(start, end time.Time, err error) {
	elapsed := end.Sub(start)
	// Two timeout budgets tolerate scheduler/cleanup overhead without dropping a
	// genuine deadline completion; its actual interval is still reported literally.
	if start.IsZero() || end.Before(start) || end.Sub(start) > 2*Timeout {
		return
	}
	outcome := "OK"
	if errors.Is(err, context.DeadlineExceeded) {
		outcome = "TIMEOUT"
	} else if err != nil {
		outcome = "HTTPS_FAILED"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		return
	}
	unknown := end.UTC().Sub(start.UTC()) != elapsed
	if !s.lastEnd.IsZero() && start.Sub(s.lastEnd) != start.UTC().Sub(s.lastEnd.UTC()) {
		unknown = true
	}
	if !s.lastEnd.IsZero() && start.Before(s.lastEnd) {
		return
	}
	if n := len(s.rows); n > 0 && start.UTC().Before(s.rows[n-1].End) {
		unknown = true
	}
	s.lastEnd = end
	start, end = start.UTC(), end.UTC()
	s.rows = append(s.rows, sample{Start: start, End: end, Outcome: outcome, ElapsedNS: int64(elapsed), ClockUnknown: unknown})
	first := 0
	for first < len(s.rows) && !s.rows[first].End.After(end.Add(-24*time.Hour)) {
		first++
	}
	if len(s.rows)-first > MaxSamples {
		first = len(s.rows) - MaxSamples
	}
	s.rows = append([]sample(nil), s.rows[first:]...)
	if s.wake != nil {
		s.persistVersion++
		s.historyStatus = "PENDING"
		select {
		case s.wake <- struct{}{}:
		default:
		}
	}
}
func (s *Store) Snapshot(now time.Time) Snapshot {
	now = now.UTC()
	begin := now.Add(-24 * time.Hour)
	g := Snapshot{SchemaVersion: 1, GeneratedAt: now, Window: Window{begin, now},
		Traffic: Traffic{Quality: "NOT_OBSERVED", Scope: "VPN_TRACKER_NOT_CONNECTED"},
		Network: Network{Scope: "WEBUI_SYSTEM_PATH_HTTPS", Target: Endpoint, IntervalSeconds: 60, TimeoutSeconds: 8, Quality: "NOT_OBSERVED", State: "NOT_OBSERVED", HistoryStatus: "MEMORY_ONLY"},
		Bins:    make([]Bin, 288)}
	g.Network.ClockStatus = "OK"
	for i := range g.Bins {
		g.Bins[i] = Bin{Start: begin.Add(time.Duration(i) * 5 * time.Minute), End: begin.Add(time.Duration(i+1) * 5 * time.Minute), TrafficQuality: "NOT_OBSERVED"}
	}
	if s == nil {
		return g
	}
	s.mu.Lock()
	rows := append([]sample(nil), s.rows...)
	g.Network.HistoryStatus = s.historyStatus
	s.mu.Unlock()
	coverage := make([]Window, 0, len(rows))
	for _, row := range rows {
		if row.ClockUnknown {
			g.Network.ClockStatus = "DISCONTINUITY"
		}
		if !row.End.After(begin) || row.End.After(now) {
			continue
		}
		g.Network.Attempts++
		if row.Outcome == "OK" {
			g.Network.Succeeded++
		}
		index := int(row.End.Sub(begin) / (5 * time.Minute))
		if index >= len(g.Bins) {
			index = len(g.Bins) - 1
		}
		g.Bins[index].Attempts++
		if row.Outcome == "OK" {
			g.Bins[index].Succeeded++
		}
		if row.ClockUnknown {
			g.Network.ClockStatus = "DISCONTINUITY"
		}
		if !row.ClockUnknown && row.End.After(row.Start) {
			coverage = append(coverage, Window{row.Start, row.End})
		}
		// Only retained past completions can establish a latest result.
		checked := row.End
		g.Network.LatestCheckedAt = &checked
		g.Network.State = "FAILED"
		g.Network.LatencyMS = nil
		if row.Outcome == "OK" {
			ms := float64(row.ElapsedNS) / float64(time.Millisecond)
			g.Network.State = "OK"
			g.Network.LatencyMS = &ms
			g.Network.LatestError = nil
		} else {
			outcome := row.Outcome
			g.Network.LatestError = &outcome
		}
	}
	// Wall placement need not follow completion order after a clock rollback.
	// Union all known intervals before clipping them into the rolling bins.
	sort.Slice(coverage, func(i, j int) bool { return coverage[i].Start.Before(coverage[j].Start) })
	merged := coverage[:0]
	for _, interval := range coverage {
		if n := len(merged); n > 0 && !interval.Start.After(merged[n-1].End) {
			if interval.End.After(merged[n-1].End) {
				merged[n-1].End = interval.End
			}
		} else {
			merged = append(merged, interval)
		}
	}
	for _, interval := range merged {
		for i := range g.Bins {
			b := &g.Bins[i]
			left, right := interval.Start, interval.End
			if left.Before(b.Start) {
				left = b.Start
			}
			if right.After(b.End) {
				right = b.End
			}
			if right.After(left) {
				d := right.Sub(left).Seconds()
				b.ObservedProbeSeconds += d
				g.Network.ObservedProbeSeconds += d
			}
		}
	}
	if g.Network.Attempts > 0 {
		ratio := float64(g.Network.Succeeded) / float64(g.Network.Attempts)
		g.Network.SampleSuccessRatio = &ratio
		g.Network.Quality = "PARTIAL"
	}
	if g.Network.LatestCheckedAt != nil && now.Sub(*g.Network.LatestCheckedAt) > 2*Interval+Timeout {
		g.Network.State = "STALE"
		g.Network.LatencyMS = nil
	}
	return g
}

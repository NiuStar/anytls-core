// Package connectionrecords defines the private, route-only recording contract.
// It has no SDK dependency and performs no filesystem or network operations.
package connectionrecords

import (
	"context"
	"errors"
	"strconv"
	"time"
)

const (
	SchemaVersion    = 1
	QueueCapacity    = 256
	MaxRecordBytes   = 256 * 1024
	MaxHeaderBytes   = 8 * 1024
	MaxStateBytes    = 8 * 1024
	MaxRequestBytes  = 8 * 1024
	MaxResponseBytes = 1024 * 1024
	MaxPageLimit     = 500
	DefaultPageLimit = 100
	BatchRecords     = 100
	IndexEntryBytes  = 16
	TelemetryTimeout = 5 * time.Second
	StatusInterval   = time.Second
)

type Decimal string

func DecimalFromUint64(n uint64) Decimal { return Decimal(strconv.FormatUint(n, 10)) }
func (d Decimal) Uint64() (uint64, error) {
	if len(d) == 0 || (len(d) > 1 && d[0] == '0') {
		return 0, ErrInvalid
	}
	for i := range d {
		if d[i] < '0' || d[i] > '9' {
			return 0, ErrInvalid
		}
	}
	n, err := strconv.ParseUint(string(d), 10, 64)
	if err != nil {
		return 0, ErrInvalid
	}
	return n, nil
}

var (
	ErrInvalid  = errors.New("connectionrecords: invalid value")
	ErrTooLarge = errors.New("connectionrecords: byte budget exceeded")
)

type Collection string

const (
	Recording         Collection = "RECORDING"
	Closing           Collection = "CLOSING"
	Closed            Collection = "CLOSED"
	IOFailed          Collection = "IO_FAILED"
	InitFailed        Collection = "INIT_FAILED"
	WorkerFailed      Collection = "WORKER_FAILED"
	IDExhausted       Collection = "ID_EXHAUSTED"
	CollectionUnknown Collection = "UNKNOWN"
)

type ProvenanceStatus string

const (
	ProvenanceVerified ProvenanceStatus = "VERIFIED"
	ProvenanceMismatch ProvenanceStatus = "MISMATCH"
	ProvenanceUnknown  ProvenanceStatus = "UNKNOWN"
)

type CleanupState string

const (
	CleanupVerified CleanupState = "VERIFIED"
	CleanupUnknown  CleanupState = "UNKNOWN"
	CleanupFailed   CleanupState = "FAILED"
)

type ErrorCode string

const (
	NoError              ErrorCode = ""
	InvalidRequest       ErrorCode = "INVALID_REQUEST"
	Forbidden            ErrorCode = "FORBIDDEN"
	Busy                 ErrorCode = "BUSY"
	StaleGeneration      ErrorCode = "STALE_GENERATION"
	TelemetryUnavailable ErrorCode = "TELEMETRY_UNAVAILABLE"
	StoreInvalid         ErrorCode = "STORE_INVALID"
	Unsupported          ErrorCode = "UNSUPPORTED"
)

func (e ErrorCode) Error() string { return string(e) }

type Hook string

const (
	HookTCP  Hook = "tcp"
	HookUDP  Hook = "udp"
	HookFlow Hook = "flow"
)

type Network string

const (
	NetworkTCP     Network = "tcp"
	NetworkUDP     Network = "udp"
	NetworkUnknown Network = "UNKNOWN"
)

type HostSource string

const (
	HostDestination HostSource = "DESTINATION_FQDN"
	HostMetadata    HostSource = "METADATA_DOMAIN"
	HostUnknown     HostSource = "UNKNOWN"
)

type TerminalKind string

const (
	TerminalDirect  TerminalKind = "DIRECT"
	TerminalNode    TerminalKind = "NODE"
	TerminalUnknown TerminalKind = "UNKNOWN"
)

type RuleKind string

const (
	RuleDomain       RuleKind = "DOMAIN"
	RuleDomainSuffix RuleKind = "DOMAIN-SUFFIX"
	RuleIPCIDR       RuleKind = "IP-CIDR"
	RuleSet          RuleKind = "RULE-SET"
	RuleMatch        RuleKind = "MATCH"
	RuleDefault      RuleKind = "DEFAULT_SELECTED"
	RuleUnknown      RuleKind = "UNKNOWN"
)

type SyntheticKind string

const (
	SyntheticNone    SyntheticKind = "NONE"
	SyntheticSniff   SyntheticKind = "SNIFF"
	SyntheticResolve SyntheticKind = "RESOLVE"
	SyntheticHijack  SyntheticKind = "HIJACK"
)

type HistoryKind string

const (
	LastRecorded HistoryKind = "LAST_RECORDED"
	Historical   HistoryKind = "HISTORICAL"
)

type Freshness string

const (
	Fresh            Freshness = "FRESH"
	Stale            Freshness = "STALE"
	FreshnessUnknown Freshness = "UNKNOWN"
)

type Continuity string

const (
	ContinuityUnknown Continuity = "UNKNOWN"
	ContinuityClosed  Continuity = "CLOSED"
)

type Binding struct {
	InstanceID string `json:"instance_id"`
	Generation string `json:"generation"`
	ManifestID string `json:"manifest_id"`
}
type Scope struct {
	UID            uint32
	ConfigIdentity string
}
type Header struct {
	SchemaVersion  int    `json:"schema_version"`
	ConfigIdentity string `json:"config_identity"`
	Binding
	RuntimeSHA256   string   `json:"runtime_sha256"`
	CreatedAt       string   `json:"created_at"`
	PreviousBinding *Binding `json:"previous_binding"`
}
type Latest struct {
	SchemaVersion int    `json:"schema_version"`
	InstanceID    string `json:"instance_id"`
}

// CapturedSources and Manifest are memory-only; never persist or expose them.
// An absent source has Present=false and SHA256=nil, distinct from empty bytes.
type SourceKind string

const (
	SourceConfig    SourceKind = "CONFIG"
	SourceSelection SourceKind = "SELECTION"
	SourceRuleSet   SourceKind = "RULE_SET"
	SourceCA        SourceKind = "CA"
)

type CapturedSource struct {
	Kind    SourceKind `json:"kind"`
	Ordinal int        `json:"ordinal"`
	Present bool       `json:"present"`
	SHA256  *string    `json:"sha256"`
}
type GroupEdge struct {
	Group    string `json:"group"`
	Selected string `json:"selected"`
}
type Condition struct {
	Kind  RuleKind `json:"kind"`
	Value string   `json:"value"`
}
type RuleSetProjection struct {
	Label  string `json:"label"`
	SHA256 string `json:"sha256"`
}
type RouteProjection struct {
	Evidence            ProvenanceStatus   `json:"evidence"`
	SourceID            *string            `json:"source_id"`
	SourceIndex         *int               `json:"source_index"`
	Kind                RuleKind           `json:"kind"`
	Condition           *Condition         `json:"condition"`
	RuleSet             *RuleSetProjection `json:"rule_set"`
	ConfiguredTarget    *string            `json:"configured_target"`
	GroupPath           []GroupEdge        `json:"group_path"`
	TerminalKind        TerminalKind       `json:"terminal_kind"`
	FinalNodeID         *string            `json:"final_node_id"`
	FinalNodeLabel      *string            `json:"final_node_label"`
	OutboundTag         string             `json:"outbound_tag"`
	OutboundType        string             `json:"outbound_type"`
	SelectionGeneration *string            `json:"selection_generation"`
}
type RuleOrigin struct {
	Type             string          `json:"type"`
	ActionType       string          `json:"action_type"`
	ExpectedOutbound string          `json:"expected_outbound"`
	Synthetic        SyntheticKind   `json:"synthetic"`
	Route            RouteProjection `json:"route"`
}
type OutboundOrigin struct {
	Tag          string       `json:"tag"`
	Type         string       `json:"type"`
	TerminalKind TerminalKind `json:"terminal_kind"`
	NodeID       *string      `json:"node_id"`
	NodeLabel    *string      `json:"node_label"`
}
type Manifest struct {
	SchemaVersion int `json:"schema_version"`
	Binding
	SelectionGeneration string           `json:"selection_generation"`
	RuntimeSHA256       string           `json:"runtime_sha256"`
	CapturedSources     []CapturedSource `json:"captured_sources"`
	Rules               []RuleOrigin     `json:"rules"`
	FinalOrigin         RouteProjection  `json:"final_origin"`
	Outbounds           []OutboundOrigin `json:"outbounds"`
}

type Destination struct {
	Host       *string    `json:"host"`
	IP         *string    `json:"ip"`
	Port       *uint16    `json:"port"`
	HostSource HostSource `json:"host_source"`
}

// Observation is a small immutable whitelist projection. The sink owns ticket,
// receipt time and all loss accounting; callers must not double-count false.
type Observation struct {
	Hook                     Hook
	Network                  Network
	Destination              Destination
	OriginDestination        *Destination
	RouteOriginalDestination *Destination
	Route                    RouteProjection
}
type Sink interface{ TryAppend(Observation) bool }

// Optional; engine reports initial binding failure even if no callback follows.
type ProvenanceReporter interface{ SetProvenanceStatus(ProvenanceStatus) }

// Writer is implemented by owner B. No duplicate placeholder Writer is declared.
type WriterAPI interface {
	Sink
	StopAdmission()
	Shutdown(context.Context) ShutdownResult
}
type ShutdownResult struct {
	Collection Collection
	Cleanup    CleanupState
	ErrorCode  ErrorCode
}
type Record struct {
	SchemaVersion int `json:"schema_version"`
	Binding
	Seq                      Decimal         `json:"seq"`
	ObservationID            Decimal         `json:"observation_id"`
	ObservedAt               string          `json:"observed_at"`
	Event                    string          `json:"event"`
	Hook                     Hook            `json:"hook"`
	Network                  Network         `json:"network"`
	Destination              Destination     `json:"destination"`
	OriginDestination        *Destination    `json:"origin_destination"`
	RouteOriginalDestination *Destination    `json:"route_original_destination"`
	Route                    RouteProjection `json:"route"`
	State                    string          `json:"state"`
	Connected                *bool           `json:"connected"`
	Active                   *bool           `json:"active"`
	Duration                 *Decimal        `json:"duration"`
	EndedAt                  *string         `json:"ended_at"`
	Error                    *string         `json:"error"`
}

// Fixed counters; nil means UNKNOWN, never an invented zero.
type LossReasons struct {
	QueueFull         *Decimal `json:"queue_full"`
	Oversize          *Decimal `json:"oversize"`
	AdmissionClosed   *Decimal `json:"admission_closed"`
	EncodingFailed    *Decimal `json:"encoding_failed"`
	IOFailed          *Decimal `json:"io_failed"`
	WorkerFailed      *Decimal `json:"worker_failed"`
	IDExhausted       *Decimal `json:"id_exhausted"`
	ShutdownDiscarded *Decimal `json:"shutdown_discarded"`
}
type State struct {
	Header
	Revision            Decimal          `json:"revision"`
	HighWaterSeq        Decimal          `json:"high_water_seq"`
	CommittedDataBytes  Decimal          `json:"committed_data_bytes"`
	CommittedIndexBytes Decimal          `json:"committed_index_bytes"`
	Collection          Collection       `json:"collection"`
	ProvenanceStatus    ProvenanceStatus `json:"provenance_status"`
	Pending             *Decimal         `json:"pending"`
	LostTotal           *Decimal         `json:"lost_total"`
	LossEpoch           *Decimal         `json:"loss_epoch"`
	LossReasons         LossReasons      `json:"loss_reasons"`
	CounterSaturated    bool             `json:"counter_saturated"`
	Gap                 bool             `json:"gap"`
	Timestamp           string           `json:"timestamp"`
	Closed              bool             `json:"closed"`
}

// Binding=nil means discovery. The codec flattens three explicit nullable keys.
type PageRequest struct {
	SchemaVersion int
	Binding       *Binding
	After         Decimal
	Limit         int
}
type Coverage struct {
	Complete         bool        `json:"complete"`
	Unobserved       []string    `json:"unobserved"`
	Gap              bool        `json:"gap"`
	LostTotal        *Decimal    `json:"lost_total"`
	LossEpoch        *Decimal    `json:"loss_epoch"`
	LossReasons      LossReasons `json:"loss_reasons"`
	CounterSaturated bool        `json:"counter_saturated"`
	Continuity       Continuity  `json:"continuity"`
}
type DNSStatus struct {
	Status   string  `json:"status"`
	Evidence *string `json:"evidence"`
}
type PageResponse struct {
	Header
	HistoryKind      HistoryKind      `json:"history_kind"`
	ProvenanceStatus ProvenanceStatus `json:"provenance_status"`
	Collection       Collection       `json:"collection"`
	Freshness        Freshness        `json:"freshness"`
	Timestamp        string           `json:"timestamp"`
	Closed           bool             `json:"closed"`
	HistoryStartSeq  *Decimal         `json:"history_start_seq"`
	HighWaterSeq     Decimal          `json:"high_water_seq"`
	NextAfter        Decimal          `json:"next_after"`
	HasMore          bool             `json:"has_more"`
	Records          []Record         `json:"records"`
	Pending          *Decimal         `json:"pending"`
	Coverage         Coverage         `json:"coverage"`
	DNS              DNSStatus        `json:"dns"`
}
type ErrorResponse struct {
	SchemaVersion int       `json:"schema_version"`
	ErrorCode     ErrorCode `json:"error_code"`
}

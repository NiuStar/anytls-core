// Package startuptimeline holds bounded auxiliary startup diagnostics. It has no
// service, SDK, filesystem or network authority.
package startuptimeline

const (
	Schema      = 1
	LegacyBytes = 4096
	ReadBytes   = 768 * 1024
	PushBytes   = 65536
	HelperHead  = 768
	HelperTail  = 256
	CoreEvents  = 64
	WebEvents   = 32
	StackDepth  = 16
	Authority   = "AUXILIARY_NOT_AUTHORITY"
)

type Event struct {
	Seq            string  `json:"seq"`
	SpanID         *string `json:"span_id"`
	Segment        string  `json:"segment"`
	Stage          string  `json:"stage"`
	State          string  `json:"state"`
	Code           string  `json:"code"`
	At             string  `json:"at"`
	ElapsedNS      string  `json:"elapsed_ns"`
	DurationNS     *string `json:"duration_ns"`
	Round          *string `json:"round"`
	Ordinal        *string `json:"ordinal"`
	RuleCount      *string `json:"rule_count"`
	CompletedCount *string `json:"completed_count"`
	Job            string  `json:"job"`
	Tun            string  `json:"tun"`
}
type CurrentPhase struct {
	Stage          string `json:"stage"`
	Segment        string `json:"segment"`
	SpanID         string `json:"span_id"`
	BeganAt        string `json:"began_at"`
	BeganElapsedNS string `json:"began_elapsed_ns"`
}
type SeqRange struct {
	First string `json:"first"`
	Last  string `json:"last"`
}
type Terminal struct {
	Result    string `json:"result"`
	At        string `json:"at"`
	ElapsedNS string `json:"elapsed_ns"`
}
type Provenance struct {
	Version          *string `json:"version"`
	GitRevision      *string `json:"git_revision"`
	Dirty            *bool   `json:"dirty"`
	SHA256           *string `json:"sha256"`
	SHAKind          string  `json:"sha_kind"`
	ExecutionMapping string  `json:"execution_mapping"`
}
type ProcessStream struct {
	Role            string        `json:"role"`
	ClockID         string        `json:"clock_id"`
	OriginAt        string        `json:"origin_at"`
	ElapsedNS       string        `json:"elapsed_ns"`
	Provenance      Provenance    `json:"provenance"`
	Current         *CurrentPhase `json:"current"`
	Events          []Event       `json:"events"`
	GeneratedEvents string        `json:"generated_events"`
	DroppedEvents   string        `json:"dropped_events"`
	FirstMissingSeq *string       `json:"first_missing_seq"`
	RetainedRanges  []SeqRange    `json:"retained_ranges"`
	Terminal        *Terminal     `json:"terminal"`
	Gap             bool          `json:"gap"`
}
type CoreSnapshot struct {
	Stream        ProcessStream `json:"stream"`
	StartupResult string        `json:"startup_result"`
	Complete      bool          `json:"complete"`
}
type CoreObservation struct {
	Availability           string        `json:"availability"`
	CapturedAt             *string       `json:"captured_at"`
	HelperReceiveElapsedNS *string       `json:"helper_receive_elapsed_ns"`
	AgeNS                  *string       `json:"age_ns"`
	ClockID                *string       `json:"clock_id"`
	Phase                  *CurrentPhase `json:"phase"`
	Gap                    bool          `json:"gap"`
}

// Diagnostics is the existing fixed lifecycle projection, not an error carrier.
type Diagnostics struct {
	Schema      int    `json:"schema"`
	Operation   string `json:"operation"`
	Outcome     string `json:"outcome"`
	Stage       string `json:"stage"`
	Reason      string `json:"reason"`
	Rollback    string `json:"rollback"`
	Restoration string `json:"restoration"`
	Cleanup     string `json:"cleanup"`
	Receipt     string `json:"receipt"`
	Job         string `json:"job"`
	Tun         string `json:"tun"`
}
type Trace struct {
	Authority       string          `json:"authority"`
	OperationID     string          `json:"operation_id"`
	HelperEpoch     *string         `json:"helper_epoch"`
	ConfigIdentity  *string         `json:"config_identity"`
	Operation       string          `json:"operation"`
	Source          string          `json:"source"`
	StartedAt       string          `json:"started_at"`
	FinishedAt      *string         `json:"finished_at"`
	State           string          `json:"state"`
	LifecycleResult string          `json:"lifecycle_result"`
	HelperReturn    string          `json:"helper_return"`
	WebReturn       string          `json:"web_return"`
	ReceiptResult   string          `json:"receipt_result"`
	Diagnostics     *Diagnostics    `json:"diagnostics"`
	Streams         []ProcessStream `json:"streams"`
	CoreObservation CoreObservation `json:"core_observation"`
	Gap             bool            `json:"gap"`
}
type ReadRequest struct {
	TimelineSchema int     `json:"timeline_schema"`
	Action         string  `json:"action"`
	OperationID    *string `json:"operation_id"`
}
type MutationRequest struct {
	TimelineSchema int    `json:"timeline_schema"`
	Action         string `json:"action"`
	OperationID    string `json:"operation_id"`
	AllowInsecure  bool   `json:"allow_insecure"`
}
type PushRequest struct {
	TimelineSchema int          `json:"timeline_schema"`
	Action         string       `json:"action"`
	HelperEpoch    string       `json:"helper_epoch"`
	OperationID    string       `json:"operation_id"`
	Snapshot       CoreSnapshot `json:"snapshot"`
}
type ReadResponse struct {
	TimelineSchema int     `json:"timeline_schema"`
	Code           string  `json:"code"`
	HelperEpoch    *string `json:"helper_epoch"`
	ConfigIdentity *string `json:"config_identity"`
	OperationID    *string `json:"operation_id"`
	Trace          *Trace  `json:"trace"`
}
type MutationResponse struct {
	TimelineSchema       int          `json:"timeline_schema"`
	Code                 string       `json:"code"`
	OK                   bool         `json:"ok"`
	HelperEpoch          *string      `json:"helper_epoch"`
	OperationID          *string      `json:"operation_id"`
	TimelineAvailability string       `json:"timeline_availability"`
	HelperVersion        *string      `json:"helper_version"`
	HelperSHA256         *string      `json:"helper_sha256"`
	ConfigIdentity       string       `json:"config_identity"`
	Loaded               bool         `json:"loaded"`
	Running              bool         `json:"running"`
	Diagnostics          *Diagnostics `json:"diagnostics"`
}
type PushAck struct {
	TimelineSchema int    `json:"timeline_schema"`
	Code           string `json:"code"`
	OperationID    string `json:"operation_id"`
}
type OperationReference struct {
	TimelineSchema int     `json:"timeline_schema"`
	OperationID    *string `json:"operation_id"`
	Availability   string  `json:"availability"`
}

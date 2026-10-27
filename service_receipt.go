package main

import (
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	st "github.com/NiuStar/anytls-core/internal/startuptimeline"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const diagnosticLimit = 64 << 10

// Source provenance constants copied from patches/sing-box/core-slim.identity.json.
// source_patch_sha256 identifies the final core-slim payload; its frozen manifest
// binds the unchanged Start cleanup identity and both final SDK source hashes.
// These identify the approved source patch, NOT the executed mapping or a
// signature/authenticity assertion. Tests pin these to the authoritative file.
const diagnosticUpstream = "7054cac5124465ffdb145870d7c01885566711b1"
const diagnosticPatch = "360694bed09a7d89d54d601a28f7f31925768ac2feaabfb891cb649f771c2e5b"

type diagnosticIdentity struct {
	App      string   `json:"app_sha256"`
	Git      string   `json:"git_revision"`
	Version  string   `json:"app_version"`
	Upstream string   `json:"upstream_source_commit"`
	Patch    string   `json:"source_patch_sha256"`
	Config   string   `json:"config_sha256"`
	Selected string   `json:"selected_sha256"`
	Rules    []string `json:"rules_sha256"`
	CA       []string `json:"ca_sha256"`
}
type diagnosticEvidence struct {
	Job     string `json:"job"`
	Public  string `json:"public_route"`
	Servers string `json:"server_routes"`
	DNS     string `json:"dns"`
}
type diagnosticServer struct {
	Ordinal     int    `json:"ordinal"`
	Baseline    string `json:"baseline"`
	Readiness   string `json:"readiness"`
	Final       string `json:"final"`
	Restoration string `json:"restoration"`
}
type serviceDiagnostic struct {
	Schema            int                `json:"schema_version"`
	Trust             string             `json:"trust"`
	Engine            string             `json:"engine_mode"`
	Network           string             `json:"network"`
	Operation         string             `json:"operation"`
	Outcome           string             `json:"outcome"`
	Code              string             `json:"error_code"`
	Readiness         string             `json:"readiness"`
	HTTPS             string             `json:"https"`
	Rollback          string             `json:"rollback"`
	Stopped           string             `json:"stopped"`
	Restoration       string             `json:"restoration"`
	Snapshot          string             `json:"snapshot"`
	Identity          diagnosticIdentity `json:"identity"`
	Baseline          diagnosticEvidence `json:"baseline"`
	BeforeHTTPS       diagnosticEvidence `json:"before_https"`
	AfterHTTPS        diagnosticEvidence `json:"after_https"`
	Restore           diagnosticEvidence `json:"restore"`
	Servers           []diagnosticServer `json:"servers"`
	ServerCount       int                `json:"server_count"`
	ServerDetails     string             `json:"server_details"`
	active            *diagnosticEvidence
	diagnostic        *startDiagnostics
	phase             string
	startupCtx        context.Context
	startupSegment    string
	startupAppInfo    os.FileInfo
	startupConfigInfo os.FileInfo
}

func diagnosticUnknown() diagnosticEvidence {
	return diagnosticEvidence{"NOT_EXECUTED", "NOT_EXECUTED", "NOT_EXECUTED", "NOT_EXECUTED"}
}
func newDiagnostic(operation string) *serviceDiagnostic {
	engine := "EMBEDDED"
	if externalCoreRequired() {
		engine = "EXTERNAL"
	}
	r := &serviceDiagnostic{Schema: 1, Trust: "UNTRUSTED_DIAGNOSTIC", Engine: engine, Network: "TUN", Operation: operation, Outcome: "UNKNOWN", Code: "NONE", Readiness: "NOT_VERIFIED", HTTPS: "NOT_EXECUTED", Rollback: "NOT_EXECUTED", Stopped: "UNKNOWN", Restoration: "NOT_EXECUTED", Snapshot: "UNKNOWN", Baseline: diagnosticUnknown(), BeforeHTTPS: diagnosticUnknown(), AfterHTTPS: diagnosticUnknown(), Restore: diagnosticUnknown(), Servers: []diagnosticServer{}, phase: "PREFLIGHT_FAILED"}
	r.Identity = diagnosticIdentity{App: "UNAVAILABLE", Git: "UNKNOWN", Version: "UNKNOWN", Upstream: diagnosticUpstream, Patch: diagnosticPatch, Config: "UNAVAILABLE", Selected: "UNAVAILABLE", Rules: []string{"UNAVAILABLE"}, CA: []string{"UNAVAILABLE"}}
	r.active = &r.Baseline
	return r
}
func (r *serviceDiagnostic) serverScope(n int, baseline string) {
	// No addresses/interfaces/paths in the receipt, only bounded ordinal evidence.
	r.ServerCount = n
	r.ServerDetails = "COMPLETE"
	if n > 128 {
		r.ServerDetails = "UNAVAILABLE_BOUND_EXCEEDED"
		n = 0
	}
	r.Servers = make([]diagnosticServer, n)
	for i := range r.Servers {
		r.Servers[i] = diagnosticServer{i + 1, baseline, "NOT_EXECUTED", "NOT_EXECUTED", "NOT_EXECUTED"}
	}
}
func (r *serviceDiagnostic) server(i int, status string) {
	if i >= len(r.Servers) {
		return
	}
	switch r.active {
	case &r.Baseline:
		r.Servers[i].Baseline = status
	case &r.BeforeHTTPS:
		r.Servers[i].Readiness = status
	case &r.AfterHTTPS:
		r.Servers[i].Final = status
	case &r.Restore:
		r.Servers[i].Restoration = status
	}
}

// Bounded collection of actual staged bytes only, no source acquisition changes.
// The user-writable parent is NOT a security authority; malicious replacement
// races, execution/hash binding and same-UID attackers are outside Plan B.
func diagnosticOpen(path string, limit int64) (*os.File, int64, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return nil, 0, err
	}
	if !st.Mode().IsRegular() || st.Size() > limit {
		return nil, 0, errors.New("diagnostic artifact unavailable")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	st, err = f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > limit {
		_ = f.Close()
		return nil, 0, errors.New("diagnostic artifact unavailable")
	}
	return f, st.Size(), nil
}
func diagnosticHash(path string, limit int64) string {
	sum, _ := diagnosticHashInfo(path, limit)
	return sum
}
func diagnosticHashInfo(path string, limit int64) (string, os.FileInfo) {
	f, _, err := diagnosticOpen(path, limit)
	if err != nil {
		return "UNAVAILABLE", nil
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "UNAVAILABLE", nil
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, limit+1))
	if err != nil || n > limit {
		return "UNAVAILABLE", nil
	}
	return hex.EncodeToString(h.Sum(nil)), info
}
func diagnosticHashes(dir string) []string {
	// Reject visible non-directories (including symlinks and no-writer FIFOs)
	// before Open can follow or block. This is not a hostile-parent race guard.
	st, err := os.Lstat(dir)
	if err != nil || !st.IsDir() {
		return []string{"UNAVAILABLE"}
	}
	f, err := os.Open(dir)
	if err != nil {
		return []string{"UNAVAILABLE"}
	}
	defer f.Close()
	st, err = f.Stat()
	if err != nil || !st.IsDir() {
		return []string{"UNAVAILABLE"}
	}
	entries, err := f.ReadDir(129)
	if err != nil && err != io.EOF || len(entries) > 128 {
		return []string{"UNAVAILABLE"}
	}
	result := []string{}
	var total int64
	for _, e := range entries {
		st, err := e.Info()
		if err != nil || !st.Mode().IsRegular() {
			return []string{"UNAVAILABLE"}
		}
		total += st.Size()
		if total > 16<<20 {
			return []string{"UNAVAILABLE"}
		}
		result = append(result, diagnosticHash(filepath.Join(dir, e.Name()), 1<<20))
	}
	// Order by digest, never encode filenames (including attacker-chosen names).
	slices.Sort(result)
	return result
}
func (r *serviceDiagnostic) capture(root string) {
	r.Identity.App, r.startupAppInfo = diagnosticHashInfo(filepath.Join(root, "anytls-macos"), 128<<20)
	r.Identity.Config, r.startupConfigInfo = diagnosticHashInfo(filepath.Join(root, "config.yaml"), 1<<20)
	r.Identity.Selected = diagnosticHash(filepath.Join(root, "config.yaml.selected"), 64<<10)
	r.Identity.Rules = diagnosticHashes(filepath.Join(root, "rules"))
	r.Identity.CA = diagnosticHashes(filepath.Join(root, "certs"))
	f, n, err := diagnosticOpen(filepath.Join(root, "anytls-macos"), 128<<20)
	if err != nil {
		return
	}
	defer f.Close()
	bi, err := buildinfo.Read(io.NewSectionReader(f, 0, n))
	if err != nil {
		return
	}
	clean, revision := false, ""
	for _, s := range bi.Settings {
		if s.Key == "vcs.modified" {
			clean = s.Value == "false"
		}
		if s.Key == "vcs.revision" {
			revision = s.Value
		}
	}
	if clean && len(revision) == 40 {
		if b, e := hex.DecodeString(revision); e == nil && len(b) == 20 {
			r.Identity.Git = revision
		}
	}
	v := bi.Main.Version
	if len(v) > 1 && len(v) <= 64 && strings.HasPrefix(v, "v") && strings.Trim(v, "v0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.+-") == "" {
		r.Identity.Version = v
	}
}
func diagnosticDestination(path string) error {
	st, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return errors.New("unsafe diagnostic destination")
	}
	return nil
}
func (r *serviceDiagnostic) write(root string) error {
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if len(raw) > diagnosticLimit {
		return errors.New("diagnostic size limit")
	}
	p := filepath.Join(filepath.Dir(root), "service-diagnostic.json")
	if err := diagnosticDestination(p); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(p), ".service-diagnostic-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	// CreateTemp uses exclusive creation and mode 0600; parent unchanged (Plan B).
	if _, err = f.Write(raw); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err := diagnosticDestination(p); err != nil {
		return err
	}
	return os.Rename(f.Name(), p)
}
func (r *serviceDiagnostic) finish(root string, result *error) {
	d := r.diagnostic
	if d != nil {
		if *result != nil && d.Reason == "NONE" {
			stage, reason := "UNKNOWN", "UNKNOWN"
			if r.Operation == "STOP" {
				stage, reason = "STOP", "STOP_FAILED"
			}
			d.fail(stage, reason, *result)
		}
		switch r.Rollback {
		case "SUCCEEDED":
			d.Rollback = "VERIFIED"
		case "FAILED":
			d.Rollback = "FAILED"
		}
	}
	if *result == nil {
		r.Outcome = "SUCCEEDED"
		r.Code = "NONE"
	} else {
		r.Outcome = "FAILED"
		r.Code = r.phase
		if d != nil {
			r.Outcome = d.Outcome
		} else if errors.Is(*result, context.Canceled) || errors.Is(*result, context.DeadlineExceeded) {
			r.Outcome = "CANCELLED"
			r.Code = "CANCELLED"
		}
	}
	segment := r.startupSegment
	if segment == "" {
		segment = "FINALIZE"
	}
	ctx := r.startupCtx
	if ctx == nil {
		ctx = context.Background()
	}
	recorder := st.FromContext(ctx)
	span := recorder.Begin(segment, "RECEIPT_WRITE", st.Fields{})
	writeErr := r.write(root)
	recorder.End(span, startupCode(writeErr), st.Fields{})
	if err := writeErr; err != nil {
		outcome := "lifecycle failed; diagnostic receipt write failed"
		if *result == nil {
			outcome = "lifecycle succeeded; diagnostic receipt write failed"
			if d != nil {
				d.Stage, d.Reason = "DIAGNOSTIC", "RECEIPT_WRITE_FAILED"
			}
		}
		if d != nil {
			d.Receipt = "FAILED"
		}
		*result = errors.Join(*result, lifecycleFailure(outcome, err))
	} else if d != nil {
		d.Receipt = "WRITTEN"
	}
	if *result != nil && d != nil {
		*result = &startDiagnosticError{*d, *result}
	}
}

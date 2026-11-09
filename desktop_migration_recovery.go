package main

// Explicit one-hop legacy recovery. Descriptors alone confer no admission:
// active continuation needs durable new STOP proof; history needs a terminal.
import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"time"
)

var migrationRecoveryHold = desktopError("RECOVERY_HOLD")

type desktopMigrationRecovery struct {
	OldOperation      string
	OldPlan           string
	OldPlanSHA256     string
	OldEvidenceSHA256 string
}
type migrationRecoveryTerminal struct {
	Schema             int    `json:"schema"`
	Disposition        string `json:"disposition"`
	OldOutcome         string `json:"old_outcome"`
	OldOperation       string `json:"old_operation"`
	NewOperation       string `json:"new_operation"`
	OldPlan            string `json:"old_plan"`
	NewPlan            string `json:"new_plan"`
	OldPlanSHA256      string `json:"old_plan_sha256"`
	OldEvidenceSHA256  string `json:"old_evidence_sha256"`
	NewPlanSHA256      string `json:"new_plan_sha256"`
	StopOperation      string `json:"stop_operation"`
	StopResponseSHA256 string `json:"stop_response_sha256"`
	StopReadSHA256     string `json:"stop_read_sha256"`
}

func migrationStrict(raw []byte, dst any) error {
	tree, e := reloadJSON(raw)
	if e != nil || json.Unmarshal(raw, dst) != nil {
		return migrationRecoveryHold
	}
	normal, e := json.Marshal(dst)
	if e != nil {
		return migrationRecoveryHold
	}
	other, e := reloadJSON(normal)
	if e != nil || !reflect.DeepEqual(tree, other) {
		return migrationRecoveryHold
	}
	return nil
}

// Bounded enumeration, including case-fold reserved names on APFS. Never
// ignore a malformed reserved leaf or an unresolved reload by prefix alone.
func (m desktopMigration) recoveryRecords() (map[string]desktopMigrationRecord, error) {
	root, e := desktopBase(m.home, m.uid, false)
	if e != nil {
		return nil, e
	}
	f, e := os.Open(root)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	entries, e := f.ReadDir(513)
	if e != nil && e != io.EOF {
		return nil, migrationRecoveryHold
	}
	if len(entries) > 512 {
		return nil, migrationRecoveryHold
	}
	records := map[string]desktopMigrationRecord{}
	var receiptBytes int64
	for _, entry := range entries {
		name := entry.Name()
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, ".desktop-candidate-") && (name != lower || !desktopMigrationToken(strings.TrimPrefix(name, ".desktop-candidate-"))) {
			return nil, migrationRecoveryHold
		}
		if strings.HasPrefix(lower, ".core-reload-") {
			if name != lower {
				return nil, migrationRecoveryHold
			}
			if e = m.reloadTerminal(name); e != nil {
				return nil, e
			}
		}
		if !strings.HasPrefix(lower, ".desktop-migration-") {
			continue
		}
		if name != lower {
			return nil, migrationRecoveryHold
		}
		op := strings.TrimPrefix(name, ".desktop-migration-")
		if !desktopMigrationToken(op) || len(records) >= 64 {
			return nil, migrationRecoveryHold
		}
		for _, leaf := range []string{"plan.json", "stop-response.json", "stop-read.json"} {
			info, err := os.Lstat(filepath.Join(m.opPath(op), leaf))
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > reloadReceiptLimit {
				return nil, migrationRecoveryHold
			}
			receiptBytes += info.Size()
			if receiptBytes > 16*1024*1024 {
				return nil, migrationRecoveryHold
			}
		}
		r, e := m.record(op)
		if e != nil {
			return nil, migrationRecoveryHold
		}
		if r.EvidenceSchema == 2 {
			children, err := migrationMembers(m.opPath(op), 7)
			if err != nil {
				return nil, migrationRecoveryHold
			}
			allowed := map[string]bool{"plan.json": true, ".sent": true, "evidence-schema": true, "stop-response.json": true, "stop-read.json": true, "old-binary": true, "supersession.json": true}
			for _, child := range children {
				if !allowed[child.Name()] {
					return nil, migrationRecoveryHold
				}
			}
		}
		records[op] = r
	}
	return records, nil
}

func migrationDirectorySame(a, b os.FileInfo) bool {
	if a == nil || b == nil || !os.SameFile(a, b) || a.Mode() != b.Mode() {
		return false
	}
	x, y := a.Sys().(*syscall.Stat_t), b.Sys().(*syscall.Stat_t)
	return x.Uid == y.Uid && x.Gid == y.Gid
}

func (m desktopMigration) recoveryImage(path, sha string) ([]byte, os.FileInfo, error) {
	before, e := desktopFile(path, m.uid, 0700)
	if e != nil || before.Size() <= 0 || before.Size() > 512*1024*1024 {
		return nil, nil, migrationRecoveryHold
	}
	b, e := controlInstallCapture(path)
	after, err := os.Lstat(path)
	if e != nil || err != nil || !reloadStable(before, after) || desktopSum(b) != sha {
		return nil, nil, migrationRecoveryHold
	}
	return b, before, nil
}

// Fingerprint original exact membership, raw bytes and physical identities.
// The old candidate need not match the current App and is never executed.
func (m desktopMigration) recoveryLegacy(op string) (desktopMigrationRecord, desktopMigrationRecovery, error) {
	var link desktopMigrationRecovery
	r, e := m.record(op)
	if e != nil {
		return r, link, e
	}
	p := r.Metadata
	if r.EvidenceSchema != 0 || p.Phase != "UNKNOWN" || r.BackupSHA256 != "" || r.StopOperation != "" || r.StopResponseSHA256 != "" || r.StopReadSHA256 != "" || r.StopDisposition != "" || r.Recovery != nil || p.RecoveryOf != "" || p.RecoveryPlanSHA256 != "" || !desktopMigrationToken(p.HelperSHA256) || p.HelperVersion == "" || !desktopMigrationToken(r.Pin.Aggregate) {
		return r, link, migrationRecoveryHold
	}
	// Validate the original preview token, not just its syntax.
	preview := r
	preview.Metadata.Phase = "INSPECTED"
	preview.Metadata.Operation = ""
	preview.Metadata.Stage = ""
	preview.Metadata.Plan = ""
	preview.Action = ""
	raw, _ := json.Marshal(struct {
		Record desktopMigrationRecord
		Loaded bool
	}{preview, r.WasLoaded})
	// Match original struct field order, not sorted map re-encoding.
	raw = bytes.Replace(raw, []byte(`"EvidenceSchema":0,`), nil, 1)
	if desktopSum(raw) != p.Plan {
		return r, link, migrationRecoveryHold
	}
	dir := m.opPath(op)
	anchor, e := desktopDir(dir, m.uid, true)
	if e != nil {
		return r, link, e
	}
	entries, e := migrationMembers(dir, 2)
	if e != nil || len(entries) != 2 || entries[0].Name() != ".sent" || entries[1].Name() != "plan.json" {
		return r, link, migrationRecoveryHold
	}
	plan, planInfo, e := reloadCapture(filepath.Join(dir, "plan.json"), m.uid)
	if e != nil {
		return r, link, e
	}
	sent, sentInfo, e := reloadCapture(filepath.Join(dir, ".sent"), m.uid)
	if e != nil || !bytes.Equal(sent, []byte("STOP\n")) {
		return r, link, migrationRecoveryHold
	}
	_, stageInfo, e := m.recoveryImage(p.Stage, p.BinarySHA256)
	if e != nil {
		return r, link, e
	}
	// Durable directory identity excludes mutable APFS directory size/nlink.
	type identity struct {
		Device   uint64
		Inode    uint64
		Mode     uint32
		UID      uint32
		GID      uint32
		Size     int64
		Modified int64
	}
	ids := []identity{}
	for i, s := range []os.FileInfo{anchor, planInfo, sentInfo, stageInfo} {
		st := s.Sys().(*syscall.Stat_t)
		v := identity{Device: uint64(st.Dev), Inode: uint64(st.Ino), Mode: uint32(s.Mode()), UID: st.Uid, GID: st.Gid}
		if i > 0 {
			v.Size = s.Size()
			v.Modified = s.ModTime().UnixNano()
		}
		ids = append(ids, v)
	}
	fingerprint, _ := json.Marshal(struct {
		Identities        []identity
		Plan, Sent, Stage string
	}{ids, desktopSum(plan), desktopSum(sent), p.BinarySHA256})
	final, e := desktopDir(dir, m.uid, true)
	again, err := migrationMembers(dir, 2)
	if e != nil || err != nil || !migrationDirectorySame(anchor, final) || len(again) != 2 || again[0].Name() != ".sent" || again[1].Name() != "plan.json" {
		return r, link, migrationRecoveryHold
	}
	for _, v := range []struct {
		path string
		info os.FileInfo
	}{{filepath.Join(dir, "plan.json"), planInfo}, {filepath.Join(dir, ".sent"), sentInfo}, {p.Stage, stageInfo}} {
		now, e := os.Lstat(v.path)
		if e != nil || !reloadStable(v.info, now) {
			return r, link, migrationRecoveryHold
		}
	}
	link = desktopMigrationRecovery{op, p.Plan, desktopSum(plan), desktopSum(fingerprint)}
	return r, link, nil
}

// A separate recovery.json is frontend-owned consent, not helper authorization.
// Only authorization.json may indicate an earlier privileged worker. It must be
// absent or an exact safe DONE record; never infer absence from a read error.
func (m desktopMigration) recoveryAuthorizationSafe() error {
	return m.recoveryAuthorizationFor(nil)
}

// Pending native intent is observation only, never permission to repeat the
// authorization or STOP. Only the exact evidenced ordinary continuation fits.
func (m desktopMigration) recoveryAuthorizationFor(pending *desktopMigrationRecord) error {
	root := filepath.Join(m.home, ".anytls-desktop-state")
	if _, e := os.Lstat(root); errors.Is(e, os.ErrNotExist) {
		return nil
	} else if e != nil {
		return migrationRecoveryHold
	}
	physical, e := filepath.EvalSymlinks(root)
	if e != nil || physical != root {
		return migrationRecoveryHold
	}
	anchor, e := desktopDir(root, m.uid, true)
	if e != nil {
		return e
	}
	entries, e := migrationMembers(root, 3)
	if e != nil || len(entries) > 3 {
		return migrationRecoveryHold
	}
	for _, v := range entries {
		if v.Name() != "authorization.json" && v.Name() != "lifecycle.lock" && v.Name() != "recovery.json" {
			return migrationRecoveryHold
		}
		if _, e = desktopFile(filepath.Join(root, v.Name()), m.uid, 0600); e != nil {
			return migrationRecoveryHold
		}
	}
	path := filepath.Join(root, "authorization.json")
	if _, e = os.Lstat(path); errors.Is(e, os.ErrNotExist) {
		return nil
	} else if e != nil {
		return migrationRecoveryHold
	}
	raw, _, e := reloadCapture(path, m.uid)
	if e != nil || len(raw) > 16384 {
		return migrationRecoveryHold
	}
	tree, e := reloadJSON(raw)
	if e != nil {
		return migrationRecoveryHold
	}
	// Swift omits nil console. A completed intent cannot retain a console or
	// resume permission: either could represent unfinished activation authority.
	shape := "schema operation stage sha state resume"
	phase := "COMMITTED"
	if pending != nil {
		if _, present := tree["console"]; present {
			shape += " console"
			if !m.recoveryHistoricalConsole(tree["console"], *pending) {
				return migrationRecoveryHold
			}
		}
		state := reloadString(tree["state"])
		if state != "ARMED" && state != "UNKNOWN" && state != "DENIED" {
			return migrationRecoveryHold
		}
		if _, ok := tree["resume"].(bool); !ok || tree["operation"] != pending.Metadata.Operation || tree["sha"] != pending.Metadata.BinarySHA256 {
			return migrationRecoveryHold
		}
		phase = "AWAITING_HELPER"
	} else if tree["state"] != "DONE" || tree["resume"] != false {
		return migrationRecoveryHold
	}
	if !reloadShape(tree, shape) || tree["schema"] != json.Number("1") {
		return migrationRecoveryHold
	}
	op := reloadString(tree["operation"])
	if !desktopMigrationToken(op) || !desktopMigrationToken(reloadString(tree["sha"])) || tree["stage"] != filepath.Join(m.home, ".anytls", ".desktop-candidate-"+op) {
		return migrationRecoveryHold
	}
	r, e := m.record(op)
	if e != nil || r.Metadata.Phase != phase || r.Metadata.BinarySHA256 != tree["sha"] {
		return migrationRecoveryHold
	}
	final, e := desktopDir(root, m.uid, true)
	if e != nil || !migrationDirectorySame(anchor, final) {
		return migrationRecoveryHold
	}
	return nil
}

func (m desktopMigration) recoveryPreview() (desktopMigrationRecord, error) {
	var empty desktopMigrationRecord
	records, e := m.recoveryRecords()
	if e != nil {
		return empty, e
	}
	old := ""
	for op, r := range records {
		if r.Recovery != nil || r.Metadata.RecoveryOf != "" || r.Metadata.RecoveryPlanSHA256 != "" {
			return empty, migrationRecoveryHold
		}
		if _, err := os.Lstat(filepath.Join(m.opPath(op), "supersession.json")); !errors.Is(err, os.ErrNotExist) {
			return empty, migrationRecoveryHold
		}
		if r.Metadata.Phase != "COMMITTED" {
			if old != "" {
				return empty, migrationRecoveryHold
			}
			old = op
		}
	}
	if old == "" {
		return empty, migrationRecoveryHold
	}
	historical, link, e := m.recoveryLegacy(old)
	if e != nil {
		return empty, e
	}
	if e = m.recoveryAuthorizationSafe(); e != nil {
		return empty, e
	}
	now, e := m.preflight()
	if e != nil {
		return empty, e
	}
	if now.Pin != historical.Pin || now.Metadata.OldBinarySHA256 != historical.Metadata.OldBinarySHA256 || now.Metadata.HelperSHA256 != historical.Metadata.HelperSHA256 || now.Metadata.HelperVersion != historical.Metadata.HelperVersion {
		return empty, migrationRecoveryHold
	}
	now.Recovery = &link
	now.Metadata.RecoveryOf = old
	now.Metadata.RecoveryPlanSHA256 = link.OldPlanSHA256
	now.Metadata.Phase = "RECOVERY_INSPECTED"
	now.Metadata.Plan = ""
	raw, _ := json.Marshal(now)
	now.Metadata.Plan = desktopSum(raw)
	return now, nil
}

func (m desktopMigration) recoveryLink(r desktopMigrationRecord) error {
	p := r.Metadata
	l := r.Recovery
	if l == nil || !desktopMigrationToken(l.OldOperation) || l.OldOperation == p.Operation || p.RecoveryOf != l.OldOperation || p.RecoveryPlanSHA256 != l.OldPlanSHA256 {
		return migrationRecoveryHold
	}
	old, actual, e := m.recoveryLegacy(l.OldOperation)
	if e != nil || actual != *l || r.Pin != old.Pin || p.OldBinarySHA256 != old.Metadata.OldBinarySHA256 || p.HelperSHA256 != old.Metadata.HelperSHA256 || p.HelperVersion != old.Metadata.HelperVersion {
		return migrationRecoveryHold
	}
	// Recompute recovery plan using original current flags, not today's flags.
	preview := r
	preview.Metadata.Phase = "RECOVERY_INSPECTED"
	preview.Metadata.Operation = ""
	preview.Metadata.Stage = ""
	preview.Metadata.Plan = ""
	preview.Action = ""
	preview.BackupSHA256 = ""
	preview.StopOperation = ""
	preview.StopResponseSHA256 = ""
	preview.StopReadSHA256 = ""
	preview.StopDisposition = ""
	raw, _ := json.Marshal(preview)
	if desktopSum(raw) != p.Plan {
		return migrationRecoveryHold
	}
	return nil
}
func (m desktopMigration) recoveryBeforeStop(r desktopMigrationRecord) error {
	records, e := m.recoveryRecords()
	if e != nil {
		return e
	}
	for op, v := range records {
		if op == r.Metadata.Operation || op == r.Recovery.OldOperation {
			continue
		}
		if v.Metadata.Phase != "COMMITTED" || v.Recovery != nil {
			return migrationRecoveryHold
		}
	}
	if e := m.recoveryLink(r); e != nil {
		return e
	}
	if e := m.recoveryAuthorizationSafe(); e != nil {
		return e
	}
	h, e := m.helper()
	if e != nil || !migrationBound(h, r.Metadata, r.Metadata.HelperSHA256) || h.HelperVersion != r.Metadata.HelperVersion || h.Loaded != r.WasLoaded || h.Running != r.Metadata.WasRunning {
		return migrationRecoveryHold
	}
	return m.unchanged(r)
}

func (m desktopMigration) recoveryCompletedEvidence(r desktopMigrationRecord) error {
	if e := m.recoveryLink(r); e != nil {
		return e
	}
	if e := m.stopEvidence(r); e != nil {
		return e
	}
	if r.EvidenceSchema != 2 || !reloadID.MatchString(r.StopOperation) || r.BackupSHA256 != r.Metadata.OldBinarySHA256 {
		return migrationRecoveryHold
	}
	members, e := migrationMembers(m.opPath(r.Metadata.Operation), 7)
	if e != nil {
		return e
	}
	want := []string{".sent", "evidence-schema", "old-binary", "plan.json", "stop-read.json", "stop-response.json"}
	if r.Metadata.Phase == "COMMITTED" {
		if _, e := os.Lstat(filepath.Join(m.opPath(r.Metadata.Operation), "supersession.json")); e == nil {
			want = append(want, "supersession.json")
		} else if !errors.Is(e, os.ErrNotExist) {
			return migrationRecoveryHold
		}
	}
	if len(members) != len(want) {
		return migrationRecoveryHold
	}
	for i, entry := range members {
		if entry.Name() != want[i] {
			return migrationRecoveryHold
		}
	}
	sent, _, e := reloadCapture(filepath.Join(m.opPath(r.Metadata.Operation), ".sent"), m.uid)
	if e != nil || string(sent) != "STOP\n" {
		return migrationRecoveryHold
	}
	if _, _, e := m.recoveryImage(filepath.Join(m.opPath(r.Metadata.Operation), "old-binary"), r.BackupSHA256); e != nil {
		return e
	}
	if _, _, e := m.recoveryImage(r.Metadata.Stage, r.Metadata.BinarySHA256); e != nil {
		return e
	}
	return nil
}
func (m desktopMigration) recoveryTerminalExpected(r desktopMigrationRecord) (migrationRecoveryTerminal, error) {
	var t migrationRecoveryTerminal
	if r.Metadata.Phase != "COMMITTED" {
		return t, migrationRecoveryHold
	}
	if e := m.recoveryCompletedEvidence(r); e != nil {
		return t, e
	}
	raw, _, e := reloadCapture(filepath.Join(m.opPath(r.Metadata.Operation), "plan.json"), m.uid)
	if e != nil {
		return t, e
	}
	l := r.Recovery
	t = migrationRecoveryTerminal{1, "OLD_FENCED_SUPERSEDED_BY_EXPLICIT_NEW_TRANSACTION", "UNKNOWN", l.OldOperation, r.Metadata.Operation, l.OldPlan, r.Metadata.Plan, l.OldPlanSHA256, l.OldEvidenceSHA256, desktopSum(raw), r.StopOperation, r.StopResponseSHA256, r.StopReadSHA256}
	return t, nil
}
func (m desktopMigration) recoveryTerminal(r desktopMigrationRecord) error {
	expected, e := m.recoveryTerminalExpected(r)
	if e != nil {
		return e
	}
	raw, _, e := reloadCapture(filepath.Join(m.opPath(r.Metadata.Operation), "supersession.json"), m.uid)
	var actual migrationRecoveryTerminal
	if e != nil || migrationStrict(raw, &actual) != nil || actual != expected {
		return migrationRecoveryHold
	}
	return nil
}
func (m desktopMigration) writeRecoveryTerminal(r desktopMigrationRecord) error {
	t, e := m.recoveryTerminalExpected(r)
	if e != nil {
		return e
	}
	dir := m.opPath(r.Metadata.Operation)
	anchor, e := desktopDir(dir, m.uid, true)
	if e != nil {
		return e
	}
	raw, _ := json.Marshal(t)
	write := m.journal
	if write == nil {
		write = controlInstallAtomic
	}
	path := filepath.Join(dir, "supersession.json")
	if _, e = os.Lstat(path); e == nil {
		return m.recoveryTerminal(r)
	} else if !errors.Is(e, os.ErrNotExist) {
		return migrationRecoveryHold
	}
	if e = write(path, raw, 0600); e != nil {
		return desktopError("TERMINAL_UNCERTAIN")
	}
	final, e := desktopDir(dir, m.uid, true)
	if e != nil || !migrationDirectorySame(anchor, final) {
		return migrationRecoveryHold
	}
	return m.recoveryTerminal(r)
}

// Build all one-hop claims before classifying any pending record. An explicit
// active exception is confined to exactly the requested new op and STOP proof.
func (m desktopMigration) recoveryPending(except string) error {
	records, e := m.recoveryRecords()
	if e != nil {
		return e
	}
	claims := map[string]string{}
	accepted := map[string]bool{}
	for op, r := range records {
		if r.Recovery == nil {
			if r.Metadata.RecoveryOf != "" || r.Metadata.RecoveryPlanSHA256 != "" {
				return migrationRecoveryHold
			}
			if _, e := os.Lstat(filepath.Join(m.opPath(op), "supersession.json")); !errors.Is(e, os.ErrNotExist) {
				return migrationRecoveryHold
			}
			continue
		}
		old := r.Recovery.OldOperation
		parent, ok := records[old]
		if !ok || old == op || parent.Recovery != nil || claims[old] != "" {
			return migrationRecoveryHold
		}
		claims[old] = op
		if e = m.recoveryLink(r); e != nil {
			return e
		}
		if r.Metadata.Phase == "COMMITTED" {
			if e = m.recoveryTerminal(r); e != nil {
				return e
			}
			accepted[old] = true
		} else if op == except && r.Metadata.Phase == "AWAITING_HELPER" {
			if e = m.recoveryCompletedEvidence(r); e != nil {
				return e
			}
			accepted[old] = true
		}
	}
	keys := []string{}
	for op := range records {
		keys = append(keys, op)
	}
	sort.Strings(keys)
	for _, op := range keys {
		r := records[op]
		if accepted[op] || op == except {
			continue
		}
		if r.Metadata.Phase != "COMMITTED" {
			if r.Metadata.Phase == "UNKNOWN" || r.Metadata.Phase == "STOP_SENT" || r.Metadata.Phase == "PUBLISHING" {
				return desktopError("MIGRATION_UNKNOWN")
			}
			return desktopError("HOLD_PENDING")
		}
	}
	return nil
}

// Application completion is not terminal authority. Bind BOTH closed native
// intents to the exact proven recovery (and, after later updates, authorization
// to a committed plain migration). Never treat a lone DONE field as a waiver.
func (m desktopMigration) recoveryIntents(r desktopMigrationRecord, records map[string]desktopMigrationRecord) error {
	var pending *desktopMigrationRecord
	for _, v := range records {
		if v.Recovery == nil && v.Metadata.Phase == "AWAITING_HELPER" {
			if pending != nil {
				return migrationRecoveryHold
			}
			copy := v
			pending = &copy
		}
	}
	if e := m.recoveryAuthorizationFor(pending); e != nil {
		return e
	}
	root := filepath.Join(m.home, ".anytls-desktop-state")
	raw, _, e := reloadCapture(filepath.Join(root, "recovery.json"), m.uid)
	if e != nil || len(raw) > 16384 {
		return migrationRecoveryHold
	}
	t, e := reloadJSON(raw)
	shape := "schema state consent plan recoveryOf recoveryPlanSHA sha operation"
	if _, present := t["console"]; present {
		shape += " console"
		if !m.recoveryHistoricalConsole(t["console"], r) {
			return migrationRecoveryHold
		}
	}
	if e != nil || !reloadShape(t, shape) || t["schema"] != json.Number("1") || t["state"] != "DONE" || t["consent"] != "EXPLICIT_NEW_STOP" || t["plan"] != r.Metadata.Plan || t["recoveryOf"] != r.Metadata.RecoveryOf || t["recoveryPlanSHA"] != r.Metadata.RecoveryPlanSHA256 || t["sha"] != r.Metadata.BinarySHA256 || t["operation"] != r.Metadata.Operation {
		return migrationRecoveryHold
	}
	raw, _, e = reloadCapture(filepath.Join(root, "authorization.json"), m.uid)
	if e != nil {
		return migrationRecoveryHold
	}
	t, e = reloadJSON(raw)
	if e != nil {
		return migrationRecoveryHold
	}
	a, ok := records[reloadString(t["operation"])]
	if !ok || (a.Metadata.Phase != "COMMITTED" && (pending == nil || a.Metadata.Operation != pending.Metadata.Operation)) || (a.Metadata.Operation != r.Metadata.Operation && a.Recovery != nil) {
		return migrationRecoveryHold
	}
	return nil
}

// The native DONE recovery retains this optional pin; unlike authorization's
// console it is historical data only. Never observe, signal or resume its PID.
func (m desktopMigration) recoveryHistoricalConsole(value any, r desktopMigrationRecord) bool {
	tree := reloadMap(value)
	if !reloadShape(tree, "pid uid seconds micros argv sha managed") {
		return false
	}
	var pin struct {
		PID     int32    `json:"pid"`
		UID     uint32   `json:"uid"`
		Seconds uint64   `json:"seconds"`
		Micros  uint64   `json:"micros"`
		Argv    []string `json:"argv"`
		SHA     string   `json:"sha"`
		Managed bool     `json:"managed"`
	}
	raw, e := json.Marshal(tree)
	if e != nil || migrationStrict(raw, &pin) != nil || pin.PID <= 1 || pin.UID != uint32(m.uid) || pin.Micros >= 1000000 || pin.SHA != r.Metadata.OldBinarySHA256 {
		return false
	}
	count := 6
	options := map[string]string{"--listen": "0.0.0.0", "--port": "18089"}
	if pin.Managed {
		count = 8
		label := desktopSum([]byte(fmt.Sprintf("%d\x00%s\x00%s", m.uid, r.Metadata.Binary, r.Metadata.Config)))[:24]
		options["--managed-agent"] = "com.anytls.webui." + label
	}
	if len(pin.Argv) != count || pin.Argv[0] != r.Metadata.Binary || pin.Argv[1] != "webui" {
		return false
	}
	for i := 2; i < len(pin.Argv); i += 2 {
		v, ok := options[pin.Argv[i]]
		if !ok || v != pin.Argv[i+1] {
			return false
		}
		delete(options, pin.Argv[i])
	}
	return len(options) == 0
}

// Validate historical completion without binding it to today's candidate SHA
// or to an obsolete canonical inode. Walk only unambiguous, fully evidenced
// plain COMMITTED successors. UNKNOWN itself remains immutable and UNKNOWN.
func (m desktopMigration) recoveryHistory(r desktopMigrationRecord, records map[string]desktopMigrationRecord, result *desktopMigrationMetadata) error {
	if e := m.recoveryTerminal(r); e != nil {
		return e
	}
	except := ""
	var awaiting *desktopMigrationRecord
	for op, v := range records {
		if v.Recovery == nil && v.Metadata.Phase == "AWAITING_HELPER" {
			if awaiting != nil {
				return migrationRecoveryHold
			}
			copy := v
			awaiting = &copy
			except = op
		}
	}
	if e := m.pending(except); e != nil {
		return e
	}
	now, e := m.capture()
	if e != nil || now.Pin.Aggregate != r.Pin.Aggregate || now.Pin.RootDevice != r.Pin.RootDevice || now.Pin.RootInode != r.Pin.RootInode || now.Pin.RootMode != r.Pin.RootMode {
		return migrationRecoveryHold
	}
	sha := r.Metadata.BinarySHA256
	tip := r.Metadata.Operation
	seen := map[string]bool{r.Metadata.Operation: true, r.Recovery.OldOperation: true}
	for {
		var next *desktopMigrationRecord
		for op, v := range records {
			if seen[op] || v.Metadata.OldBinarySHA256 != sha {
				continue
			}
			if next != nil || v.Recovery != nil || v.EvidenceSchema != 2 || (v.Metadata.Phase != "COMMITTED" && v.Metadata.Phase != "AWAITING_HELPER") || v.Pin.Aggregate != r.Pin.Aggregate || v.Pin.RootDevice != r.Pin.RootDevice || v.Pin.RootInode != r.Pin.RootInode || v.Pin.RootMode != r.Pin.RootMode || v.Metadata.HelperSHA256 != sha || v.BackupSHA256 != sha {
				return migrationRecoveryHold
			}
			// Recompute the original plain preview token, not merely the
			// record's syntax or STOP receipt hashes.
			preview := v
			preview.Metadata.Phase = "INSPECTED"
			preview.Metadata.Operation, preview.Metadata.Stage, preview.Metadata.Plan = "", "", ""
			preview.Action, preview.BackupSHA256 = "", ""
			preview.StopOperation, preview.StopResponseSHA256, preview.StopReadSHA256, preview.StopDisposition = "", "", "", ""
			raw, _ := json.Marshal(struct {
				Record desktopMigrationRecord
				Loaded bool
			}{preview, preview.WasLoaded})
			if desktopSum(raw) != v.Metadata.Plan {
				return migrationRecoveryHold
			}
			if e := m.stopEvidence(v); e != nil {
				return e
			}
			if _, _, e := m.recoveryImage(v.Metadata.Stage, v.Metadata.BinarySHA256); e != nil {
				return e
			}
			if _, _, e := m.recoveryImage(filepath.Join(m.opPath(op), "old-binary"), sha); e != nil {
				return e
			}
			sent, _, e := reloadCapture(filepath.Join(m.opPath(op), ".sent"), m.uid)
			members, err := migrationMembers(m.opPath(op), 6)
			if e != nil || err != nil || string(sent) != "STOP\n" || len(members) != 6 {
				return migrationRecoveryHold
			}
			copy := v
			next = &copy
		}
		if next == nil {
			break
		}
		seen[next.Metadata.Operation] = true
		if next.Metadata.Phase == "AWAITING_HELPER" {
			if awaiting == nil || next.Metadata.Operation != awaiting.Metadata.Operation || m.unchanged(*next) != nil {
				return migrationRecoveryHold
			}
			// An unpublished leaf does not advance the canonical lineage tip.
			tip = next.Metadata.Operation
			break
		}
		sha = next.Metadata.BinarySHA256
		tip = next.Metadata.Operation
	}
	raw, _, err := reloadCapture(filepath.Join(m.home, ".anytls-desktop-state", "authorization.json"), m.uid)
	auth, decodeErr := reloadJSON(raw)
	authSHA := sha
	if awaiting != nil {
		authSHA = awaiting.Metadata.BinarySHA256
	}
	if err != nil || decodeErr != nil || auth["operation"] != tip || auth["sha"] != authSHA {
		return migrationRecoveryHold
	}
	// No disconnected newer transaction may be mistaken for our lineage.
	for op := range records {
		if !seen[op] {
			return migrationRecoveryHold
		}
	}
	if now.Metadata.OldBinarySHA256 != sha {
		return migrationRecoveryHold
	}
	if awaiting != nil {
		h, err := m.helper()
		oldReady := err == nil && migrationBound(h, awaiting.Metadata, sha) && h.HelperVersion == awaiting.Metadata.HelperVersion
		newReady := err == nil && migrationBound(h, awaiting.Metadata, awaiting.Metadata.BinarySHA256) && h.HelperVersion == currentVersion()
		if (!oldReady && !newReady) || !migrationStopped(h) || m.unchanged(*awaiting) != nil {
			return migrationRecoveryHold
		}
		*result = awaiting.Metadata
		return desktopError("HOLD_PENDING")
	}
	// Capture the fully proven published bytes before a helper callback can
	// replace canonical. No execution ever uses that mutable installed path.
	before, e := desktopFile(now.Metadata.Binary, m.uid, 0755)
	if e != nil {
		return e
	}
	image, e := controlInstallCapture(now.Metadata.Binary)
	after, err := os.Lstat(now.Metadata.Binary)
	if e != nil || err != nil || !reloadStable(before, after) || desktopSum(image) != sha {
		return migrationRecoveryHold
	}
	h, e := m.helper()
	if e != nil || !migrationBound(h, now.Metadata, sha) || !migrationStopped(h) || validateBuildVersion(h.HelperVersion) != nil {
		return migrationRecoveryHold
	}
	current, err := os.Lstat(now.Metadata.Binary)
	if err != nil || !reloadStable(before, current) {
		return migrationRecoveryHold
	}
	version, e := m.recoveryImageVersion(image, sha)
	if e != nil || version != h.HelperVersion {
		return migrationRecoveryHold
	}
	current, err = os.Lstat(now.Metadata.Binary)
	if err != nil || !reloadStable(before, current) {
		return migrationRecoveryHold
	}
	// The last preflight has another callback: bind its exported old SHA/helper
	// to the historical lineage tip, then capture again AFTER that callback.
	preview, e := m.preflight()
	if e != nil || preview.Metadata.OldBinarySHA256 != sha || preview.Metadata.HelperSHA256 != sha || preview.Metadata.HelperVersion != version || preview.Metadata.WasRunning || preview.WasLoaded {
		return migrationRecoveryHold
	}
	final, e := m.capture()
	if e != nil || final.Pin != preview.Pin || final.Metadata.OldBinarySHA256 != sha || final.Metadata.BinarySHA256 != preview.Metadata.BinarySHA256 || final.Pin.Aggregate != r.Pin.Aggregate || final.Pin.RootDevice != r.Pin.RootDevice || final.Pin.RootInode != r.Pin.RootInode || final.Pin.RootMode != r.Pin.RootMode {
		return migrationRecoveryHold
	}
	*result = preview.Metadata
	return nil
}

// Only called with a lineage-proven incumbent capture. The private copy is
// exclusive, no-follow, rehashed and executed with only -version; never consult
// TMPDIR, candidate stages or the mutable installed pathname for execution.
func (m desktopMigration) recoveryImageVersion(image []byte, sha string) (version string, resultErr error) {
	if len(image) == 0 || desktopSum(image) != sha {
		return "", migrationRecoveryHold
	}
	root, e := desktopBase(m.home, m.uid, false)
	if e != nil {
		return "", e
	}
	dir, e := os.MkdirTemp(root, ".migration-version-")
	if e != nil {
		return "", migrationRecoveryHold
	}
	defer func() {
		if cleanupErr := os.RemoveAll(dir); cleanupErr != nil {
			// A retained executable is not successful inspection. Preserve any
			// primary failure and expose only the fixed public HOLD code.
			version = ""
			resultErr = errors.Join(resultErr, migrationRecoveryHold)
		}
	}()
	if _, e = desktopDir(dir, m.uid, true); e != nil {
		return "", e
	}
	path := filepath.Join(dir, "anytls-macos")
	fd, e := syscall.Open(path, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0700)
	if e != nil {
		return "", migrationRecoveryHold
	}
	f := os.NewFile(uintptr(fd), path)
	n, writeErr := f.Write(image)
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil || n != len(image) {
		return "", migrationRecoveryHold
	}
	if _, _, e = m.recoveryImage(path, sha); e != nil {
		return "", e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, diagnostic := migrationVersionOutput{cancel: cancel}, migrationVersionOutput{cancel: cancel}
	cmd := exec.CommandContext(ctx, path, "-version")
	cmd.Dir = dir
	cmd.Stdout, cmd.Stderr = &out, &diagnostic
	// Bound pipe drain even if a descendant inherits a pipe. Run/Wait owns and
	// reaps the direct child; cancellation kills only that owned direct child.
	cmd.WaitDelay = 200 * time.Millisecond
	if e = cmd.Run(); e != nil || ctx.Err() != nil || out.overflow || diagnostic.overflow {
		return "", migrationRecoveryHold
	}
	if _, _, e = m.recoveryImage(path, sha); e != nil {
		return "", e
	}
	return strings.TrimSpace(string(out.b)), nil
}

// webBoundedOutput was considered but silently discards at 64KiB and cannot
// cancel; the version contract needs a strict 256-byte per-stream write bound.
type migrationVersionOutput struct {
	b        []byte
	overflow bool
	cancel   context.CancelFunc
}

func (w *migrationVersionOutput) Write(p []byte) (int, error) {
	if len(p) > 256-len(w.b) {
		w.overflow = true
		w.cancel()
		return 0, migrationRecoveryHold
	}
	w.b = append(w.b, p...)
	return len(p), nil
}

// Shared read-only predicates for explicit finalization and inspection. Do not
// compare the old canonical inode after publication: capture must bind the
// current bundle/current canonical hash, unchanged root/config and new helper.
// Native authorization READY is legitimate here; the strict pre-STOP DONE
// admission policy is intentionally not reused for a no-STOP continuation.
func (m desktopMigration) recoveryPublished(r desktopMigrationRecord, records map[string]desktopMigrationRecord) error {
	if r.Recovery == nil || r.Metadata.Phase != "COMMITTED" {
		return migrationRecoveryHold
	}
	for other, v := range records {
		if other == r.Metadata.Operation || other == r.Recovery.OldOperation {
			continue
		}
		if v.Recovery != nil || v.Metadata.RecoveryOf != "" || v.Metadata.RecoveryPlanSHA256 != "" || v.Metadata.Phase != "COMMITTED" {
			return migrationRecoveryHold
		}
		if _, e := os.Lstat(filepath.Join(m.opPath(other), "supersession.json")); !errors.Is(e, os.ErrNotExist) {
			return migrationRecoveryHold
		}
	}
	if e := m.recoveryCompletedEvidence(r); e != nil {
		return e
	}
	// A missing terminal is recoverable; a present invalid terminal is not.
	if _, e := os.Lstat(filepath.Join(m.opPath(r.Metadata.Operation), "supersession.json")); e == nil {
		if e = m.recoveryTerminal(r); e != nil {
			return e
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return migrationRecoveryHold
	}
	now, e := m.capture()
	if e != nil || now.Pin.Aggregate != r.Pin.Aggregate || now.Pin.RootDevice != r.Pin.RootDevice || now.Pin.RootInode != r.Pin.RootInode || now.Pin.RootMode != r.Pin.RootMode || now.Metadata.OldBinarySHA256 != r.Metadata.BinarySHA256 || now.Metadata.BinarySHA256 != r.Metadata.BinarySHA256 {
		return migrationRecoveryHold
	}
	if _, e = desktopFile(r.Metadata.Binary, m.uid, 0755); e != nil {
		return e
	}
	h, e := m.helper()
	if e != nil || !migrationBound(h, r.Metadata, r.Metadata.BinarySHA256) || h.HelperVersion != currentVersion() || !migrationStopped(h) {
		return migrationRecoveryHold
	}
	return nil
}

func (m desktopMigration) recoveryFinalize(op string) (desktopMigrationMetadata, error) {
	var empty desktopMigrationMetadata
	if !desktopMigrationToken(op) {
		return empty, desktopError("INVALID_COMMAND")
	}
	lock, e := m.lock()
	if e != nil {
		return empty, e
	}
	defer lock.Close()
	records, e := m.recoveryRecords()
	if e != nil {
		return empty, e
	}
	r, ok := records[op]
	if !ok || r.Recovery == nil || r.Metadata.Phase != "COMMITTED" {
		return empty, migrationRecoveryHold
	}
	if e = m.recoveryPublished(r, records); e != nil {
		return empty, e
	}
	if e = m.writeRecoveryTerminal(r); e != nil {
		return empty, e
	}
	if e = m.pending(""); e != nil {
		return empty, e
	}
	return r.Metadata, nil
}

// Inspect never creates the lock or any journal. The original migration owns
// this existing shared installer lock; absent/unsafe lock is HOLD.
func (m desktopMigration) recoveryInspect() (desktopMigrationMetadata, error) {
	var empty desktopMigrationMetadata
	if _, e := desktopBase(m.home, m.uid, false); e != nil {
		return empty, e
	}
	path := filepath.Join(m.home, ".anytls", ".install.lock")
	before, e := desktopFile(path, m.uid, 0600)
	if e != nil {
		return empty, e
	}
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return empty, migrationRecoveryHold
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !reloadStable(before, opened) {
		return empty, migrationRecoveryHold
	}
	if e = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		return empty, desktopError("INSTALL_BUSY")
	}
	r, e := m.recoveryPreview()
	return r.Metadata, e
}

func migrationMembers(path string, limit int) ([]os.DirEntry, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	entries, e := f.ReadDir(limit + 1)
	if e != nil && e != io.EOF || len(entries) > limit {
		return nil, migrationRecoveryHold
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	return entries, nil
}

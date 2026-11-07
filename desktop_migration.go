package main

// Narrow, explicit canonical-install upgrade. Never installs a helper, starts
// VPN, restarts a console, removes unknown leaves, or replays an uncertain STOP.
import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type desktopMigrationMetadata struct {
	Schema          int    `json:"schema"`
	Phase           string `json:"phase"`
	Plan            string `json:"plan"`
	Operation       string `json:"operation,omitempty"`
	Binary          string `json:"binary"`
	Config          string `json:"config"`
	ConfigIdentity  string `json:"config_identity"`
	BinarySHA256    string `json:"binary_sha256"`
	OldBinarySHA256 string `json:"old_binary_sha256"`
	HelperSHA256    string `json:"helper_sha256"`
	HelperVersion   string `json:"helper_version"`
	Stage           string `json:"stage,omitempty"`
	UID             int    `json:"uid"`
	Home            string `json:"home"`
	WasRunning      bool   `json:"was_running"`
}

// Private fingerprints include credential bytes only in an aggregate digest.
// No raw config, selected state, or standalone password hash enters JSON.
type desktopMigrationPin struct {
	Aggregate  string
	Device     uint64
	Inode      uint64
	Mode       uint32
	RootDevice uint64
	RootInode  uint64
	RootMode   uint32
}
type desktopMigrationRecord struct {
	Metadata     desktopMigrationMetadata
	Pin          desktopMigrationPin
	WasLoaded    bool
	Action       string
	BackupSHA256 string
}
type desktopMigration struct {
	home, source string
	uid          int
	status       func(context.Context) (controlHelperResponse, error)
	stop         func(context.Context) (controlHelperResponse, error)
	journal      func(string, []byte, os.FileMode) error // fixture fault seam; production uses the fixed atomic writer
}

func desktopMigrationToken(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && strings.ToLower(s) == s
}
func (m desktopMigration) sourceImage() ([]byte, error) {
	app := filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(m.source))))
	if !filepath.IsAbs(m.source) || filepath.Clean(m.source) != m.source || filepath.Base(app) != "AnyTLSMenuBar.app" || m.source != filepath.Join(app, "Contents", "Resources", "runtime", "anytls-macos") {
		return nil, desktopError("INVALID_BUNDLE_LAYOUT")
	}
	p, e := filepath.EvalSymlinks(m.source)
	if e != nil || p != m.source {
		return nil, desktopError("UNSAFE_SOURCE")
	}
	s, e := os.Lstat(m.source)
	if e != nil || !s.Mode().IsRegular() || s.Mode().Perm()&0111 == 0 || s.Mode().Perm()&0022 != 0 {
		return nil, desktopError("UNSAFE_SOURCE")
	}
	st, ok := s.Sys().(*syscall.Stat_t)
	if !ok || st.Nlink != 1 {
		return nil, desktopError("UNSAFE_SOURCE")
	}
	b, e := controlInstallCapture(m.source)
	if e != nil || len(b) == 0 {
		return nil, desktopError("SOURCE_CAPTURE_FAILED")
	}
	return b, nil
}
func (m desktopMigration) capture() (desktopMigrationRecord, error) {
	var r desktopMigrationRecord
	image, e := m.sourceImage()
	if e != nil {
		return r, e
	}
	root, e := desktopBase(m.home, m.uid, false)
	if e != nil {
		return r, e
	}
	anchor, e := desktopDir(root, m.uid, false)
	if e != nil || anchor.Mode().Perm()&0200 == 0 {
		return r, desktopError("UNSAFE_DIRECTORY")
	}
	if _, e = os.Lstat(filepath.Join(root, "anytls")); !errors.Is(e, os.ErrNotExist) {
		return r, desktopError("LEGACY_LAYOUT_REQUIRES_REVIEW")
	}
	target := filepath.Join(root, "anytls-macos")
	s, e := desktopFile(target, m.uid, 0)
	if e != nil || (s.Mode() != 0700 && s.Mode() != 0755) {
		return r, desktopError("UNSAFE_RUNTIME")
	}
	old, e := controlInstallCapture(target)
	if e != nil {
		return r, desktopError("TARGET_CAPTURE_FAILED")
	}
	aggregate := []byte{}
	for _, name := range []string{"config.yaml", "config.yaml.selected", "webui.password"} {
		path := filepath.Join(root, name)
		mode := os.FileMode(0)
		if name == "webui.password" {
			mode = 0600
		}
		_, e = desktopFile(path, m.uid, mode)
		if name == "config.yaml.selected" && errors.Is(e, os.ErrNotExist) {
			aggregate = append(aggregate, []byte(name+":ABSENT\n")...)
			continue
		}
		if e != nil {
			return r, desktopError("UNSAFE_CONFIG_OR_CREDENTIAL")
		}
		b, e := controlInstallCapture(path)
		if e != nil {
			return r, desktopError("CONFIG_CAPTURE_FAILED")
		}
		aggregate = append(aggregate, []byte(name+":"+desktopSum(b)+"\n")...)
	}
	st := s.Sys().(*syscall.Stat_t)
	a := anchor.Sys().(*syscall.Stat_t)
	r.Pin = desktopMigrationPin{desktopSum(aggregate), uint64(st.Dev), uint64(st.Ino), uint32(s.Mode()), uint64(a.Dev), uint64(a.Ino), uint32(anchor.Mode())}
	r.Metadata = desktopMigrationMetadata{Schema: 1, Phase: "INSPECTED", Binary: target, Config: filepath.Join(root, "config.yaml"), BinarySHA256: desktopSum(image), OldBinarySHA256: desktopSum(old), UID: m.uid, Home: m.home}
	r.Metadata.ConfigIdentity = desktopSum([]byte(r.Metadata.Config))
	return r, nil
}
func (m desktopMigration) helper() (controlHelperResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	r, e := m.status(ctx)
	if e != nil || !r.OK || !desktopMigrationToken(r.HelperSHA256) || r.HelperVersion == "" {
		return r, desktopError("HELPER_UNAVAILABLE")
	}
	return r, nil
}
func migrationBound(r controlHelperResponse, p desktopMigrationMetadata, sha string) bool {
	return r.OK && r.ConfigIdentity == p.ConfigIdentity && r.HelperSHA256 == sha
}
func migrationStopped(r controlHelperResponse) bool { return !r.Loaded && !r.Running }
func (m desktopMigration) preflight() (desktopMigrationRecord, error) {
	r, e := m.capture()
	if e != nil {
		return r, e
	}
	h, e := m.helper()
	if e != nil {
		return r, e
	}
	if h.ConfigIdentity != r.Metadata.ConfigIdentity {
		return r, desktopError("HELPER_CONFIG_MISMATCH")
	}
	r.Metadata.HelperSHA256 = h.HelperSHA256
	r.Metadata.HelperVersion = h.HelperVersion
	r.Metadata.WasRunning = h.Running
	r.WasLoaded = h.Loaded
	// Bind stopped/loaded as well as running to the preview, without exporting
	// password or selection hashes independently.
	raw, _ := json.Marshal(struct {
		Record desktopMigrationRecord
		Loaded bool
	}{r, h.Loaded})
	r.Metadata.Plan = desktopSum(raw)
	return r, nil
}
func migrationSync(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	return errors.Join(f.Sync(), f.Close())
}
func (m desktopMigration) pending(except string) error {
	root := filepath.Join(m.home, ".anytls")
	entries, e := os.ReadDir(root)
	if e != nil {
		return desktopError("MIGRATION_HOLD")
	}
	for _, entry := range entries {
		n := entry.Name()
		if strings.HasPrefix(n, ".core-reload-") {
			if err := m.reloadTerminal(n); err != nil {
				return err
			}
			continue
		}
		if !strings.HasPrefix(n, ".desktop-migration-") {
			continue
		}
		op := strings.TrimPrefix(n, ".desktop-migration-")
		if op == except {
			continue
		}
		if !desktopMigrationToken(op) {
			return desktopError("HOLD_PENDING")
		}
		r, e := m.record(op)
		if e != nil {
			return desktopError("HOLD_PENDING")
		}
		if r.Metadata.Phase != "COMMITTED" {
			if r.Metadata.Phase == "STOP_SENT" || r.Metadata.Phase == "UNKNOWN" || r.Metadata.Phase == "PUBLISHING" {
				return desktopError("MIGRATION_UNKNOWN")
			}
			return desktopError("HOLD_PENDING")
		}
	}
	return nil
}
func (m desktopMigration) inspect() (desktopMigrationMetadata, error) {
	var p desktopMigrationMetadata
	if _, e := desktopBase(m.home, m.uid, false); e != nil {
		return p, e
	}
	if e := m.pending(""); e != nil {
		// Read-only recovery metadata. No authority to repair/replay a phase.
		entries, _ := os.ReadDir(filepath.Join(m.home, ".anytls"))
		for _, entry := range entries {
			op := strings.TrimPrefix(entry.Name(), ".desktop-migration-")
			if r, readErr := m.record(op); readErr == nil && r.Metadata.Phase != "COMMITTED" {
				return r.Metadata, e
			}
		}
		return p, e
	}
	r, e := m.preflight()
	return r.Metadata, e
}
func (m desktopMigration) lock() (*os.File, error) {
	root, e := desktopBase(m.home, m.uid, false)
	if e != nil {
		return nil, e
	}
	p := filepath.Join(root, ".install.lock")
	fd, e := syscall.Open(p, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if e != nil {
		return nil, desktopError("INSTALL_LOCK_UNSAFE")
	}
	f := os.NewFile(uintptr(fd), p)
	s, e := f.Stat()
	if e != nil {
		f.Close()
		return nil, desktopError("INSTALL_LOCK_UNSAFE")
	}
	st, ok := s.Sys().(*syscall.Stat_t)
	if !ok || !s.Mode().IsRegular() || st.Uid != uint32(m.uid) || st.Nlink != 1 || s.Mode().Perm() != 0600 {
		f.Close()
		return nil, desktopError("INSTALL_LOCK_UNSAFE")
	}
	if e = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		f.Close()
		return nil, desktopError("INSTALL_BUSY")
	}
	return f, nil
}
func (m desktopMigration) opPath(op string) string {
	return filepath.Join(m.home, ".anytls", ".desktop-migration-"+op)
}
func (m desktopMigration) record(op string) (desktopMigrationRecord, error) {
	var r desktopMigrationRecord
	if !desktopMigrationToken(op) {
		return r, desktopError("INVALID_COMMAND")
	}
	dir := m.opPath(op)
	if _, e := desktopDir(dir, m.uid, true); e != nil {
		return r, desktopError("HOLD_PENDING")
	}
	path := filepath.Join(dir, "plan.json")
	if _, e := desktopFile(path, m.uid, 0600); e != nil {
		return r, desktopError("HOLD_PENDING")
	}
	b, e := controlInstallCapture(path)
	if e != nil || json.Unmarshal(b, &r) != nil {
		return r, desktopError("HOLD_PENDING")
	}
	p := r.Metadata
	root := filepath.Dir(dir)
	if r.Action != "STOP" || p.Schema != 1 || p.Operation != op || p.Home != m.home || p.UID != m.uid || p.Binary != filepath.Join(root, "anytls-macos") || p.Config != filepath.Join(root, "config.yaml") || p.ConfigIdentity != desktopSum([]byte(p.Config)) || p.Stage != filepath.Join(root, ".desktop-candidate-"+op) || !desktopMigrationToken(p.Plan) || !desktopMigrationToken(p.BinarySHA256) || !desktopMigrationToken(p.OldBinarySHA256) {
		return r, desktopError("HOLD_PENDING")
	}
	return r, nil
}
func (m desktopMigration) save(r desktopMigrationRecord) error {
	b, _ := json.Marshal(r)
	write := m.journal
	if write == nil {
		write = controlInstallAtomic
	}
	if e := write(filepath.Join(m.opPath(r.Metadata.Operation), "plan.json"), b, 0600); e != nil {
		return desktopError("JOURNAL_UNCERTAIN")
	}
	return nil
}
func migrationAck(r controlHelperResponse) bool {
	d := r.Diagnostics
	if d == nil {
		return true
	} // authenticated legacy acknowledgement
	return d.Schema == 1 && d.Operation == "STOP" && d.Outcome == "SUCCEEDED" && (d.Restoration == "VERIFIED" || d.Restoration == "NOT_ATTEMPTED") && (d.Cleanup == "VERIFIED" || d.Cleanup == "NOT_ATTEMPTED") && (d.Receipt == "WRITTEN" || d.Receipt == "NOT_ATTEMPTED")
}
func (m desktopMigration) unchanged(r desktopMigrationRecord) error {
	now, e := m.capture()
	if e != nil || now.Pin != r.Pin || now.Metadata.OldBinarySHA256 != r.Metadata.OldBinarySHA256 || now.Metadata.BinarySHA256 != r.Metadata.BinarySHA256 {
		return desktopError("PLAN_CHANGED")
	}
	return nil
}
func (m desktopMigration) commit(plan string) (desktopMigrationMetadata, error) {
	var empty desktopMigrationMetadata
	if !desktopMigrationToken(plan) {
		return empty, desktopError("INVALID_COMMAND")
	}
	lock, e := m.lock()
	if e != nil {
		return empty, e
	}
	defer lock.Close()
	if e = m.pending(""); e != nil {
		return empty, e
	}
	r, e := m.preflight()
	if e != nil {
		return empty, e
	}
	if r.Metadata.Plan != plan {
		return empty, desktopError("PLAN_CHANGED")
	}
	op, e := webRandom(32)
	if e != nil {
		return empty, desktopError("OP_CREATE_FAILED")
	}
	op = desktopSum([]byte(op))
	r.Metadata.Operation = op
	r.Metadata.Stage = filepath.Join(m.home, ".anytls", ".desktop-candidate-"+op)
	dir := m.opPath(op)
	if e = os.Mkdir(dir, 0700); e != nil {
		return empty, desktopError("OP_CREATE_FAILED")
	}
	if e = migrationSync(filepath.Dir(dir)); e != nil {
		return empty, desktopError("JOURNAL_UNCERTAIN")
	}
	image, e := m.sourceImage()
	if e != nil {
		return empty, e
	}
	anchor, e := desktopDir(filepath.Dir(dir), m.uid, false)
	if e != nil {
		return empty, e
	}
	if desktopSum(image) != r.Metadata.BinarySHA256 {
		return empty, desktopError("SOURCE_CHANGED")
	}
	if e = desktopPublish(filepath.Dir(dir), filepath.Base(r.Metadata.Stage), image, 0700, anchor); e != nil {
		return empty, e
	}
	stage, stageErr := controlInstallCapture(r.Metadata.Stage)
	if stageErr != nil || desktopSum(stage) != r.Metadata.BinarySHA256 {
		return empty, desktopError("STAGE_CHANGED")
	}
	if e = m.unchanged(r); e != nil {
		return empty, e
	}
	h, e := m.helper()
	if e != nil || !migrationBound(h, r.Metadata, r.Metadata.HelperSHA256) || h.Running != r.Metadata.WasRunning || h.Loaded != r.WasLoaded || h.HelperVersion != r.Metadata.HelperVersion {
		return empty, desktopError("HELPER_CHANGED")
	}
	// Durable write-ahead intent precedes exactly one dispatch. STOP_SENT is a
	// sticky UNKNOWN after a crash; plain stopped status never repairs it.
	r.Metadata.Phase = "STOP_SENT"
	r.Action = "STOP"
	if e = m.save(r); e != nil {
		return empty, e
	}
	if e = m.unchanged(r); e != nil {
		return empty, desktopError("MIGRATION_UNKNOWN")
	}
	privateIntent, intentErr := desktopDir(dir, m.uid, true)
	if intentErr != nil {
		return empty, desktopError("JOURNAL_UNCERTAIN")
	}
	if e = desktopPublish(dir, ".sent", []byte("STOP\n"), 0600, privateIntent); e != nil {
		return empty, desktopError("JOURNAL_UNCERTAIN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	ack, stopErr := m.stop(ctx)
	cancel()
	if stopErr == nil && migrationBound(ack, r.Metadata, r.Metadata.HelperSHA256) && migrationAck(ack) {
		h, e = m.helper()
	} else {
		e = desktopError("MIGRATION_UNKNOWN")
	}
	if e != nil || !migrationBound(h, r.Metadata, r.Metadata.HelperSHA256) || !migrationStopped(h) {
		r.Metadata.Phase = "UNKNOWN"
		_ = m.save(r)
		return empty, desktopError("MIGRATION_UNKNOWN")
	}
	r.Metadata.Phase = "STOP_VERIFIED"
	if e = m.save(r); e != nil {
		return empty, e
	}
	if e = m.unchanged(r); e != nil {
		return empty, e
	}
	old, e := controlInstallCapture(r.Metadata.Binary)
	if e != nil {
		return empty, desktopError("BACKUP_FAILED")
	}
	private, e := desktopDir(dir, m.uid, true)
	if e != nil {
		return empty, e
	}
	if e = desktopPublish(dir, "old-binary", old, 0700, private); e != nil {
		return empty, e
	}
	b, e := controlInstallCapture(filepath.Join(dir, "old-binary"))
	if e != nil || desktopSum(b) != r.Metadata.OldBinarySHA256 {
		return empty, desktopError("BACKUP_FAILED")
	}
	r.BackupSHA256 = desktopSum(b)
	r.Metadata.Phase = "AWAITING_HELPER"
	if e = m.save(r); e != nil {
		return empty, e
	}
	return r.Metadata, nil
}
func (m desktopMigration) finish(op string) (desktopMigrationMetadata, error) {
	var empty desktopMigrationMetadata
	if !desktopMigrationToken(op) {
		return empty, desktopError("INVALID_COMMAND")
	}
	lock, e := m.lock()
	if e != nil {
		return empty, e
	}
	defer lock.Close()
	if e = m.pending(op); e != nil {
		return empty, e
	}
	r, e := m.record(op)
	if e != nil {
		return empty, e
	}
	if r.Metadata.Phase == "COMMITTED" {
		now, readErr := m.capture()
		if readErr != nil || now.Pin.Aggregate != r.Pin.Aggregate || now.Pin.RootDevice != r.Pin.RootDevice || now.Pin.RootInode != r.Pin.RootInode || now.Metadata.OldBinarySHA256 != r.Metadata.BinarySHA256 {
			return empty, desktopError("COMMITTED_STATE_CHANGED")
		}
		if _, readErr = desktopFile(r.Metadata.Binary, m.uid, 0755); readErr != nil {
			return empty, desktopError("COMMITTED_STATE_CHANGED")
		}
		return r.Metadata, nil
	}
	if r.Metadata.Phase != "AWAITING_HELPER" {
		return empty, desktopError("MIGRATION_UNKNOWN")
	}
	if e = m.unchanged(r); e != nil {
		return empty, e
	}
	h, e := m.helper()
	if e != nil || !migrationBound(h, r.Metadata, r.Metadata.BinarySHA256) || !migrationStopped(h) || h.HelperVersion != currentVersion() {
		return empty, desktopError("NEW_HELPER_NOT_READY")
	}
	if _, e = desktopFile(r.Metadata.Stage, m.uid, 0700); e != nil {
		return empty, desktopError("STAGE_CHANGED")
	}
	b, e := controlInstallCapture(r.Metadata.Stage)
	if e != nil || desktopSum(b) != r.Metadata.BinarySHA256 {
		return empty, desktopError("STAGE_CHANGED")
	}
	backup := filepath.Join(m.opPath(op), "old-binary")
	if _, e = desktopFile(backup, m.uid, 0700); e != nil {
		return empty, desktopError("BACKUP_CHANGED")
	}
	old, e := controlInstallCapture(backup)
	if e != nil || desktopSum(old) != r.BackupSHA256 || r.BackupSHA256 != r.Metadata.OldBinarySHA256 {
		return empty, desktopError("BACKUP_CHANGED")
	}
	// Exclusive fsynced candidate; preserve authorization stage for diagnostics.
	root := filepath.Dir(r.Metadata.Binary)
	f, e := os.CreateTemp(root, ".desktop-publish-*")
	if e != nil {
		return empty, desktopError("PUBLICATION_FAILED")
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	e = f.Chmod(0755)
	if e == nil {
		var n int
		n, e = f.Write(b)
		if n != len(b) && e == nil {
			e = desktopError("PUBLICATION_FAILED")
		}
	}
	if e == nil {
		e = f.Sync()
	}
	e = errors.Join(e, f.Close())
	if e != nil {
		return empty, desktopError("PUBLICATION_FAILED")
	}
	if e = m.unchanged(r); e != nil {
		return empty, e
	}
	h, e = m.helper()
	if e != nil || !migrationBound(h, r.Metadata, r.Metadata.BinarySHA256) || !migrationStopped(h) {
		return empty, desktopError("NEW_HELPER_NOT_READY")
	}
	if e = m.unchanged(r); e != nil {
		return empty, e
	}
	r.Metadata.Phase = "PUBLISHING"
	if e = m.save(r); e != nil {
		return empty, e
	}
	if e = os.Rename(tmp, r.Metadata.Binary); e == nil {
		e = migrationSync(root)
	}
	actual, readErr := controlInstallCapture(r.Metadata.Binary)
	if e != nil || readErr != nil || desktopSum(actual) != r.Metadata.BinarySHA256 {
		r.Metadata.Phase = "UNKNOWN"
		_ = m.save(r)
		return empty, desktopError("MIGRATION_UNKNOWN")
	}
	r.Metadata.Phase = "COMMITTED"
	if e = m.save(r); e != nil {
		return empty, desktopError("MIGRATION_UNKNOWN")
	}
	return r.Metadata, nil
}
func desktopMigrationRun(args []string, home, source string, uid int) (desktopMigrationMetadata, error) {
	m := desktopMigration{home: home, source: source, uid: uid, status: controlInstallStatus, stop: func(ctx context.Context) (controlHelperResponse, error) {
		return controlHelperRequest(ctx, "stop", false)
	}}
	if _, err := m.sourceImage(); err != nil {
		return desktopMigrationMetadata{}, err
	}
	switch args[0] {
	case "migration-inspect":
		return m.inspect()
	case "migration-commit":
		return m.commit(args[1])
	case "migration-finish":
		return m.finish(args[1])
	}
	return desktopMigrationMetadata{}, desktopError("INVALID_COMMAND")
}

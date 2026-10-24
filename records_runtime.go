package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"time"

	cr "github.com/NiuStar/anytls-core/internal/connectionrecords"
)

// The only CLI option is an eligibility marker, not a path/UID/store override.
// The caller invokes this only for an explicit -record-service compiled Run.
func openRunRecords(stagedConfig string, compiled compiledRuntime) (*cr.Writer, error) {
	if os.Geteuid() != 0 || externalCoreRequired() || !controlHelperSupported() {
		return nil, cr.TelemetryUnavailable
	}
	reg, err := recordsReadRegistration()
	if err != nil {
		return nil, cr.TelemetryUnavailable
	}
	scope, header, err := runRecordsBinding(stagedConfig, compiled, reg, time.Now())
	if err != nil {
		return nil, err
	}
	fd, e := syscall.Open(stagedConfig, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, cr.TelemetryUnavailable
	}
	leaf := os.NewFile(uintptr(fd), stagedConfig)
	li, e := leaf.Stat()
	st, ok := infoSys(li)
	if e == nil && (!ok || st.Uid != 0 || st.Nlink != 1 || !li.Mode().IsRegular() || li.Mode().Perm() != 0600) {
		e = cr.StoreInvalid
	}
	if e == nil {
		parent, pe := os.Lstat(filepath.Dir(stagedConfig))
		if pe != nil || !controlHelperRootOwned(parent) {
			e = cr.StoreInvalid
		}
	}
	if e == nil {
		current, ce := os.Lstat(stagedConfig)
		if ce != nil || !os.SameFile(li, current) {
			e = cr.StoreInvalid
		}
	}
	e = errors.Join(e, leaf.Close())
	if e != nil {
		return nil, cr.TelemetryUnavailable
	}
	// Re-read the protected registration after binding. No current YAML compiler
	// or raw manifest is persisted or used to relabel the originating generation.
	again, err := recordsReadRegistration()
	if err != nil || again != reg {
		return nil, cr.TelemetryUnavailable
	}
	return cr.OpenWriter(scope, header)
}
func recordsReadRegistration() (controlHelperRegistration, error) {
	var reg controlHelperRegistration
	if err := controlHelperTrustedPath(controlHelperRegistrationPath, false); err != nil {
		return reg, err
	}
	fd, err := syscall.Open(controlHelperRegistrationPath, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return reg, err
	}
	f := os.NewFile(uintptr(fd), controlHelperRegistrationPath)
	info, err := f.Stat()
	if err == nil && (!info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !controlHelperRootOwned(info)) {
		err = cr.StoreInvalid
	}
	if st, ok := infoSys(info); err == nil && (!ok || st.Nlink != 1) {
		err = cr.StoreInvalid
	}
	if err == nil {
		err = controlHelperDecode(f, map[string]any{"uid": &reg.UID, "config": &reg.Config, "home": &reg.Home})
	}
	if err == nil {
		now, e := os.Lstat(controlHelperRegistrationPath)
		if e != nil || !os.SameFile(info, now) || now.Size() != info.Size() || !now.ModTime().Equal(info.ModTime()) {
			err = cr.StoreInvalid
		}
	}
	err = errors.Join(err, f.Close())
	if err != nil || reg.UID == 0 || !controlHelperAbsolute(reg.Config) || !controlHelperAbsolute(reg.Home) {
		return controlHelperRegistration{}, cr.TelemetryUnavailable
	}
	return reg, nil
}
func infoSys(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return st, ok
}

// Pure association/digest validation separated only for isolated nonroot tests;
// production eligibility always passes through the root checks above.
func runRecordsBinding(stagedConfig string, compiled compiledRuntime, reg controlHelperRegistration, now time.Time) (cr.Scope, cr.Header, error) {
	unavailable := func() (cr.Scope, cr.Header, error) { return cr.Scope{}, cr.Header{}, cr.TelemetryUnavailable }
	if reg.UID == 0 || !controlHelperAbsolute(reg.Config) || !controlHelperAbsolute(stagedConfig) || compiled.Manifest == nil {
		return unavailable()
	}
	expected := filepath.Join(filepath.Dir(reg.Config), "service", "config.yaml")
	if stagedConfig != expected {
		return unavailable()
	}
	info, err := os.Lstat(stagedConfig)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return unavailable()
	}
	// Staging lives under the existing user directory and is not upgraded to
	// root-ancestor authenticity, but its immediate root and leaf must be actual
	// root-created private snapshot objects in production.
	parent, e := os.Lstat(filepath.Dir(stagedConfig))
	if e != nil || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 || parent.Mode().Perm() != 0700 {
		return unavailable()
	}
	identity, err := controlHelperConfigIdentity(reg.Config)
	if err != nil {
		return unavailable()
	}
	m := compiled.Manifest
	if cr.Validate(*m) != nil {
		return unavailable()
	}
	digest, err := cr.ManifestDigest(*m, cr.ManifestBudget(m))
	if err != nil || digest != m.ManifestID {
		return unavailable()
	}
	sum := sha256.Sum256(compiled.JSON)
	if m.RuntimeSHA256 != hex.EncodeToString(sum[:]) {
		return unavailable()
	}
	// The manifest self-digest and actual runtime byte digest above are checked
	// without persisting or publishing the manifest itself.
	h := cr.Header{SchemaVersion: cr.SchemaVersion, ConfigIdentity: identity, Binding: m.Binding, RuntimeSHA256: m.RuntimeSHA256, CreatedAt: now.UTC().Format(time.RFC3339Nano)}
	if cr.Validate(h) != nil {
		return unavailable()
	}
	return cr.Scope{UID: reg.UID, ConfigIdentity: identity}, h, nil
}

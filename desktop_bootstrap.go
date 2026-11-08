package main

// Desktop bootstrap deliberately does not own helper, console or VPN lifecycle.
// It reuses the existing fixed installer authority and adjacent-config layout.
import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	osuser "os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"time"
)

const desktopStarter = "# Add your own nodes using the complete console; VPN is not started automatically.\nproxies: []\nproxy-groups: []\nrules: []\n"

type desktopMetadata struct {
	Schema         int    `json:"schema"`
	Version        string `json:"version"`
	Binary         string `json:"binary"`
	Config         string `json:"config"`
	ConfigIdentity string `json:"config_identity"`
	BinarySHA256   string `json:"binary_sha256"`
	Endpoint       string `json:"endpoint"`
	Listen         string `json:"listen"`
	Port           int    `json:"port"`
	UID            int    `json:"uid"`
	Home           string `json:"home"`
	Installed      bool   `json:"installed"`
	HelperState    string `json:"helper_state"`
	Loaded         bool   `json:"loaded"`
	Running        bool   `json:"running"`
}

func desktopSum(b []byte) string     { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func desktopError(code string) error { return errors.New(code) }

// No environment override: production authority is the system account record.
func desktopIdentity() (string, int, error) {
	uid := os.Getuid()
	if runtime.GOOS != "darwin" || uid <= 0 || os.Geteuid() != uid {
		return "", 0, desktopError("UNSUPPORTED_IDENTITY")
	}
	u, err := osuser.LookupId(strconv.Itoa(uid))
	if err != nil {
		return "", 0, desktopError("UNSUPPORTED_IDENTITY")
	}
	home, err := filepath.EvalSymlinks(u.HomeDir)
	if err != nil || home != u.HomeDir {
		return "", 0, desktopError("UNSAFE_HOME")
	}
	return home, uid, nil
}

func desktopCommand(args []string) error { return desktopDispatch(args, os.Stdout) }
func desktopDispatch(args []string, out io.Writer) error {
	fail := func(code string) error {
		err := json.NewEncoder(out).Encode(struct {
			Schema int    `json:"schema"`
			Error  string `json:"error"`
		}{1, code})
		if err != nil {
			return desktopError("desktop response failed")
		}
		return desktopError("desktop bootstrap refused; inspect safe JSON error")
	}
	migration := len(args) > 0 && (args[0] == "migration-inspect" || args[0] == "migration-commit" || args[0] == "migration-finish" || args[0] == "migration-recovery-inspect" || args[0] == "migration-recovery-commit" || args[0] == "migration-recovery-finalize")
	inspectMigration := migration && (args[0] == "migration-inspect" || args[0] == "migration-recovery-inspect")
	validMigration := migration && ((inspectMigration && len(args) == 1) || (!inspectMigration && len(args) == 2 && desktopMigrationToken(args[1])))
	if !validMigration && (len(args) != 1 || (args[0] != "prepare" && args[0] != "inspect" && args[0] != "credentials")) {
		return fail("INVALID_COMMAND")
	}
	if externalCoreRequired() {
		return fail("EMBEDDED_CORE_REQUIRED")
	}
	if args[0] == "credentials" {
		// Refuse terminal and regular-file output. The GUI supplies a private
		// anonymous pipe; credentials must never become an evidence/log file.
		pipe, ok := out.(*os.File)
		if !ok {
			return fail("PRIVATE_PIPE_REQUIRED")
		}
		info, pipeErr := pipe.Stat()
		if pipeErr != nil || info.Mode()&os.ModeNamedPipe == 0 {
			return fail("PRIVATE_PIPE_REQUIRED")
		}
	}
	home, uid, err := desktopIdentity()
	if err != nil {
		return fail(err.Error())
	}
	source, err := os.Executable()
	if err != nil {
		return fail("EXECUTABLE_UNAVAILABLE")
	}
	// Do not normalize a symlink source into an apparently acceptable path.
	physical, err := filepath.EvalSymlinks(source)
	if err != nil || physical != source {
		return fail("UNSAFE_EXECUTABLE")
	}
	if migration {
		m, err := desktopMigrationRun(args, home, source, uid)
		if err != nil {
			if m.Operation != "" {
				if encodeErr := json.NewEncoder(out).Encode(struct {
					Schema    int                      `json:"schema"`
					Error     string                   `json:"error"`
					Migration desktopMigrationMetadata `json:"migration"`
				}{1, err.Error(), m}); encodeErr != nil {
					return desktopError("desktop response failed")
				}
				return desktopError("desktop migration held; inspect safe JSON error")
			}
			return fail(err.Error())
		}
		return json.NewEncoder(out).Encode(m)
	}
	if args[0] == "prepare" {
		// A helper without this default runtime may belong to a custom old
		// installer root. Do not create a competing default installation.
		if _, helperErr := os.Lstat(controlHelperExecutable); helperErr == nil || !errors.Is(helperErr, os.ErrNotExist) {
			if _, targetErr := os.Lstat(filepath.Join(home, ".anytls", "anytls-macos")); targetErr != nil {
				return fail("EXISTING_HELPER_REQUIRES_REVIEW")
			}
		}
		m, err := desktopPrepare(home, source, uid)
		if err != nil {
			return fail(err.Error())
		}
		return json.NewEncoder(out).Encode(m)
	}
	target := filepath.Join(home, ".anytls", "anytls-macos")
	if source != target {
		return fail("INSTALLED_RUNTIME_REQUIRED")
	}
	m, err := desktopInspect(home, uid)
	if err != nil {
		return fail(err.Error())
	}
	if args[0] == "inspect" {
		return json.NewEncoder(out).Encode(m)
	}
	if m.HelperState != "ready" {
		return fail("HELPER_NOT_READY")
	}
	secret, err := desktopReadCredential(home, uid)
	if err != nil {
		return fail("UNSAFE_PASSWORD")
	}
	// Dedicated private pipe to the app only. Never include this object in logs.
	return json.NewEncoder(out).Encode(struct {
		Schema   int    `json:"schema"`
		Endpoint string `json:"endpoint"`
		Password string `json:"password"`
	}{1, m.Endpoint, secret})
}

func desktopDir(path string, uid int, private bool) (os.FileInfo, error) {
	s, err := os.Lstat(path)
	if err != nil {
		return nil, desktopError("UNSAFE_DIRECTORY")
	}
	st, ok := s.Sys().(*syscall.Stat_t)
	if !ok || !s.IsDir() || s.Mode()&os.ModeSymlink != 0 || st.Uid != uint32(uid) || s.Mode().Perm()&0022 != 0 || (private && s.Mode().Perm() != 0700) {
		return nil, desktopError("UNSAFE_DIRECTORY")
	}
	return s, nil
}
func desktopFile(path string, uid int, mode os.FileMode) (os.FileInfo, error) {
	s, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, os.ErrNotExist
		}
		return nil, desktopError("UNSAFE_FILE")
	}
	st, ok := s.Sys().(*syscall.Stat_t)
	if !ok || !s.Mode().IsRegular() || st.Uid != uint32(uid) || st.Nlink != 1 || s.Mode()&os.ModeType != 0 || (mode != 0 && s.Mode().Perm() != mode) || s.Mode().Perm()&0022 != 0 {
		return nil, desktopError("UNSAFE_FILE")
	}
	return s, nil
}
func desktopBase(home string, uid int, create bool) (string, error) {
	if !filepath.IsAbs(home) || filepath.Clean(home) != home {
		return "", desktopError("UNSAFE_HOME")
	}
	physical, err := filepath.EvalSymlinks(home)
	if err != nil || physical != home {
		return "", desktopError("UNSAFE_HOME")
	}
	if _, err = desktopDir(home, uid, false); err != nil {
		return "", err
	}
	root := filepath.Join(home, ".anytls")
	if create {
		if err = os.Mkdir(root, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return "", desktopError("CREATE_FAILED")
		}
	}
	if _, err = desktopDir(root, uid, false); err != nil {
		return "", err
	}
	return root, nil
}
func desktopInfo(home, root string, uid int, image []byte) desktopMetadata {
	config := filepath.Join(root, "config.yaml")
	return desktopMetadata{Schema: 1, Version: currentVersion(), Binary: filepath.Join(root, "anytls-macos"), Config: config, ConfigIdentity: desktopSum([]byte(config)), BinarySHA256: desktopSum(image), Endpoint: "http://127.0.0.1:18089", Listen: "0.0.0.0", Port: 18089, UID: uid, Home: home, HelperState: "not_checked"}
}

func desktopPrepare(home, source string, uid int) (desktopMetadata, error) {
	var empty desktopMetadata
	suffix := filepath.Join("AnyTLSMenuBar.app", "Contents", "Resources", "runtime", "anytls-macos")
	if !filepath.IsAbs(source) || filepath.Clean(source) != source || filepath.Base(filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(source))))) != "AnyTLSMenuBar.app" {
		return empty, desktopError("INVALID_BUNDLE_LAYOUT")
	}
	app := filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(source))))
	if source != filepath.Join(filepath.Dir(app), suffix) {
		return empty, desktopError("INVALID_BUNDLE_LAYOUT")
	}
	physical, err := filepath.EvalSymlinks(source)
	if err != nil || physical != source {
		return empty, desktopError("UNSAFE_SOURCE")
	}
	s, err := os.Lstat(source)
	if err != nil || !s.Mode().IsRegular() || s.Mode().Perm()&0111 == 0 {
		return empty, desktopError("UNSAFE_SOURCE")
	}
	image, err := controlInstallCapture(source)
	if err != nil || len(image) == 0 {
		return empty, desktopError("SOURCE_CAPTURE_FAILED")
	}
	root, err := desktopBase(home, uid, true)
	if err != nil {
		return empty, err
	}
	anchor, err := desktopDir(root, uid, false)
	if err != nil {
		return empty, err
	}
	m := desktopInfo(home, root, uid, image)
	// The old installer also accepted the legacy leaf `anytls`. Do not infer
	// that this is an absent/fresh installation and silently create a sibling.
	if _, legacyErr := os.Lstat(filepath.Join(root, "anytls")); legacyErr == nil || !errors.Is(legacyErr, os.ErrNotExist) {
		return empty, desktopError("LEGACY_LAYOUT_REQUIRES_REVIEW")
	}
	exists := false
	if _, err = desktopFile(m.Binary, uid, 0755); err == nil {
		exists = true
		old, e := controlInstallCapture(m.Binary)
		if e != nil {
			return empty, desktopError("TARGET_CAPTURE_FAILED")
		}
		if desktopSum(old) != m.BinarySHA256 {
			return empty, desktopError("UPDATE_REQUIRED")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return empty, err
	}
	// Validate all existing managed leaves before writing anything inside root.
	for _, name := range []string{"config.yaml", "webui.password"} {
		mode := os.FileMode(0)
		if name == "webui.password" {
			mode = 0600
		}
		if _, err = desktopFile(filepath.Join(root, name), uid, mode); err != nil && !errors.Is(err, os.ErrNotExist) {
			return empty, err
		}
	}
	password := filepath.Join(root, "webui.password")
	if _, err = os.Lstat(password); err == nil {
		if _, err = webReadPassword(password); err != nil {
			return empty, desktopError("UNSAFE_PASSWORD")
		}
	}
	// A partial fresh setup is safe to retry: only absent leaves are published.
	if err = desktopPublish(root, "config.yaml", []byte(desktopStarter), 0600, anchor); err != nil {
		return empty, err
	}
	if _, err = os.Lstat(password); errors.Is(err, os.ErrNotExist) {
		secret, e := webRandom(24)
		if e != nil {
			return empty, desktopError("PASSWORD_CREATE_FAILED")
		}
		if err = desktopPublish(root, "webui.password", []byte(secret+"\n"), 0600, anchor); err != nil {
			return empty, err
		}
	}
	if _, err = webReadPassword(password); err != nil {
		return empty, desktopError("UNSAFE_PASSWORD")
	}
	if !exists {
		if err = desktopPublish(root, "anytls-macos", image, 0755, anchor); err != nil {
			return empty, err
		}
		m.Installed = true
	}
	// Read back installed bytes and identity, not only successful publication.
	if _, err = desktopFile(m.Binary, uid, 0755); err != nil {
		return empty, err
	}
	actual, err := controlInstallCapture(m.Binary)
	if err != nil || desktopSum(actual) != m.BinarySHA256 {
		return empty, desktopError("TARGET_READBACK_FAILED")
	}
	if err = controlInstallUserPaths(uid, home, m.Binary); err != nil {
		return empty, desktopError("RUNTIME_BINDING_FAILED")
	}
	return m, nil
}

// Link publication is atomic and never replaces an incumbent, including one
// created concurrently. Same-UID Plan B integrity, not a hostile-user sandbox.
func desktopPublish(root, name string, data []byte, mode os.FileMode, anchor os.FileInfo) error {
	owner, ok := anchor.Sys().(*syscall.Stat_t)
	if !ok {
		return desktopError("DIRECTORY_CHANGED")
	}
	current, err := desktopDir(root, int(owner.Uid), false)
	if err != nil || !os.SameFile(anchor, current) || current.Mode() != anchor.Mode() {
		return desktopError("DIRECTORY_CHANGED")
	}
	dest := filepath.Join(root, name)
	if _, err = os.Lstat(dest); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return desktopError("TARGET_UNAVAILABLE")
	}
	f, err := os.CreateTemp(root, ".desktop-*")
	if err != nil {
		return desktopError("STAGING_FAILED")
	}
	temp := f.Name()
	defer os.Remove(temp)
	if err = f.Chmod(mode); err == nil {
		var n int
		n, err = f.Write(data)
		if err == nil && n != len(data) {
			err = io.ErrShortWrite
		}
	}
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return desktopError("STAGING_FAILED")
	}
	current, err = desktopDir(root, int(owner.Uid), false)
	if err != nil || !os.SameFile(anchor, current) || current.Mode() != anchor.Mode() {
		return desktopError("DIRECTORY_CHANGED")
	}
	if err = os.Link(temp, dest); err != nil {
		return desktopError("PUBLICATION_CONFLICT")
	}
	if err = os.Remove(temp); err != nil {
		return desktopError("PUBLICATION_FAILED")
	}
	dir, err := os.Open(root)
	if err != nil {
		return desktopError("SYNC_FAILED")
	}
	err = errors.Join(dir.Sync(), dir.Close())
	if err != nil {
		return desktopError("SYNC_FAILED")
	}
	return nil
}
func desktopReadCredential(home string, uid int) (string, error) {
	root, err := desktopBase(home, uid, false)
	if err != nil {
		return "", err
	}
	path := filepath.Join(root, "webui.password")
	if _, err = desktopFile(path, uid, 0600); err != nil {
		return "", err
	}
	return webReadPassword(path)
}

func desktopHelperState(m desktopMetadata, r controlHelperResponse, err error) string {
	if err != nil {
		return "unavailable"
	}
	if !r.OK || r.HelperSHA256 != m.BinarySHA256 || r.ConfigIdentity != m.ConfigIdentity {
		return "mismatch"
	}
	return "ready"
}
func desktopInspect(home string, uid int) (desktopMetadata, error) {
	var empty desktopMetadata
	root, err := desktopBase(home, uid, false)
	if err != nil {
		return empty, err
	}
	target := filepath.Join(root, "anytls-macos")
	if _, err = desktopFile(target, uid, 0755); err != nil {
		return empty, desktopError("UNSAFE_RUNTIME")
	}
	if err = controlInstallUserPaths(uid, home, target); err != nil {
		return empty, desktopError("RUNTIME_BINDING_FAILED")
	}
	if _, err = desktopFile(filepath.Join(root, "webui.password"), uid, 0600); err != nil {
		return empty, desktopError("UNSAFE_PASSWORD")
	}
	image, err := controlInstallCapture(target)
	if err != nil {
		return empty, desktopError("TARGET_CAPTURE_FAILED")
	}
	m := desktopInfo(home, root, uid, image)
	if _, err = os.Lstat(controlHelperExecutable); errors.Is(err, os.ErrNotExist) {
		m.HelperState = "missing"
		return m, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r, err := controlInstallStatus(ctx)
	m.HelperState = desktopHelperState(m, r, err)
	if m.HelperState == "ready" {
		m.Loaded = r.Loaded
		m.Running = r.Running
	}
	return m, nil
}

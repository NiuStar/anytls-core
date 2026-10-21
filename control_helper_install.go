package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	osuser "os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Installer constants intentionally have their own namespace; the protocol and
// server own their public constants and registration schema.
const (
	controlInstallRoot  = "/Library/PrivilegedHelperTools/com.nousresearch.anytls-control"
	controlInstallLabel = "com.nousresearch.anytls-control"
	controlInstallPlist = "/Library/LaunchDaemons/com.nousresearch.anytls-control.plist"
)

func controlHelperCommand(args []string) error {
	if len(args) != 1 || (args[0] != "install" && args[0] != "status") {
		return errors.New("usage: anytls helper install|status")
	}
	if runtime.GOOS != "darwin" {
		return errors.New("control helper requires macOS")
	}
	if args[0] == "status" {
		if _, err := os.Lstat(controlInstallRoot + "/anytls-control"); errors.Is(err, os.ErrNotExist) {
			return errors.New("control helper not installed; run 'anytls helper install' in a local terminal")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		response, err := controlInstallStatus(ctx)
		if err != nil {
			return fmt.Errorf("helper unavailable (if not installed, run 'anytls helper install'): %w", err)
		}
		return json.NewEncoder(os.Stdout).Encode(response)
	}
	if externalCoreRequired() {
		return errors.New("control helper installation requires an embedded_core build")
	}
	if os.Geteuid() == 0 {
		return errors.New("run 'anytls helper install' as the ordinary user in a local terminal")
	}
	user, err := osuser.Current()
	if err != nil {
		return err
	}
	uid, err := strconv.Atoi(user.Uid)
	if err != nil || uid <= 0 || uid != os.Getuid() {
		return errors.New("cannot identify installing user")
	}
	binary, _, _, err := servicePaths()
	if err != nil {
		return err
	}
	if err := controlInstallUserPaths(uid, user.HomeDir, binary); err != nil {
		return err
	}
	// Native sudo owns the terminal prompt. No password is read, retained, or
	// transported through the application or HTTP API.
	cmd := exec.Command("/usr/bin/sudo", "--", binary, "helper-install-root", user.Uid, user.HomeDir)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("helper authorization/install failed: %w", err)
	}
	// launchctl loaded is not readiness. The ordinary client verifies the
	// socket peer and executable identity; root is deliberately not a client.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for {
		response, err := controlInstallStatus(ctx)
		if err == nil {
			return json.NewEncoder(os.Stdout).Encode(response)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("helper installed but authenticated status readback failed: %w", err)
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// controlHelperInstallRoot is called only by the fixed three-argument main
// dispatch: helper-install-root UID HOME. No destination comes from argv.
func controlHelperInstallRoot(uid int, home string) error {
	if runtime.GOOS != "darwin" || os.Geteuid() != 0 {
		return errors.New("helper installer requires macOS root authorization")
	}
	if externalCoreRequired() {
		return errors.New("control helper installation requires an embedded_core build")
	}
	user, err := osuser.LookupId(strconv.Itoa(uid))
	if err != nil || uid <= 0 || uint64(uid) > uint64(^uint32(0)) || home != user.HomeDir {
		return errors.New("authorized UID/home does not match the system user")
	}
	userGID, err := strconv.ParseUint(user.Gid, 10, 32)
	if err != nil {
		return errors.New("cannot identify authorized user's primary group")
	}
	binary, _, _, err := servicePaths()
	if err != nil {
		return err
	}
	if err := controlInstallUserPaths(uid, home, binary); err != nil {
		return err
	}
	config := filepath.Join(filepath.Dir(binary), "config.yaml")
	// Capture and hash the same open handle. This is the explicitly authorized
	// Plan B source, not a claim to resist a malicious same-UID application.
	image, err := controlInstallCapture(binary)
	if err != nil {
		return err
	}
	registration, err := json.Marshal(controlHelperRegistration{UID: uint32(uid), Config: config, Home: home})
	if err != nil {
		return err
	}
	plist, err := controlInstallPlistBytes(config)
	if err != nil {
		return err
	}
	for _, dir := range []string{filepath.Dir(controlInstallRoot), filepath.Dir(controlInstallPlist)} {
		if err := controlInstallGuardAncestors(dir, 0); err != nil {
			return err
		}
	}
	if err := os.Mkdir(controlInstallRoot, 0755); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return err
		}
	}
	if err := controlInstallGuardAncestors(controlInstallRoot, 0); err != nil {
		return err
	}
	if err := os.Chmod(controlInstallRoot, 0755); err != nil {
		return err
	}
	// Leave the root directory in place on failure: never recursively remove
	// a parent, nor claim files which this attempt did not create.

	files := []controlInstallFile{
		{path: filepath.Join(controlInstallRoot, "anytls-control"), data: image, mode: 0755},
		{path: filepath.Join(controlInstallRoot, "registration.json"), data: registration, mode: 0600},
		{path: controlInstallPlist, data: plist, mode: 0644},
	}
	log := filepath.Join(controlInstallRoot, "control.log")
	_, err = os.Lstat(log)
	logExists := err == nil
	if errors.Is(err, os.ErrNotExist) {
		err = nil
	}
	if err != nil {
		return err
	}
	if err := controlInstallLog(log); err != nil {
		return err
	}
	tool := func(args ...string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if out, err := runTool(ctx, "/bin/launchctl", args...); err != nil {
			if args[0] == "print" && ctx.Err() == nil && strings.Contains(out, "Could not find service \""+controlInstallLabel+"\"") {
				return os.ErrNotExist
			}
			return fmt.Errorf("helper launchctl %s failed: %w", args[0], err)
		}
		return nil
	}
	expected := sha256.Sum256(image)
	err = controlInstallTransaction(files, controlInstallAtomic, tool, func() error {
		return controlInstallVerifyReady(uint32(uid), uint32(userGID), home, hex.EncodeToString(expected[:]))
	})
	if err != nil && !logExists && errors.Is(tool("print", "system/"+controlInstallLabel), os.ErrNotExist) {
		if removeErr := os.Remove(log); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			err = errors.Join(err, removeErr)
		}
	}
	return err
}

// controlInstallVerifyReady runs before the root transaction releases its old
// files. Root itself never connects to the socket: only this fixed, read-only
// command in the protected candidate runs with the registered ordinary UID.
func controlInstallVerifyReady(uid, gid uint32, home, expectedSHA string) error {
	if uid == 0 {
		return errors.New("helper readiness requires an ordinary UID")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var last error
	for {
		probe, done := context.WithTimeout(ctx, 4*time.Second)
		out, err := runTool(probe, "/bin/launchctl", "print", "system/"+controlInstallLabel)
		if err == nil && !isServiceActive(controlInstallLabel, out) {
			err = errors.New("candidate helper is not running with a PID")
		}
		if err == nil {
			err = controlHelperTrustedPath(controlInstallRoot+"/anytls-control", false)
		}
		if err == nil {
			cmd := controlInstallStatusCommand(probe, uid, gid, home)
			var status bytes.Buffer
			cmd.Stdout = &status
			// Stderr is intentionally discarded; never reflect child/tool details.
			err = cmd.Run()
			if err == nil {
				err = controlInstallReadyResponse(status.Bytes(), expectedSHA)
			}
		}
		if err == nil {
			err = probe.Err()
		}
		done()
		if err == nil {
			return nil
		}
		last = err
		select {
		case <-ctx.Done():
			return fmt.Errorf("candidate helper authenticated readiness failed: %w", errors.Join(last, ctx.Err()))
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func controlInstallStatusCommand(ctx context.Context, uid, gid uint32, home string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, controlInstallRoot+"/anytls-control", "helper", "status")
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{
		Uid: uid, Gid: gid, Groups: []uint32{gid},
	}}
	cmd.Dir = "/"
	// No inherited USER, dynamic-loader variables, app flags, or user PATH.
	// The status branch does not call os/user.Current (including CGO=0 builds).
	cmd.Env = []string{"HOME=" + home, "PATH=/usr/bin:/bin"}
	return cmd
}

func controlInstallReadyResponse(data []byte, expectedSHA string) error {
	var response controlHelperResponse
	d := json.NewDecoder(bytes.NewReader(data))
	if err := d.Decode(&response); err != nil {
		return errors.New("candidate helper status is not valid JSON")
	}
	var trailing any
	if err := d.Decode(&trailing); err != io.EOF {
		return errors.New("candidate helper status has trailing data")
	}
	if !response.OK || response.HelperSHA256 != expectedSHA {
		return errors.New("candidate helper status rejected or SHA256 does not match candidate")
	}
	return nil
}

func controlInstallStatus(ctx context.Context) (controlHelperResponse, error) {
	response, err := controlHelperRequest(ctx, "status", false)
	if err != nil {
		return response, err
	}
	if err := controlHelperTrustedPath(controlInstallRoot+"/anytls-control", false); err != nil {
		return response, err
	}
	image, err := controlInstallCapture(controlInstallRoot + "/anytls-control")
	if err != nil {
		return response, fmt.Errorf("cannot verify installed helper digest: %w", err)
	}
	sum := sha256.Sum256(image)
	if response.HelperSHA256 != hex.EncodeToString(sum[:]) {
		return response, errors.New("helper status executable SHA256 does not match installed helper")
	}
	return response, nil
}

func controlInstallWithin(home, path string) bool {
	rel, err := filepath.Rel(home, path)
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && !filepath.IsAbs(rel)
}

func controlInstallUserPaths(uid int, home, binary string) error {
	if uid <= 0 || !filepath.IsAbs(home) || filepath.Clean(home) != home || !filepath.IsAbs(binary) || filepath.Clean(binary) != binary || !controlInstallWithin(home, binary) {
		return errors.New("installer requires a physical executable beneath the authorized home")
	}
	// Home, source parents, executable and config must all be real entries.
	// User-writable config directories are intentional existing Plan B policy.
	for path := binary; ; path = filepath.Dir(path) {
		st, err := os.Lstat(path)
		if err != nil || st.Mode()&os.ModeSymlink != 0 {
			return errors.New("installer source path is missing or contains a symlink")
		}
		if path == binary {
			if !st.Mode().IsRegular() || st.Mode().Perm()&0111 == 0 {
				return errors.New("installer source must be a regular executable")
			}
		} else if !st.IsDir() {
			return errors.New("installer source parent must be a directory")
		}
		if path == home {
			s, ok := st.Sys().(*syscall.Stat_t)
			if !ok || s.Uid != uint32(uid) {
				return errors.New("home must be owned by the authorized user")
			}
			break
		}
	}
	// Also reject a symlink above home; ownership above home may be root.
	for p := filepath.Dir(home); ; p = filepath.Dir(p) {
		st, err := os.Lstat(p)
		if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return errors.New("home ancestry must not contain symlinks")
		}
		if p == string(os.PathSeparator) {
			break
		}
	}
	config := filepath.Join(filepath.Dir(binary), "config.yaml")
	st, err := os.Lstat(config)
	if err != nil || !st.Mode().IsRegular() {
		return errors.New("fixed sibling config.yaml must be a regular file")
	}
	return nil
}

func controlInstallGuardAncestors(path string, uid uint32) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("helper target must be an absolute clean path")
	}
	for p := path; ; p = filepath.Dir(p) {
		st, err := os.Lstat(p)
		if err != nil {
			return fmt.Errorf("helper target ancestor unavailable: %w", err)
		}
		s, ok := st.Sys().(*syscall.Stat_t)
		if !ok || s.Uid != uid || !st.IsDir() || st.Mode().Perm()&0022 != 0 || st.Mode()&os.ModeSymlink != 0 {
			return errors.New("helper target ancestry must be root-owned, non-writable real directories")
		}
		if p == string(os.PathSeparator) {
			return nil
		}
	}
}

func controlInstallCapture(path string) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return nil, errors.New("helper source is not a regular file")
	}
	var b bytes.Buffer
	hash := sha256.New()
	if _, err := io.Copy(io.MultiWriter(&b, hash), f); err != nil {
		return nil, err
	}
	// Verify capture metadata before publishing its immutable byte slice.
	after, err := f.Stat()
	if err != nil || st.Size() != after.Size() || !st.ModTime().Equal(after.ModTime()) || int64(b.Len()) != st.Size() {
		return nil, errors.New("helper source changed while capturing")
	}
	sum := sha256.Sum256(b.Bytes())
	if hex.EncodeToString(hash.Sum(nil)) != hex.EncodeToString(sum[:]) {
		return nil, errors.New("helper capture digest mismatch")
	}
	return b.Bytes(), nil
}

func controlInstallPlistBytes(config string) ([]byte, error) {
	if !filepath.IsAbs(config) || filepath.Clean(config) != config || strings.ContainsAny(config, "\x00\r\n") {
		return nil, errors.New("helper config must be a clean absolute path")
	}
	escape := func(s string) string {
		var b bytes.Buffer
		_ = xml.EscapeText(&b, []byte(s))
		return b.String()
	}
	log := controlInstallRoot + "/control.log"
	return []byte("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n" +
		"<key>Label</key><string>" + controlInstallLabel + "</string>\n" +
		"<key>ProgramArguments</key><array><string>" + controlInstallRoot + "/anytls-control</string><string>helper-serve</string></array>\n" +
		"<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>\n<key>ThrottleInterval</key><integer>10</integer>\n" +
		"<key>WorkingDirectory</key><string>" + escape(filepath.Dir(config)) + "</string>\n" +
		"<key>StandardOutPath</key><string>" + log + "</string>\n<key>StandardErrorPath</key><string>" + log + "</string>\n</dict></plist>\n"), nil
}

type controlInstallFile struct {
	path string
	data []byte
	mode os.FileMode
}

func controlInstallExisting(path string) ([]byte, bool, error) {
	st, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok || s.Uid != uint32(os.Geteuid()) || !st.Mode().IsRegular() || st.Mode().Perm()&0022 != 0 {
		return nil, false, errors.New("unsafe existing helper target")
	}
	b, err := controlInstallCapture(path)
	return b, true, err
}

func controlInstallAtomic(path string, data []byte, mode os.FileMode) (err error) {
	if _, _, err := controlInstallExisting(path); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".anytls-install-*")
	if err != nil {
		return err
	}
	temp := f.Name()
	defer os.Remove(temp)
	defer func() {
		if f != nil {
			_ = f.Close()
		}
	}()
	if err = f.Chmod(mode); err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	err = f.Close()
	f = nil
	if err != nil {
		return err
	}
	if err = os.Rename(temp, path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func controlInstallLog(path string) error {
	st, err := os.Lstat(path)
	if err == nil {
		s, ok := st.Sys().(*syscall.Stat_t)
		if !ok || s.Uid != uint32(os.Geteuid()) || !st.Mode().IsRegular() || st.Mode().Perm()&0022 != 0 {
			return errors.New("unsafe helper log")
		}
		return os.Chmod(path, 0600)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return controlInstallAtomic(path, nil, 0600)
}

// The only launchctl target is the helper label, never the VPN label. The
// fixture seam changes I/O, not production paths or authorization checks.
// The variadic readiness hook preserves old fixtures; production always supplies
// controlInstallVerifyReady and cannot commit on launchctl registration alone.
func controlInstallTransaction(files []controlInstallFile, write func(string, []byte, os.FileMode) error, tool func(...string) error, ready ...func() error) error {
	old := make([]controlInstallFile, len(files))
	exists := make([]bool, len(files))
	for i, f := range files {
		b, found, err := controlInstallExisting(f.path)
		if err != nil {
			return err
		}
		old[i] = controlInstallFile{path: f.path, data: b, mode: f.mode}
		exists[i] = found
		if found {
			st, err := os.Lstat(f.path)
			if err != nil {
				return err
			}
			old[i].mode = st.Mode().Perm()
		}
	}
	if exists[0] {
		if err := write(files[0].path+".backup", old[0].data, 0755); err != nil {
			return fmt.Errorf("helper backup failed: %w", err)
		}
	}
	// Detect an absent job without treating arbitrary bootout failures as OK.
	stateErr := tool("print", "system/"+controlInstallLabel)
	if stateErr != nil && !errors.Is(stateErr, os.ErrNotExist) {
		return stateErr
	}
	loaded := stateErr == nil
	if loaded {
		if err := tool("bootout", "system/"+controlInstallLabel); err != nil {
			return err
		}
	}
	touched := 0
	rollback := func(cause error) error {
		var failures []error
		failures = append(failures, cause)
		for i := touched - 1; i >= 0; i-- {
			var err error
			if exists[i] {
				err = write(old[i].path, old[i].data, old[i].mode)
			} else {
				err = os.Remove(files[i].path)
				if errors.Is(err, os.ErrNotExist) {
					err = nil
				}
			}
			if err != nil {
				failures = append(failures, fmt.Errorf("helper rollback file: %w", err))
			}
		}
		if len(failures) == 1 && exists[0] && exists[1] && exists[2] {
			if err := tool("bootstrap", "system", files[2].path); err != nil {
				failures = append(failures, fmt.Errorf("old helper bootstrap failed: %w", err))
			}
		}
		return errors.Join(failures...)
	}
	for i, f := range files {
		// Include a rename followed by fsync failure in rollback ownership.
		touched = i + 1
		if err := write(f.path, f.data, f.mode); err != nil {
			return rollback(err)
		}
	}
	if err := tool("bootstrap", "system", files[2].path); err != nil {
		// A failed bootstrap may still have partially registered its job.
		if stateErr := tool("print", "system/"+controlInstallLabel); !errors.Is(stateErr, os.ErrNotExist) {
			if stopErr := tool("bootout", "system/"+controlInstallLabel); stopErr != nil {
				return errors.Join(err, fmt.Errorf("rollback blocked: cannot unload new helper: %w", stopErr))
			}
		}
		return rollback(err)
	}
	if err := tool("print", "system/"+controlInstallLabel); err != nil {
		stopErr := tool("bootout", "system/"+controlInstallLabel)
		if stopErr != nil {
			return errors.Join(err, fmt.Errorf("rollback blocked: cannot unload new helper: %w", stopErr))
		}
		return rollback(err)
	}
	for _, verify := range ready {
		if err := verify(); err != nil {
			// Never rewrite files under a candidate whose unload is unknown.
			if stopErr := tool("bootout", "system/"+controlInstallLabel); stopErr != nil {
				return errors.Join(err, fmt.Errorf("rollback blocked: cannot unload new helper: %w", stopErr))
			}
			return rollback(err)
		}
	}
	return nil
}

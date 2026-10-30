package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// The flag/label is a locator, not authority. Every readiness decision re-reads
// secure files AND launchd's actual program/argument/path/PID fields.
type webAgentSpec struct {
	Binary, Config, Home, Host string
	Port, UID                  int
}

func (s webAgentSpec) label() string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%d\x00%s\x00%s", s.UID, s.Binary, s.Config)))
	return "com.anytls.webui." + hex.EncodeToString(h[:12])
}
func (s webAgentSpec) path() string {
	return filepath.Join(s.Home, "Library", "LaunchAgents", s.label()+".plist")
}
func (s webAgentSpec) target() string { return fmt.Sprintf("gui/%d/%s", s.UID, s.label()) }
func (s webAgentSpec) argv() []string {
	return []string{s.Binary, "webui", "--listen", s.Host, "--port", strconv.Itoa(s.Port), "--managed-agent", s.label()}
}
func webXML(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}
func (s webAgentSpec) plist() []byte {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>Label</key><string>` + webXML(s.label()) + `</string><key>ProgramArguments</key><array>`)
	for _, a := range s.argv() {
		b.WriteString("<string>" + webXML(a) + "</string>")
	}
	b.WriteString(`</array><key>EnvironmentVariables</key><dict><key>HOME</key><string>` + webXML(s.Home) + `</string></dict><key>RunAtLoad</key><true/><key>KeepAlive</key><true/><key>ExitTimeOut</key><integer>0</integer><key>ThrottleInterval</key><integer>3</integer></dict></plist>`)
	return []byte(b.String())
}

// Refuse symlinks, writable ancestors and foreign-owned leaves; do not chmod or
// repair operator paths. Root ownership is permitted only on ancestors.
func webAgentSecure(path string, uid int, dir bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\r\n\t\x00") {
		return errors.New("agent path must be absolute and canonical")
	}
	parts := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	p := string(filepath.Separator)
	for i, part := range parts {
		p = filepath.Join(p, part)
		f, err := os.Lstat(p)
		if err != nil {
			return err
		}
		st, ok := f.Sys().(*syscall.Stat_t)
		if !ok {
			return errors.New("agent file ownership unavailable")
		}
		leaf := i == len(parts)-1
		if f.Mode()&os.ModeSymlink != 0 || f.Mode().Perm()&0022 != 0 || (st.Uid != uint32(uid) && (leaf || st.Uid != 0)) {
			return errors.New("unsafe agent file ownership, link or permissions")
		}
		if (!leaf || dir) && !f.IsDir() || leaf && !dir && !f.Mode().IsRegular() {
			return errors.New("agent path has wrong file type")
		}
	}
	return nil
}
func (s webAgentSpec) secure() error {
	if s.UID <= 0 || s.UID != os.Getuid() || os.Geteuid() != s.UID || filepath.Join(filepath.Dir(s.Binary), "config.yaml") != s.Config {
		return errors.New("agent identity mismatch")
	}
	if s.Port < 1024 || s.Port > 65535 {
		return errors.New("invalid agent port")
	}
	if err := webValidateListen(s.Host); err != nil {
		return err
	}
	for _, p := range []string{s.Binary, s.Config} {
		if err := webAgentSecure(p, s.UID, false); err != nil {
			return err
		}
	}
	return webAgentSecure(s.Home, s.UID, true)
}
func (s webAgentSpec) validatePlist() error {
	if err := s.secure(); err != nil {
		return err
	}
	if err := webAgentSecure(s.path(), s.UID, false); err != nil {
		return err
	}
	b, err := os.ReadFile(s.path())
	if err != nil {
		return err
	}
	if !bytes.Equal(b, s.plist()) {
		return errors.New("agent plist differs from generated contract")
	}
	return nil
}
func webAgentLaunch(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "/bin/launchctl", args...)
	var out webBoundedOutput
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	err := cmd.Run()
	if err != nil || out.overflow {
		return "", errors.New("launchctl unavailable or job not found")
	}
	return string(out.b), nil
}

// launchctl print is structured text. Only exact direct keys are authoritative;
// nested service names, old PIDs and substring matches cannot grant authority.
func webAgentJobMatches(text string, s webAgentSpec, pid int) error {
	lines := strings.Split(text, "\n")
	fields := map[string]string{}
	var args []string
	inArgs := false
	if len(lines) == 0 || !strings.HasPrefix(lines[0], s.target()+" = {") {
		return errors.New("launchd target mismatch")
	}
	for _, line := range lines[1:] {
		if inArgs {
			if line == "\t}" {
				inArgs = false
				continue
			}
			if !strings.HasPrefix(line, "\t\t") || strings.HasPrefix(line, "\t\t\t") {
				return errors.New("invalid launchd argument block")
			}
			args = append(args, strings.TrimPrefix(line, "\t\t"))
			continue
		}
		if !strings.HasPrefix(line, "\t") || strings.HasPrefix(line, "\t\t") {
			continue
		}
		key, val, ok := strings.Cut(strings.TrimPrefix(line, "\t"), " = ")
		if !ok {
			continue
		}
		if key == "arguments" {
			if val != "{" || args != nil {
				return errors.New("invalid launchd arguments")
			}
			inArgs = true
			args = []string{}
			continue
		}
		if key == "path" || key == "program" || key == "pid" || key == "type" || key == "state" || key == "domain" || key == "properties" {
			if _, exists := fields[key]; exists {
				return errors.New("duplicate launchd key")
			}
			fields[key] = val
		}
	}
	if inArgs || fields["path"] != s.path() || fields["program"] != s.Binary || fields["pid"] != strconv.Itoa(pid) || strings.Join(args, "\x00") != strings.Join(s.argv(), "\x00") {
		return errors.New("launchd process does not match managed console")
	}
	if fields["type"] != "LaunchAgent" || fields["state"] != "running" || !strings.HasPrefix(fields["domain"], fmt.Sprintf("gui/%d [", s.UID)) {
		return errors.New("launchd domain or state mismatch")
	}
	keepalive, runatload := false, false
	for _, p := range strings.Split(fields["properties"], " | ") {
		if p == "keepalive" {
			keepalive = true
		}
		if p == "runatload" {
			runatload = true
		}
	}
	if !keepalive || !runatload {
		return errors.New("launchd restart policy mismatch")
	}
	return nil
}
func (s webAgentSpec) verify(pid int) error {
	if runtime.GOOS != "darwin" {
		return errors.New("LaunchAgents require macOS")
	}
	if err := s.validatePlist(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	text, err := webAgentLaunch(ctx, "print", s.target())
	if err != nil {
		return err
	}
	return webAgentJobMatches(text, s, pid)
}
func webAgentCurrent(host string, port int) (webAgentSpec, error) {
	binary, config, _, err := servicePaths()
	if err != nil {
		return webAgentSpec{}, err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return webAgentSpec{}, err
	}
	return webAgentSpec{binary, config, home, host, port, os.Getuid()}, nil
}

type webAgentFlags struct {
	fs   *flag.FlagSet
	host *string
	port *int
}

func newWebAgentFlags(action string) webAgentFlags {
	fs := flag.NewFlagSet("webui "+action, flag.ContinueOnError)
	return webAgentFlags{fs, fs.String("listen", "127.0.0.1", "existing WebUI listen IPv4"), fs.Int("port", 18089, "existing WebUI port")}
}
func webAgentCommand(action string, args []string) error {
	if runtime.GOOS != "darwin" {
		return errors.New("user LaunchAgents require macOS")
	}
	fs := newWebAgentFlags(action)
	if err := fs.fs.Parse(args); err != nil {
		return err
	}
	if fs.fs.NArg() != 0 {
		return errors.New("unexpected agent arguments")
	}
	s, err := webAgentCurrent(*fs.host, *fs.port)
	if err != nil {
		return err
	}
	if err = s.secure(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if action == "agent-status" {
		text, lookupErr := webAgentLaunch(ctx, "print", s.target())
		pid := webAgentJobPID(text)
		managed := lookupErr == nil && pid > 0 && s.verify(pid) == nil
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"label": s.label(), "target": s.target(), "plist": s.path(), "pid": pid, "restartManaged": managed})
	}
	if _, err := webAgentLaunch(ctx, "print", s.target()); err == nil {
		return errors.New("agent job already loaded; inspect agent-status; bootout is idle-only and may interrupt an active installation and its child; never unload during installation")
	}
	// Never kill or take over a manual listener, even if it looks like AnyTLS.
	listener, err := net.Listen("tcp4", net.JoinHostPort(s.Host, strconv.Itoa(s.Port)))
	if err != nil {
		return errors.New("console address is occupied; stop the old WebUI explicitly (not the VPN) before installing its agent")
	}
	listener.Close()
	parent := filepath.Dir(s.path())
	// Create one owned level at a time, validating existing paths before descent.
	for _, p := range []string{filepath.Join(s.Home, "Library"), parent} {
		if err := os.Mkdir(p, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		if err := webAgentSecure(p, s.UID, true); err != nil {
			return err
		}
	}
	if _, err := os.Lstat(s.path()); err == nil {
		if err := s.validatePlist(); err != nil {
			return errors.New("refusing to overwrite existing foreign or modified agent plist")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	} else {
		f, err := os.CreateTemp(parent, ".anytls-webui-*.plist")
		if err != nil {
			return err
		}
		name := f.Name()
		defer os.Remove(name)
		if _, err = f.Write(s.plist()); err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		// Atomic no-clobber publication, preserving every existing file/backup.
		if err := os.Link(name, s.path()); err != nil {
			return err
		}
	}
	if err := s.validatePlist(); err != nil {
		return err
	}
	if _, err := webAgentLaunch(ctx, "bootstrap", fmt.Sprintf("gui/%d", s.UID), s.path()); err != nil {
		return fmt.Errorf("agent plist preserved at %s; bootstrap failed (GUI login required)", s.path())
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		text, err := webAgentLaunch(ctx, "print", s.target())
		pid := webAgentJobPID(text)
		if err == nil && pid > 0 && s.verify(pid) == nil {
			fmt.Printf("WebUI agent loaded: %s\nPlist: %s\nWARNING: bootout is idle-only; it may interrupt an active installation and its child even with ExitTimeOut=0. Never unload during installation.\nStop without respawn (idle only): launchctl bootout %s\n", s.target(), s.path(), s.target())
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("agent loaded but process identity not confirmed; inspect agent-status; plist retained")
}
func webAgentJobPID(text string) int {
	pid := 0
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "\tpid = ") {
			if pid != 0 {
				return 0
			}
			n, err := strconv.Atoi(strings.TrimPrefix(line, "\tpid = "))
			if err != nil || n <= 0 {
				return 0
			}
			pid = n
		}
	}
	return pid
}

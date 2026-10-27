package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	st "github.com/NiuStar/anytls-core/internal/startuptimeline"
	"golang.org/x/term"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const serviceLabel = "com.nousresearch.anytls-macos"
const serviceLogName = "anytls.log"
const serviceBaselineName = "baseline.json"

func serviceRoot() (string, error) {
	_, config, _, err := servicePaths()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(config), "service"), nil
}
func servicePlistPath() (string, error) {
	root, err := serviceRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "anytls.plist"), nil
}

type networkBaseline struct {
	Version         int               `json:",omitempty"`
	Servers         map[string]string `json:",omitempty"`
	Server          string
	ServerInterface string
	PublicInterface string
	DNS             []string
}

func dnsServers() ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := runTool(ctx, "/usr/sbin/scutil", "--dns")
	if err != nil {
		return nil, err
	}
	var entries []string
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "nameserver[") {
			entries = append(entries, strings.TrimSpace(line))
		}
	}
	return entries, nil
}

func servicePlist(binary, config, core, log string, insecure bool) (string, error) {
	return servicePlistStartup(binary, config, core, log, insecure, "", "")
}
func serviceArgs(binary, config, core string, insecure bool, operation, epoch string) []string {
	args := []string{binary, "-config", config}
	if externalCoreRequired() {
		args = append(args, "-core", core)
	}
	args = append(args, "-network", "tun")
	if !externalCoreRequired() {
		args = append(args, "-record-service")
	}
	if insecure {
		args = append(args, "-allow-insecure")
	}
	if operation != "" && epoch != "" && !externalCoreRequired() {
		args = append(args, "-startup-operation", operation, "-startup-epoch", epoch)
	}
	return append(args, "run")
}
func servicePlistStartup(binary, config, core, log string, insecure bool, operation, epoch string) (string, error) {
	if operation != "" || epoch != "" {
		if externalCoreRequired() || st.Validate(st.PushAck{TimelineSchema: 1, Code: "OK", OperationID: operation}) != nil || st.Validate(st.PushAck{TimelineSchema: 1, Code: "OK", OperationID: epoch}) != nil {
			return "", errors.New("invalid startup correlation")
		}
	}
	paths := []string{binary, config}
	if externalCoreRequired() {
		paths = append(paths, core)
	}
	paths = append(paths, log)
	for _, s := range paths {
		if !filepath.IsAbs(s) || strings.ContainsAny(s, "<>\"'&\n\r\x00") {
			return "", errors.New("service paths must be absolute without XML control characters")
		}
	}
	args := serviceArgs(binary, config, core, insecure, operation, epoch)
	var b strings.Builder
	b.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n<key>Label</key><string>" + serviceLabel + "</string>\n<key>ProgramArguments</key><array>\n")
	for _, v := range args {
		var escaped bytes.Buffer
		if err := xml.EscapeText(&escaped, []byte(v)); err != nil {
			return "", err
		}
		b.WriteString("<string>" + escaped.String() + "</string>\n")
	}
	b.WriteString("</array>\n<key>RunAtLoad</key><true/>\n<key>KeepAlive</key><false/>\n<key>StandardOutPath</key><string>" + log + "</string>\n<key>StandardErrorPath</key><string>" + log + "</string>\n</dict></plist>\n")
	return b.String(), nil
}

func isServiceActive(label, output string) bool {
	if strings.Contains(output, "state = running") && strings.Contains(output, "pid = ") {
		return strings.Contains(output, "system/"+label+" = {")
	}
	return false
}

func runTool(ctx context.Context, name string, args ...string) (string, error) {
	c := exec.CommandContext(ctx, name, args...)
	out, err := c.CombinedOutput()
	return string(out), err
}
func serviceState() (loaded, running bool, err error) {
	return serviceStateWithTool(runTool)
}
func serviceStateWithTool(tool func(context.Context, string, ...string) (string, error)) (loaded, running bool, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	out, e := tool(ctx, "/bin/launchctl", "print", "system/"+serviceLabel)
	if e != nil {
		if ctx.Err() == nil && strings.Contains(out, "Could not find service \""+serviceLabel+"\"") {
			return false, false, nil
		}
		return false, false, lifecycleFailure("launchctl job state unavailable", e)
	}
	if !strings.Contains(out, "system/"+serviceLabel+" = {") {
		return false, false, errors.New("launchctl returned an unrecognized job state")
	}
	return true, isServiceActive(serviceLabel, out), nil
}
func launched() (bool, error) {
	_, running, err := serviceState()
	return running, err
}

func routeInterface(ip string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	out, err := runTool(ctx, "/sbin/route", "-n", "get", ip)
	if err != nil {
		return "", fmt.Errorf("route %s: %w", ip, err)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "interface:") {
			return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "interface:")), nil
		}
	}
	return "", errors.New("route interface missing")
}
func preflightServiceNode(config string) (node, error) {
	captured, err := captureServiceConfig(config)
	if err != nil {
		return node{}, err
	}
	n, err := captured.selected()
	if err != nil {
		return node{}, err
	}
	// Routed insecure nodes require the same explicit selected-node consent.
	if _, err := captured.compile(n.SkipVerify); err != nil {
		return node{}, err
	}
	return n, nil
}

func selectedServiceNode(config string) (node, error) {
	captured, err := captureServiceConfig(config)
	if err != nil {
		return node{}, err
	}
	return captured.selected()
}

// One bounded capture is shared by selection and routing compilation. This is
// byte coherence, not an atomic pair snapshot or a hostile same-UID boundary.
type serviceConfigBytes struct {
	path              string
	config, selection []byte
}

func captureServiceConfig(config string) (serviceConfigBytes, error) {
	captured := serviceConfigBytes{path: config}
	var err error
	captured.config, err = readSnapshotSource(config, snapshotConfigLimit, false)
	if err != nil {
		return captured, err
	}
	captured.selection, err = readSnapshotSource(selectedPath(config), snapshotSelectedLimit, false)
	if errors.Is(err, os.ErrNotExist) {
		err = nil
	}
	return captured, err
}

func (captured serviceConfigBytes) selected() (node, error) {
	nodes, err := loadNodesBytes(captured.config)
	if err != nil {
		return node{}, err
	}
	if captured.selection == nil {
		return node{}, errors.New("select a node first with 'anytls config'")
	}
	current, err := selectedBytes(captured.selection, nodes)
	if err != nil {
		return node{}, err
	}
	if current == "" {
		return node{}, errors.New("select a node first with 'anytls config'")
	}
	n, err := choose(nodes, current)
	if err != nil {
		return node{}, err
	}
	if _, err := buildNode(n, "tun", 0, n.SkipVerify); err != nil {
		return node{}, err
	}
	return n, nil
}
func servicePaths() (binary, config, core string, err error) {
	binary, err = os.Executable()
	if err != nil {
		return
	}
	binary, err = filepath.EvalSymlinks(binary)
	if err != nil {
		return
	}
	dir := filepath.Dir(binary)
	config = filepath.Join(dir, "config.yaml")
	core = filepath.Join(dir, "sing-box")
	return
}
func sudoSubcommand(sub string, insecure bool) error {
	binary, _, _, err := servicePaths()
	if err != nil {
		return err
	}
	args := []string{binary, sub}
	if insecure {
		args = append(args, "-allow-insecure")
	}
	c := exec.Command("/usr/bin/sudo", args...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	return c.Run()
}
func checkProxyInactive() error {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	out, err := runTool(ctx, "/usr/sbin/scutil", "--proxy")
	if err != nil {
		return err
	}
	for _, key := range []string{"HTTPEnable", "HTTPSEnable", "SOCKSEnable"} {
		if strings.Contains(out, key+" : 1") {
			return &systemProxyActiveError{}
		}
	}
	return nil
}
func stagePrivateRun(binary, config, core, root string) error {
	return stagePrivateRunOwned(binary, config, core, root, &snapshotRootIdentity{})
}
func stagePrivateRunOwned(binary, config, core, root string, owned *snapshotRootIdentity) (result error) {
	return stagePrivateRunOwnedContext(context.Background(), binary, config, core, root, owned)
}
func stagePrivateRunOwnedContext(ctx context.Context, binary, config, core, root string, owned *snapshotRootIdentity) (result error) {
	if err := os.Mkdir(root, 0700); err != nil {
		return lifecycleFailure("snapshot root cannot be created", err)
	}
	captured, err := snapshotRootAt(root)
	if err != nil {
		return &snapshotStageError{cause: err}
	}
	*owned = *captured
	defer func() {
		if err := owned.check(); err != nil {
			result = errors.Join(result, err)
		}
		if result != nil {
			result = &snapshotStageError{cause: result, owned: owned}
		}
	}()
	r := st.FromContext(ctx)
	span := r.Begin("START", "SNAPSHOT_APP_CONFIG_SELECTED", st.Fields{})
	defer func() {
		if span != 0 {
			r.End(span, startupCode(result), st.Fields{})
		}
	}()
	for _, f := range []struct {
		source, name string
		mode         os.FileMode
		limit        int64
	}{
		{binary, "anytls-macos", 0700, snapshotAppLimit}, {core, "sing-box", 0700, snapshotAppLimit},
		{config, "config.yaml", 0600, snapshotConfigLimit}, {selectedPath(config), "config.yaml.selected", 0600, snapshotSelectedLimit},
	} {
		if f.name == "sing-box" && !externalCoreRequired() {
			continue
		}
		b, err := readSnapshotSource(f.source, f.limit, false)
		if err != nil {
			return err
		}
		if err := owned.check(); err != nil {
			return err
		}
		if err := writeSnapshotLeaf(filepath.Join(root, f.name), b, f.mode); err != nil {
			return err
		}
	}
	r.End(span, "OK", st.Fields{})
	span = 0
	if err := startupSpan(ctx, "START", "SNAPSHOT_RULES", func() error { return stageRuleSets(config, root) }); err != nil {
		return err
	}
	return startupSpan(ctx, "START", "SNAPSHOT_CA", func() error { return stageCAs(root) })
}

func confirmInsecure(in *os.File) error {
	if !term.IsTerminal(int(in.Fd())) {
		return errors.New("TLS certificate verification disabled; run start in a terminal to confirm")
	}
	fmt.Fprint(os.Stderr, "警告：此节点跳过 TLS 证书校验，可能被中间人攻击。仅继续连通测试？输入 yes: ")
	r := bufio.NewReader(in)
	line, err := r.ReadString('\n')
	if err != nil {
		return err
	}
	if strings.TrimSpace(line) != "yes" {
		return errors.New("cancelled: TLS risk not accepted")
	}
	return nil
}
func serviceStart(allowInsecure bool) error {
	if os.Geteuid() != 0 {
		return errors.New("service-start requires sudo")
	}
	binary, config, core, err := servicePaths()
	if err != nil {
		return err
	}
	root, err := serviceRoot()
	if err != nil {
		return err
	}
	return newServiceLifecycle(root).start(binary, config, core, allowInsecure)
}
func serviceStop() error {
	if os.Geteuid() != 0 {
		return errors.New("service-stop requires sudo")
	}
	root, err := serviceRoot()
	if err != nil {
		return err
	}
	return newServiceLifecycle(root).stop()
}

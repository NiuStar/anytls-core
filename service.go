package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"golang.org/x/term"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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
	for _, s := range []string{binary, config, core, log} {
		if !filepath.IsAbs(s) || strings.ContainsAny(s, "<>\"'&\n\r\x00") {
			return "", errors.New("service paths must be absolute without XML control characters")
		}
	}
	args := []string{binary, "-config", config, "-core", core, "-network", "tun"}
	if insecure {
		args = append(args, "-allow-insecure")
	}
	args = append(args, "run")
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
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	out, e := runTool(ctx, "/bin/launchctl", "print", "system/"+serviceLabel)
	if e != nil {
		if strings.Contains(out, "Could not find service") || strings.Contains(out, "service is disabled") {
			return false, false, nil
		}
		return false, false, fmt.Errorf("launchctl print: %s: %w", strings.TrimSpace(out), e)
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
func selectedServiceNode(config string) (node, error) {
	nodes, err := loadNodes(config)
	if err != nil {
		return node{}, err
	}
	current, err := selectedNode(config, nodes)
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
			return errors.New("system proxy active; turn it off before starting TUN")
		}
	}
	return nil
}
func stagePrivateRun(binary, config, core, root string) error {
	if err := os.Mkdir(root, 0700); err != nil {
		return err
	}
	for _, f := range []struct {
		source, name string
		mode         os.FileMode
	}{
		{binary, "anytls-macos", 0700}, {core, "sing-box", 0700},
		{config, "config.yaml", 0600}, {selectedPath(config), "config.yaml.selected", 0600},
	} {
		st, err := os.Lstat(f.source)
		if err != nil {
			return err
		}
		if !st.Mode().IsRegular() {
			return fmt.Errorf("unsafe source file: %s", f.name)
		}
		b, err := os.ReadFile(f.source)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(root, f.name), b, f.mode); err != nil {
			return err
		}
	}
	return stageRuleSets(config, root)
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
	n, err := selectedServiceNode(config)
	if err != nil {
		return err
	}
	if n.SkipVerify && !allowInsecure {
		return errors.New("unconfirmed insecure TLS")
	}
	if err := checkProxyInactive(); err != nil {
		return err
	}
	{ // Validate every configured outbound server before touching system routes.
		nodes, err := loadNodes(config)
		if err != nil {
			return err
		}
		cfg, err := buildNode(n, "tun", 0, allowInsecure)
		if err != nil {
			return err
		}
		if err := applyRouting(config, nodes, n, cfg, allowInsecure); err != nil {
			return err
		}
		for _, entry := range cfg["outbounds"].([]any) {
			out := entry.(map[string]any)
			if out["type"] != "anytls" {
				continue
			}
			server := out["server"].(string)
			iface, err := routeInterface(server)
			if err != nil {
				return err
			}
			if iface == "" || strings.HasPrefix(iface, "utun") {
				return fmt.Errorf("server route %s is not on physical interface", server)
			}
		}
	}
	loaded, active, err := serviceState()
	if err != nil {
		return err
	}
	if loaded {
		return errors.New("AnyTLS job already loaded; run 'anytls stop' before starting")
	}
	if active {
		return errors.New("already running")
	}
	beforeServer, err := routeInterface(n.Server)
	if err != nil {
		return err
	}
	beforePublic, err := routeInterface("1.1.1.1")
	if err != nil {
		return err
	}
	beforeDNS, err := dnsServers()
	if err != nil {
		return err
	}
	if beforeServer == "" || strings.HasPrefix(beforeServer, "utun") || beforePublic == "" || strings.HasPrefix(beforePublic, "utun") {
		return errors.New("server/public route is not on physical interface")
	}
	root, err := serviceRoot()
	if err != nil {
		return err
	}
	if err := stagePrivateRun(binary, config, core, root); err != nil {
		if !errors.Is(err, os.ErrExist) {
			_ = os.RemoveAll(root)
		}
		return err
	}
	baselineBytes, err := json.Marshal(networkBaseline{Server: n.Server, ServerInterface: beforeServer, PublicInterface: beforePublic, DNS: beforeDNS})
	if err != nil {
		os.RemoveAll(root)
		return err
	}
	if err := os.WriteFile(filepath.Join(root, serviceBaselineName), baselineBytes, 0600); err != nil {
		os.RemoveAll(root)
		return err
	}
	defer func() {
		loaded, _, _ := serviceState()
		if !loaded {
			_ = os.RemoveAll(root)
		}
	}()
	plist, err := servicePlist(filepath.Join(root, "anytls-macos"), filepath.Join(root, "config.yaml"), filepath.Join(root, "sing-box"), filepath.Join(root, serviceLogName), n.SkipVerify)
	if err != nil {
		return err
	}
	servicePath := filepath.Join(root, "anytls.plist")
	if st, err := os.Lstat(servicePath); err == nil {
		if !st.Mode().IsRegular() {
			return errors.New("service plist path is not regular")
		}
		return errors.New("service plist already exists; inspect and remove stale job before start")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.OpenFile(servicePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err = f.WriteString(plist); err != nil {
		f.Close()
		os.Remove(servicePath)
		return err
	}
	if err = f.Close(); err != nil {
		os.Remove(servicePath)
		return err
	}
	checkCtx, checkCancel := context.WithTimeout(context.Background(), 5*time.Second)
	checkOut, checkErr := runTool(checkCtx, "/usr/bin/plutil", "-lint", servicePath)
	checkCancel()
	if checkErr != nil {
		os.Remove(servicePath)
		return fmt.Errorf("invalid launchd plist: %s: %w", strings.TrimSpace(checkOut), checkErr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if out, err := runTool(ctx, "/bin/launchctl", "bootstrap", "system", servicePath); err != nil {
		os.Remove(servicePath)
		return fmt.Errorf("launchd bootstrap: %s: %w", strings.TrimSpace(out), err)
	}
	success := false
	defer func() {
		if !success {
			_ = serviceStop()
		}
	}()
	for i := 0; i < 16; i++ {
		live, _ := launched()
		target, _ := routeInterface("1.1.1.1")
		server, _ := routeInterface(n.Server)
		if live && strings.HasPrefix(target, "utun") {
			if server != beforeServer {
				return errors.New("server route entered TUN; rolled back")
			}
			probeCtx, probeCancel := context.WithTimeout(context.Background(), 15*time.Second)
			probe, probeErr := runTool(probeCtx, "/usr/bin/curl", "--noproxy", "*", "-4", "-fsS", "--connect-timeout", "5", "--max-time", "12", "https://api.ipify.org")
			probeCancel()
			if probeErr != nil || net.ParseIP(strings.TrimSpace(probe)) == nil {
				return errors.New("TUN route present but HTTPS exit probe failed; rolled back")
			}
			success = true
			fmt.Printf("TUN started: node=%s, public=%s, server=%s, observed exit=%s; TLS identity %s\n", n.Name, target, server, strings.TrimSpace(probe), map[bool]string{true: "unverified", false: "verified by configured CA"}[n.SkipVerify])
			return nil
		}
		time.Sleep(time.Second)
	}
	return errors.New("TUN did not become ready; rolled back")
}
func serviceStop() error {
	if os.Geteuid() != 0 {
		return errors.New("service-stop requires sudo")
	}
	loaded, _, err := serviceState()
	if err != nil {
		return err
	}
	if !loaded {
		fmt.Println("AnyTLS is not running")
		return nil
	}
	root, err := serviceRoot()
	if err != nil {
		return err
	}
	servicePath := filepath.Join(root, "anytls.plist")
	var baseline networkBaseline
	b, readErr := os.ReadFile(filepath.Join(root, serviceBaselineName))
	if readErr == nil {
		readErr = json.Unmarshal(b, &baseline)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	if out, err := runTool(ctx, "/bin/launchctl", "bootout", "system/"+serviceLabel); err != nil {
		return fmt.Errorf("launchd bootout: %s: %w", strings.TrimSpace(out), err)
	}
	for i := 0; i < 12; i++ {
		loaded, _, err := serviceState()
		if err != nil {
			return err
		}
		target, _ := routeInterface("1.1.1.1")
		server, _ := routeInterface(baseline.Server)
		dns, _ := dnsServers()
		if !loaded && readErr != nil && !strings.HasPrefix(target, "utun") {
			return fmt.Errorf("service stopped, public route %s; baseline unavailable: %w", target, readErr)
		}
		if !loaded && target == baseline.PublicInterface && server == baseline.ServerInterface && slices.Equal(dns, baseline.DNS) {
			if err := os.Remove(servicePath); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			if err := os.RemoveAll(root); err != nil {
				return err
			}
			fmt.Println("AnyTLS stopped; public route restored to", target)
			return nil
		}
		time.Sleep(time.Second)
	}
	return errors.New("service stopped but public route still on utun; inspect network now")
}

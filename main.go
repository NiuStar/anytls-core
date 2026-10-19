package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type options struct{ Server, SNI, Password, CA string }

func splitEndpoint(endpoint string) (string, int, error) {
	host, p, err := net.SplitHostPort(endpoint)
	if err != nil || net.ParseIP(host) == nil || strings.Contains(host, "%") {
		return "", 0, errors.New("server must be an IP:port (IPv6 in brackets)")
	}
	port, err := strconv.Atoi(p)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, errors.New("invalid server port")
	}
	return host, port, nil
}

func build(o options) (map[string]any, error) {
	host, port, err := splitEndpoint(o.Server)
	if err != nil {
		return nil, err
	}
	if o.SNI == "" || strings.ContainsAny(o.SNI, "/: \t\n") {
		return nil, errors.New("a valid TLS server name is required")
	}
	if o.Password == "" {
		return nil, errors.New("password is required")
	}
	if o.CA == "" {
		return nil, errors.New("CA PEM file is required; certificate verification cannot be disabled")
	}
	st, err := os.Stat(o.CA)
	if err != nil || !st.Mode().IsRegular() || st.Size() == 0 {
		return nil, errors.New("CA PEM must be a nonempty regular file")
	}
	ca, err := filepath.Abs(o.CA)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"log":       map[string]any{"level": "info", "timestamp": true},
		"dns":       map[string]any{"servers": []any{map[string]any{"type": "https", "tag": "secure-dns", "server": "1.1.1.1", "tls": map[string]any{"server_name": "cloudflare-dns.com"}, "detour": "anytls-out"}}, "final": "secure-dns"},
		"inbounds":  []any{map[string]any{"type": "tun", "tag": "tun-in", "address": []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"}, "mtu": 1500, "auto_route": true, "dns_mode": "hijack", "stack": "mixed"}},
		"outbounds": []any{map[string]any{"type": "anytls", "tag": "anytls-out", "server": host, "server_port": port, "password": o.Password, "tls": map[string]any{"enabled": true, "server_name": o.SNI, "certificate_path": ca}}},
		"route":     map[string]any{"auto_detect_interface": true, "final": "anytls-out"},
	}, nil
}

func execute(args []string) error {
	if len(args) == 0 {
		args = []string{"select"}
	}
	if len(args) == 1 && args[0] == "config" {
		loaded, _, err := serviceState()
		if err != nil {
			return err
		}
		if loaded {
			return errors.New("stop AnyTLS before changing nodes")
		}
		args = []string{"select"}
	}
	if len(args) == 1 && args[0] == "status" {
		live, err := launched()
		if err != nil {
			return err
		}
		if live {
			fmt.Println("AnyTLS TUN running")
		} else {
			fmt.Println("AnyTLS TUN stopped")
		}
		return nil
	}
	if len(args) == 1 && args[0] == "start" {
		_, config, _, err := servicePaths()
		if err != nil {
			return err
		}
		n, err := selectedServiceNode(config)
		if err != nil {
			return err
		}
		loaded, live, err := serviceState()
		if err != nil {
			return err
		}
		if loaded {
			return errors.New("AnyTLS job already loaded; run 'anytls stop' before switching nodes")
		}
		if live {
			return errors.New("AnyTLS already running; stop before switching nodes")
		}
		if n.SkipVerify {
			if err := confirmInsecure(os.Stdin); err != nil {
				return err
			}
		}
		return sudoSubcommand("service-start", n.SkipVerify)
	}
	if len(args) == 1 && args[0] == "stop" {
		loaded, _, err := serviceState()
		if err != nil {
			return err
		}
		if !loaded {
			fmt.Println("AnyTLS is not running")
			return nil
		}
		return sudoSubcommand("service-stop", false)
	}
	if len(args) > 0 && (args[0] == "service-start" || args[0] == "service-stop") {
		if args[0] == "service-stop" && len(args) == 1 {
			return serviceStop()
		}
		if args[0] == "service-start" && (len(args) == 1 || (len(args) == 2 && args[1] == "-allow-insecure")) {
			return serviceStart(len(args) == 2)
		}
		return errors.New("invalid service command")
	}
	if len(args) == 1 && (args[0] == "help" || args[0] == "--help" || args[0] == "-h") {
		fmt.Println("Commands: config (choose node), start (system TUN), stop, status, list, check, run; config uses ↑/↓ and Enter/Space")
		return nil
	}
	fs := flag.NewFlagSet("anytls-macos", flag.ContinueOnError)
	server := fs.String("server", "", "AnyTLS server IP:port (IPv6: [IP]:port)")
	sni := fs.String("sni", "", "TLS certificate hostname")
	ca := fs.String("ca", "", "trusted CA/certificate PEM file")
	passwordFile := fs.String("password-file", "", "file holding the AnyTLS password, mode 0600")
	core := fs.String("core", "sing-box", "sing-box executable path")
	config := fs.String("config", "", "private YAML file with proxies/nodes")
	nodeName := fs.String("node", "", "select AnyTLS node by name")
	mode := fs.String("network", "proxy", "proxy (loopback SOCKS/HTTP) or tun (system VPN)")
	localPort := fs.Int("local-port", 11080, "loopback SOCKS/HTTP listen port")
	allowInsecure := fs.Bool("allow-insecure", false, "explicitly allow skip-cert-verify (MITM risk)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 || (fs.Arg(0) != "list" && fs.Arg(0) != "select" && fs.Arg(0) != "check" && fs.Arg(0) != "run") {
		return errors.New("usage: anytls-macos [flags] list|select|check|run")
	}
	if *config == "" && *server == "" {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		exe, err = filepath.EvalSymlinks(exe)
		if err != nil {
			return err
		}
		candidate := filepath.Join(filepath.Dir(exe), "config.yaml")
		if _, err := os.Stat(candidate); err == nil {
			*config = candidate
		}
	}
	var cfg map[string]any
	if *config != "" {
		nodes, err := loadNodes(*config)
		if err != nil {
			return err
		}
		current, err := selectedNode(*config, nodes)
		if err != nil {
			return err
		}
		if fs.Arg(0) == "list" {
			printNodes(os.Stdout, nodes, current)
			groups, err := groupChoices(*config)
			if err != nil {
				return err
			}
			for _, g := range groups {
				fmt.Printf("策略组 %s → %s\n", g.Name, g.Selected)
			}
			return nil
		}
		if fs.Arg(0) == "select" {
			groups, err := groupChoices(*config)
			if err != nil {
				return err
			}
			if len(groups) > 0 {
				return selectGroupMenu(*config, nodes, groups, os.Stdin, os.Stdout)
			}
			return selectMenu(*config, nodes, current, os.Stdin, os.Stdout)
		}
		if *nodeName == "" {
			*nodeName = current
		}
		if *nodeName == "" {
			return errors.New("no node selected; use select or -node")
		}
		n, err := choose(nodes, *nodeName)
		if err != nil {
			return err
		}
		cfg, err = buildNode(n, *mode, *localPort, *allowInsecure)
		if err != nil {
			return err
		}
		if err := applyRouting(*config, nodes, n, cfg, *allowInsecure); err != nil {
			return err
		}
		if n.EgressIP != "" {
			fmt.Fprintln(os.Stderr, "note: egress-ip is server-side policy, not an AnyTLS client setting; verify observed exit IP")
		}
	} else {
		if fs.Arg(0) == "list" || fs.Arg(0) == "select" {
			return errors.New("-config is required for list/select")
		}
		if *passwordFile == "" {
			return errors.New("password-file is required")
		}
		st, err := os.Stat(*passwordFile)
		if err != nil {
			return err
		}
		if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
			return errors.New("password-file must be regular and private (chmod 600)")
		}
		pass, err := os.ReadFile(*passwordFile)
		if err != nil {
			return err
		}
		password := strings.TrimSuffix(strings.TrimSuffix(string(pass), "\n"), "\r")
		if strings.ContainsAny(password, "\r\n") {
			return errors.New("password-file must contain one line")
		}
		cfg, err = build(options{*server, *sni, password, *ca})
		if err != nil {
			return err
		}
	}
	if fs.Arg(0) == "run" && runtime.GOOS != "darwin" {
		return errors.New("run is only supported on macOS; use check on other systems")
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	configDir := ""
	if *config != "" {
		configDir = filepath.Dir(*config)
	} else {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		exe, err = filepath.EvalSymlinks(exe)
		if err != nil {
			return err
		}
		configDir = filepath.Dir(exe)
	}
	configPath := filepath.Join(configDir, "runtime.json")
	f, err := os.OpenFile(configPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("runtime config already exists; another instance may be running: %w", err)
	}
	defer os.Remove(configPath)
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	path, err := exec.LookPath(*core)
	if errors.Is(err, exec.ErrNotFound) && *core == "sing-box" {
		exe, exeErr := os.Executable()
		if exeErr != nil {
			return exeErr
		}
		exe, exeErr = filepath.EvalSymlinks(exe)
		if exeErr != nil {
			return exeErr
		}
		path, err = exec.LookPath(filepath.Join(filepath.Dir(exe), "sing-box"))
	}
	if err != nil {
		return fmt.Errorf("sing-box executable: %w", err)
	}
	if err := coreCmd(path, "check", configPath); err != nil {
		return err
	}
	if fs.Arg(0) == "check" {
		fmt.Println("sing-box configuration valid")
		return nil
	}
	return coreCmd(path, "run", configPath)
}

func coreCmd(path, sub, configPath string) error {
	cmd := exec.Command(path, sub, "-c", configPath)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("sing-box %s: %w", sub, err)
	}
	if sub == "run" {
		sig := make(chan os.Signal, 1)
		stop := make(chan struct{})
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		defer signal.Stop(sig)
		defer close(stop)
		go func() {
			select {
			case s := <-sig:
				_ = cmd.Process.Signal(s)
				select {
				case <-time.After(5 * time.Second):
					_ = cmd.Process.Kill()
				case <-stop:
				}
			case <-stop:
			}
		}()
	}
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("sing-box %s: %w", sub, err)
	}
	return nil
}

func main() {
	if err := execute(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

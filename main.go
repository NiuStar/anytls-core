package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
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
	if len(args) > 0 {
		switch args[0] {
		case "version", "--version", "-version":
			if len(args) != 1 {
				return errors.New("usage: anytls version")
			}
			fmt.Println(currentVersion())
			return nil
		case "webui":
			return webuiCommand(args[1:])
		case "password":
			return passwordCommand(args[1:])
		case "update":
			return updateCommand(args[1:])
		case "reload":
			if len(args) != 1 {
				return errors.New("usage: anytls reload")
			}
			return reloadCommand()
		}
	}
	if len(args) == 1 && args[0] == "config" {
		// Edits affect the next run, not the currently staged service snapshot.
		// Apply a saved choice explicitly with reload.
		args = []string{"select"}
	}
	if len(args) == 1 && args[0] == "status" {
		root, err := serviceRoot()
		if err != nil {
			return err
		}
		status, err := newServiceLifecycle(root).status()
		fmt.Println(status)
		return err
	}
	if len(args) == 1 && args[0] == "start" {
		_, config, _, err := servicePaths()
		if err != nil {
			return err
		}
		n, err := preflightServiceNode(config)
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
			root, err := serviceRoot()
			if err != nil {
				return err
			}
			if _, err := os.Lstat(root); errors.Is(err, os.ErrNotExist) {
				fmt.Println("AnyTLS TUN stopped")
				return nil
			}
			// Existing or unreadable private evidence requires privileged recovery
			// verification, even when launchd has already unloaded the job.
		}
		return sudoSubcommand("service-stop", false)
	}
	if len(args) > 0 && args[0] == "service-reload" {
		if len(args) == 1 || (len(args) == 2 && args[1] == "-allow-insecure") {
			return serviceReload(len(args) == 2)
		}
		return errors.New("invalid service-reload command")
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
		fmt.Println("Commands: config, start, stop, reload, status, webui, password [reset], update [--check], version, list, check, run; saved choices apply with reload")
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
	if err := validateCoreFlag(fs); err != nil {
		return err
	}
	o := runtimeOptions{Command: fs.Arg(0), Config: *config, NodeName: *nodeName, Mode: *mode, Server: *server, SNI: *sni, CA: *ca, PasswordFile: *passwordFile, LocalPort: *localPort, AllowInsecure: *allowInsecure}
	cfg, err := prepareRuntime(&o)
	if err != nil || cfg == nil {
		return err
	}
	if fs.Arg(0) == "run" && runtime.GOOS != "darwin" {
		return errors.New("run is only supported on macOS; use check on other systems")
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return dispatchEngine(o.Command, b, o.Config, *core)
}

func main() {
	if err := execute(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

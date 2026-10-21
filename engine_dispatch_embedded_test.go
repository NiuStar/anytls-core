//go:build embedded_core

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	anytls "github.com/anytls/sing-anytls"
	"github.com/anytls/sing-anytls/padding"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
)

// Test helper uses the actual executable entrypoint without building another
// binary inside a test (the supervisor owns all compilation).
func TestEmbeddedCLIProcess(t *testing.T) {
	if os.Getenv("G21_CLI_CHILD") != "1" {
		return
	}
	args := os.Args
	for i, a := range args {
		if a == "--" {
			os.Args = append([]string{args[0]}, args[i+1:]...)
			main()
			return
		}
	}
	os.Exit(99)
}
func embeddedChild(t *testing.T, dir, path string, args ...string) *exec.Cmd {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, append([]string{"-test.run=^TestEmbeddedCLIProcess$", "--"}, args...)...)
	cmd.Dir = dir
	cmd.Env = []string{"G21_CLI_CHILD=1", "HOME=" + dir, "PATH=" + path, "TMPDIR=" + dir}
	return cmd
}
func embeddedNoRuntime(t *testing.T, dir, marker string) {
	t.Helper()
	for _, p := range []string{filepath.Join(dir, "runtime.json"), marker} {
		if _, e := os.Stat(p); !os.IsNotExist(e) {
			t.Fatalf("unexpected runtime/external-core side effect at %s", filepath.Base(p))
		}
	}
}
func TestEmbeddedCheckStrictCAWithoutExternalCore(t *testing.T) {
	for _, withFake := range []bool{false, true} {
		t.Run(fmt.Sprint(withFake), func(t *testing.T) {
			d := t.TempDir()
			ca, _ := runtimeCertificate(t)
			runtimeWrite(t, filepath.Join(d, "ca.pem"), ca, 0600)
			config := filepath.Join(d, "config.yaml")
			runtimeWrite(t, config, []byte(fmt.Sprintf("proxies:\n - {name: a, type: anytls, server: 127.0.0.1, port: 443, password: synthetic, sni: g21.invalid, ca: %s}\n", filepath.Join(d, "ca.pem"))), 0644)
			marker := filepath.Join(d, "core-invoked")
			path := ""
			if withFake {
				path = d
				runtimeWrite(t, filepath.Join(d, "sing-box"), []byte("#!/bin/sh\n: > '"+marker+"'\nexit 91\n"), 0700)
			}
			cmd := embeddedChild(t, d, path, "-config", config, "-node", "a", "check")
			if out, err := cmd.CombinedOutput(); err != nil || !bytes.Contains(out, []byte("embedded configuration valid")) {
				t.Fatalf("actual CLI check failed: %v", err)
			}
			embeddedNoRuntime(t, d, marker)
			for _, value := range []string{"sing-box", filepath.Join(d, "sing-box"), ""} {
				cmd := embeddedChild(t, d, path, "-core="+value, "-config", config, "-node", "a", "check")
				out, err := cmd.CombinedOutput()
				if err == nil || !bytes.Contains(out, []byte("-core is not supported")) {
					t.Fatalf("actual CLI accepted core: %v", err)
				}
				embeddedNoRuntime(t, d, marker)
			}
		})
	}
}

// The only authorized destination is itself: the AnyTLS stream handler is a
// binary echo endpoint. No arbitrary dial, DNS, production config, TUN or sudo.
type embeddedEcho struct{ done chan struct{} }

func (e embeddedEcho) NewConnectionEx(_ context.Context, c net.Conn, _ M.Socksaddr, d M.Socksaddr, _ N.CloseHandlerFunc) {
	go func() {
		defer c.Close()
		defer close(e.done)
		if d.String() != "127.0.0.1:32123" {
			return
		}
		_, _ = io.Copy(c, c)
	}()
}

type embeddedDialer struct{}

func (embeddedDialer) DialContext(ctx context.Context, n string, d M.Socksaddr) (net.Conn, error) {
	return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, n, d.String())
}
func (embeddedDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("unused")
}
func TestEmbeddedRunProxyLoopbackAndSignal(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("CLI run is macOS-only")
	}
	d := t.TempDir()
	ca, cert := runtimeCertificate(t)
	capath := filepath.Join(d, "ca.pem")
	runtimeWrite(t, capath, ca, 0600)
	secret := make([]byte, 24)
	if _, e := rand.Read(secret); e != nil {
		t.Fatal(e)
	}
	password := hex.EncodeToString(secret)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	echo := embeddedEcho{done: make(chan struct{})}
	svc, err := anytls.NewService(anytls.ServiceConfig{Users: []anytls.User{{Name: "fixture", Password: password}}, PaddingScheme: padding.DefaultPaddingScheme, Handler: echo, Logger: logger.NOP()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	serverDone := make(chan error, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, e := listener.Accept()
		if e != nil {
			serverDone <- e
			return
		}
		defer c.Close()
		tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
		_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
		if e := tc.HandshakeContext(ctx); e != nil {
			serverDone <- errors.New("strict TLS handshake failed")
			return
		}
		serverDone <- svc.NewConnection(ctx, tc, M.SocksaddrFromNet(c.RemoteAddr()), nil)
	}()
	defer func() {
		cancel()
		listener.Close()
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("owned server did not join")
		}
	}()
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := free.Addr().(*net.TCPAddr).Port
	free.Close()
	config := filepath.Join(d, "config.yaml")
	runtimeWrite(t, config, []byte(fmt.Sprintf("proxies:\n - {name: a, type: anytls, server: 127.0.0.1, port: %d, password: %s, sni: g21.invalid, ca: %s}\n", listener.Addr().(*net.TCPAddr).Port, password, capath)), 0644)
	marker := filepath.Join(d, "core-invoked")
	runtimeWrite(t, filepath.Join(d, "sing-box"), []byte("#!/bin/sh\n: > '"+marker+"'\nexit 91\n"), 0700)
	cmd := embeddedChild(t, d, d, "-config", config, "-node", "a", "-local-port", fmt.Sprint(port), "run")
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		if !waited {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, e := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 50*time.Millisecond)
		if e == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("CLI proxy listener not ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	client := socks.NewClient(embeddedDialer{}, M.ParseSocksaddr(fmt.Sprintf("127.0.0.1:%d", port)), socks.Version5, "", "")
	dialctx, stop := context.WithTimeout(ctx, 4*time.Second)
	defer stop()
	c, err := client.DialContext(dialctx, "tcp", M.ParseSocksaddr("127.0.0.1:32123"))
	if err != nil {
		t.Fatal("CLI SOCKS to owned AnyTLS failed")
	}
	_ = c.SetDeadline(time.Now().Add(4 * time.Second))
	payload := []byte{0, 1, 255, 42, 0, 13}
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatal("CLI AnyTLS echo mismatch")
	}
	c.Close()
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case e := <-done:
		waited = true
		var exit *exec.ExitError
		if !errors.As(e, &exit) || exit.ExitCode() != 1 {
			t.Fatalf("documented cancellation exit 1 not retained: %v", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("CLI did not stop on signal")
	}
	if !bytes.Contains(output.Bytes(), []byte("context canceled")) {
		t.Fatal("CLI cancellation cause missing")
	}
	embeddedNoRuntime(t, d, marker)
	l, e := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if e != nil {
		t.Fatal("proxy listener not released")
	}
	l.Close()
	select {
	case <-echo.done:
	case <-time.After(4 * time.Second):
		t.Fatal("owned echo stream not closed")
	}
	select {
	case <-serverDone:
	case <-time.After(4 * time.Second):
		t.Fatal("owned TLS session not closed")
	}
}

func TestEmbeddedRejectsExplicitCoreBeforeConfig(t *testing.T) {
	for _, value := range []string{"sing-box", "/nonexistent/core", ""} {
		t.Run(value, func(t *testing.T) {
			dir := t.TempDir()
			err := execute([]string{"-core=" + value, "-config", filepath.Join(dir, "missing.yaml"), "check"})
			if err == nil || !strings.Contains(err.Error(), "-core is not supported by embedded_core") {
				t.Fatalf("explicit core not rejected before config: %v", err)
			}
			if _, err := os.Stat(filepath.Join(dir, "runtime.json")); !os.IsNotExist(err) {
				t.Fatalf("runtime file created: %v", err)
			}
		})
	}
}

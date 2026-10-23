//go:build !embedded_core

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

func dispatchCompiledEngine(command string, compiled compiledRuntime, config, core string, recordService bool) error {
	if recordService && command == "run" {
		fmt.Fprintln(os.Stderr, "connection recording unavailable")
	}
	return dispatchEngine(command, compiled.JSON, config, core)
}

func externalCoreRequired() bool { return true }

func validateCoreFlag(_ *flag.FlagSet) error { return nil }

func dispatchEngine(command string, b []byte, config, core string) error {
	configDir := ""
	if config != "" {
		configDir = filepath.Dir(config)
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
	path, err := exec.LookPath(core)
	if errors.Is(err, exec.ErrNotFound) && core == "sing-box" {
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
	if command == "check" {
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

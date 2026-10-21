package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Per-invocation seams replace only external effects in tests. Production uses
// the existing compiler, launchd state probe and privileged start/stop wrappers.
// Reload is deliberately stop/start, not a seamless hot reload or an attempt to
// reconstruct the previous root-private configuration from the user's files.
type reloadDependencies struct {
	state     func() (bool, bool, error)
	preflight func() (node, error)
	stop      func() error
	start     func(bool) error
}

func serviceReloadDependencies() (reloadDependencies, error) {
	_, config, _, err := servicePaths()
	if err != nil {
		return reloadDependencies{}, lifecycleFailure("reload service paths unavailable", err)
	}
	lifecycle := newServiceLifecycle(filepath.Join(filepath.Dir(config), "service"))
	return reloadDependencies{
		state:     lifecycle.state,
		preflight: func() (node, error) { return preflightServiceNode(config) },
		stop:      serviceStop,
		start:     serviceStart,
	}, nil
}

// No service control, snapshot writes or network changes before this returns.
func reloadPreflight(d reloadDependencies) (node, error) {
	loaded, _, err := d.state()
	if err != nil {
		return node{}, lifecycleFailure("reload job state unavailable; service unchanged", err)
	}
	if !loaded {
		return node{}, errors.New("AnyTLS not running (job not loaded); run 'anytls start' first")
	}
	n, err := d.preflight()
	if err != nil {
		return node{}, lifecycleFailure("reload disk configuration rejected; service unchanged", err)
	}
	return n, nil
}

func reloadCommand() error {
	d, err := serviceReloadDependencies()
	if err != nil {
		return err
	}
	return reloadCommandWithDependencies(d, func() error { return confirmInsecure(os.Stdin) }, func(allow bool) error {
		fmt.Fprintln(os.Stderr, "Reload uses stop then start; connectivity will be interrupted briefly.")
		return sudoSubcommand("service-reload", allow)
	})
}

func reloadCommandWithDependencies(d reloadDependencies, confirm func() error, elevate func(bool) error) error {
	n, err := reloadPreflight(d)
	if err != nil {
		return err
	}
	if n.SkipVerify {
		if err := confirm(); err != nil {
			return lifecycleFailure("reload cancelled: TLS risk not accepted; service unchanged", err)
		}
	}
	if err := elevate(n.SkipVerify); err != nil {
		return lifecycleFailure("reload privileged operation failed; inspect 'anytls status' and service diagnostics", err)
	}
	return nil
}

func serviceReload(allowInsecure bool) error {
	if os.Geteuid() != 0 {
		return errors.New("service-reload requires sudo")
	}
	d, err := serviceReloadDependencies()
	if err != nil {
		return err
	}
	return reloadWithDependencies(allowInsecure, d)
}

func reloadWithDependencies(allowInsecure bool, d reloadDependencies) error {
	// Re-read current disk inputs as root; user-side consent does not bless a
	// newly insecure replacement. serviceStart also recompiles its staged bytes.
	n, err := reloadPreflight(d)
	if err != nil {
		return err
	}
	if n.SkipVerify && !allowInsecure {
		return errors.New("reload requires explicit TLS risk consent; service unchanged")
	}
	if err := d.stop(); err != nil {
		return lifecycleFailure("reload stop/restoration failed; new start not attempted; inspect service diagnostics", err)
	}
	if err := d.start(allowInsecure); err != nil {
		// Existing start performs its own rollback/restoration checks. Do not
		// guess the old root snapshot or mask any of those original causes.
		return lifecycleFailure("reload start failed after stopping previous service; recovery is not guaranteed; previous configuration not restarted; inspect 'anytls status' and start recovery diagnostics", err)
	}
	return nil
}

package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

const updateAPI = "https://api.github.com/repos/NiuStar/anytls-core"
const updateRepository = "https://github.com/NiuStar/anytls-core"

// These are trusted local build-time inputs, never executed from the archive.
//
//go:embed scripts/install.py
var updateInstaller string

//go:embed scripts/install-binary.py
var updateBinaryInstaller string

// updateError is the only CLI error eligible for the reserved update protocol.
// Preserve the cause for errors.Is/As, never classify by error text.
type updateError struct {
	code     int
	cause    error
	argument bool // fixed local usage/validation text only, never network/tool errors
}

func (e *updateError) Error() string {
	if e.argument {
		return e.cause.Error()
	}
	return updateErrorName(e.code)
}
func (e *updateError) Unwrap() error { return e.cause }

func updateErrorName(code int) string {
	switch code {
	case 40:
		return "UPDATE_CHECK_FAILED"
	case 41:
		return "UPDATE_PYTHON_REQUIRED"
	case 42:
		return "UPDATE_BINARY_UNAVAILABLE"
	case 43:
		return "UPDATE_DOWNLOAD_FAILED"
	case 44:
		return "UPDATE_VALIDATION_FAILED"
	case 45:
		return "UPDATE_PUBLISH_FAILED"
	case 46:
		return "UPDATE_VERIFY_FAILED"
	default:
		return "UPDATE_UNAVAILABLE"
	}
}

func updateFailure(code int, cause error) error {
	if code < 40 || code > 47 {
		code = 47
	}
	return &updateError{code: code, cause: cause}
}

func updateExitCode(err error) int {
	var failure *updateError
	if errors.As(err, &failure) && failure.code >= 40 && failure.code <= 47 {
		return failure.code
	}
	return 1
}

func updateChildFailure(err error) error {
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() >= 40 && exit.ExitCode() <= 47 {
		return updateFailure(exit.ExitCode(), err)
	}
	return updateFailure(47, err)
}

func webUpdateErrorName(err error) string {
	return updateErrorName(updateExitCode(err))
}

type updateCheckResult struct {
	CurrentVersion  string `json:"current_version"`
	LatestVersion   string `json:"latest_version"`
	UpdateAvailable bool   `json:"update_available"`
	SourceOnly      bool   `json:"source_only"`
	ReleaseURL      string `json:"release_url"`
}

var updateSemver = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
var updateDate = regexp.MustCompile(`^v([0-9]{4}-[0-9]{2}-[0-9]{2})-[0-9]{2}$`)

func validateUpdateVersion(version string) error {
	if updateSemver.MatchString(version) {
		return nil
	}
	if match := updateDate.FindStringSubmatch(version); match != nil {
		if match[1][:4] == "0000" {
			return errors.New("release year must be positive")
		}
		if _, err := time.Parse("2006-01-02", match[1]); err == nil {
			return nil
		}
	}
	return errors.New("version must be stable vYYYY-MM-DD-NN or vMAJOR.MINOR.PATCH, never a URL")
}

func updateHTTPClient() *http.Client {
	return &http.Client{Timeout: 45 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return errors.New("release API redirects are not accepted")
	}}
}

func readUpdateRelease(ctx context.Context, client *http.Client, endpoint, version string) (updateCheckResult, error) {
	result := updateCheckResult{CurrentVersion: currentVersion(), SourceOnly: true}
	if version != "" {
		if err := validateUpdateVersion(version); err != nil {
			return result, err
		}
		endpoint += "/releases/tags/" + url.PathEscape(version)
	} else {
		endpoint += "/releases/latest"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return result, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "anytls-update")
	response, err := client.Do(req)
	if err != nil {
		return result, errors.New("release API request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return result, fmt.Errorf("release API HTTP %d", response.StatusCode)
	}
	var release struct {
		TagName    string `json:"tag_name"`
		HTMLURL    string `json:"html_url"`
		Draft      *bool  `json:"draft"`
		Prerelease *bool  `json:"prerelease"`
		Assets     []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	decoder := json.NewDecoder(response.Body)
	if err := decoder.Decode(&release); err != nil {
		return result, errors.New("malformed release API JSON")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return result, errors.New("trailing release API JSON")
	}
	if release.Draft == nil || release.Prerelease == nil || *release.Draft || *release.Prerelease {
		return result, errors.New("not a stable published release")
	}
	if err := validateUpdateVersion(release.TagName); err != nil {
		return result, err
	}
	if version != "" && version != release.TagName {
		return result, errors.New("release tag mismatch")
	}
	if release.HTMLURL != updateRepository+"/releases/tag/"+release.TagName {
		return result, errors.New("release URL mismatch")
	}
	source := "anytls-core-" + release.TagName + "-source.tar.gz"
	binary := "anytls-core-" + release.TagName + "-darwin-" + runtime.GOARCH + ".tar.gz"
	ccs := "anytls-core-" + release.TagName + "-corresponding-source.tar.gz"
	if runtime.GOARCH == "amd64" {
		ccs = "anytls-core-" + release.TagName + "-darwin-amd64-corresponding-source.tar.gz"
	}
	names := map[string]int{source: 0, "SHA256SUMS": 0, binary: 0, ccs: 0}
	for _, asset := range release.Assets {
		if _, wanted := names[asset.Name]; wanted {
			if asset.URL != updateRepository+"/releases/download/"+release.TagName+"/"+asset.Name {
				return result, errors.New("release asset URL/tag mismatch")
			}
			names[asset.Name]++
			if names[asset.Name] > 1 {
				return result, errors.New("duplicate release asset")
			}
		}
	}
	if names[source] != 1 || names["SHA256SUMS"] != 1 {
		return result, errors.New("release must contain one source archive and SHA256SUMS")
	}
	result.SourceOnly = (runtime.GOARCH != "arm64" && runtime.GOARCH != "amd64") || names[binary] != 1 || names[ccs] != 1
	result.LatestVersion, result.ReleaseURL = release.TagName, release.HTMLURL
	// Only explicit --version permits rollback or switching version schemes.
	result.UpdateAvailable = (version != "" && result.CurrentVersion != result.LatestVersion) || newerStableVersion(result.CurrentVersion, result.LatestVersion)
	return result, nil
}

// Unknown/development versions and different version schemes are not ordered.
func newerStableVersion(current, latest string) bool {
	if validateUpdateVersion(current) != nil || validateUpdateVersion(latest) != nil {
		return false
	}
	if updateDate.MatchString(current) && updateDate.MatchString(latest) {
		return latest > current
	}
	if !updateSemver.MatchString(current) || !updateSemver.MatchString(latest) {
		return false
	}
	left, right := strings.Split(current[1:], "."), strings.Split(latest[1:], ".")
	for i := range left {
		if left[i] != right[i] {
			return len(right[i]) > len(left[i]) || (len(right[i]) == len(left[i]) && right[i] > left[i])
		}
	}
	return false
}

func updateTargetAllowed(binary string) bool {
	name := filepath.Base(binary)
	return name == "anytls-macos" || name == "anytls" // legacy installation
}

func updateCommand(args []string) (err error) {
	parsing := true
	defer func() {
		if err != nil && updateExitCode(err) == 1 {
			err = &updateError{code: 40, cause: err, argument: parsing}
		}
	}()
	check, version := false, ""
	for len(args) > 0 {
		switch args[0] {
		case "--check":
			if check {
				return errors.New("duplicate --check")
			}
			check = true
			args = args[1:]
		case "--version":
			if version != "" || len(args) < 2 {
				return errors.New("usage: anytls update [--check] [--version VERSION]")
			}
			version, args = args[1], args[2:]
			if err := validateUpdateVersion(version); err != nil {
				return err
			}
		default:
			return errors.New("usage: anytls update [--check] [--version VERSION]")
		}
	}
	parsing = false
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	result, err := readUpdateRelease(ctx, updateHTTPClient(), updateAPI, version)
	if err != nil {
		return err
	}
	if check {
		return json.NewEncoder(os.Stdout).Encode(result)
	}
	if runtime.GOOS != "darwin" || (runtime.GOARCH != "arm64" && runtime.GOARCH != "amd64") || externalCoreRequired() || os.Geteuid() == 0 {
		return updateFailure(42, errors.New("prebuilt update requires an unprivileged macOS embedded_core build"))
	}
	if !result.UpdateAvailable {
		fmt.Println("No newer comparable stable release; current " + currentVersion() + ", latest " + result.LatestVersion + ". Use --version for an explicit rollback or version-scheme change.")
		return nil
	}
	if result.SourceOnly {
		return updateFailure(42, errors.New("current architecture prebuilt materials are unavailable"))
	}
	binary, err := os.Executable()
	if err != nil {
		return updateFailure(44, err)
	}
	binary, err = filepath.EvalSymlinks(binary)
	if err != nil {
		return updateFailure(44, err)
	}
	if !updateTargetAllowed(binary) {
		return updateFailure(44, errors.New("update target must be the installed anytls-macos or legacy anytls"))
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		return updateFailure(41, err)
	}
	app := filepath.Dir(binary)
	work, err := os.MkdirTemp(app, "update-driver-")
	if err != nil {
		return updateFailure(45, err)
	}
	defer os.RemoveAll(work)
	for name, contents := range map[string]string{"install.py": updateInstaller, "install-binary.py": updateBinaryInstaller} {
		if err := os.WriteFile(filepath.Join(work, name), []byte(contents), 0600); err != nil {
			return updateFailure(45, err)
		}
	}
	publishCtx, publishCancel := context.WithTimeout(context.Background(), 35*time.Minute)
	defer publishCancel()
	command := exec.CommandContext(publishCtx, python, "-I", filepath.Join(work, "install-binary.py"), "--update-only", "--app-dir", app, "--target", binary, "--update-arch", runtime.GOARCH, "--version", result.LatestVersion)
	command.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := command.Run(); err != nil {
		if publishCtx.Err() != nil {
			return updateFailure(47, publishCtx.Err())
		}
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() >= 42 && exit.ExitCode() <= 47 {
			return updateFailure(exit.ExitCode(), err)
		}
		return updateFailure(47, err)
	}
	fmt.Println("Installed " + result.LatestVersion + "; current process is still " + strings.TrimSpace(currentVersion()) + ". Restart WebUI to load the installed version; VPN was not reloaded.")
	return nil
}

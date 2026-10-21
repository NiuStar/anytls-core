package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func updateFixture(tag string) map[string]any {
	assets := []map[string]string{}
	for _, name := range []string{"anytls-core-" + tag + "-source.tar.gz", "SHA256SUMS"} {
		assets = append(assets, map[string]string{"name": name, "browser_download_url": updateRepository + "/releases/download/" + tag + "/" + name})
	}
	return map[string]any{"tag_name": tag, "html_url": updateRepository + "/releases/tag/" + tag, "draft": false, "prerelease": false, "assets": assets}
}

func TestUpdateVersions(t *testing.T) {
	for _, version := range []string{"v2026-10-21-02", "v1.2.3", "v0.0.0"} {
		if err := validateUpdateVersion(version); err != nil {
			t.Fatalf("%s: %v", version, err)
		}
	}
	for _, version := range []string{"https://evil/release", "v2026-02-30-02", "v2026-10-21-2", "v01.2.3", "v1.2.3-rc1", "v1.2.3/../../x"} {
		if validateUpdateVersion(version) == nil {
			t.Fatalf("accepted %s", version)
		}
	}
}

func TestUpdateStableOrdering(t *testing.T) {
	for _, tc := range []struct {
		current, latest string
		want            bool
	}{
		{"v2026-10-21-01", "v2026-10-21-02", true},
		{"v2026-10-21-02", "v2026-10-21-01", false},
		{"v2026-10-21-01", "v2026-10-21-01", false},
		{"v2027-01-01-01", "v2026-12-31-99", false},
		{"v1.9.9", "v1.10.0", true},
		{"v10.0.0", "v9.99.99", false},
		{"v1.0.0", "v1.0.0", false},
		{"v999999999999999999999.0.0", "v1000000000000000000000.0.0", true},
		{"v2026-10-21-01", "v1.0.0", false},
		{"v1.0.0", "v2026-10-21-01", false},
		{"dev", "v1.0.0", false},
		{"v1.2.3-dev", "v1.2.3", false},
	} {
		if got := newerStableVersion(tc.current, tc.latest); got != tc.want {
			t.Errorf("%s -> %s = %v, want %v", tc.current, tc.latest, got, tc.want)
		}
	}
}

func TestUpdateInstalledNames(t *testing.T) {
	for _, name := range []string{"/home/user/.anytls/anytls-macos", "/home/user/.anytls/anytls"} {
		if !updateTargetAllowed(name) {
			t.Errorf("rejected installed binary %s", name)
		}
	}
	if updateTargetAllowed("/tmp/anytls-dev") {
		t.Fatal("accepted unrelated build name")
	}
}

func TestUpdateLatestDoesNotRollbackAndExplicitVersionDoes(t *testing.T) {
	fixture := updateFixture("v0.0.0")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(fixture)
	}))
	defer server.Close()
	for _, version := range []string{"", "v0.0.0"} {
		result, err := readUpdateRelease(context.Background(), server.Client(), server.URL, version)
		if err != nil {
			t.Fatal(err)
		}
		if result.UpdateAvailable != (version != "" && currentVersion() != version) {
			t.Fatalf("rollback policy for %q: %+v", version, result)
		}
	}
}

func TestUpdateCheckSourceRelease(t *testing.T) {
	fixture := updateFixture(currentVersion())
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/releases/latest" {
			t.Error("wrong release endpoint")
		}
		if r.Header.Get("Accept") != "application/vnd.github+json" {
			t.Error("missing API header")
		}
		json.NewEncoder(w).Encode(fixture)
	}))
	defer server.Close()
	result, err := readUpdateRelease(context.Background(), server.Client(), server.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	if result.UpdateAvailable || !result.SourceOnly || result.CurrentVersion != currentVersion() {
		t.Fatalf("wrong result: %+v", result)
	}
	data, _ := json.Marshal(result)
	var fields map[string]any
	json.Unmarshal(data, &fields)
	if len(fields) != 5 {
		t.Fatal("WebUI JSON must contain exactly five fields")
	}
	for _, key := range []string{"current_version", "latest_version", "update_available", "source_only", "release_url"} {
		if _, ok := fields[key]; !ok {
			t.Fatalf("missing JSON contract field %s", key)
		}
	}
}

func TestUpdateCheckRejectsUnsafeRelease(t *testing.T) {
	for _, mode := range []string{"draft", "prerelease", "wrong-tag", "missing-assets", "wrong-url", "malformed", "trailing", "http-error"} {
		t.Run(mode, func(t *testing.T) {
			fixture := updateFixture("v1.2.3")
			switch mode {
			case "draft", "prerelease":
				fixture[mode] = true
			case "wrong-tag":
				fixture["tag_name"] = "https://evil"
			case "missing-assets":
				delete(fixture, "assets")
			case "wrong-url":
				fixture["html_url"] = "https://evil"
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mode == "http-error" {
					w.WriteHeader(500)
					return
				}
				if mode == "malformed" {
					w.Write([]byte("{"))
					return
				}
				json.NewEncoder(w).Encode(fixture)
				if mode == "trailing" {
					w.Write([]byte("{}"))
				}
			}))
			defer server.Close()
			if _, err := readUpdateRelease(context.Background(), server.Client(), server.URL, ""); err == nil {
				t.Fatal("accepted unsafe release")
			}
		})
	}
}

func TestUpdateExplicitVersionValidatedBeforeNetwork(t *testing.T) {
	for _, args := range [][]string{{"--version", "https://evil"}, {"--version"}, {"--unknown"}, {"--check", "--check"}} {
		if updateCommand(args) == nil {
			t.Fatal("invalid arguments accepted")
		}
	}
}

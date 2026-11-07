package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBuildVersion(t *testing.T) {
	for _, version := range []string{"v0.3.0", "v2026-11-07-01", "v2026-11-07-unified-r1-candidate", "v2024-02-29-unified-r123-candidate"} {
		if err := validateBuildVersion(version); err != nil {
			t.Errorf("rejected build %q: %v", version, err)
		}
	}
	for _, version := range []string{"", "dev", "v2026-02-29-unified-r1-candidate", "v2026-02-30-unified-r1-candidate", "v0000-01-01-unified-r1-candidate", "v2026-13-01-unified-r1-candidate", "v2026-11-07-unified-r0-candidate", "v2026-11-07-unified-r01-candidate", "v2026-11-07-unified-r-1-candidate", "v2026-11-07-unified-r1-rc", "v2026-11-7-unified-r1-candidate", "v2026-11-07-unified-r1-candidate-extra", " v2026-11-07-unified-r1-candidate", "v2026-11-07-unified-r1-candidate\n", "v2026-11-07-unified-r1-candidate\x00", "https://evil/v2026-11-07-unified-r1-candidate", "v2026-11-07-unified-r1-candidate/../x", "v1.2.3-rc1"} {
		if validateBuildVersion(version) == nil {
			t.Errorf("accepted invalid build %q", version)
		}
	}
}

func TestBuildVersionOrdering(t *testing.T) {
	for _, tc := range []struct {
		current, latest string
		want            bool
	}{
		{"v2026-11-07-unified-r999999999999999999999999-candidate", "v2026-11-07-00", true},
		{"v2026-11-07-unified-r2-candidate", "v2026-11-06-99", false},
		{"v2026-11-07-unified-r1-candidate", "v2026-11-08-unified-r1-candidate", false},
		{"v2026-11-07-unified-r1-candidate", "v2026-02-30-01", false},
		{"v2026-11-07-unified-r0-candidate", "v2026-11-08-01", false},
		{"v2026-11-07-unified-r1-candidate\n", "v2026-11-08-01", false},
		{"v2026-11-07-01", "v2026-11-07-02", true},
		{"v1.9.9", "v1.10.0", true},
		{"v1.10.0", "v1.9.9", false},
		{"dev", "v2026-11-08-01", false},
	} {
		if got := newerReleaseForBuild(tc.current, tc.latest); got != tc.want {
			t.Errorf("%q -> %q = %v, want %v", tc.current, tc.latest, got, tc.want)
		}
	}
}

func TestUpdateCandidateCurrentBuild(t *testing.T) {
	original := Version
	t.Cleanup(func() { Version = original })
	Version = "v2026-11-07-unified-r1-candidate\n"
	for _, tc := range []struct {
		latest, explicit string
		want             bool
	}{
		{"v2026-11-06-99", "", false},
		{"v2026-11-07-00", "", true},
		{"v2026-11-08-01", "", true},
		{"v0.3.0", "", false},
		{"v2026-11-06-99", "v2026-11-06-99", true},
		{"v0.3.0", "v0.3.0", true},
	} {
		t.Run(tc.latest+"/"+tc.explicit, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				wantPath := "/releases/latest"
				if tc.explicit != "" {
					wantPath = "/releases/tags/" + tc.explicit
				}
				if r.URL.Path != wantPath {
					t.Errorf("path %q, want %q", r.URL.Path, wantPath)
				}
				json.NewEncoder(w).Encode(updateFixture(tc.latest))
			}))
			defer server.Close()
			got, err := readUpdateRelease(context.Background(), server.Client(), server.URL, tc.explicit)
			if err != nil {
				t.Fatal(err)
			}
			want := updateCheckResult{CurrentVersion: "v2026-11-07-unified-r1-candidate", LatestVersion: tc.latest, UpdateAvailable: tc.want, SourceOnly: true, ReleaseURL: updateRepository + "/releases/tag/" + tc.latest}
			if got != want {
				t.Fatalf("got %+v, want %+v", got, want)
			}
		})
	}
	Version = "v2026-02-30-unified-r1-candidate"
	if newerReleaseForBuild(currentVersion(), "v2026-11-08-01") {
		t.Fatal("ordered malformed current build")
	}
}

func TestUpdateRejectsCandidateReleaseChannel(t *testing.T) {
	for _, tag := range []string{"v2026-11-07-unified-r1-candidate", "v2026-02-30-unified-r1-candidate"} {
		t.Run(tag, func(t *testing.T) {
			if validateUpdateVersion(tag) == nil {
				t.Fatal("candidate accepted as stable")
			}
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				json.NewEncoder(w).Encode(updateFixture(tag)) // Stable flags and self-consistent URLs must not bypass tag validation.
			}))
			defer server.Close()
			if _, err := readUpdateRelease(context.Background(), server.Client(), server.URL, tag); err == nil {
				t.Fatal("accepted explicit candidate")
			}
			if requests != 0 {
				t.Fatal("explicit candidate reached network")
			}
			if _, err := readUpdateRelease(context.Background(), server.Client(), server.URL, ""); err == nil {
				t.Fatal("accepted remote candidate")
			}
			if requests != 1 {
				t.Fatalf("latest requests = %d", requests)
			}
		})
	}
}

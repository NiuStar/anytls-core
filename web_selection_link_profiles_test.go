package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestWebSelectionLinkProfileAndImportProjection(t *testing.T) {
	config := strings.Replace(selectionLinkConfig, "selected: DIRECT}", "selected: b}", 1)
	for _, path := range []string{"profile-switch", "import"} {
		t.Run(path, func(t *testing.T) {
			w, cookie, csrf := linkFixture(t, selectionLinkConfig, "a")
			if path == "import" {
				preview := importPreview(t, w, cookie, csrf, map[string]any{"yaml": config})
				out := importCommit(t, w, cookie, csrf, preview)
				if out.Code != 200 {
					t.Fatalf("import: %d %s", out.Code, out.Body.String())
				}
			} else {
				selection := "a\n"
				p := webProfile{Name: "linked", YAML: config, Selected: &selection}
				if err := w.publishProfile(&p); err != nil {
					t.Fatal(err)
				}
				b, _ := os.ReadFile(w.configPath)
				out := groupETagRequest(w, cookie, csrf, "/api/v1/profiles/switch", `{"id":"`+p.ID+`","confirm_replace":true,"confirm_insecure":true}`, `"`+shaHex(b)+`"`)
				if out.Code != 200 {
					t.Fatalf("switch: %d %s", out.Code, out.Body.String())
				}
			}
			b, _ := os.ReadFile(w.configPath)
			if string(b) != config {
				t.Fatal("profile/import silently rewrote saved group policies")
			}
			nodes, _ := loadNodesBytes(b)
			got, _ := selectedNode(w.configPath, nodes)
			if got != "a" {
				t.Fatalf("expected independent legacy selection retained, got %q", got)
			}
			linkAssertDTO(t, w, cookie, "a", "b", false, "a", "b")
			linkAssertRuntimeDNS(t, w, "127.0.0.1", "127.0.0.2")
			// The effective default card B must be reachable in one explicit request.
			linkPost(t, w, cookie, csrf, "/api/v1/nodes/selection", `{"name":"b"}`)
			linkAssert(t, w, "b", "b", "127.0.0.2")
			linkAssertDTO(t, w, cookie, "b", "b", true)
			linkAssertRuntimeDNS(t, w, "127.0.0.2", "127.0.0.2")
		})
	}
}

func TestWebSelectionLinkSubscriptionRetentionProjection(t *testing.T) {
	selection := "a\n"
	old := webProfile{YAML: strings.Replace(selectionLinkConfig, "selected: DIRECT}", "selected: b}", 1), Selected: &selection}
	// Exercise the existing refresh preparation helpers without a network fetch.
	b, invalid := subscriptionGroupSelections(old, []byte(selectionLinkConfig))
	selected, invalidSelection := subscriptionSelection(old, b)
	if invalid || invalidSelection || selected == nil || *selected != "a\n" {
		t.Fatal("subscription retention changed")
	}
	if !bytes.Contains(b, []byte("selected: a")) || !bytes.Contains(b, []byte("selected: b")) {
		t.Fatal("dedicated or default choice lost")
	}
	w, cookie, csrf := linkFixture(t, string(b), strings.TrimSuffix(*selected, "\n"))
	before, _ := w.profileFiles()
	linkAssertDTO(t, w, cookie, "a", "b", false, "a", "b")
	linkAssertRuntimeDNS(t, w, "127.0.0.1", "127.0.0.2")
	after, _ := w.profileFiles()
	if !webProfileEqual(before, after) {
		t.Fatal("GET/compile changed retained subscription state")
	}
	linkPost(t, w, cookie, csrf, "/api/v1/nodes/selection", `{"name":"b"}`)
	linkAssertDTO(t, w, cookie, "b", "b", true)
	linkAssertRuntimeDNS(t, w, "127.0.0.2", "127.0.0.2")
}

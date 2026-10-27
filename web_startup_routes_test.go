package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"testing"

	st "github.com/NiuStar/anytls-core/internal/startuptimeline"
)

// These four existing save entry points use actual authenticated routes and real
// config/selection readback, not a direct finishConfigSave call. The additional
// rule/profile/import/append source cases use the common-finish matrix.
func TestWebStartupFourRealSaveRoutes(t *testing.T) {
	sources := map[string]string{"config": "SAVE_YAML", "nodes": "SAVE_NODE", "nodes/selection": "SAVE_SELECTION", "groups/selection": "SAVE_GROUP"}
	for route, source := range sources {
		for _, mode := range []string{"success", "failure", "same", "stopped"} {
			t.Run(route+"/"+mode, func(t *testing.T) {
				w, password := webFixture(t)
				webNodeFile(t, w, webAutoConfig)
				if err := os.WriteFile(selectedPath(w.configPath), []byte("first\n"), 0600); err != nil {
					t.Fatal(err)
				}
				cookie, csrf := webLogin(t, w, password)
				old := w.beginStartup("start", "MANUAL_START")
				calls := 0
				w.state = func() (bool, bool, error) { return mode != "stopped", mode != "stopped", nil }
				w.serviceAction = func(context.Context, string, bool) error {
					calls++
					if mode == "failure" {
						return errors.New("SECRET_SENTINEL")
					}
					return nil
				}
				rec := httptest.NewRecorder()
				w.ServeHTTP(rec, webAutoRequest(t, w, cookie, csrf, route, mode != "same", true))
				var body struct {
					Saved   bool                   `json:"saved"`
					Applied bool                   `json:"applied"`
					Ref     *st.OperationReference `json:"startup_operation"`
				}
				if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &body) != nil || !body.Saved {
					t.Fatal(rec.Code, rec.Body.String())
				}
				if mode == "same" || mode == "stopped" {
					if body.Ref != nil || calls != 0 || w.startupLatest != old {
						t.Fatal(rec.Body.String(), calls)
					}
				} else {
					if body.Ref == nil || body.Ref.OperationID == nil || calls != 1 || w.startupLatest.source != source || body.Applied != (mode == "success") {
						t.Fatal(rec.Body.String(), calls)
					}
				}
			})
		}
	}
}
func TestWebStartupValidationFailureExplicitNull(t *testing.T) {
	w, password := webFixture(t)
	cookie, csrf := webLogin(t, w, password)
	old := w.beginStartup("start", "MANUAL_START")
	rec := webRequest(w, "PUT", "/api/v1/config", `{"yaml":"invalid"}`, cookie, csrf)
	// Missing If-Match is a save precondition failure, not an accepted operation.
	var body map[string]json.RawMessage
	if rec.Code != 428 || json.Unmarshal(rec.Body.Bytes(), &body) != nil || string(body["startup_operation"]) != "null" || w.startupLatest != old {
		t.Fatal(rec.Code, rec.Body.String())
	}
}

// Frozen get projection from 321f73f8b875ca8e2e77e79c90fa552564c9426a.
package main

import (
	"context"
	"encoding/json"
	"gopkg.in/yaml.v3"
	"net/http"
	"time"
)

func (w *webConsole) getSourceBaselineOracle(rw http.ResponseWriter, r *http.Request, session webSession) {
	switch r.URL.Path {
	case "/api/v1/subscriptions":
		w.getSubscriptions(rw, r)
	case "/api/v1/profiles":
		// getProfiles owns actionMu; acquiring it here would reject every list.
		w.getProfiles(rw, r)
	case "/api/v1/config/export":
		w.exportCurrent(rw, r)
	case "/api/v1/subscription":
		w.getSubscription(rw)
	case "/api/v1/session":
		webJSON(rw, 200, map[string]any{"csrf": session.csrf, "username": "admin"})
	case "/api/v1/status":
		loaded, running, err := w.state()
		pending, known := w.pendingState()
		availability := "AVAILABLE"
		if err != nil {
			availability = "UNAVAILABLE"
		}
		webJSON(rw, 200, map[string]any{"loaded": loaded, "running": running, "availability": availability, "pendingReload": pending, "pendingKnown": known, "version": currentVersion(), "readiness": "NOT_OBSERVED", "transport": w.transport(), "listenHost": w.listenHost})
	case "/api/v1/nodes", "/api/v1/groups":
		b, err := readSnapshotSource(w.configPath, snapshotConfigLimit, false)
		if err != nil {
			webError(rw, 500, "CONFIG_UNAVAILABLE")
			return
		}
		nodes, err := loadNodesBytes(b)
		if err != nil {
			webError(rw, 422, "CONFIG_INVALID")
			return
		}
		if r.URL.Path == "/api/v1/nodes" {
			selected := effectiveWebSelection(w.configPath, b, nodes)
			defaultSelected, linked, needsSync := webSelectionLinkState(b, nodes, selected)
			list := make([]map[string]any, 0, len(nodes))
			for _, n := range nodes {
				list = append(list, map[string]any{"name": n.Name, "type": n.Type, "server": n.Server, "port": n.Port, "hasPassword": n.Password != "", "selectable": selectable(n), "skipVerify": n.SkipVerify, "sni": n.SNI, "selected": selected == n.Name, "defaultSelected": defaultSelected == n.Name, "selectionNeedsSync": needsSync[n.Name]})
			}
			webJSON(rw, 200, map[string]any{"nodes": list, "etag": `"` + shaHex(b) + `"`, "selection_linked": linked})
			return
		}
		var doc struct {
			Groups []proxyGroup `yaml:"proxy-groups"`
		}
		if yaml.Unmarshal(b, &doc) != nil {
			webError(rw, 422, "CONFIG_INVALID")
			return
		}
		list := make([]map[string]any, 0, len(doc.Groups))
		for _, g := range doc.Groups {
			resolved, err := resolveGroup(g.Name, nodes, doc.Groups)
			list = append(list, map[string]any{"name": g.Name, "type": g.Type, "choices": g.Proxies, "selected": g.Selected, "resolved": resolved, "valid": err == nil})
		}
		webJSON(rw, 200, map[string]any{"groups": list, "etag": `"` + shaHex(b) + `"`})
	case "/api/v1/rules":
		w.getRules(rw, r)
	case "/api/v1/config":
		b, err := readSnapshotSource(w.configPath, snapshotConfigLimit, false)
		if err != nil {
			webError(rw, 500, "CONFIG_UNAVAILABLE")
			return
		}
		etag := `"` + shaHex(b) + `"`
		rw.Header().Set("ETag", etag)
		webJSON(rw, 200, map[string]string{"yaml": string(b), "etag": etag})
	case "/api/v1/helper/status":
		webControlStatus(rw, r)
	case "/api/v1/version":
		webJSON(rw, 200, map[string]string{"version": currentVersion()})
	case "/api/v1/update-check":
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		result, err := w.updateAction(ctx, true)
		if err != nil {
			webError(rw, 503, webUpdateErrorName(err))
			return
		}
		var body map[string]any
		if json.Unmarshal(result, &body) != nil || body == nil {
			webError(rw, 503, "UPDATE_RESPONSE_INVALID")
			return
		}
		body["restartManaged"] = w.restartCheck != nil && w.restartRequest != nil && w.restartCheck() == nil
		body["restartScheduled"] = false
		webJSON(rw, 200, body)
	default:
		webError(rw, 404, "NOT_FOUND")
	}
}

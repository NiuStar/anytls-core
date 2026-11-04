package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Private metadata is stored with the complete profile in one atomic 0600 file.
// Public DTOs are explicit allowlists, never a serialization of these structs.
type webProfileLink struct {
	Auto         bool                      `json:"auto"`
	Last         string                    `json:"last,omitempty"`
	Next         string                    `json:"next"`
	Updated      string                    `json:"updated,omitempty"`
	Result       string                    `json:"result"`
	Baseline     string                    `json:"baseline"`
	SourceDigest string                    `json:"source_digest,omitempty"`
	Candidate    *webSubscriptionCandidate `json:"candidate,omitempty"`
	Previous     *webProfileSnapshot       `json:"previous,omitempty"`
}
type webProfileSnapshot struct {
	YAML         string  `json:"yaml"`
	Selected     *string `json:"selected"`
	Subscription *string `json:"subscription"`
}
type webSubscriptionCandidate struct {
	Snapshot     webProfileSnapshot  `json:"snapshot"`
	Base         string              `json:"base"`
	SourceDigest string              `json:"source_digest,omitempty"`
	Invalid      bool                `json:"invalid"`
	Conflict     bool                `json:"conflict,omitempty"`
	Conversion   webConversionReport `json:"conversion"`
}
type webSubscriptionPreview struct {
	Profile     webProfile
	Token, CSRF string
	Expires     time.Time
	Conversion  webConversionReport
}

func profileSnapshot(p webProfile) webProfileSnapshot {
	return webProfileSnapshot{p.YAML, p.Selected, p.Subscription}
}
func setProfileSnapshot(p *webProfile, s webProfileSnapshot) {
	p.YAML, p.Selected, p.Subscription = s.YAML, s.Selected, s.Subscription
}
func profileVersion(p webProfile) string { b, _ := json.Marshal(p); return shaHex(b) }
func profileContent(p webProfile) string { b, _ := json.Marshal(profileSnapshot(p)); return shaHex(b) }
func candidateVersion(c *webSubscriptionCandidate) string {
	if c == nil {
		return ""
	}
	b, _ := json.Marshal(c)
	return shaHex(b)
}
func (w *webConsole) activePath() string {
	return filepath.Join(filepath.Dir(w.configPath), "active-profile")
}
func (w *webConsole) activeProfile() (string, error) {
	f, e := webProfileCapture(w.activePath(), 128, true, true)
	if e != nil {
		return "", e
	}
	if !f.exists {
		return "", nil
	}
	id := strings.TrimSpace(string(f.data))
	if !webProfileID.MatchString(id) {
		return "", errors.New("unsafe active profile")
	}
	if _, _, e = w.readProfile(id); e != nil {
		return "", e
	}
	return id, nil
}
func (w *webConsole) setActiveProfile(id string) error {
	if e := webAtomicWrite(w.activePath(), []byte(id+"\n")); e != nil {
		return e
	}
	if w.profileMarkerReadback != nil {
		if e := w.profileMarkerReadback(); e != nil {
			return e
		}
	}
	got, e := w.activeProfile()
	if e != nil || got != id {
		return errors.New("active profile readback")
	}
	return nil
}
func (w *webConsole) allProfiles() ([]webProfile, error) {
	root, e := w.profileDir(false)
	if errors.Is(e, os.ErrNotExist) {
		return []webProfile{}, nil
	}
	if e != nil {
		return nil, e
	}
	entries, e := os.ReadDir(root)
	if e != nil {
		return nil, e
	}
	out := []webProfile{}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		p, _, e := w.readProfile(id)
		if e != nil {
			return nil, e
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt < out[j].CreatedAt })
	return out, nil
}
func (w *webConsole) profileNameAvailable(name, except string) bool {
	ps, e := w.allProfiles()
	if e != nil {
		return false
	}
	for _, p := range ps {
		if p.ID != except && p.Name == name {
			return false
		}
	}
	return true
}
func uniqueProfileName(ps []webProfile, base string) string {
	names := map[string]bool{}
	for _, p := range ps {
		names[p.Name] = true
	}
	name := base
	for i := 2; names[name]; i++ {
		name = base + " " + strconv.Itoa(i)
	}
	return name
}

func (w *webConsole) replaceProfile(p webProfile, source webProfileFile) error {
	if !webProfileSame(source) {
		return errors.New("profile conflict")
	}
	b, e := json.Marshal(p)
	if e != nil || int64(len(b)) > webProfileLimit {
		return errors.New("profile size")
	}
	if e = webAtomicWrite(source.path, b); e != nil {
		return e
	}
	_, f, e := w.readProfile(p.ID)
	if e != nil || !bytes.Equal(f.data, b) {
		return errors.New("profile readback")
	}
	return nil
}
func (w *webConsole) syncActiveProfile() error {
	id, e := w.activeProfile()
	if e != nil || id == "" {
		return e
	}
	p, f, e := w.readProfile(id)
	if e != nil {
		return e
	}
	files, e := w.profileFiles()
	if e != nil {
		return e
	}
	if webProfileEqual(files, webProfilePayload(p, w.configPath)) {
		return nil
	}
	p.YAML = string(files[0].data)
	p.Selected = nil
	p.Subscription = nil
	if files[1].exists {
		s := string(files[1].data)
		p.Selected = &s
	}
	if files[2].exists {
		s := string(files[2].data)
		p.Subscription = &s
	}
	for _, f := range files {
		if !webProfileSame(f) {
			return errors.New("active profile conflict")
		}
	}
	return w.replaceProfile(p, f)
}
func (w *webConsole) getProfilesDetail(rw http.ResponseWriter, r *http.Request) {
	if !w.actionMu.TryLock() {
		webError(rw, 409, "ACTION_BUSY")
		return
	}
	defer w.actionMu.Unlock()
	ps, e := w.allProfiles()
	if e != nil {
		webError(rw, 503, "PROFILE_STORE_UNAVAILABLE")
		return
	}
	id, e := w.activeProfile()
	if e != nil {
		webError(rw, 503, "PROFILE_STORE_UNAVAILABLE")
		return
	}
	if id == "" {
		files, e := w.profileFiles()
		if e != nil {
			webError(rw, 503, "PROFILE_STORE_UNAVAILABLE")
			return
		}
		name := uniqueProfileName(ps, "当前方案")
		p := webProfile{Name: name, YAML: string(files[0].data)}
		if files[1].exists {
			s := string(files[1].data)
			p.Selected = &s
		}
		if files[2].exists {
			s := string(files[2].data)
			p.Subscription = &s
		}
		if w.publishProfile(&p) != nil || w.setActiveProfile(p.ID) != nil {
			webError(rw, 500, "PROFILE_SAVE_FAILED")
			return
		}
		id = p.ID
		ps = append(ps, p)
	}
	list := []map[string]any{}
	for _, p := range ps {
		list = append(list, map[string]any{"id": p.ID, "name": p.Name, "created_at": p.CreatedAt, "current": p.ID == id, "version": profileVersion(p), "linked": p.Link != nil})
	}
	files, e := w.profileFiles()
	if e != nil {
		webError(rw, 503, "CONFIG_UNAVAILABLE")
		return
	}
	etag := `"` + shaHex(files[0].data) + `"`
	rw.Header().Set("ETag", etag)
	webJSON(rw, 200, map[string]any{"profiles": list, "active_id": id, "etag": etag, "switch_version": webProfileSwitchVersion(id, files)})
}
func (w *webConsole) editProfile(rw http.ResponseWriter, r *http.Request) {
	var in struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Version string `json:"version"`
		Confirm bool   `json:"confirm"`
	}
	if webDecode(rw, r, &in) != nil || !webProfileID.MatchString(in.ID) {
		webError(rw, 400, "PROFILE_INVALID")
		return
	}
	p, f, e := w.readProfile(in.ID)
	if e != nil {
		webProfileReadError(rw, e)
		return
	}
	if in.Version == "" || in.Version != profileVersion(p) {
		webError(rw, 412, "PROFILE_CONFLICT")
		return
	}
	if strings.HasSuffix(r.URL.Path, "/delete") {
		if !in.Confirm {
			webError(rw, 400, "CONFIRMATION_REQUIRED")
			return
		}
		id, e := w.activeProfile()
		if e != nil {
			webError(rw, 503, "PROFILE_STORE_UNAVAILABLE")
			return
		}
		if id == p.ID {
			webError(rw, 409, "PROFILE_ACTIVE")
			return
		}
		if !webProfileSame(f) || os.Remove(f.path) != nil {
			webError(rw, 500, "PROFILE_DELETE_FAILED")
			return
		}
		if _, e := os.Lstat(f.path); !errors.Is(e, os.ErrNotExist) {
			webError(rw, 500, "PROFILE_DELETE_FAILED")
			return
		}
	} else {
		if !webProfileName(in.Name) {
			webError(rw, 400, "PROFILE_INVALID")
			return
		}
		if !w.profileNameAvailable(in.Name, p.ID) {
			webError(rw, 409, "PROFILE_NAME_EXISTS")
			return
		}
		p.Name = in.Name
		if w.replaceProfile(p, f) != nil {
			webError(rw, 500, "PROFILE_SAVE_FAILED")
			return
		}
	}
	webJSON(rw, 200, map[string]any{"ok": true, "id": p.ID, "name": p.Name})
}
func subscriptionURL(p webProfile) (string, error) {
	if p.Subscription == nil {
		return "", errors.New("no subscription")
	}
	var v struct {
		URL string `json:"url"`
	}
	d := json.NewDecoder(strings.NewReader(*p.Subscription))
	d.DisallowUnknownFields()
	if d.Decode(&v) != nil {
		return "", errors.New("subscription invalid")
	}
	if _, e := webImportURL(v.URL); e != nil {
		return "", e
	}
	return v.URL, nil
}
func (w *webConsole) subscriptionDTO(p webProfile) map[string]any {
	l := p.Link
	raw, _ := subscriptionURL(p)
	host := ""
	if u, e := webImportURL(raw); e == nil {
		host = u.Hostname()
	}
	active, _ := w.activeProfile()
	conflict := false
	invalid := false
	choices := []string{}
	if l.Candidate != nil {
		conflict = l.Candidate.Conflict || l.Candidate.Base != profileContent(p) || l.Baseline != profileContent(p)
		invalid = l.Candidate.Invalid
		nodes, _ := loadNodesBytes([]byte(l.Candidate.Snapshot.YAML))
		for _, n := range nodes {
			if selectable(n) {
				choices = append(choices, n.Name)
			}
		}
	}
	return map[string]any{"id": p.ID, "profile_id": p.ID, "profile_name": p.Name, "source_host": host, "auto_check": l.Auto, "last_check": l.Last, "next_check": l.Next, "last_updated": l.Updated, "result": l.Result, "busy": w.subscriptionBusy[p.ID], "version": profileVersion(p), "target_version": profileVersion(p), "candidate_version": candidateVersion(l.Candidate), "conflict": conflict, "selection_invalid": invalid, "candidate_choices": choices, "has_previous": l.Previous != nil, "current": active == p.ID}
}
func (w *webConsole) getSubscriptions(rw http.ResponseWriter, r *http.Request) {
	if !w.actionMu.TryLock() {
		webError(rw, 409, "ACTION_BUSY")
		return
	}
	defer w.actionMu.Unlock()
	ps, e := w.allProfiles()
	if e != nil {
		webError(rw, 503, "PROFILE_STORE_UNAVAILABLE")
		return
	}
	out := []map[string]any{}
	for _, p := range ps {
		if p.Link != nil {
			out = append(out, w.subscriptionDTO(p))
		}
	}
	webJSON(rw, 200, map[string]any{"subscriptions": out, "interval_seconds": 3600})
}
func (w *webConsole) subscriptionConvert(ctx context.Context, raw string) ([]byte, webConversionReport, error) {
	var report webConversionReport
	if _, e := webImportURL(raw); e != nil {
		return nil, report, e
	}
	fetch := w.importFetch
	if fetch == nil {
		fetch = webImportSecureFetch
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	b, e := fetch(ctx, raw)
	if e != nil {
		return nil, report, errors.New("IMPORT_FETCH_FAILED")
	}
	if code := webSubscriptionResponseCode(b); code != "" {
		return nil, report, errors.New(code)
	}
	b, report, e = webConvertConfiguration(ctx, b, true, fetch)
	if e != nil {
		return nil, report, errors.New(webConversionErrorCode(e))
	}
	if len(report.Issues) > 0 {
		return nil, report, errors.New("CONFIG_CONVERSION_UNSUPPORTED")
	}
	if e = webImportFormat(b, false); e != nil {
		return nil, report, e
	}
	if webValidateConfig(w.configPath, b) != nil {
		return nil, report, errors.New("CONFIG_VALIDATION_FAILED")
	}
	if e = ctx.Err(); e != nil {
		return nil, report, errors.New("CONFIG_CONVERSION_CANCELED")
	}
	return b, report, nil
}

// A strict typed node identity includes its source name, type, target, credentials,
// and TLS boundary. Same-name nodes with changed targets never inherit selection.
func subscriptionSelection(old webProfile, b []byte) (*string, bool) {
	if old.Selected == nil {
		return nil, false
	}
	oldNodes, _ := loadNodesBytes([]byte(old.YAML))
	newNodes, _ := loadNodesBytes(b)
	name := strings.TrimSuffix(*old.Selected, "\n")
	n, e := choose(oldNodes, name)
	if e != nil {
		return nil, true
	}
	a, _ := json.Marshal(n)
	for _, v := range newNodes {
		z, _ := json.Marshal(v)
		if bytes.Equal(a, z) && selectable(v) {
			s := v.Name + "\n"
			return &s, false
		}
	}
	return nil, true
}

// Retain explicit group choices only when the complete resolution path and
// terminal typed node identity survive; changed-target aliases are not identity.
func subscriptionGroupSelections(old webProfile, b []byte) ([]byte, bool) {
	var before, after struct {
		Groups []proxyGroup `yaml:"proxy-groups"`
	}
	if yaml.Unmarshal([]byte(old.YAML), &before) != nil || yaml.Unmarshal(b, &after) != nil {
		return b, true
	}
	oldNodes, _ := loadNodesBytes([]byte(old.YAML))
	newNodes, _ := loadNodesBytes(b)
	var doc yaml.Node
	if yaml.Unmarshal(b, &doc) != nil || len(doc.Content) != 1 {
		return b, true
	}
	groups := snapshotYAMLField(doc.Content[0], "proxy-groups")
	if groups == nil {
		return b, len(before.Groups) > 0
	}
	changed, invalid := false, false
	for _, g := range before.Groups {
		if g.Selected == "" {
			continue
		}
		oldTerminal, oldEdges, e := resolveGroupPath(g.Name, oldNodes, before.Groups)
		if e != nil {
			invalid = true
			continue
		}
		test := append([]proxyGroup{}, after.Groups...)
		found := false
		for i := range test {
			if test[i].Name == g.Name && test[i].Type == g.Type {
				for _, choice := range test[i].Proxies {
					if choice == g.Selected {
						test[i].Selected = g.Selected
						found = true
					}
				}
			}
		}
		if !found {
			invalid = true
			continue
		}
		terminal, edges, e := resolveGroupPath(g.Name, newNodes, test)
		same := e == nil && terminal == oldTerminal
		edgeA, _ := json.Marshal(oldEdges)
		edgeB, _ := json.Marshal(edges)
		same = same && bytes.Equal(edgeA, edgeB)
		if terminal != "DIRECT" && terminal != "REJECT" {
			n, e := choose(oldNodes, oldTerminal)
			q, f := choose(newNodes, terminal)
			a, _ := json.Marshal(n)
			z, _ := json.Marshal(q)
			same = same && e == nil && f == nil && bytes.Equal(a, z)
		}
		if !same {
			invalid = true
			continue
		}
		for _, n := range groups.Content {
			if v := snapshotYAMLField(n, "name"); v != nil && v.Value == g.Name {
				selected := snapshotYAMLField(n, "selected")
				if selected == nil {
					n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "selected"}, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: g.Selected})
					changed = true
				} else if selected.Value != g.Selected {
					selected.Value = g.Selected
					selected.Tag = "!!str"
					changed = true
				}
			}
		}
	}
	if changed {
		out, e := yaml.Marshal(&doc)
		if e != nil {
			return b, true
		}
		return out, invalid
	}
	return b, invalid
}

// Preview/check own only short action phases. Neither fetch nor conversion holds
// the global mutation lock; completion re-reads the exact source and target.
func (w *webConsole) subscriptionNetwork(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		webError(rw, 405, "METHOD_NOT_ALLOWED")
		return
	}
	var in struct {
		ID   string `json:"id"`
		URL  string `json:"url"`
		Name string `json:"name"`
	}
	if webDecode(rw, r, &in) != nil {
		webError(rw, 400, "INVALID_INPUT")
		return
	}
	if strings.HasSuffix(r.URL.Path, "/check") {
		if !webProfileID.MatchString(in.ID) || in.URL != "" || in.Name != "" {
			webError(rw, 400, "INVALID_INPUT")
			return
		}
		p, code := w.checkSubscriptionAuthorized(r.Context(), in.ID, w.manualSubscriptionAuthority(r))
		if code != "" {
			status := 422
			if code == "AUTH_REQUIRED" {
				status = 401
			}
			if code == "SUBSCRIPTION_BUSY" || code == "ACTION_BUSY" {
				status = 409
			}
			webError(rw, status, code)
			return
		}
		w.actionMu.Lock()
		defer w.actionMu.Unlock()
		webJSON(rw, 200, w.subscriptionDTO(p))
		return
	}
	if in.ID != "" || in.URL == "" || (in.Name != "" && !webProfileName(in.Name)) {
		webError(rw, 400, "INVALID_INPUT")
		return
	}
	if !w.actionMu.TryLock() {
		webError(rw, 409, "ACTION_BUSY")
		return
	}
	w.subscriptionPreview = nil
	if w.restartPending {
		w.actionMu.Unlock()
		webError(rw, 409, "RESTART_PENDING")
		return
	}
	if in.Name == "" {
		ps, e := w.allProfiles()
		if e != nil {
			w.actionMu.Unlock()
			webError(rw, 503, "PROFILE_STORE_UNAVAILABLE")
			return
		}
		in.Name = uniqueProfileName(ps, "订阅方案")
	}
	if !w.profileNameAvailable(in.Name, "") {
		w.actionMu.Unlock()
		webError(rw, 409, "PROFILE_NAME_EXISTS")
		return
	}
	generation, _ := webRandom(32)
	if w.subscriptionSources == nil {
		w.subscriptionSources = map[string]bool{}
	}
	if w.subscriptionSources[in.URL] {
		w.actionMu.Unlock()
		webError(rw, 409, "SUBSCRIPTION_BUSY")
		return
	}
	w.subscriptionSources[in.URL] = true
	w.subscriptionPreviewGeneration = generation
	w.actionMu.Unlock()
	b, report, e := w.subscriptionConvert(r.Context(), in.URL)
	w.actionMu.Lock()
	defer w.actionMu.Unlock()
	delete(w.subscriptionSources, in.URL)
	release, authorized := w.manualSubscriptionAuthority(r)()
	if !authorized {
		webError(rw, 401, "AUTH_REQUIRED")
		return
	}
	defer release()
	if e != nil {
		webError(rw, 422, e.Error())
		return
	}
	if r.Context().Err() != nil || w.subscriptionPreviewGeneration != generation {
		webError(rw, 409, "IMPORT_PREVIEW_EXPIRED")
		return
	}
	token, e := webRandom(32)
	if e != nil {
		webError(rw, 500, "RANDOM_UNAVAILABLE")
		return
	}
	metadata, _ := json.Marshal(map[string]string{"url": in.URL})
	s := string(metadata)
	p := webProfile{Name: in.Name, YAML: string(b), Subscription: &s}
	nodes, _ := loadNodesBytes(b)
	for _, n := range nodes {
		if selectable(n) {
			s := n.Name + "\n"
			p.Selected = &s
			break
		}
	}
	if p.Selected == nil {
		webError(rw, 422, "IMPORT_NO_SELECTABLE_NODES")
		return
	}
	w.subscriptionPreview = &webSubscriptionPreview{p, token, r.Header.Get("X-CSRF-Token"), w.now().Add(10 * time.Minute), report}
	var doc struct {
		Groups []proxyGroup `yaml:"proxy-groups"`
		Rules  []string     `yaml:"rules"`
	}
	_ = yaml.Unmarshal(b, &doc)
	u, _ := webImportURL(in.URL)
	webJSON(rw, 200, map[string]any{"token": token, "name": in.Name, "source_host": u.Hostname(), "nodes": len(nodes), "groups": len(doc.Groups), "rules": len(doc.Rules), "conversion": report})
}

func (w *webConsole) checkSubscription(ctx context.Context, id string) (webProfile, string) {
	return w.checkSubscriptionAuthorized(ctx, id, subscriptionWorkerAuthority(ctx))
}

// Browser calls never use this service-owned authority.
func subscriptionWorkerAuthority(ctx context.Context) func() (func(), bool) {
	return func() (func(), bool) { return func() {}, ctx.Err() == nil }
}

func (w *webConsole) checkSubscriptionAuthorized(ctx context.Context, id string, authority func() (func(), bool)) (webProfile, string) {
	var empty webProfile
	if !w.actionMu.TryLock() {
		return empty, "ACTION_BUSY"
	}
	p, _, e := w.readProfile(id)
	if e != nil || p.Link == nil {
		w.actionMu.Unlock()
		return empty, "SUBSCRIPTION_NOT_FOUND"
	}
	raw, e := subscriptionURL(p)
	if e != nil {
		w.actionMu.Unlock()
		return empty, "SUBSCRIPTION_UNAVAILABLE"
	}
	if w.restartPending {
		w.actionMu.Unlock()
		return empty, "RESTART_PENDING"
	}
	if w.subscriptionBusy == nil {
		w.subscriptionBusy = map[string]bool{}
	}
	ps, e := w.allProfiles()
	if e != nil {
		w.actionMu.Unlock()
		return empty, "PROFILE_STORE_UNAVAILABLE"
	}
	for _, other := range ps {
		otherURL, _ := subscriptionURL(other)
		if w.subscriptionBusy[other.ID] && otherURL == raw {
			w.actionMu.Unlock()
			return empty, "SUBSCRIPTION_BUSY"
		}
	}
	w.subscriptionBusy[id] = true
	if w.subscriptionSources == nil {
		w.subscriptionSources = map[string]bool{}
	}
	if w.subscriptionSources[raw] {
		delete(w.subscriptionBusy, id)
		w.actionMu.Unlock()
		return empty, "SUBSCRIPTION_BUSY"
	}
	w.subscriptionSources[raw] = true
	baseVersion := profileVersion(p)
	w.actionMu.Unlock()
	b, report, fetchErr := w.subscriptionConvert(ctx, raw)
	w.actionMu.Lock()
	defer w.actionMu.Unlock()
	delete(w.subscriptionBusy, id)
	delete(w.subscriptionSources, raw)
	if ctx.Err() != nil {
		return empty, "CONFIG_CONVERSION_CANCELED"
	}
	release, authorized := authority()
	if !authorized {
		return empty, "AUTH_REQUIRED"
	}
	defer release()
	current, f, e := w.readProfile(id)
	if e != nil || current.Link == nil {
		return empty, "SUBSCRIPTION_NOT_FOUND"
	}
	currentURL, e := subscriptionURL(current)
	if e != nil || currentURL != raw {
		return empty, "SUBSCRIPTION_CONFLICT"
	}
	if ctx.Err() != nil || w.restartPending {
		return empty, "CONFIG_CONVERSION_CANCELED"
	}
	unchanged := profileVersion(current) == baseVersion
	l := current.Link
	l.Last = w.now().UTC().Format(time.RFC3339Nano)
	l.Next = w.now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
	if fetchErr != nil {
		l.Result = "CHECK_FAILED"
		if w.replaceProfile(current, f) != nil {
			return empty, "PROFILE_SAVE_FAILED"
		}
		return current, ""
	}
	digest := shaHex(b)
	if digest == l.SourceDigest || string(b) == current.YAML {
		l.Result = "NO_CHANGE"
		if w.replaceProfile(current, f) != nil {
			return empty, "PROFILE_SAVE_FAILED"
		}
		return current, ""
	}
	b, groupInvalid := subscriptionGroupSelections(current, b)
	selected, invalid := subscriptionSelection(current, b)
	invalid = invalid || groupInvalid
	candidate := &webSubscriptionCandidate{Snapshot: webProfileSnapshot{string(b), selected, current.Subscription}, Base: profileContent(current), SourceDigest: digest, Invalid: invalid, Conflict: !unchanged, Conversion: report}
	active, e := w.activeProfile()
	if e != nil {
		return empty, "PROFILE_STORE_UNAVAILABLE"
	}
	if active != id && unchanged && l.Baseline == profileContent(current) && !invalid && len(report.Warnings) == 0 && len(report.Skipped) == 0 {
		prev := profileSnapshot(current)
		l.Previous = &prev
		setProfileSnapshot(&current, candidate.Snapshot)
		l.Baseline = profileContent(current)
		l.SourceDigest = digest
		l.Candidate = nil
		l.Result = "UPDATED"
		l.Updated = l.Last
	} else {
		l.Candidate = candidate
		l.Result = "UPDATE_PENDING"
	}
	if w.replaceProfile(current, f) != nil {
		return empty, "PROFILE_SAVE_FAILED"
	}
	return current, ""
}
func (w *webConsole) subscriptionMutation(rw http.ResponseWriter, r *http.Request) {
	var in struct {
		ID        string `json:"id"`
		Token     string `json:"token"`
		Name      string `json:"name"`
		Version   string `json:"version"`
		Target    string `json:"target_version"`
		Candidate string `json:"candidate_version"`
		Selected  string `json:"selected"`
		Auto      *bool  `json:"auto_check"`
		Confirm   bool   `json:"confirm"`
		Insecure  bool   `json:"confirm_insecure"`
		Accept    bool   `json:"accept_conversion"`
	}
	if webDecode(rw, r, &in) != nil {
		webError(rw, 400, "INVALID_INPUT")
		return
	}
	if strings.HasSuffix(r.URL.Path, "/import") {
		preview := w.subscriptionPreview
		if !in.Confirm || !in.Insecure {
			webError(rw, 400, "CONFIRMATION_REQUIRED")
			return
		}
		if preview == nil || !w.now().Before(preview.Expires) || !webEqual(in.Token, preview.Token) || !webEqual(r.Header.Get("X-CSRF-Token"), preview.CSRF) {
			webError(rw, 409, "IMPORT_PREVIEW_EXPIRED")
			return
		}
		if (len(preview.Conversion.Warnings) > 0 || len(preview.Conversion.Skipped) > 0) && !in.Accept {
			webError(rw, 400, "CONVERSION_CONFIRMATION_REQUIRED")
			return
		}
		p := preview.Profile
		if in.Name != "" {
			p.Name = in.Name
		}
		if !webProfileName(p.Name) {
			webError(rw, 400, "PROFILE_INVALID")
			return
		}
		if !w.profileNameAvailable(p.Name, "") {
			webError(rw, 409, "PROFILE_NAME_EXISTS")
			return
		}
		p.Link = &webProfileLink{Auto: true, Next: w.now().Add(time.Hour).UTC().Format(time.RFC3339Nano), Result: "NOT_CHECKED", Baseline: profileContent(p), SourceDigest: shaHex([]byte(p.YAML))}
		if w.publishProfile(&p) != nil {
			webError(rw, 500, "PROFILE_SAVE_FAILED")
			return
		}
		w.subscriptionPreview = nil
		webJSON(rw, 200, map[string]any{"ok": true, "id": p.ID, "name": p.Name})
		return
	}
	if !webProfileID.MatchString(in.ID) {
		webError(rw, 400, "INVALID_INPUT")
		return
	}
	p, f, e := w.readProfile(in.ID)
	if e != nil || p.Link == nil {
		webError(rw, 404, "SUBSCRIPTION_NOT_FOUND")
		return
	}
	apply := strings.HasSuffix(r.URL.Path, "/apply")
	if apply {
		if !in.Confirm || !in.Insecure {
			webError(rw, 400, "CONFIRMATION_REQUIRED")
			return
		}
		if in.Target != profileVersion(p) || p.Link.Candidate == nil || in.Candidate != candidateVersion(p.Link.Candidate) {
			webError(rw, 412, "SUBSCRIPTION_CONFLICT")
			return
		}
	} else if in.Version != profileVersion(p) {
		webError(rw, 412, "SUBSCRIPTION_CONFLICT")
		return
	}
	active, e := w.activeProfile()
	if e != nil {
		webError(rw, 503, "PROFILE_STORE_UNAVAILABLE")
		return
	}
	switch {
	case strings.HasSuffix(r.URL.Path, "/options"):
		if in.Auto == nil {
			webError(rw, 400, "INVALID_INPUT")
			return
		}
		p.Link.Auto = *in.Auto
		if *in.Auto {
			p.Link.Next = w.now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
		}
	case strings.HasSuffix(r.URL.Path, "/unlink"):
		if !in.Confirm {
			webError(rw, 400, "CONFIRMATION_REQUIRED")
			return
		}
		p.Link = nil
		p.Subscription = nil
	case strings.HasSuffix(r.URL.Path, "/restore"):
		if !in.Confirm || p.Link.Previous == nil {
			webError(rw, 400, "PREVIOUS_VERSION_UNAVAILABLE")
			return
		}
		p.Link.Candidate = &webSubscriptionCandidate{Snapshot: *p.Link.Previous, Base: profileContent(p), SourceDigest: shaHex([]byte(p.Link.Previous.YAML))}
		p.Link.Result = "RESTORE_PENDING"
	case apply:
		c := p.Link.Candidate
		if (len(c.Conversion.Warnings) > 0 || len(c.Conversion.Skipped) > 0) && !in.Accept {
			webError(rw, 400, "CONVERSION_CONFIRMATION_REQUIRED")
			return
		}
		if c.Invalid {
			if in.Selected == "" {
				webError(rw, 422, "SELECTION_REQUIRED")
				return
			}
			nodes, _ := loadNodesBytes([]byte(c.Snapshot.YAML))
			n, e := choose(nodes, in.Selected)
			if e != nil || !selectable(n) {
				webError(rw, 422, "SELECTION_REQUIRED")
				return
			}
			s := in.Selected + "\n"
			c.Snapshot.Selected = &s
		}
		previous := profileSnapshot(p)
		setProfileSnapshot(&p, c.Snapshot)
		if c.SourceDigest != "" {
			p.Link.SourceDigest = c.SourceDigest
		}
		p.Link.Previous = &previous
		p.Link.Candidate = nil
		p.Link.Baseline = profileContent(p)
		p.Link.Result = "UPDATED"
		p.Link.Updated = w.now().UTC().Format(time.RFC3339Nano)
		if webProfileValidate(p, w.configPath) != nil {
			webError(rw, 422, "PROFILE_INVALID")
			return
		}
	default:
		webError(rw, 405, "METHOD_NOT_ALLOWED")
		return
	}
	var old []webProfileFile
	if active == p.ID && (apply || p.Link == nil) {
		old, e = w.profileFiles()
		if e != nil {
			webError(rw, 503, "PROFILE_STORE_UNAVAILABLE")
			return
		}
		var original webProfile
		if json.Unmarshal(f.data, &original) != nil {
			webError(rw, 503, "PROFILE_STORE_UNAVAILABLE")
			return
		}
		if !webProfileEqual(old, webProfilePayload(original, w.configPath)) {
			webError(rw, 412, "SUBSCRIPTION_CONFLICT")
			return
		}
		code := w.commitProfile(p, f, old, webAtomicWrite)
		if code != "" {
			webError(rw, 500, code)
			return
		}
	}
	if w.replaceProfile(p, f) != nil {
		code := "PROFILE_SAVE_FAILED"
		if old != nil {
			for _, f := range old {
				if webProfileWriteFile(f, webAtomicWrite) != nil {
					code = "PROFILE_STATE_UNCERTAIN"
				}
			}
			for _, f := range old {
				f.info = nil
				if !webProfileSame(f) {
					code = "PROFILE_STATE_UNCERTAIN"
				}
			}
		}
		webError(rw, 500, code)
		return
	}
	if old != nil && apply {
		changed := !webProfileEqual(old[:2], webProfilePayload(p, w.configPath)[:2])
		w.finishConfigSave(rw, r, changed, `"`+shaHex([]byte(p.YAML))+`"`, in.Insecure)
		return
	}
	if apply {
		webJSON(rw, 200, map[string]any{"ok": true, "startup_operation": nil})
		return
	}
	webJSON(rw, 200, map[string]any{"ok": true})
}
func (w *webConsole) checkSubscriptionsDue(ctx context.Context) {
	if !w.actionMu.TryLock() {
		return
	}
	ps, e := w.allProfiles()
	ids := []string{}
	if e == nil && !w.restartPending {
		for _, p := range ps {
			if p.Link == nil || !p.Link.Auto {
				continue
			}
			next, e := time.Parse(time.RFC3339Nano, p.Link.Next)
			if e == nil && !w.now().Before(next) {
				ids = append(ids, p.ID)
			}
		}
	}
	w.actionMu.Unlock()
	for _, id := range ids {
		if ctx.Err() != nil {
			return
		}
		_, _ = w.checkSubscription(ctx, id)
	}
}
func (w *webConsole) runSubscriptionWorker(ctx context.Context) {
	w.checkSubscriptionsDue(ctx)
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.checkSubscriptionsDue(ctx)
		}
	}
}

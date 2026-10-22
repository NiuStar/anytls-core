package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

const webProfileLimit = 6*snapshotConfigLimit + 6*snapshotSelectedLimit + 6*snapshotConfigLimit + 64<<10

var webProfileID = regexp.MustCompile(`^[0-9a-f]{32}$`)

// Profiles retain bytes and references, not external CA/rule resources. Rule
// paths keep the active config directory; CA resolution keeps existing policy.
// nil optional strings mean absent files, distinct from empty files.
type webProfile struct {
	ID           string  `json:"id"`
	Name         string  `json:"name"`
	CreatedAt    string  `json:"created_at"`
	YAML         string  `json:"yaml"`
	Selected     *string `json:"selected"`
	Subscription *string `json:"subscription"`
}
type webProfileSummary struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
	Current   bool   `json:"current"`
}

func webProfileName(s string) bool {
	if !utf8.ValidString(s) || strings.TrimSpace(s) == "" || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}
func webProfileOwned(st os.FileInfo) bool {
	if st == nil {
		return false
	}
	v, ok := st.Sys().(*syscall.Stat_t)
	return ok && int(v.Uid) == os.Geteuid()
}
func (w *webConsole) profileDir(create bool) (string, error) {
	root := filepath.Join(filepath.Dir(w.configPath), "profiles")
	if create {
		if e := os.Mkdir(root, 0700); e != nil && !errors.Is(e, os.ErrExist) {
			return "", e
		}
	}
	st, e := os.Lstat(root)
	if e != nil {
		return "", e
	}
	if !st.IsDir() || st.Mode().Perm() != 0700 || !webProfileOwned(st) {
		return "", errors.New("unsafe profile store")
	}
	return root, nil
}

// All sources use nonblocking, final-component nofollow handles and owner checks.
// This is optimistic race detection, not protection against hostile same-UID
// ancestor replacement or arbitrary in-place writes.
type webProfileFile struct {
	webImportFile
	info os.FileInfo
}

func webProfileCapture(path string, limit int64, optional, private bool) (webProfileFile, error) {
	f := webProfileFile{webImportFile: webImportFile{path: path}}
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK|unix.O_NOFOLLOW, 0)
	if optional && errors.Is(e, os.ErrNotExist) {
		return f, nil
	}
	if e != nil {
		return f, e
	}
	file := os.NewFile(uintptr(fd), "profile source")
	st, e := file.Stat()
	if e != nil || !webProfileOwned(st) || (private && st.Mode().Perm() != 0600) {
		file.Close()
		return f, errors.New("unsafe profile source")
	}
	b, e := readSnapshotOpened(file, limit)
	if e != nil {
		return f, e
	}
	f.info = st
	f.exists = true
	f.data = b
	return f, nil
}
func webProfileSame(f webProfileFile) bool {
	got, e := webProfileCapture(f.path, webProfileLimit, true, false)
	return e == nil && got.exists == f.exists && bytes.Equal(got.data, f.data) && (f.info == nil || got.info != nil && os.SameFile(f.info, got.info) && f.info.Mode() == got.info.Mode() && f.info.ModTime().Equal(got.info.ModTime()) && snapshotChangeTimeEqual(f.info, got.info))
}
func (w *webConsole) profileFiles() ([]webProfileFile, error) {
	files := make([]webProfileFile, 0, 3)
	for _, s := range []struct {
		path     string
		limit    int64
		optional bool
	}{{w.configPath, snapshotConfigLimit, false}, {selectedPath(w.configPath), snapshotSelectedLimit, true}, {w.subscriptionPath(), snapshotConfigLimit, true}} {
		f, e := webProfileCapture(s.path, s.limit, s.optional, false)
		if e != nil {
			return nil, e
		}
		files = append(files, f)
	}
	return files, nil
}
func webProfilePayload(p webProfile, config string) []webProfileFile {
	files := []webProfileFile{{webImportFile: webImportFile{path: config, data: []byte(p.YAML), exists: true}}, {webImportFile: webImportFile{path: selectedPath(config)}}, {webImportFile: webImportFile{path: filepath.Join(filepath.Dir(config), "subscription.json")}}}
	if p.Selected != nil {
		files[1].data = []byte(*p.Selected)
		files[1].exists = true
	}
	if p.Subscription != nil {
		files[2].data = []byte(*p.Subscription)
		files[2].exists = true
	}
	return files
}
func webProfileEqual(a, b []webProfileFile) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].exists != b[i].exists || !bytes.Equal(a[i].data, b[i].data) {
			return false
		}
	}
	return true
}
func webProfileValidate(p webProfile, config string) error {
	if !webProfileID.MatchString(p.ID) || !webProfileName(p.Name) || !utf8.ValidString(p.YAML) || len(p.YAML) == 0 || int64(len(p.YAML)) > snapshotConfigLimit {
		return errors.New("invalid profile")
	}
	if _, e := time.Parse(time.RFC3339Nano, p.CreatedAt); e != nil {
		return e
	}
	if p.Selected != nil && (!utf8.ValidString(*p.Selected) || int64(len(*p.Selected)) > snapshotSelectedLimit) {
		return errors.New("invalid selection")
	}
	if p.Subscription != nil && (!utf8.ValidString(*p.Subscription) || int64(len(*p.Subscription)) > snapshotConfigLimit) {
		return errors.New("invalid subscription")
	}
	if e := webValidateConfig(config, []byte(p.YAML)); e != nil {
		return e
	}
	nodes, e := loadNodesBytes([]byte(p.YAML))
	if e != nil {
		return e
	}
	if p.Selected == nil {
		return nil
	}
	name, e := selectedBytes([]byte(*p.Selected), nodes)
	if e != nil {
		return e
	}
	n, e := choose(nodes, name)
	if e != nil {
		return e
	}
	_, e = buildNode(n, "proxy", 11080, true)
	return e
}
func (w *webConsole) readProfile(id string) (webProfile, webProfileFile, error) {
	var p webProfile
	if !webProfileID.MatchString(id) {
		return p, webProfileFile{}, errors.New("invalid ID")
	}
	root, e := w.profileDir(false)
	if e != nil {
		return p, webProfileFile{}, e
	}
	f, e := webProfileCapture(filepath.Join(root, id+".json"), webProfileLimit, false, true)
	if e != nil {
		return p, f, e
	}
	d := json.NewDecoder(bytes.NewReader(f.data))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil {
		return p, f, errors.New("invalid profile JSON")
	}
	var extra any
	if d.Decode(&extra) != io.EOF || p.ID != id || !webProfileName(p.Name) {
		return p, f, errors.New("invalid profile metadata")
	}
	if _, e = time.Parse(time.RFC3339Nano, p.CreatedAt); e != nil {
		return p, f, e
	}
	// Full validation is for save/switch. Listing must not read external resources.
	if int64(len(p.YAML)) > snapshotConfigLimit || (p.Selected != nil && int64(len(*p.Selected)) > snapshotSelectedLimit) || (p.Subscription != nil && int64(len(*p.Subscription)) > snapshotConfigLimit) {
		return p, f, errors.New("invalid profile size")
	}
	return p, f, nil
}
func (w *webConsole) publishProfile(p *webProfile) error {
	root, e := w.profileDir(true)
	if e != nil {
		return e
	}
	var id [16]byte
	if _, e = rand.Read(id[:]); e != nil {
		return e
	}
	p.ID = hex.EncodeToString(id[:])
	p.CreatedAt = w.now().UTC().Format(time.RFC3339Nano)
	b, e := json.Marshal(p)
	if e != nil || int64(len(b)) > webProfileLimit {
		return errors.New("profile encoding failed")
	}
	// CreateTemp uses O_EXCL. Link atomically publishes the complete synced inode
	// without ever replacing an existing immutable profile ID.
	f, e := os.CreateTemp(root, ".profile-*")
	if e != nil {
		return e
	}
	temp := f.Name()
	defer os.Remove(temp)
	if e = f.Chmod(0600); e != nil {
		f.Close()
		return e
	}
	n, e := f.Write(b)
	if e != nil || n != len(b) {
		f.Close()
		return errors.New("profile write failed")
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if _, e = w.profileDir(false); e != nil {
		return e
	}
	path := filepath.Join(root, p.ID+".json")
	if e = os.Link(temp, path); e != nil {
		return e
	}
	dir, e := os.Open(root)
	if e != nil {
		return e
	}
	syncErr := dir.Sync()
	closeErr := dir.Close()
	if syncErr != nil || closeErr != nil {
		return errors.New("profile sync failed")
	}
	_, got, e := w.readProfile(p.ID)
	if e != nil || !bytes.Equal(got.data, b) {
		return errors.New("profile readback failed")
	}
	return nil
}

// Parent router must call mutations under existing auth/CSRF/actionMu. GET owns
// the action lock itself because normal GET dispatch intentionally does not.
func (w *webConsole) getProfiles(rw http.ResponseWriter, r *http.Request) {
	if !w.actionMu.TryLock() {
		webError(rw, 409, "ACTION_BUSY")
		return
	}
	defer w.actionMu.Unlock()
	current, e := w.profileFiles()
	if e != nil {
		webError(rw, 503, "PROFILE_STORE_UNAVAILABLE")
		return
	}
	profiles := []webProfileSummary{}
	root, e := w.profileDir(false)
	if e != nil && !errors.Is(e, os.ErrNotExist) {
		webError(rw, 503, "PROFILE_STORE_UNAVAILABLE")
		return
	}
	if e == nil {
		entries, e := os.ReadDir(root)
		if e != nil {
			webError(rw, 503, "PROFILE_STORE_UNAVAILABLE")
			return
		}
		for _, entry := range entries {
			name := entry.Name()
			if !strings.HasSuffix(name, ".json") {
				continue
			}
			id := strings.TrimSuffix(name, ".json")
			if !webProfileID.MatchString(id) {
				webError(rw, 503, "PROFILE_STORE_UNAVAILABLE")
				return
			}
			p, _, e := w.readProfile(id)
			if e != nil {
				webError(rw, 503, "PROFILE_STORE_UNAVAILABLE")
				return
			}
			profiles = append(profiles, webProfileSummary{p.ID, p.Name, p.CreatedAt, webProfileEqual(current, webProfilePayload(p, w.configPath))})
		}
	}
	for _, f := range current {
		if !webProfileSame(f) {
			webError(rw, 409, "PROFILE_CONFLICT")
			return
		}
	}
	sort.Slice(profiles, func(i, j int) bool {
		if profiles[i].CreatedAt == profiles[j].CreatedAt {
			return profiles[i].ID < profiles[j].ID
		}
		return profiles[i].CreatedAt < profiles[j].CreatedAt
	})
	etag := `"` + shaHex(current[0].data) + `"`
	rw.Header().Set("ETag", etag)
	webJSON(rw, 200, map[string]any{"profiles": profiles, "etag": etag})
}
func (w *webConsole) saveProfile(rw http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
	}
	if webDecode(rw, r, &in) != nil || !webProfileName(in.Name) {
		webError(rw, 400, "PROFILE_INVALID")
		return
	}
	files, e := w.profileFiles()
	if e != nil {
		webError(rw, 503, "PROFILE_STORE_UNAVAILABLE")
		return
	}
	p := webProfile{Name: in.Name, YAML: string(files[0].data), ID: strings.Repeat("0", 32), CreatedAt: w.now().UTC().Format(time.RFC3339Nano)}
	if files[1].exists {
		s := string(files[1].data)
		p.Selected = &s
	}
	if files[2].exists {
		s := string(files[2].data)
		p.Subscription = &s
	}
	if webProfileValidate(p, w.configPath) != nil {
		webError(rw, 422, "PROFILE_INVALID")
		return
	}
	for _, f := range files {
		if !webProfileSame(f) {
			webError(rw, 409, "PROFILE_CONFLICT")
			return
		}
	}
	if _, e = w.profileDir(true); e != nil {
		webError(rw, 503, "PROFILE_STORE_UNAVAILABLE")
		return
	}
	if w.publishProfile(&p) != nil {
		webError(rw, 500, "PROFILE_SAVE_FAILED")
		return
	}
	webJSON(rw, 200, map[string]any{"ok": true, "id": p.ID, "name": p.Name, "created_at": p.CreatedAt})
}
func (w *webConsole) copyProfile(rw http.ResponseWriter, r *http.Request) {
	var in struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if webDecode(rw, r, &in) != nil || !webProfileID.MatchString(in.ID) || !webProfileName(in.Name) {
		webError(rw, 400, "PROFILE_INVALID")
		return
	}
	p, source, e := w.readProfile(in.ID)
	if e != nil {
		webProfileReadError(rw, e)
		return
	}
	p.Name = in.Name
	if !webProfileSame(source) {
		webError(rw, 409, "PROFILE_CONFLICT")
		return
	}
	if w.publishProfile(&p) != nil {
		webError(rw, 500, "PROFILE_SAVE_FAILED")
		return
	}
	webJSON(rw, 200, map[string]any{"ok": true, "id": p.ID, "name": p.Name, "created_at": p.CreatedAt})
}
func webProfileReadError(rw http.ResponseWriter, e error) {
	if errors.Is(e, os.ErrNotExist) {
		webError(rw, 404, "PROFILE_NOT_FOUND")
	} else {
		webError(rw, 503, "PROFILE_STORE_UNAVAILABLE")
	}
}
func webProfileWriteFile(f webProfileFile, write func(string, []byte) error) error {
	if f.exists {
		return write(f.path, f.data)
	}
	// The path is generated internally, never supplied by the request.
	existing, e := webProfileCapture(f.path, webProfileLimit, true, false)
	if e != nil {
		return e
	}
	if !existing.exists {
		return nil
	}
	return os.Remove(f.path)
}
func (w *webConsole) commitProfile(p webProfile, source webProfileFile, old []webProfileFile, write func(string, []byte) error) string {
	target := webProfilePayload(p, w.configPath)
	if !webProfileSame(source) {
		return "PROFILE_CONFLICT"
	}
	for _, f := range old {
		if !webProfileSame(f) {
			return "PROFILE_CONFLICT"
		}
	}
	if webProfileEqual(old, target) {
		return ""
	}
	backupRoot := filepath.Join(filepath.Dir(w.configPath), "import-backups")
	if st, e := os.Lstat(backupRoot); e == nil && (!st.IsDir() || !webProfileOwned(st)) {
		return "PROFILE_STORE_UNAVAILABLE"
	}
	backup := make([]webImportFile, len(old))
	for i, f := range old {
		backup[i] = f.webImportFile
	}
	if webImportBackup(backup, w.configPath) != nil {
		return "PROFILE_SAVE_FAILED"
	}
	if !webProfileSame(source) {
		return "PROFILE_CONFLICT"
	}
	for _, f := range old {
		if !webProfileSame(f) {
			return "PROFILE_CONFLICT"
		}
	}
	failed := false
	for i, f := range target {
		if !webProfileEqual(old[i:i+1], target[i:i+1]) {
			if webProfileWriteFile(f, write) != nil {
				failed = true
				break
			}
		}
	}
	if !failed {
		for _, f := range target {
			if !webProfileSame(f) {
				failed = true
				break
			}
		}
	}
	if !failed {
		return ""
	}
	// Any partial transaction invalidates previews, even if rollback succeeds.
	w.importPending = nil
	restored := true
	for _, f := range old {
		if webProfileWriteFile(f, write) != nil {
			restored = false
		}
	}
	for _, f := range old {
		f.info = nil // Rollback intentionally publishes replacement inodes.
		if !webProfileSame(f) {
			restored = false
		}
	}
	if restored {
		return "PROFILE_SWITCH_FAILED_ROLLED_BACK"
	}
	return "PROFILE_STATE_UNCERTAIN"
}
func (w *webConsole) switchProfile(rw http.ResponseWriter, r *http.Request) {
	var in struct {
		ID              string `json:"id"`
		ConfirmInsecure bool   `json:"confirm_insecure"`
		ConfirmReplace  bool   `json:"confirm_replace"`
	}
	if webDecode(rw, r, &in) != nil || !webProfileID.MatchString(in.ID) || !in.ConfirmReplace || !in.ConfirmInsecure {
		webError(rw, 400, "PROFILE_INVALID")
		return
	}
	if r.Header.Get("If-Match") == "" {
		webError(rw, 428, "IF_MATCH_REQUIRED")
		return
	}
	p, source, e := w.readProfile(in.ID)
	if e != nil {
		webProfileReadError(rw, e)
		return
	}
	old, e := w.profileFiles()
	if e != nil {
		webError(rw, 503, "PROFILE_STORE_UNAVAILABLE")
		return
	}
	if r.Header.Get("If-Match") != `"`+shaHex(old[0].data)+`"` {
		webError(rw, 412, "PROFILE_CONFLICT")
		return
	}
	if webProfileValidate(p, w.configPath) != nil {
		webError(rw, 422, "PROFILE_INVALID")
		return
	}
	code := w.commitProfile(p, source, old, webAtomicWrite)
	if code != "" {
		status := 500
		if code == "PROFILE_CONFLICT" {
			status = 412
		}
		if code == "PROFILE_STORE_UNAVAILABLE" {
			status = 503
		}
		webError(rw, status, code)
		return
	}
	w.importPending = nil
	target := webProfilePayload(p, w.configPath)
	changed := !webProfileEqual(old[:2], target[:2])
	w.finishConfigSave(rw, r, changed, `"`+shaHex([]byte(p.YAML))+`"`, in.ConfirmInsecure)
}

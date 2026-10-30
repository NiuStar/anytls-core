package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestWebAgentExactLaunchdIdentity(t *testing.T) {
	s := webAgentSpec{"/Users/example/app/anytls", "/Users/example/app/config.yaml", "/Users/example", "192.168.1.3", 18889, 501}
	text := s.target() + " = {\n\tpath = " + s.path() + "\n\tprogram = " + s.Binary + "\n\targuments = {\n"
	for _, a := range s.argv() {
		text += "\t\t" + a + "\n"
	}
	text += "\t}\n\tpid = 123\n\ttype = LaunchAgent\n\tstate = running\n\tdomain = gui/501 [100020]\n\tproperties = keepalive | runatload | inferred program\n}\n"
	if err := webAgentJobMatches(text, s, 123); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{strings.Replace(text, "\tpid = 123", "\tpid = 1234", 1), strings.Replace(text, "\tpid = 123", "\t\tpid = 123", 1), strings.Replace(text, "\tprogram = "+s.Binary, "\tprogram = /foreign", 1), strings.Replace(text, "\t\t192.168.1.3", "\t\t127.0.0.1", 1), text + "\tpid = 123\n", strings.Replace(text, s.path(), s.path()+".foreign", 1)} {
		if webAgentJobMatches(bad, s, 123) == nil {
			t.Fatalf("accepted untrusted job: %q", bad)
		}
	}
	s2 := s
	s2.Config = "/Users/example/other/config.yaml"
	if s.label() == s2.label() {
		t.Fatal("label not app scoped")
	}
}
func TestWebAgentSecureRefusesSymlinksAndWritableFiles(t *testing.T) {
	// macOS TempDir has /var -> /private/var; resolve it before checking.
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "file")
	if err = os.WriteFile(p, []byte("a"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = webAgentSecure(p, os.Getuid(), false); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(p, 0622); err != nil {
		t.Fatal(err)
	}
	if webAgentSecure(p, os.Getuid(), false) == nil {
		t.Fatal("accepted writable file")
	}
	os.Chmod(p, 0600)
	link := filepath.Join(dir, "link")
	os.Symlink(p, link)
	if webAgentSecure(link, os.Getuid(), false) == nil {
		t.Fatal("accepted symlink")
	}
}
func TestWebAgentDrainTimeoutRetainsActiveHandler(t *testing.T) {
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	d := &webAgentDrain{handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { close(entered); <-release })}
	go func() { d.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil)); close(done) }()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if d.drain(ctx) {
		t.Fatal("active handler declared drained")
	}
	r := httptest.NewRecorder()
	d.ServeHTTP(r, httptest.NewRequest("POST", "/", nil))
	if r.Code != 409 {
		t.Fatal("new work admitted")
	}
	close(release)
	<-done
	if !d.drain(context.Background()) {
		t.Fatal("finished handler not drained")
	}
}
func TestWebAgentPlistPreservesLiteralArguments(t *testing.T) {
	s := webAgentSpec{"/Users/a & b/app/anytls", "/Users/a & b/app/config.yaml", "/Users/a & b", "0.0.0.0", 18889, 501}
	b := s.plist()
	if bytes.Contains(b, []byte("a & b")) || !bytes.Contains(b, []byte("a &amp; b")) || !bytes.Contains(b, []byte("<key>KeepAlive</key><true/>")) {
		t.Fatal(string(b))
	}
	if len(s.argv()) != 8 || s.argv()[3] != "0.0.0.0" || s.argv()[5] != strconv.Itoa(s.Port) {
		t.Fatal(fmt.Sprint(s.argv()))
	}
}

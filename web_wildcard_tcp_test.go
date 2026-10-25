package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestWebWildcardHostSyntax(t *testing.T) {
	w, _ := webFixture(t)
	w.listenHost = "0.0.0.0"
	for _, host := range []string{"", ":18089", "example.com", "example.com:18090", "example.com:018089", "user@example.com:18089", "example.com.:18089/path", "a b:18089", "-bad.example:18089", "a..b:18089", "[example.com]:18089", "[127.0.0.1]:18089", "example.com:18089:18089", "example.com:18089\r\n", "http://example.com:18089"} {
		t.Run(host, func(t *testing.T) {
			r := httptest.NewRequest("GET", "http://127.0.0.1:18089/", nil)
			r.Host = host
			r.Header.Set("X-Forwarded-Host", "localhost:18089")
			rec := httptest.NewRecorder()
			w.ServeHTTP(rec, r)
			if rec.Code != 403 || !strings.Contains(rec.Body.String(), "INVALID_HOST") {
				t.Fatal("invalid Host accepted", rec.Code, rec.Body.String())
			}
		})
	}
}

// Real IPv4 wildcard listener, concrete loopback connection and DNS Host:
// neither DNS resolution nor a per-machine allowlist is involved.
func TestWebWildcardTCPAuthenticated(t *testing.T) {
	w, password := webFixture(t)
	listener, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	w.listenHost, w.port = "0.0.0.0", listener.Addr().(*net.TCPAddr).Port
	s := httptest.NewUnstartedServer(w)
	s.Listener.Close()
	s.Listener = listener
	s.Start()
	defer s.Close()
	client := s.Client()
	base := "http://127.0.0.1:" + strconv.Itoa(w.port)
	host := fmt.Sprintf("server.example:%d", w.port)
	body, _ := json.Marshal(map[string]string{"username": "admin", "password": password})
	r, _ := http.NewRequest("POST", base+"/api/v1/login", bytes.NewReader(body))
	r.Host = host
	r.Header.Set("Origin", "http://"+host)
	r.Header.Set("Content-Type", "application/json")
	login, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer login.Body.Close()
	if login.StatusCode != 200 {
		t.Fatal("login", login.StatusCode)
	}
	cookies := login.Cookies()
	if len(cookies) != 1 {
		t.Fatal("cookie", cookies)
	}
	r, _ = http.NewRequest("GET", base+"/api/v1/status", nil)
	r.Host = host
	r.AddCookie(cookies[0])
	status, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer status.Body.Close()
	data, err := io.ReadAll(status.Body)
	if err != nil || status.StatusCode != 200 || !bytes.Contains(data, []byte(`"transport":"network-http"`)) {
		t.Fatal(status.StatusCode, string(data), err)
	}
}

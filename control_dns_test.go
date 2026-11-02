package main

import (
	"context"
	"errors"
	de "github.com/NiuStar/anytls-core/internal/dnsevidence"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDNSRuntimeUnixHTTP(t *testing.T) { dnsRuntimeUnixHTTP(t, nil) }
func dnsRuntimeUnixHTTP(t *testing.T, producer *de.Collector) {
	w, password := webFixture(t)
	cookie, _ := webLogin(t, w, password)
	identity, _ := controlHelperConfigIdentity(w.configPath)
	root := filepath.Join(filepath.Dir(w.configPath), "service")
	if e := os.Mkdir(root, 0700); e != nil {
		t.Fatal(e)
	}
	staged := filepath.Join(root, "config.yaml")
	raw, e := os.ReadFile(w.configPath)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(staged, raw, 0600); e != nil {
		t.Fatal(e)
	}
	stagedIdentity, _ := controlHelperConfigIdentity(staged)
	if identity == stagedIdentity {
		t.Fatal("source and stage must be independent")
	}
	s := &controlHelperServer{registration: controlHelperRegistration{UID: 501, Config: w.configPath}}
	// UNIT-SIMULATED root/kernel authority. Real Unix framing and HTTP authentication.
	var peerUID atomic.Uint32
	s.peer = func(net.Conn) (uint32, error) { return peerUID.Load(), nil }
	s.startupRegistration = func() (controlHelperRegistration, error) { return s.registration, nil }
	var authCalls atomic.Int32
	s.startupAuthenticate = func(net.Conn, *startupBinding) bool { authCalls.Add(1); return true }
	epoch, operation := strings.Repeat("e", 32), strings.Repeat("f", 32)
	s.dnsBind(&startupBinding{}, epoch, operation, identity)
	// The real engine producer may predate this fixture's simulated bind.
	s.dns.boundAt = time.Now().Add(-time.Minute)
	b := de.Binding{InstanceID: strings.Repeat("a", 32), Generation: strings.Repeat("b", 32), ManifestID: strings.Repeat("c", 64), RuntimeSHA256: strings.Repeat("d", 64)}
	collector := de.New(b)
	collector.Loaded()
	if producer != nil {
		collector = producer
		b = producer.Binding()
	}
	path := filepath.Join(t.TempDir(), "d.sock")
	listener, e := net.Listen("unix", path)
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			go s.handle(c)
		}
	}()
	defer func() { listener.Close(); <-done }()
	push := func(q de.Push) de.Ack {
		c, e := net.Dial("unix", path)
		if e != nil {
			t.Fatal(e)
		}
		defer c.Close()
		var ack de.Ack
		if e = dnsExchange(context.Background(), c, q, &ack, func(net.Conn) (uint32, error) { return 0, nil }); e != nil {
			t.Fatal(e)
		}
		return ack
	}
	ctx := withDNSObservation(context.Background(), operation, epoch)
	ctx = context.WithValue(ctx, dnsReporterAuthorityKey{}, dnsReporterAuthority{
		registration: func() (controlHelperRegistration, error) { return s.registration, nil },
		protected: func(p string, dir bool) error {
			if p != staged && !(dir && p == filepath.Dir(staged)) {
				return errors.New("wrong snapshot")
			}
			return nil
		}, // UNIT-SIMULATED root ownership only.
	})
	delivered := make(chan de.Push, 1)
	stop := launchDNSReporter(ctx, collector, staged, func(_ context.Context, q de.Push) error {
		ack := push(q)
		if ack.Code != "OK" {
			return errors.New(ack.Code)
		}
		select {
		case delivered <- q:
		default:
		}
		return nil
	})
	var q de.Push
	select {
	case q = <-delivered:
	case <-time.After(2500 * time.Millisecond):
		stop()
		t.Fatal("actual reporter -> Unix helper did not admit source/staged run")
	}
	stop()
	if q.ConfigIdentity != identity || authCalls.Load() != 2 {
		t.Fatal("reporter identity/composite authority mismatch")
	}
	wrong := q
	wrong.Snapshot.Revision = "18446744073709551615"
	if a := push(wrong); a.Code != "IDENTITY_MISMATCH" {
		t.Fatal("future revision accepted")
	}
	wrong = q
	wrong.Snapshot.ElapsedNS = "18446744073709551615"
	if a := push(wrong); a.Code != "IDENTITY_MISMATCH" {
		t.Fatal("future elapsed accepted")
	}
	wrong = q
	wrong.ConfigIdentity = stagedIdentity
	if a := push(wrong); a.Code != "IDENTITY_MISMATCH" {
		t.Fatal("stage accepted as registration namespace")
	}
	if a := push(q); a.Code != "IDENTITY_MISMATCH" {
		t.Fatal("replay accepted")
	}
	q.Snapshot = collector.Snapshot()
	q.Binding.Generation = strings.Repeat("9", 32)
	if a := push(q); a.Code != "IDENTITY_MISMATCH" {
		t.Fatal("run rewrite")
	}
	peerUID.Store(501)
	w.dnsRequest = func(ctx context.Context, q de.Read) (de.Response, error) {
		c, e := net.Dial("unix", path)
		if e != nil {
			return de.Response{}, e
		}
		defer c.Close()
		var r de.Response
		e = dnsExchange(ctx, c, q, &r, func(net.Conn) (uint32, error) { return 0, nil })
		return r, e
	}
	request := func(query string, change func(*http.Request)) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "http://127.0.0.1:18089/api/v1/dns-runtime"+query, nil)
		r.AddCookie(cookie)
		r.Header.Set("X-AnyTLS-Origin", "http://"+r.Host)
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		if change != nil {
			change(r)
		}
		rec := httptest.NewRecorder()
		w.ServeHTTP(rec, r)
		return rec
	}
	rec := request("", nil)
	var response de.Response
	if rec.Code != 200 || de.Decode(rec.Body.Bytes(), &response) != nil || response.Snapshot != nil || response.Binding == nil {
		t.Fatalf("discovery %d %s", rec.Code, rec.Body.String())
	}
	query := "?instance_id=" + b.InstanceID + "&generation=" + b.Generation + "&manifest_id=" + b.ManifestID
	w.actionMu.Lock()
	rec = request(query, nil)
	w.actionMu.Unlock()
	if rec.Code != 200 || de.Decode(rec.Body.Bytes(), &response) != nil || response.Snapshot == nil || response.Snapshot.State != "LOADED" {
		t.Fatalf("bound %d %s", rec.Code, rec.Body.String())
	}
	for _, x := range []struct {
		query  string
		status int
		change func(*http.Request)
	}{{"?" + strings.Repeat("k=v&", de.ReadBytes), 400, nil}, {"?generation=x", 400, nil}, {query + "&generation=x", 400, nil}, {"?unknown=1", 400, nil}, {query, 403, func(r *http.Request) { r.Header.Del("X-AnyTLS-Origin") }}, {query, 401, func(r *http.Request) { r.Header.Del("Cookie") }}} {
		if got := request(x.query, x.change); got.Code != x.status {
			t.Fatalf("negative %d want %d", got.Code, x.status)
		}
	}
	if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("headers")
	}
	old := s.dns.received
	s.dns.received = time.Now().Add(-3 * time.Second)
	if r := s.dnsRead(de.Read{DNSSchema: 1, Action: "dns.read", InstanceID: &b.InstanceID, Generation: &b.Generation, ManifestID: &b.ManifestID}); r.Availability != "STALE" {
		t.Fatal("freshness")
	}
	s.dns.received = old
	s.dnsInvalidate()
	if r := s.dnsRead(de.Read{DNSSchema: 1, Action: "dns.read"}); r.Code != "UNAVAILABLE" {
		t.Fatal("adopted invalidated run")
	}
}

//go:build with_utls

package engine

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/service"
)

func TestLiveDNSDoubleExitHeldQuery(t *testing.T) {
	var ac, bc atomic.Int64
	reached := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	server := func(answer string, count *atomic.Int64, hold bool) *httptest.Server {
		s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			count.Add(1)
			b, _ := io.ReadAll(r.Body)
			q := new(dns.Msg)
			if q.Unpack(b) != nil {
				w.WriteHeader(400)
				return
			}
			if hold && q.Question[0].Name == "held.fixture.invalid." {
				once.Do(func() { close(reached) })
				<-release
			}
			reply := new(dns.Msg).SetReply(q)
			rr, _ := dns.NewRR(q.Question[0].Name + " 300 IN A " + answer)
			reply.Answer = []dns.RR{rr}
			raw, _ := reply.Pack()
			w.Header().Set("Content-Type", "application/dns-message")
			w.Write(raw)
		}))
		t.Cleanup(s.Close)
		return s
	}
	sa, sb := server("192.0.2.1", &ac, true), server("192.0.2.2", &bc, false)
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	a, b := g13New(t), g13New(t)
	// Same literal DNS destination and same domain; the actual authenticated
	// AnyTLS exit determines which fixture HTTPS server receives the query.
	a.dnsTargets = map[string]string{"127.0.0.1:44444": sa.Listener.Addr().String()}
	b.dnsTargets = map[string]string{"127.0.0.1:44444": sb.Listener.Addr().String()}
	var cfg, other map[string]any
	json.Unmarshal(a.config(freeLoopbackPort(t), nil), &cfg)
	json.Unmarshal(b.config(0, nil), &other)
	oa := cfg["outbounds"].([]any)[0].(map[string]any)
	oa["tag"] = "a"
	ob := other["outbounds"].([]any)[0].(map[string]any)
	ob["tag"] = "b"
	cfg["outbounds"] = []any{oa, ob, map[string]any{"type": LiveSelectionType, "tag": "live", "outbounds": []string{"a", "b"}, "default": "a"}}
	cfg["route"] = map[string]any{"final": "live"}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: sa.Certificate().Raw})
	cfg["dns"] = map[string]any{"servers": []any{map[string]any{"type": "https", "tag": "doh", "server": "127.0.0.1", "server_port": 44444, "detour": "live", "tls": map[string]any{"enabled": true, "certificate": []string{string(cert)}}}}, "final": "doh"}
	raw, _ := json.Marshal(cfg)
	live := NewLiveSelection()
	parent, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ctx := context.WithValue(parent, liveKey{}, live)
	ctx, opts, e := decodeOptions(ctx, raw)
	if e != nil {
		t.Fatal(e)
	}
	// RunControlled installs the same owned registry; obtain its real router through
	// a context registry that is populated by Box.New.
	_ = opts
	done := make(chan error, 1)
	go func() { done <- RunControlled(ctx, raw, nil, live) }()
	defer func() { cancel(); awaitRun(t, done) }()
	for !live.Snapshot().Ready {
		select {
		case <-parent.Done():
			t.Fatal("not ready")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	// The Run registry is freshly owned: exercise the real router via its live
	// owner seam rather than accidentally querying the unused decode registry.
	router := live.dnsRouter
	if router == nil {
		t.Fatal("DNS router unavailable")
	}
	query := func(name, want string) error {
		q := new(dns.Msg).SetQuestion(name, dns.TypeA)
		r, e := router.Exchange(parent, q, adapter.DNSQueryOptions{})
		if e != nil {
			return e
		}
		if len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != want {
			return &net.DNSError{Err: "wrong exit answer"}
		}
		return nil
	}
	if e = query("same.fixture.invalid.", "192.0.2.1"); e != nil {
		t.Fatal(e)
	}
	if e = query("same.fixture.invalid.", "192.0.2.1"); e != nil {
		t.Fatal(e)
	}
	if ac.Load() != 1 {
		t.Fatalf("cache regression before switch requests=%d", ac.Load())
	}
	old := make(chan error, 1)
	go func() { old <- query("held.fixture.invalid.", "192.0.2.1") }()
	select {
	case <-reached:
	case <-parent.Done():
		t.Fatal("held query not reached")
	}
	snap := live.Snapshot()
	if e = live.Switch(snap.Generation, snap.Revision, "b"); e != nil {
		t.Fatal(e)
	}
	if e = query("same.fixture.invalid.", "192.0.2.2"); e != nil {
		t.Fatal(e)
	}
	close(release)
	<-old // Reset may fail the old exchange; never let it mint new cache.
	if e = query("held.fixture.invalid.", "192.0.2.2"); e != nil {
		t.Fatal(e)
	}
	if e = query("same.fixture.invalid.", "192.0.2.2"); e != nil {
		t.Fatal(e)
	}
	if ac.Load() != 2 || bc.Load() != 2 {
		t.Fatalf("cross-exit cache/pool leak a=%d b=%d", ac.Load(), bc.Load())
	}
	t.Logf("same-domain cached A=1 before switch; held A=1; new B=2; post-switch cache retained")
	_ = service.FromContext[adapter.DNSRouter](ctx)
}

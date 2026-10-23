package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	cr "github.com/NiuStar/anytls-core/internal/connectionrecords"
)

// Private real Unix EOF exchange, with explicit simulated root-peer credentials;
// never connects to the installed helper or invokes a lifecycle operation.
func qb01RawExchange(t *testing.T, raw []byte, q cr.PageRequest) (cr.PageResponse, error) {
	t.Helper()
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(unitControlSocketDir(t), "q.sock"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, e := l.AcceptUnix()
		if e != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		io.Copy(io.Discard, c)
		c.Write(raw)
	}()
	c, err := net.DialUnix("unix", nil, l.Addr().(*net.UnixAddr))
	if err != nil {
		t.Fatal(err)
	}
	page, err := controlHelperRecordsExchange(context.Background(), c, q, func(net.Conn) (uint32, error) { return 0, nil })
	c.Close()
	select {
	case <-done:
	case <-time.After(4 * time.Second):
		t.Fatal("private responder not joined")
	}
	return page, err
}
func TestQB01HelperAndAuthenticatedHTTP(t *testing.T) {
	w, password := webFixture(t)
	cookie, _ := webLogin(t, w, password)
	identity, err := controlHelperConfigIdentity(w.configPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"unknown_positive", "closed_positive", "lost_total", "reason", "saturated", "unclosed_continuity"} {
		t.Run(name, func(t *testing.T) {
			p := recordsTestPage(identity)
			p.Collection = cr.Recording
			p.Freshness = cr.Fresh
			p.Coverage.Gap = false
			one := cr.Decimal("1")
			switch name {
			case "closed_positive":
				p.Collection = cr.Closed
				p.Closed = true
				p.Coverage.Continuity = cr.ContinuityClosed
			case "lost_total":
				p.Coverage.LostTotal = &one
			case "reason":
				p.Coverage.LossReasons.IOFailed = &one
			case "saturated":
				p.Coverage.CounterSaturated = true
			case "unclosed_continuity":
				p.Coverage.Continuity = cr.ContinuityClosed
			}
			raw, e := json.Marshal(p)
			if e != nil {
				t.Fatal(e)
			}
			positive := name == "unknown_positive" || name == "closed_positive"
			q := cr.PageRequest{SchemaVersion: 1, After: "0", Limit: 100}
			got, e := qb01RawExchange(t, raw, q)
			if positive {
				if e != nil || !reflect.DeepEqual(got, p) {
					t.Fatal("positive exchange", e)
				}
			} else if e != cr.TelemetryUnavailable || !reflect.DeepEqual(got, cr.PageResponse{}) {
				t.Errorf("QB01 invalid helper page accepted or partially returned: %v", e)
			}
			w.recordsRequest = func(_ context.Context, q cr.PageRequest) (cr.PageResponse, error) { return qb01RawExchange(t, raw, q) }
			response := recordsHTTPRequest(w, cookie, "", nil)
			if positive {
				if response.Code != 200 {
					t.Fatal("positive HTTP", response.Code)
				}
			} else if response.Code == 200 {
				t.Error("QB01 invalid cross-field page escaped authenticated ServeHTTP")
			}
		})
	}
}

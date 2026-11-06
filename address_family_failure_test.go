//go:build embedded_core && with_utls

package main

import (
	"context"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/protocol/socks"
)

// Default IPv4 policy must not weaken strict DoH or manufacture A answers.
// AAAA is local NOERROR/NODATA, including during strict upstream failures.
func TestIPv4InitialDNSStrictFailure(t *testing.T) {
	for _, failure := range []string{"http503", "doh_ca", "doh_san", "disconnect", "password", "node_ca"} {
		t.Run(failure, func(t *testing.T) {
			f := unifiedDNSStartPolicy(t, "DOMAIN,unused.invalid,DIRECT\n - MATCH,business", failure, "")
			for _, network := range []string{"tcp", "udp"} {
				f.exchange(t, network, f.traps[0].tcp.Addr().String(), dns.TypeA, false)
				question := unifiedDNSQuery()
				question.Question[0].Qtype = dns.TypeAAAA
				client := socks.NewClient(recordsSOCKSDialer{}, M.ParseSocksaddr(f.addr), socks.Version5, "", "")
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				c, err := client.DialContext(ctx, network, M.ParseSocksaddr(f.traps[0].tcp.Addr().String()))
				if err != nil {
					t.Fatal(err)
				}
				c.SetDeadline(time.Now().Add(2 * time.Second))
				var answer *dns.Msg
				if network == "tcp" {
					dc := &dns.Conn{Conn: c}
					err = dc.WriteMsg(question)
					if err == nil {
						answer, err = dc.ReadMsg()
					}
				} else {
					wire, _ := question.Pack()
					_, err = c.Write(wire)
					if err == nil {
						b := make([]byte, 65535)
						var n int
						var from net.Addr
						n, from, err = c.(net.PacketConn).ReadFrom(b)
						if err == nil {
							if from.String() != f.traps[0].tcp.Addr().String() {
								t.Error("redirected reply")
							}
							answer = new(dns.Msg)
							err = answer.Unpack(b[:n])
						}
					}
				}
				c.Close()
				if err != nil || answer == nil || !answer.Response || answer.Id != question.Id || answer.Rcode != dns.RcodeSuccess || !reflect.DeepEqual(answer.Question, question.Question) || len(answer.Answer) != 0 {
					t.Fatalf("AAAA must be NOERROR/NODATA, never REFUSED/leaked: %v %v", answer, err)
				}
			}
			f.verify(t, false)
			f.mu.Lock()
			defer f.mu.Unlock()
			for key := range f.questions {
				if strings.HasSuffix(key, "/28") {
					t.Fatal("AAAA leaked upstream")
				}
			}
		})
	}
}

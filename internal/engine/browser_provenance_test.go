package engine

import (
 "context"
 "net/netip"
 "testing"
 "time"

 "github.com/miekg/dns"
 "github.com/sagernet/sing-box/adapter"
 M "github.com/sagernet/sing/common/metadata"
 "github.com/sagernet/sing/service"
)

type browserFixtureTransport struct { adapter.DNSTransport }
func (*browserFixtureTransport) Tag() string { return "secure" }
type browserFixtureResolver struct { adapter.DNSRouter; calls int; loseOriginal bool }
func (r *browserFixtureResolver) Exchange(ctx context.Context,q *dns.Msg,options adapter.DNSQueryOptions)(*dns.Msg,error) {
 r.calls++
 if options.Transport==nil || !options.DisableCache || !options.DisableOptimisticCache || ctx.Value(browserRefreshKey{})==nil {panic("refresh escaped owned secure context")}
 value:="192.0.2.1";if q.Question[0].Qtype==dns.TypeAAAA {value="2001:db8::1";if r.loseOriginal {value="2001:db8::2"}}
 _,answer:=browserAnswer(q.Question[0].Name,q.Question[0].Qtype,value,30);answer.Id=q.Id
 operation:=ctx.Value(browserRefreshKey{}).(*browserRefresh)
 operation.owner.ObserveBrowserDNS(ctx,q,answer,options.Transport)
 return answer,nil
}

func TestBrowserCandidateActualRulesOwnedRefreshAndLaunchExpiry(t *testing.T) {
 raw:=[]byte(`{"outbounds":[{"type":"direct","tag":"P"}],"dns":{"servers":[{"type":"https","tag":"secure","server":"127.0.0.1","server_port":9}]},"route":{"rules":[{"domain":["a.test"],"outbound":"P"}],"final":"P"}}`)
 instance:=recordsBox(t,raw)
 now:=time.Unix(100,0);s:=newBrowserProvenance();s.now=func()time.Time{return now};s.static=browserStaticPolicy(raw)
 transport:=&browserFixtureTransport{};s.trust(transport)
 resolver:=&browserFixtureResolver{}
 ctx:=service.ContextWithRegistry(context.Background(),service.NewRegistry())
 ctx=service.ContextWith[adapter.DNSRouter](ctx,resolver)
 ctx=service.ContextWith[adapter.OutboundManager](ctx,instance.Outbound())
 m:=adapter.InboundContext{Inbound:"tun",Source:M.Socksaddr{Addr:netip.MustParseAddr("192.0.2.10")},Network:"tcp",Domain:"a.test",IPVersion:6,Destination:M.Socksaddr{Addr:netip.MustParseAddr("2001:db8::1"),Port:443}}
 scope,_:=browserScope(m);q,r:=browserAnswer("a.test",dns.TypeAAAA,"2001:db8::1",30);s.observe(scope,"secure",q,r)
 selected:=instance.Router().Rules()[0];outbound:=instance.Outbound().Default()
 prepared:=s.PrepareBrowserCandidate(ctx,instance.Router(),m,selected,0,outbound)
 ticket,ok:=browserAlternate(prepared,outbound)
 if !ok || ticket.Address!=netip.MustParseAddr("192.0.2.1") || resolver.calls!=2 {t.Fatal("certified candidate missing",ok,resolver.calls)}
 now=now.Add(31*time.Second)
 if _,ok:=browserAlternate(prepared,outbound);ok {t.Fatal("expired launch ticket")}
 now=now.Add(time.Second);s.observe(scope,"secure",q,r);resolver.loseOriginal=true
 if _,_,ok:=s.BrowserCandidate(ctx,instance.Router(),m,selected,0,outbound);ok {t.Fatal("new AAAA lost original but issued candidate")}
}

func browserAnswer(name string, kind uint16, value string, ttl uint32) (*dns.Msg, *dns.Msg) {
 q := new(dns.Msg); q.SetQuestion(dns.Fqdn(name), kind)
 r := new(dns.Msg); r.SetReply(q)
 h := dns.RR_Header{Name:dns.Fqdn(name), Rrtype:kind, Class:dns.ClassINET, Ttl:ttl}
 if kind == dns.TypeAAAA { r.Answer=[]dns.RR{&dns.AAAA{Hdr:h, AAAA:netip.MustParseAddr(value).AsSlice()}} } else { r.Answer=[]dns.RR{&dns.A{Hdr:h, A:netip.MustParseAddr(value).AsSlice()}} }
 return q,r
}

func TestBrowserUnregisteredTransportCannotMintReceipt(t *testing.T) {
 s:=newBrowserProvenance()
 m:=adapter.InboundContext{Inbound:"tun",Source:M.Socksaddr{Addr:netip.MustParseAddr("192.0.2.10")}}
 ctx,metadata:=adapter.ExtendContext(context.Background());*metadata=m
 q,r:=browserAnswer("a.test",dns.TypeAAAA,"2001:db8::1",30)
 transport:=&browserFixtureTransport{}
 s.ObserveBrowserDNS(ctx,q,r,transport)
 scope,_:=browserScope(m)
 if _,ok:=s.receipt(scope,netip.MustParseAddr("2001:db8::1"));ok {t.Fatal("unregistered response minted authority")}
 s.trust(transport);s.ObserveBrowserDNS(ctx,q,r,transport)
 if _,ok:=s.receipt(scope,netip.MustParseAddr("2001:db8::1"));!ok {t.Fatal("trusted return seam not recorded")}
}

func TestBrowserReceiptKeepsConflictsAndScope(t *testing.T) {
 now:=time.Unix(100,0)
 s:=newBrowserProvenance(); s.now=func()time.Time{return now}
 m:=adapter.InboundContext{Inbound:"tun", Source:M.Socksaddr{Addr:netip.MustParseAddr("192.0.2.10")}}
 scope,ok:=browserScope(m); if !ok {t.Fatal("scope")}
 q,r:=browserAnswer("a.test",dns.TypeAAAA,"2001:db8::1",30)
 s.observe(scope,"secure",q,r)
 if _,ok:=s.receipt(scope,netip.MustParseAddr("2001:db8::1")); !ok {t.Fatal("missing original receipt")}
 other:=scope; other.source=netip.MustParseAddr("192.0.2.11")
 if _,ok:=s.receipt(other,netip.MustParseAddr("2001:db8::1")); ok {t.Fatal("cross-client receipt")}
 q,r=browserAnswer("b.test",dns.TypeAAAA,"2001:db8::1",10); s.observe(scope,"secure",q,r)
 if _,ok:=s.receipt(scope,netip.MustParseAddr("2001:db8::1")); ok {t.Fatal("shared IP accepted")}
 r.Answer=nil; s.observe(scope,"secure",q,r)
 if _,ok:=s.receipt(scope,netip.MustParseAddr("2001:db8::1")); ok {t.Fatal("negative refresh erased conflict")}
 now=now.Add(11*time.Second)
 if _,ok:=s.receipt(scope,netip.MustParseAddr("2001:db8::1")); !ok {t.Fatal("expired conflict not retired")}
 now=now.Add(20*time.Second)
 if _,ok:=s.receipt(scope,netip.MustParseAddr("2001:db8::1")); ok {t.Fatal("expired receipt accepted")}
}

func TestBrowserCapacityAndInvalidationFailClosed(t *testing.T) {
 s:=newBrowserProvenance(); s.limit=1
 scope:=browserClientScope{inbound:"tun",source:netip.MustParseAddr("192.0.2.10")}
 q,r:=browserAnswer("a.test",dns.TypeAAAA,"2001:db8::1",30); s.observe(scope,"secure",q,r)
 q,r=browserAnswer("b.test",dns.TypeAAAA,"2001:db8::2",30); s.observe(scope,"secure",q,r)
 if _,ok:=s.receipt(scope,netip.MustParseAddr("2001:db8::1")); ok {t.Fatal("overflow restored uniqueness")}
 s=newBrowserProvenance(); s.observe(scope,"secure",q,r); s.InvalidateBrowserDNS()
 if _,ok:=s.receipt(scope,netip.MustParseAddr("2001:db8::2")); ok {t.Fatal("network reset retained authority")}
}

func TestBrowserBundleRequiresOriginalAndSameTerminal(t *testing.T) {
 now:=time.Now()
 q6,r6:=browserAnswer("a.test",dns.TypeAAAA,"2001:db8::1",30)
 q4,r4:=browserAnswer("a.test",dns.TypeA,"192.0.2.1",20)
 six,ok:=browserRRSet(q6,r6,now); if !ok {t.Fatal("AAAA")}
 four,ok:=browserRRSet(q4,r4,now); if !ok {t.Fatal("A")}
 old:=browserReceipt{name:six.name, terminal:six.terminal, ip:six.ips[0], expires:six.expires}
 if !browserBundle(old,six,four,now) {t.Fatal("valid bundle")}
 six.ips=[]netip.Addr{netip.MustParseAddr("2001:db8::2")}
 if browserBundle(old,six,four,now) {t.Fatal("original missing from refreshed AAAA")}
 six.ips=[]netip.Addr{old.ip}; four.terminal="other.test."
 if browserBundle(old,six,four,now) {t.Fatal("CNAME terminal mismatch")}
 if browserBundle(old,six,four,now.Add(time.Minute)) {t.Fatal("expired bundle")}
}

func TestBrowserActualCompiledRulesKeepIdentityAndReject(t *testing.T) {
 raw:=[]byte(`{"outbounds":[{"type":"direct","tag":"P"}],"dns":{"servers":[{"type":"https","tag":"secure","server":"127.0.0.1","server_port":9}]},"route":{"rules":[{"ip_cidr":["192.0.2.0/24"],"action":"reject"},{"domain":["a.test"],"outbound":"P"}],"final":"P"}}`)
 if !browserStaticPolicy(raw) {t.Fatal("fixture not frozen")}
 box:=recordsBox(t,raw)
 m:=adapter.InboundContext{Network:"tcp",Domain:"a.test",IPVersion:6,Destination:M.Socksaddr{Addr:netip.MustParseAddr("2001:db8::1"),Port:443}}
 original:=m
 rule,index,ok:=browserPureMatch(box.Router(),m)
 if !ok || index!=1 || rule!=box.Router().Rules()[1] {t.Fatal("actual DOMAIN rule")}
 m.Destination.Addr=netip.MustParseAddr("192.0.2.1");m.IPVersion=4
 if _,_,ok:=browserPureMatch(box.Router(),m);ok {t.Fatal("actual REJECT bypassed")}
 m=original
 if m.Destination.Addr!=netip.MustParseAddr("2001:db8::1") || m.IPVersion!=6 {t.Fatal("original mutated")}
 sameTag:=[]byte(`{"outbounds":[{"type":"direct","tag":"P"}],"dns":{"servers":[{"type":"https","tag":"secure","server":"127.0.0.1","server_port":9}]},"route":{"rules":[{"ip_version":6,"outbound":"P"},{"ip_version":4,"outbound":"P"}],"final":"P"}}`)
 box2:=recordsBox(t,sameTag)
 a,ai,ok:=browserPureMatch(box2.Router(),original);if !ok {t.Fatal("v6 rule")}
 m=original;m.IPVersion=4;m.Destination.Addr=netip.MustParseAddr("192.0.2.1")
 b,bi,ok:=browserPureMatch(box2.Router(),m);if !ok || a==b || ai==bi {t.Fatal("same outbound erased rule identity")}
}

func TestBrowserPolicyWhitelistFailsClosed(t *testing.T) {
 for _,raw:=range []string{
 `{"route":{"rules":[{"action":"sniff"}]}}`,
 `{"route":{"rules":[{"action":"resolve"}]}}`,
 `{"route":{"rules":[{"ip_cidr":["192.0.2.0/24"],"outbound":"P","override_port":80}]}}`,
 `{"route":{"rules":[{"rule_set":["geoip-cn"],"outbound":"P"}]}}`,
 } { if browserStaticPolicy([]byte(raw)) {t.Fatal("unsupported effect/ruleset accepted",raw)} }
 if !browserStaticPolicy([]byte(`{"route":{"rules":[{"domain":["a.test"],"outbound":"P"},{"ip_cidr":["192.0.2.0/24"],"action":"reject"}]}}`)) {t.Fatal("plain compiled policy rejected")}
 s:=newBrowserProvenance()
 if _,_,ok:=s.BrowserCandidate(context.Background(),nil,adapter.InboundContext{},nil,-1,nil);ok {t.Fatal("unknown became candidate")}
}

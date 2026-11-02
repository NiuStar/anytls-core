package engine

import (
 "context"
 "encoding/json"
 "net/netip"
 "strings"
 "sync"
 "time"

 "github.com/miekg/dns"
 "github.com/sagernet/sing-box/adapter"
 R "github.com/sagernet/sing-box/route/rule"
 M "github.com/sagernet/sing/common/metadata"
 "github.com/sagernet/sing/service"
)

// These aliases must exactly match the anonymous SDK service keys. The SDK
// callback is a trusted return seam, not a caller-controlled 'trusted' boolean.
type browserDNSObserver = interface {
 ObserveBrowserDNS(context.Context, *dns.Msg, *dns.Msg, adapter.DNSTransport)
 InvalidateBrowserDNS()
}
type browserRouteGuard = interface {
 PrepareBrowserCandidate(context.Context, adapter.Router, adapter.InboundContext, adapter.Rule, int, adapter.Outbound) context.Context
}
type browserClientScope struct { inbound string; source netip.Addr }
type browserReceipt struct {
 scope browserClientScope
 name, terminal, transport string
 ip netip.Addr
 expires time.Time
 epoch uint64
}
type browserSet struct { name, terminal string; ips []netip.Addr; expires time.Time }
type browserProvenance struct {
 mu sync.Mutex
 now func() time.Time
 claims []browserReceipt
 secure map[adapter.DNSTransport]struct{}
 blockedUntil time.Time
 epoch uint64
 limit int
 static bool
 refresh chan struct{}
}
type browserRefreshKey struct{}
type browserRefresh struct { owner *browserProvenance; expected adapter.DNSTransport; mu sync.Mutex; verified map[*dns.Msg]*dns.Msg }
type browserCandidateKey struct{}

// BrowserAlternate is a private-context-owned launch ticket. It never changes
// metadata.Destination, source, selected outbound, SNI, or application bytes.
// The coordinator MUST call browserAlternate immediately before CONNECT; it
// MUST NOT interpret this ticket as target ACK/TLS success.
type BrowserAlternate struct {
 Address netip.Addr
 Expires time.Time
 owner *browserProvenance
 receipt browserReceipt
 outbound adapter.Outbound
 rule adapter.Rule
 ruleIndex int
}

func newBrowserProvenance() *browserProvenance {
 return &browserProvenance{now:time.Now, secure:make(map[adapter.DNSTransport]struct{}), limit:512, epoch:1, refresh:make(chan struct{},8)}
}
func installBrowserProvenance(ctx context.Context, raw []byte) context.Context {
 s:=newBrowserProvenance(); s.static=browserStaticPolicy(raw)
 ctx=service.ContextWith[browserDNSObserver](ctx,s)
 return service.ContextWith[browserRouteGuard](ctx,s)
}
func browserScope(m adapter.InboundContext) (browserClientScope,bool) {
 ip:=m.Source.Addr.Unmap()
 return browserClientScope{inbound:m.Inbound,source:ip},m.Inbound!="" && ip.IsValid() && !ip.IsUnspecified()
}
func browserName(s string) string { return strings.ToLower(dns.Fqdn(s)) }

// Strict bounded parser: only a single IN question, linear CNAME chain, and
// the requested address family at its terminal. No HTTPS hints/additional RRs.
// All answer TTLs contribute to the lease, never production TTL rewrites.
func browserRRSet(q,r *dns.Msg, now time.Time) (browserSet,bool) {
 var out browserSet
 if q==nil || r==nil || len(q.Question)!=1 || len(q.Extra)!=0 || len(r.Question)!=1 || !r.Response || r.Id!=q.Id || r.Truncated || r.Rcode!=dns.RcodeSuccess || len(r.Answer)==0 || len(r.Answer)>32 {return out,false}
 question:=q.Question[0]; reply:=r.Question[0]
 if question.Qclass!=dns.ClassINET || reply.Qclass!=question.Qclass || reply.Qtype!=question.Qtype || browserName(reply.Name)!=browserName(question.Name) || (question.Qtype!=dns.TypeA && question.Qtype!=dns.TypeAAAA) {return out,false}
 out.name=browserName(question.Name)
 if len(out.name)>254 {return out,false}
 aliases:=map[string]string{}; ttl:=uint32(1<<32-1)
 for _,rr:=range r.Answer {
  h:=rr.Header(); if h.Class!=dns.ClassINET || h.Ttl==0 || len(browserName(h.Name))>254 {return out,false}
  if c,ok:=rr.(*dns.CNAME);ok && len(browserName(c.Target))>254 {return out,false}
  if h.Ttl<ttl {ttl=h.Ttl}
  switch v:=rr.(type) {
  case *dns.CNAME:
   n:=browserName(h.Name); if _,exists:=aliases[n];exists {return out,false}; aliases[n]=browserName(v.Target)
  case *dns.A: if question.Qtype!=dns.TypeA {return out,false}
  case *dns.AAAA: if question.Qtype!=dns.TypeAAAA {return out,false}
  default: return out,false
  }
 }
 terminal:=out.name; seen:=map[string]bool{}
 for aliases[terminal]!="" {if seen[terminal] || len(seen)>=8 {return out,false}; seen[terminal]=true; terminal=aliases[terminal]}
 if len(seen)!=len(aliases) {return out,false}
 out.terminal=terminal
 for _,rr:=range r.Answer {
  var ip netip.Addr
  switch v:=rr.(type) {
  case *dns.A: ip=M.AddrFromIP(v.A).Unmap()
  case *dns.AAAA: ip=M.AddrFromIP(v.AAAA)
  default: continue
  }
  if browserName(rr.Header().Name)!=terminal || !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() || (question.Qtype==dns.TypeA && !ip.Is4()) || (question.Qtype==dns.TypeAAAA && (!ip.Is6() || ip.Is4In6())) {return out,false}
  out.ips=append(out.ips,ip)
 }
 out.expires=now.Add(time.Duration(ttl)*time.Second)
 return out,len(out.ips)>0
}
func (s *browserProvenance) trust(t adapter.DNSTransport) {
 s.mu.Lock(); defer s.mu.Unlock()
 // The run has a finite configured transport set. Fail closed above the cap.
 if len(s.secure)<32 {s.secure[t]=struct{}{}}
}
func (s *browserProvenance) ObserveBrowserDNS(ctx context.Context,q,r *dns.Msg,t adapter.DNSTransport) {
 if refresh,ok:=ctx.Value(browserRefreshKey{}).(*browserRefresh);ok {
  if refresh.owner==s && refresh.expected==t && q!=nil && r!=nil {
   s.mu.Lock();_,trusted:=s.secure[t];s.mu.Unlock()
   if trusted {refresh.mu.Lock();if len(refresh.verified)<2 {refresh.verified[q]=r};refresh.mu.Unlock()}
  }
  return
 }
 metadata:=adapter.ContextFrom(ctx); if metadata==nil {return}
 scope,ok:=browserScope(*metadata); if !ok {return}
 s.mu.Lock(); _,secure:=s.secure[t]; s.mu.Unlock()
 if !secure || q==nil || len(q.Question)!=1 || q.Question[0].Qtype!=dns.TypeAAAA {return}
 s.observe(scope,t.Tag(),q,r)
}
func (s *browserProvenance) observe(scope browserClientScope, transport string,q,r *dns.Msg) {
 s.mu.Lock(); defer s.mu.Unlock()
 now:=s.now(); set,ok:=browserRRSet(q,r,now); if !ok {return}
 s.prune(now)
 if now.Before(s.blockedUntil) && set.expires.After(s.blockedUntil) {s.blockedUntil=set.expires}
 for _,ip:=range set.ips {
  found:=false
  for i:=range s.claims {
   c:=&s.claims[i]
   if c.scope==scope && c.ip==ip && c.name==set.name && c.terminal==set.terminal && c.transport==transport {
    if set.expires.After(c.expires) {c.expires=set.expires};found=true;break
   }
  }
  if found {continue}
  if len(s.claims)>=s.limit {
   // Never LRU-forget a conflict. A single bounded global quarantine covers
   // every retained/refused lease; traffic may extend it, never shorten it.
   if set.expires.After(s.blockedUntil) {s.blockedUntil=set.expires}
   for _,c:=range s.claims {if c.expires.After(s.blockedUntil) {s.blockedUntil=c.expires}}
   continue
  }
  s.claims=append(s.claims,browserReceipt{scope:scope,name:set.name,terminal:set.terminal,transport:transport,ip:ip,expires:set.expires,epoch:s.epoch})
 }
}
func (s *browserProvenance) prune(now time.Time) {
 n:=0;for _,c:=range s.claims {if now.Before(c.expires) {s.claims[n]=c;n++}}
 clear(s.claims[n:]);s.claims=s.claims[:n]
}
func (s *browserProvenance) receipt(scope browserClientScope,ip netip.Addr) (browserReceipt,bool) {
 s.mu.Lock();defer s.mu.Unlock();now:=s.now();s.prune(now)
 if now.Before(s.blockedUntil) {return browserReceipt{},false}
 var result browserReceipt;found:=false
 for _,c:=range s.claims {
  if c.scope!=scope || c.ip!=ip {continue}
  if found && (result.name!=c.name || result.terminal!=c.terminal || result.transport!=c.transport) {return browserReceipt{},false}
  result=c;found=true
 }
 return result,found
}
func (s *browserProvenance) InvalidateBrowserDNS() {
 s.mu.Lock();defer s.mu.Unlock();clear(s.claims);s.claims=nil;s.epoch++
 // Keep quarantine through its full original horizon; invalidation must not
 // erase conflicts and accidentally rehabilitate an in-flight old ticket.
}
func browserBundle(old browserReceipt,six,four browserSet,now time.Time) bool {
 if !now.Before(old.expires) || !now.Before(six.expires) || !now.Before(four.expires) || old.name!=six.name || old.name!=four.name || old.terminal!=six.terminal || old.terminal!=four.terminal || len(four.ips)==0 {return false}
 for _,ip:=range six.ips {if ip==old.ip {return true}}
 return false
}

// Whitelist freezes the supported policy surface before the real SDK compiles
// it. Matching is then done on those actual compiled rules, not a second policy
// model. Any effectful action, process lookup, rule-set/reload or unknown field
// disables this seam for the run. GEOIP rule-set needs an immutable snapshot
// adapter; until that exists it deliberately returns UNKNOWN.
func browserStaticPolicy(raw []byte) bool {
 var root map[string]json.RawMessage
 if json.Unmarshal(raw,&root)!=nil {return false}
 // ECS/optimistic/rewritten-TTL resolver configurations need a richer query
 // scope witness. Do not certify them using this deliberately narrow seam.
 var dnsConfig any
 if v:=root["dns"];v!=nil && json.Unmarshal(v,&dnsConfig)!=nil {return false}
 var unsupportedDNS func(any) bool
 unsupportedDNS=func(v any)bool {
  switch x:=v.(type) {
  case map[string]any:for k,item:=range x {if k=="client_subnet" || k=="rewrite_ttl" || k=="optimistic_cache" {return true};if unsupportedDNS(item) {return true}}
  case []any:for _,item:=range x {if unsupportedDNS(item) {return true}}
  }
  return false
 }
 if unsupportedDNS(dnsConfig) {return false}
 var route map[string]json.RawMessage
 if v:=root["route"];v!=nil && json.Unmarshal(v,&route)!=nil {return false}
 for key:=range route {if key!="rules" && key!="final" {return false}}
 var rules []map[string]json.RawMessage
 if v:=route["rules"];v!=nil && json.Unmarshal(v,&rules)!=nil {return false}
 allowed:=map[string]bool{"type":true,"action":true,"outbound":true,"domain":true,"domain_suffix":true,"ip_cidr":true,"source_ip_cidr":true,"port":true,"source_port":true,"network":true,"ip_version":true,"inbound":true,"invert":true}
 for _,rule:=range rules {
  for key:=range rule {if !allowed[key] {return false}}
  var kind,action string
  if v:=rule["type"];v!=nil && json.Unmarshal(v,&kind)!=nil {return false}
  if v:=rule["action"];v!=nil && json.Unmarshal(v,&action)!=nil {return false}
  if (kind!="" && kind!="default") || (action!="" && action!="route" && action!="reject") {return false}
 }
 return true
}
func browserPureMatch(router adapter.Router,m adapter.InboundContext) (adapter.Rule,int,bool) {
 // Value copy plus no slice/pointer match fields permitted by the whitelist.
 // Reset stale v6 geo/cache information before matching the candidate literal.
 m.GeoIPCode="";m.DestinationAddresses=nil;m.DNSResponse=nil;m.NamedDNSResponses=nil;m.DestinationAddressMatchFromResponse=false
 for i,r:=range router.Rules() {
  m.ResetRuleCache()
  if r.Match(&m) {
   if _,ok:=r.Action().(*R.RuleActionRoute);!ok {return nil,-1,false}
   return r,i,true
  }
 }
 return nil,-1,true
}
func (s *browserProvenance) BrowserCandidate(ctx context.Context,router adapter.Router,m adapter.InboundContext,selected adapter.Rule,index int,outbound adapter.Outbound) (netip.Addr,time.Time,bool) {
 if !s.static || router==nil || outbound==nil || m.Network!="tcp" || !m.Destination.Addr.Is6() || m.Destination.Addr.Is4In6() || m.FakeIP || m.RouteOriginalDestination.IsValid() {return netip.Addr{},time.Time{},false}
 scope,ok:=browserScope(m);if !ok {return netip.Addr{},time.Time{},false}
 old,ok:=s.receipt(scope,m.Destination.Addr);if !ok {return netip.Addr{},time.Time{},false}
 if m.Domain!="" && browserName(m.Domain)!=old.name {return netip.Addr{},time.Time{},false}
 originalRule,originalIndex,ok:=browserPureMatch(router,m)
 if !ok || originalRule!=selected || originalIndex!=index {return netip.Addr{},time.Time{},false}
 manager:=service.FromContext[adapter.OutboundManager](ctx)
 if manager==nil {return netip.Addr{},time.Time{},false}
 if selected!=nil {
  action,ok:=selected.Action().(*R.RuleActionRoute);if !ok {return netip.Addr{},time.Time{},false}
  leaf,loaded:=manager.Outbound(action.Outbound)
  if !loaded || leaf!=outbound {return netip.Addr{},time.Time{},false}
 } else if manager.Default()!=outbound {return netip.Addr{},time.Time{},false}
 // Only concrete immutable leaves supported. Selector/urltest generations are
 // not equal to a tag and require their own leaf-generation witness.
 if outbound.Type()!="anytls" && outbound.Type()!="direct" {return netip.Addr{},time.Time{},false}
 var secure adapter.DNSTransport
 s.mu.Lock();for t:=range s.secure {if t.Tag()==old.transport {secure=t;break}};s.mu.Unlock()
 resolver:=service.FromContext[adapter.DNSRouter](ctx)
 if secure==nil || resolver==nil {return netip.Addr{},time.Time{},false}
 // One private refresh operation owns both questions; never combine unrelated
 // browser A/AAAA messages. Pin the original strict HTTPS transport+detour,
 // bypass stale/optimistic caches, and retain current protocol TTL semantics.
 select {case s.refresh<-struct{}{}:defer func(){<-s.refresh}();default:return netip.Addr{},time.Time{},false}
 operation:=&browserRefresh{owner:s,expected:secure,verified:make(map[*dns.Msg]*dns.Msg)}
 refresh,cancel:=context.WithTimeout(context.WithValue(ctx,browserRefreshKey{},operation),2*time.Second);defer cancel()
 options:=adapter.DNSQueryOptions{Transport:secure,DisableCache:true,DisableOptimisticCache:true}
 q6:=new(dns.Msg);q6.SetQuestion(old.name,dns.TypeAAAA)
 r6,err:=resolver.Exchange(refresh,q6,options);if err!=nil {return netip.Addr{},time.Time{},false}
 sixReceived:=s.now()
 q4:=new(dns.Msg);q4.SetQuestion(old.name,dns.TypeA)
 r4,err:=resolver.Exchange(refresh,q4,options);if err!=nil {return netip.Addr{},time.Time{},false}
 operation.mu.Lock();certified:=operation.verified[q6]==r6 && operation.verified[q4]==r4;operation.mu.Unlock()
 if !certified {return netip.Addr{},time.Time{},false}
 now:=s.now();six,ok6:=browserRRSet(q6,r6,sixReceived);four,ok4:=browserRRSet(q4,r4,now)
 if !ok6 || !ok4 || !browserBundle(old,six,four,now) {return netip.Addr{},time.Time{},false}
 current,ok:=s.receipt(scope,old.ip);if !ok || current.epoch!=old.epoch || current.name!=old.name || current.terminal!=old.terminal || current.transport!=old.transport {return netip.Addr{},time.Time{},false}
 expires:=old.expires;if six.expires.Before(expires) {expires=six.expires};if four.expires.Before(expires) {expires=four.expires}
 for _,ip:=range four.ips {
  candidate:=m;candidate.Destination=M.Socksaddr{Addr:ip,Port:m.Destination.Port};candidate.IPVersion=4
  rule,candidateIndex,ok:=browserPureMatch(router,candidate)
  // Same actual immutable rule object implies same frozen action/options,
  // unlike merely comparing an outbound tag. REJECT/unknown never passes.
  if ok && rule==selected && candidateIndex==index {return ip,expires,true}
 }
 return netip.Addr{},time.Time{},false
}
func (s *browserProvenance) PrepareBrowserCandidate(ctx context.Context,router adapter.Router,m adapter.InboundContext,selected adapter.Rule,index int,outbound adapter.Outbound) context.Context {
 scope,scoped:=browserScope(m);if !scoped {return ctx}
 before,ok:=s.receipt(scope,m.Destination.Addr);if !ok {return ctx}
 ip,expires,ok:=s.BrowserCandidate(ctx,router,m,selected,index,outbound);if !ok {return ctx}
 receipt,ok:=s.receipt(scope,m.Destination.Addr);if !ok || receipt.epoch!=before.epoch || receipt.name!=before.name || receipt.terminal!=before.terminal || receipt.transport!=before.transport {return ctx}
 ticket:=BrowserAlternate{Address:ip,Expires:expires,owner:s,receipt:receipt,outbound:outbound,rule:selected,ruleIndex:index}
 return context.WithValue(ctx,browserCandidateKey{},ticket)
}
func browserAlternate(ctx context.Context,outbound adapter.Outbound) (BrowserAlternate,bool) {
 ticket,ok:=ctx.Value(browserCandidateKey{}).(BrowserAlternate)
 if !ok || ticket.owner==nil || ticket.outbound!=outbound || ctx.Err()!=nil || !ticket.owner.now().Before(ticket.Expires) {return BrowserAlternate{},false}
 current,ok:=ticket.owner.receipt(ticket.receipt.scope,ticket.receipt.ip)
 if !ok || current.epoch!=ticket.receipt.epoch || current.name!=ticket.receipt.name || current.terminal!=ticket.receipt.terminal || current.transport!=ticket.receipt.transport {return BrowserAlternate{},false}
 return ticket,true
}

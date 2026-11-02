// Package familypolicy carries compiler-owned, memory-only policy source leases.
// It performs no I/O and does not implement a second routing model.
package familypolicy

import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "reflect"
 cr "github.com/NiuStar/anytls-core/internal/connectionrecords"
)

// Source is the exact SHA-validated JSON read by the compiler, in first-load order.
// These bytes must never be persisted in connection records or exposed by an API.
type Source struct { Tag string; JSON []byte }
type Snapshot struct { runtimeSHA, generation, manifestID string }
type contextKey struct{}
func sha(b []byte) string { s:=sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// Capture authenticates the manifest/runtime and verifies that the actual inline
// SDK rules are the rules decoded from each captured source. A file path, user
// tag or self-described checksum is not sufficient authority. The compiler has
// already checked source SHA using the same read that supplied inline rules.
func Capture(raw []byte, m *cr.Manifest, sources []Source) *Snapshot {
 if m == nil || m.RuntimeSHA256 != sha(raw) { return nil }
 d,err:=cr.ManifestDigest(*m,cr.ManifestBudget(m)); if err != nil || d != m.ManifestID { return nil }
 var root struct { Route struct { Sets []struct { Type string `json:"type"`; Tag string `json:"tag"`; Rules []json.RawMessage `json:"rules"` } `json:"rule_set"` } `json:"route"` }
 if json.Unmarshal(raw,&root)!=nil || len(root.Route.Sets)!=len(sources) { return nil }
 var captures []cr.CapturedSource
 for _,s:=range m.CapturedSources { if s.Kind==cr.SourceRuleSet { captures=append(captures,s) } }
 if len(captures)!=len(sources) { return nil }
 seen:=map[string]bool{}
 for i,s:=range sources {
  c:=captures[i]; set:=root.Route.Sets[i]
  if s.Tag=="" || seen[s.Tag] || set.Tag!=s.Tag || set.Type!="inline" || c.Ordinal!=i || !c.Present || c.SHA256==nil || *c.SHA256!=sha(s.JSON) { return nil }
  seen[s.Tag]=true
  var doc struct { Version int `json:"version"`; Rules []json.RawMessage `json:"rules"` }
  if json.Unmarshal(s.JSON,&doc)!=nil || doc.Version!=3 || len(doc.Rules)==0 || len(doc.Rules)!=len(set.Rules) { return nil }
  for j,r:=range doc.Rules {
   var a,b any
   if json.Unmarshal(r,&a)!=nil || json.Unmarshal(set.Rules[j],&b)!=nil || !reflect.DeepEqual(a,b) { return nil }
  }
 }
 return &Snapshot{runtimeSHA:m.RuntimeSHA256,generation:m.Generation,manifestID:m.ManifestID}
}
func (s *Snapshot) Matches(raw []byte) bool { return s!=nil && s.generation!="" && s.manifestID!="" && s.runtimeSHA==sha(raw) }
func WithSnapshot(ctx context.Context,s *Snapshot) context.Context { return context.WithValue(ctx,contextKey{},s) }
func FromContext(ctx context.Context) *Snapshot { s,_:=ctx.Value(contextKey{}).(*Snapshot); return s }

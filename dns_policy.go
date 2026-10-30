package main

// Each runtime owns fresh maps. The literal endpoint avoids resolver bootstrap;
// detour is the global selected AnyTLS node, not the business MATCH target.
func unifiedTUNDNS() map[string]any {
 return map[string]any{
  "servers": []any{map[string]any{"type":"https", "tag":"secure-dns", "server":"1.1.1.1", "tls":map[string]any{"server_name":"cloudflare-dns.com"}, "detour":"anytls-out"}},
  "final":"secure-dns", "reverse_mapping":true,
 }
}

func unifiedTUNDNSRules() []any {
 return []any{
  map[string]any{"port":53,"action":"hijack-dns"},
  map[string]any{"action":"sniff"},
  map[string]any{"protocol":[]string{"dns"},"action":"hijack-dns"},
 }
}

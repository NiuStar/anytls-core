package engine

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
)

// Frozen pre-candidate decoder: keep the original extended helper as the oracle.
func originalOptions(ctx context.Context, content []byte) (context.Context, option.Options, error) {
	ctx = Context(service.ContextWithRegistry(ctx, service.NewRegistry()))
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, content)
	if err != nil {
		return ctx, option.Options{}, lifecycleError("decode options", err)
	}
	if options.Log != nil && !options.Log.Disabled && options.Log.Level != "" {
		if _, err := log.ParseLevel(options.Log.Level); err != nil {
			return ctx, option.Options{}, lifecycleError("log options", err)
		}
	}
	options.Log = &option.LogOptions{Disabled: true}
	return ctx, options, nil
}

func orderedRuleJSON(n int) []byte {
	var b strings.Builder
	b.WriteString(`{"route":{"rules":[`)
	for i := 0; i < n; i++ {
		if i != 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"domain":["ordered-%06d.fixture.invalid"],"action":"route","outbound":"direct"}`, i)
	}
	b.WriteString(`]},"outbounds":[{"type":"direct","tag":"direct"}]}`)
	return []byte(b.String())
}

func allocatedDecode(t *testing.T, decode func(context.Context, []byte) (context.Context, option.Options, error), content []byte) uint64 {
	t.Helper()
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, options, err := decode(context.Background(), content)
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	if options.Route == nil || len(options.Route.Rules) != 4000 {
		t.Fatal("ordered rules lost")
	}
	runtime.KeepAlive(options)
	return after.TotalAlloc - before.TotalAlloc
}

func TestRouteRulePreallocationAllocation(t *testing.T) {
	content := orderedRuleJSON(4000)
	// Warm both decoder paths before measuring cumulative allocations, not RSS.
	_, _, _ = originalOptions(context.Background(), content)
	_, _, _ = decodeOptions(context.Background(), content)
	oldBytes := allocatedDecode(t, originalOptions, content)
	newBytes := allocatedDecode(t, decodeOptions, content)
	t.Logf("old_bytes=%d candidate_bytes=%d", oldBytes, newBytes)
	// Broad relative budget: baseline fails at ~100%; exact capacities and time
	// are intentionally not contractual. Reflective union-slice growth is large.
	if newBytes >= oldBytes*9/10 {
		t.Fatalf("route-rule allocation not reduced by 10%%: old=%d candidate=%d", oldBytes, newBytes)
	}
}

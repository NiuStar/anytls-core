package engine

import (
	"context"
	stdjson "encoding/json"
	"unsafe"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
)

// decodeOptions owns a new (not cloned) sing service registry per invocation.
// Parent application values, deadline and cancellation are preserved, but parent
// sing registries/services cannot widen the supported surface or be mutated by New.
func decodeOptions(ctx context.Context, runtimeJSON []byte) (context.Context, option.Options, error) {
	ctx = Context(service.ContextWithRegistry(ctx, service.NewRegistry()))
	decoded, err := json.UnmarshalExtendedContext[preallocatedOptions](ctx, runtimeJSON)
	options := option.Options(decoded)
	if err != nil {
		return ctx, option.Options{}, lifecycleError("decode options", err)
	}
	if options.Log != nil && !options.Log.Disabled && options.Log.Level != "" {
		if _, err := log.ParseLevel(options.Log.Level); err != nil {
			return ctx, option.Options{}, lifecycleError("log options", err)
		}
	}
	// Library calls are silent, including upstream logs and configured log files.
	// Callers own diagnostics; never echo untrusted options or credentials.
	options.Log = &option.LogOptions{Disabled: true}
	return ctx, options, nil
}

// This local decode target lets the existing extended helper retain its exact
// syntax-error decoration while the SDK still owns all parsing and validation.
type preallocatedOptions option.Options

func (o *preallocatedOptions) Comments() *json.CommentSet {
	return (*option.Options)(o).Comments()
}

func (o *preallocatedOptions) SetComments(comments *json.CommentSet) {
	(*option.Options)(o).SetComments(comments)
}

func (o *preallocatedOptions) UnmarshalJSONContext(ctx context.Context, content []byte) error {
	if count := routeRuleCapacityHint(content); count > 0 {
		o.Route = &option.RouteOptions{Rules: make([]option.Rule, 0, count)}
	}
	return (*option.Options)(o).UnmarshalJSONContext(ctx, content)
}

func routeRuleCapacityHint(content []byte) int {
	var hint struct {
		Route *struct {
			Rules []stdjson.RawMessage `json:"rules"`
		} `json:"route"`
	}
	if err := stdjson.Unmarshal(content, &hint); err == nil && hint.Route != nil {
		count := len(hint.Route.Rules)
		// A hint is never a rule quota. Bound speculative union allocation by
		// actual payload bytes (32x), including tiny/null/duplicate-key input.
		// Short rules simply grow normally under the unchanged SDK decoder.
		const bytesPerRule = (int(unsafe.Sizeof(option.Rule{})) + 31) / 32
		if limit := len(content) / bytesPerRule; count > limit {
			count = limit
		}
		return count
	}
	return 0
}

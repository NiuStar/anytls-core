package engine

import (
	"context"

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
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, runtimeJSON)
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

package engine

import (
	"context"
	"strings"
	"testing"
	"time"
)

func coreSlimHasCause(err error, text string) bool {
	if err == nil {
		return false
	}
	if strings.Contains(err.Error(), text) {
		return true
	}
	switch e := err.(type) {
	case interface{ Unwrap() []error }:
		for _, cause := range e.Unwrap() {
			if coreSlimHasCause(cause, text) {
				return true
			}
		}
	case interface{ Unwrap() error }:
		return coreSlimHasCause(e.Unwrap(), text)
	}
	return false
}

func TestCoreSlimCacheFileRejected(t *testing.T) {
	err := Check(context.Background(), []byte(`{"experimental":{"cache_file":{"enabled":true}},"outbounds":[{"type":"direct","tag":"direct"}]}`))
	if !coreSlimHasCause(err, "cache file is unsupported") {
		t.Fatal("cache rejection lacks explicit unsupported cause")
	}
}

func TestCoreSlimDebugHTTPRejected(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := Run(ctx, []byte(`{"experimental":{"debug":{"listen":"127.0.0.1:0"}},"outbounds":[{"type":"direct","tag":"direct"}]}`))
	if !coreSlimHasCause(err, "debug HTTP is unsupported") {
		t.Fatal("debug listener not explicitly rejected at Run/preStart")
	}
}

func TestCoreSlimDefaultCheckAccepted(t *testing.T) {
	if err := Check(context.Background(), []byte(`{"outbounds":[{"type":"direct","tag":"direct"}]}`)); err != nil {
		t.Fatal(err)
	}
}

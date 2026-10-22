package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestConversionProviderDeadlineIsNotFormatError(t *testing.T) {
	input := []byte(`proxies:
  - {name: good, type: anytls, server: 8.8.8.8, port: 443, password: synthetic}
rule-providers:
  remote: {type: http, behavior: domain, url: https://example.com/rules}
rules: ["RULE-SET,remote,good", "MATCH,good"]
`)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	calls := 0
	data, _, err := webConvertConfiguration(ctx, input, true, func(ctx context.Context, _ string) ([]byte, error) {
		calls++
		<-ctx.Done()
		return nil, ctx.Err()
	})
	if calls != 1 || len(data) != 0 || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline must abort without candidate: calls=%d bytes=%d error=%v", calls, len(data), err)
	}
	if got := webConversionErrorCode(err); got != "CONFIG_CONVERSION_TIMEOUT" {
		t.Fatalf("deadline mislabeled as %s", got)
	}
}

func TestConversionCancellationIsNotFormatOrSizeError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := webConvertConfiguration(ctx, []byte("nodes: []\n"), false, nil)
	if !errors.Is(err, context.Canceled) || webConversionErrorCode(err) != "CONFIG_CONVERSION_CANCELED" {
		t.Fatal("cancellation mislabeled", err)
	}
	if webConversionErrorCode(fmt.Errorf("wrapped: %w", context.DeadlineExceeded)) != "CONFIG_CONVERSION_TIMEOUT" {
		t.Fatal("wrapped deadline mislabeled")
	}
	if webConversionErrorCode(errWebConversionTooLarge) != "CONFIG_CONVERSION_TOO_LARGE" || webConversionErrorCode(errWebConversionInvalid) != "CONFIG_CONVERSION_INVALID" {
		t.Fatal("other errors changed")
	}
}

func TestConversionNativeCanceledAfterParseDoesNotReturnOriginal(t *testing.T) {
	// A context whose first check succeeds and subsequent checks observe cancellation.
	ctx := &conversionCancelAfterCheck{}
	input := []byte("nodes: []\n")
	out, _, err := webConvertConfiguration(ctx, input, false, nil)
	if bytes.Equal(out, input) || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled parse returned original or lost cause: %v", err)
	}
}

func TestWebConversionDeadlinePreservesConfigAndNoPreview(t *testing.T) {
	w, password := webFixture(t)
	cookie, csrf := webLogin(t, w, password)
	before, err := os.ReadFile(w.configPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Return valid YAML, but end the request at the fetch/conversion boundary.
	w.importFetch = func(context.Context, string) ([]byte, error) {
		cancel()
		return []byte(clashExportFixture), nil
	}
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:18089/api/v1/import/preview", strings.NewReader(`{"url":"https://subscription.example/profile?token=PRIVATE"}`)).WithContext(ctx)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://127.0.0.1:18089")
	request.Header.Set("X-CSRF-Token", csrf)
	request.AddCookie(cookie)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, request)
	if rec.Code != 422 || !strings.Contains(rec.Body.String(), "CONFIG_CONVERSION_CANCELED") || strings.Contains(rec.Body.String(), "PRIVATE") || w.importPending != nil {
		t.Fatal("canceled handler did not fail closed with safe code", rec.Code)
	}
	after, err := os.ReadFile(w.configPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("canceled preview changed configuration")
	}
}

type conversionCancelAfterCheck struct {
	context.Context
	calls int
}

func (c *conversionCancelAfterCheck) Err() error {
	c.calls++
	if c.calls > 1 {
		return context.Canceled
	}
	return nil
}

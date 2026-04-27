package dns

import (
	"testing"
	"time"
)

func TestDefaultResolverConfig(t *testing.T) {
	cfg := DefaultResolverConfig()
	if cfg.UpstreamDNS != "8.8.8.8:53" {
		t.Errorf("expected upstream DNS 8.8.8.8:53, got %s", cfg.UpstreamDNS)
	}
	if cfg.Retries != 3 {
		t.Errorf("expected retries 3, got %d", cfg.Retries)
	}
	if !cfg.CacheEnabled {
		t.Error("expected cache to be enabled by default")
	}
}

func TestNewResolver(t *testing.T) {
	cfg := DefaultResolverConfig()
	r := NewResolver(cfg)
	if r == nil {
		t.Fatal("expected non-nil resolver")
	}
	if r.cache == nil {
		t.Error("expected cache to be initialized")
	}
}

func TestNewResolverNoCache(t *testing.T) {
	cfg := DefaultResolverConfig()
	cfg.CacheEnabled = false
	r := NewResolver(cfg)
	if r.cache != nil {
		t.Error("expected nil cache when disabled")
	}
}

func TestResolveLocalhost(t *testing.T) {
	cfg := DefaultResolverConfig()
	cfg.Timeout = 2 * time.Second
	r := NewResolver(cfg)
	ips, err := r.Resolve("localhost")
	if err != nil {
		t.Fatalf("unexpected error resolving localhost: %v", err)
	}
	if len(ips) == 0 {
		t.Error("expected at least one IP for localhost")
	}
}

func TestResolveCacheHit(t *testing.T) {
	cfg := DefaultResolverConfig()
	r := NewResolver(cfg)

	// First resolve populates cache
	_, err := r.Resolve("localhost")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if r.cache.Size() == 0 {
		t.Error("expected cache to have entries after resolve")
	}

	// Second resolve should hit cache
	ips, ok := r.cache.Get("localhost")
	if !ok {
		t.Error("expected cache hit for localhost")
	}
	if len(ips) == 0 {
		t.Error("expected IPs in cache")
	}
}

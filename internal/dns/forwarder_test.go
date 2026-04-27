package dns

import (
	"testing"
	"time"
)

func TestDefaultForwarderConfig(t *testing.T) {
	cfg := DefaultForwarderConfig()
	if cfg.Timeout != 5*time.Second {
		t.Errorf("expected 5s timeout, got %v", cfg.Timeout)
	}
	if cfg.MaxRetries != 2 {
		t.Errorf("expected 2 retries, got %d", cfg.MaxRetries)
	}
}

func TestNewForwarderNoClients(t *testing.T) {
	_, err := NewForwarder(DefaultForwarderConfig())
	if err == nil {
		t.Fatal("expected error when no clients provided")
	}
}

func TestNewForwarderWithClient(t *testing.T) {
	client, err := NewUpstreamClient(DefaultUpstreamConfig())
	if err != nil {
		t.Fatalf("failed to create upstream client: %v", err)
	}
	f, err := NewForwarder(DefaultForwarderConfig(), client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f == nil {
		t.Fatal("expected non-nil forwarder")
	}
}

func TestForwardNilMessage(t *testing.T) {
	client, _ := NewUpstreamClient(DefaultUpstreamConfig())
	f, _ := NewForwarder(DefaultForwarderConfig(), client)
	_, err := f.Forward(nil)
	if err == nil {
		t.Fatal("expected error for nil message")
	}
}

func TestForwardMultipleClients(t *testing.T) {
	// Two clients with the same default config; the forwarder should accept both.
	c1, _ := NewUpstreamClient(DefaultUpstreamConfig())
	c2, _ := NewUpstreamClient(DefaultUpstreamConfig())
	f, err := NewForwarder(DefaultForwarderConfig(), c1, c2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(f.clients) != 2 {
		t.Errorf("expected 2 clients, got %d", len(f.clients))
	}
}

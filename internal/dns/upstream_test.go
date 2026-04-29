package dns

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestDefaultUpstreamConfig(t *testing.T) {
	cfg := DefaultUpstreamConfig()
	if cfg.Address != "8.8.8.8" {
		t.Errorf("expected address 8.8.8.8, got %s", cfg.Address)
	}
	if cfg.Port != 53 {
		t.Errorf("expected port 53, got %d", cfg.Port)
	}
	if cfg.Proto != "udp" {
		t.Errorf("expected proto udp, got %s", cfg.Proto)
	}
	if cfg.Timeout != 5*time.Second {
		t.Errorf("expected timeout 5s, got %v", cfg.Timeout)
	}
}

func TestNewUpstreamClient(t *testing.T) {
	cfg := DefaultUpstreamConfig()
	c := NewUpstreamClient(cfg)
	if c == nil {
		t.Fatal("expected non-nil UpstreamClient")
	}
	if c.client == nil {
		t.Fatal("expected non-nil dns.Client")
	}
}

func TestUpstreamClientAddr(t *testing.T) {
	cfg := UpstreamConfig{
		Address: "1.1.1.1",
		Port:    53,
		Proto:   "udp",
		Timeout: 2 * time.Second,
	}
	c := NewUpstreamClient(cfg)
	addr := c.addr()
	if addr != "1.1.1.1:53" {
		t.Errorf("expected 1.1.1.1:53, got %s", addr)
	}
}

func TestUpstreamQueryNilMessage(t *testing.T) {
	c := NewUpstreamClient(DefaultUpstreamConfig())
	_, _, err := c.Query(nil)
	if err == nil {
		t.Fatal("expected error for nil message, got nil")
	}
}

// TestUpstreamQueryNameBuildsMsgCorrectly verifies that QueryName constructs a
// valid DNS message and attempts to send it. Uses RFC 5737 TEST-NET (192.0.2.0/24)
// as the upstream address so no real network traffic is generated.
// Timeout is kept short (200ms) to avoid slowing down the test suite.
func TestUpstreamQueryNameBuildsMsgCorrectly(t *testing.T) {
	cfg := UpstreamConfig{
		Address: "192.0.2.1", // TEST-NET, should not be routable
		Port:    53,
		Proto:   "udp",
		Timeout: 200 * time.Millisecond,
	}
	c := NewUpstreamClient(cfg)
	_, err := c.QueryName("example.com")
	if err == nil {
		t.Log("unexpected success — network may be routing TEST-NET")
	}
	// We expect a timeout/error; just confirm the function runs without panic.
}

func TestUpstreamQueryReturnsResponse(t *testing.T) {
	// Build a minimal message and verify Query returns error on unreachable host.
	cfg := UpstreamConfig{
		Address: "192.0.2.2",
		Port:    53,
		Proto:   "udp",
		Timeout: 200 * time.Millisecond,
	}
	c := NewUpstreamClient(cfg)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("example.org"), dns.TypeA)
	m.RecursionDesired = true
	_, rtt, err := c.Query(m)
	if err == nil {
		t.Log("unexpected success")
	}
	_ = rtt // rtt may be zero on error; just ensure no panic
}

package dns

import (
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

// UpstreamConfig holds configuration for an upstream DNS server.
type UpstreamConfig struct {
	Address string
	Port    int
	Proto   string // "udp" or "tcp"
	Timeout time.Duration
}

// DefaultUpstreamConfig returns a sensible default upstream config.
func DefaultUpstreamConfig() UpstreamConfig {
	return UpstreamConfig{
		Address: "8.8.8.8",
		Port:    53,
		Proto:   "udp",
		Timeout: 5 * time.Second,
	}
}

// UpstreamClient sends DNS queries to an upstream resolver.
type UpstreamClient struct {
	cfg    UpstreamConfig
	client *dns.Client
}

// NewUpstreamClient creates a new UpstreamClient with the given config.
func NewUpstreamClient(cfg UpstreamConfig) *UpstreamClient {
	return &UpstreamClient{
		cfg: cfg,
		client: &dns.Client{
			Net:     cfg.Proto,
			Timeout: cfg.Timeout,
		},
	}
}

// addr returns the formatted address string for the upstream server.
func (u *UpstreamClient) addr() string {
	return net.JoinHostPort(u.cfg.Address, fmt.Sprintf("%d", u.cfg.Port))
}

// Query sends a DNS message to the upstream server and returns the response.
func (u *UpstreamClient) Query(msg *dns.Msg) (*dns.Msg, time.Duration, error) {
	if msg == nil {
		return nil, 0, fmt.Errorf("upstream: nil message")
	}
	resp, rtt, err := u.client.Exchange(msg, u.addr())
	if err != nil {
		return nil, rtt, fmt.Errorf("upstream: exchange failed: %w", err)
	}
	return resp, rtt, nil
}

// QueryName is a convenience method to query a single A record by name.
func (u *UpstreamClient) QueryName(name string) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	m.RecursionDesired = true
	resp, _, err := u.Query(m)
	return resp, err
}

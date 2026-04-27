package dns

import (
	"errors"
	"net"
	"time"

	"github.com/miekg/dns"
)

// ForwarderConfig holds configuration for the DNS forwarder.
type ForwarderConfig struct {
	// Timeout is the per-query deadline when contacting upstream servers.
	Timeout time.Duration
	// MaxRetries is the number of times a failed query is retried.
	MaxRetries int
}

// DefaultForwarderConfig returns a ForwarderConfig with sensible defaults.
func DefaultForwarderConfig() ForwarderConfig {
	return ForwarderConfig{
		Timeout:    5 * time.Second,
		MaxRetries: 2,
	}
}

// Forwarder resolves DNS queries by forwarding them to a list of upstream
// clients in order, returning the first successful response.
type Forwarder struct {
	cfg     ForwarderConfig
	clients []*UpstreamClient
}

// NewForwarder creates a Forwarder from the provided upstream clients.
// At least one client must be supplied.
func NewForwarder(cfg ForwarderConfig, clients ...*UpstreamClient) (*Forwarder, error) {
	if len(clients) == 0 {
		return nil, errors.New("forwarder: at least one upstream client is required")
	}
	return &Forwarder{cfg: cfg, clients: clients}, nil
}

// Forward sends msg to each upstream client in turn until a response is
// received or all clients (and retries) are exhausted.
func (f *Forwarder) Forward(msg *dns.Msg) (*dns.Msg, error) {
	if msg == nil {
		return nil, errors.New("forwarder: nil message")
	}
	var lastErr error
	for _, c := range f.clients {
		for attempt := 0; attempt <= f.cfg.MaxRetries; attempt++ {
			resp, err := queryWithTimeout(c, msg, f.cfg.Timeout)
			if err == nil {
				return resp, nil
			}
			lastErr = err
		}
	}
	return nil, lastErr
}

// queryWithTimeout wraps UpstreamClient.Query with a deadline enforced via a
// dedicated goroutine so that slow upstreams do not block indefinitely.
func queryWithTimeout(c *UpstreamClient, msg *dns.Msg, timeout time.Duration) (*dns.Msg, error) {
	type result struct {
		resp *dns.Msg
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		resp, err := c.Query(msg.Question[0].Name, msg.Question[0].Qtype)
		ch <- result{resp, err}
	}()
	select {
	case r := <-ch:
		return r.resp, r.err
	case <-time.After(timeout):
		return nil, &net.OpError{Op: "dial", Err: errors.New("timeout")}
	}
}

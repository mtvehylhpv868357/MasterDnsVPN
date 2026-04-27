package dns

import (
	"fmt"
	"net"
	"time"
)

// ResolverConfig holds configuration for the DNS resolver
type ResolverConfig struct {
	UpstreamDNS  string
	Timeout      time.Duration
	Retries      int
	CacheEnabled bool
	CacheTTL     time.Duration
}

// DefaultResolverConfig returns a default resolver configuration
func DefaultResolverConfig() ResolverConfig {
	return ResolverConfig{
		UpstreamDNS:  "8.8.8.8:53",
		Timeout:      5 * time.Second,
		Retries:      3,
		CacheEnabled: true,
		CacheTTL:     60 * time.Second,
	}
}

// Resolver handles DNS resolution with optional caching
type Resolver struct {
	config ResolverConfig
	cache  *Cache
}

// NewResolver creates a new DNS resolver
func NewResolver(cfg ResolverConfig) *Resolver {
	r := &Resolver{config: cfg}
	if cfg.CacheEnabled {
		r.cache = NewCache(cfg.CacheTTL)
	}
	return r
}

// Resolve resolves a hostname to IP addresses
func (r *Resolver) Resolve(hostname string) ([]net.IP, error) {
	if r.cache != nil {
		if ips, ok := r.cache.Get(hostname); ok {
			return ips, nil
		}
	}

	var ips []net.IP
	var err error

	for attempt := 0; attempt < r.config.Retries; attempt++ {
		ips, err = r.resolveOnce(hostname)
		if err == nil {
			break
		}
	}

	if err != nil {
		return nil, fmt.Errorf("dns resolve failed for %s: %w", hostname, err)
	}

	if r.cache != nil {
		r.cache.Set(hostname, ips)
	}

	return ips, nil
}

func (r *Resolver) resolveOnce(hostname string) ([]net.IP, error) {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx interface{ Deadline() (time.Time, bool) }, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: r.config.Timeout}
			return d.DialContext(nil, "udp", r.config.UpstreamDNS)
		},
	}
	_ = resolver
	addrs, err := net.LookupHost(hostname)
	if err != nil {
		return nil, err
	}
	var ips []net.IP
	for _, addr := range addrs {
		if ip := net.ParseIP(addr); ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips, nil
}

// Package dns provides DNS resolution utilities for MasterDnsVPN.
//
// It includes a thread-safe in-memory cache with TTL-based expiry
// and a configurable resolver that supports upstream DNS servers,
// retry logic, and optional caching.
//
// Basic usage:
//
//	cfg := dns.DefaultResolverConfig()
//	cfg.UpstreamDNS = "1.1.1.1:53"
//	cfg.CacheTTL = 120 * time.Second
//
//	r := dns.NewResolver(cfg)
//	ips, err := r.Resolve("example.com")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	for _, ip := range ips {
//	    fmt.Println(ip)
//	}
package dns

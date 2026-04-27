// Package dns provides building blocks for a DNS proxy / VPN gateway.
//
// # Components
//
//   - Cache      – in-memory TTL-aware record cache.
//   - HostsTable – static /etc/hosts-style override table.
//   - Resolver   – ties cache, hosts, and upstream together into a single
//     query entry-point.
//   - UpstreamClient – thin wrapper around a single upstream DNS server.
//   - Forwarder  – fan-out / retry logic across multiple UpstreamClients.
//   - Middleware  – composable Handler chain (logging, recovery, …).
//
// # Typical usage
//
//	cache   := dns.NewCache(dns.DefaultCacheConfig())
//	hosts,_ := dns.NewHostsTable("/etc/hosts")
//	upstream,_ := dns.NewUpstreamClient(dns.DefaultUpstreamConfig())
//	fwd,_   := dns.NewForwarder(dns.DefaultForwarderConfig(), upstream)
//	_ = fwd // pass to your server handler
package dns

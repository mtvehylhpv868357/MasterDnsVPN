package dns

import (
	"net"
	"sync"
	"time"
)

// cacheEntry stores cached DNS results with expiry
type cacheEntry struct {
	ips       []net.IP
	expiresAt time.Time
}

// Cache is a thread-safe DNS response cache
type Cache struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry
	ttl     time.Duration
}

// NewCache creates a new DNS cache with the given TTL
func NewCache(ttl time.Duration) *Cache {
	c := &Cache{
		entries: make(map[string]cacheEntry),
		ttl:     ttl,
	}
	go c.evictLoop()
	return c
}

// Get retrieves IPs for a hostname if cached and not expired
func (c *Cache) Get(hostname string) ([]net.IP, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.entries[hostname]
	if !ok || time.Now().After(entry.expiresAt) {
		return nil, false
	}
	return entry.ips, true
}

// Set stores IPs for a hostname in the cache
func (c *Cache) Set(hostname string, ips []net.IP) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[hostname] = cacheEntry{
		ips:       ips,
		expiresAt: time.Now().Add(c.ttl),
	}
}

// Flush removes all entries from the cache
func (c *Cache) Flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]cacheEntry)
}

// Size returns the number of cached entries
func (c *Cache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

func (c *Cache) evictLoop() {
	ticker := time.NewTicker(c.ttl / 2)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		c.mu.Lock()
		for k, v := range c.entries {
			if now.After(v.expiresAt) {
				delete(c.entries, k)
			}
		}
		c.mu.Unlock()
	}
}

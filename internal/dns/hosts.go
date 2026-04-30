package dns

import (
	"bufio"
	"net"
	"os"
	"strings"
	"sync"
)

// HostsTable holds a parsed in-memory map of hostname -> IP from a hosts file.
type HostsTable struct {
	mu      sync.RWMutex
	entries map[string]net.IP
}

// NewHostsTable creates an empty HostsTable.
func NewHostsTable() *HostsTable {
	return &HostsTable{
		entries: make(map[string]net.IP),
	}
}

// LoadFile parses a hosts-format file and populates the table.
// Lines starting with '#' and blank lines are ignored.
// Each valid line has the form: <ip> <hostname> [aliases...]
// Note: calling LoadFile replaces all existing entries atomically.
func (h *HostsTable) LoadFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	newEntries := make(map[string]net.IP)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Strip inline comments
		if idx := strings.IndexByte(line, '#'); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ip := net.ParseIP(fields[0])
		if ip == nil {
			continue
		}
		for _, name := range fields[1:] {
			newEntries[strings.ToLower(name)] = ip
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	h.mu.Lock()
	h.entries = newEntries
	h.mu.Unlock()
	return nil
}

// Lookup returns the IP for the given hostname, or nil if not found.
// The hostname is normalized to lowercase before lookup.
func (h *HostsTable) Lookup(hostname string) net.IP {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.entries[strings.ToLower(hostname)]
}

// Set manually adds or overrides an entry in the table.
func (h *HostsTable) Set(hostname string, ip net.IP) {
	h.mu.Lock()
	h.entries[strings.ToLower(hostname)] = ip
	h.mu.Unlock()
}

// Delete removes an entry from the table if it exists.
func (h *HostsTable) Delete(hostname string) {
	h.mu.Lock()
	delete(h.entries, strings.ToLower(hostname))
	h.mu.Unlock()
}

// Len returns the number of entries in the table.
func (h *HostsTable) Len() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.entries)
}

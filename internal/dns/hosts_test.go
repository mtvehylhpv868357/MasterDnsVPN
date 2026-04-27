package dns

import (
	"net"
	"os"
	"testing"
)

func writeTempHostsFile(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp("", "hosts_test_*.txt")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	f.Close()
	t.Cleanup(func() { os.Remove(f.Name()) })
	return f.Name()
}

func TestNewHostsTable(t *testing.T) {
	h := NewHostsTable()
	if h == nil {
		t.Fatal("expected non-nil HostsTable")
	}
	if h.Len() != 0 {
		t.Errorf("expected empty table, got %d entries", h.Len())
	}
}

func TestHostsTableLoadFile(t *testing.T) {
	content := `# This is a comment
127.0.0.1   localhost
192.168.1.1 router gateway  # inline comment

::1         localhost6
`
	path := writeTempHostsFile(t, content)
	h := NewHostsTable()
	if err := h.LoadFile(path); err != nil {
		t.Fatalf("LoadFile error: %v", err)
	}
	if h.Len() != 4 {
		t.Errorf("expected 4 entries, got %d", h.Len())
	}
}

func TestHostsTableLookup(t *testing.T) {
	content := "127.0.0.1 localhost\n10.0.0.1 vpn.internal\n"
	path := writeTempHostsFile(t, content)
	h := NewHostsTable()
	_ = h.LoadFile(path)

	ip := h.Lookup("localhost")
	if ip == nil || ip.String() != "127.0.0.1" {
		t.Errorf("expected 127.0.0.1, got %v", ip)
	}

	ip = h.Lookup("VPN.INTERNAL") // case-insensitive
	if ip == nil || ip.String() != "10.0.0.1" {
		t.Errorf("expected 10.0.0.1, got %v", ip)
	}
}

func TestHostsTableLookupMiss(t *testing.T) {
	h := NewHostsTable()
	if ip := h.Lookup("notexist.local"); ip != nil {
		t.Errorf("expected nil, got %v", ip)
	}
}

func TestHostsTableSet(t *testing.T) {
	h := NewHostsTable()
	h.Set("custom.host", net.ParseIP("172.16.0.1"))
	ip := h.Lookup("custom.host")
	if ip == nil || ip.String() != "172.16.0.1" {
		t.Errorf("expected 172.16.0.1, got %v", ip)
	}
}

func TestHostsTableLoadFileNotFound(t *testing.T) {
	h := NewHostsTable()
	if err := h.LoadFile("/nonexistent/path/hosts"); err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

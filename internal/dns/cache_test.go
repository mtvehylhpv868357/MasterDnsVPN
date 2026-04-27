package dns

import (
	"net"
	"testing"
	"time"
)

func TestCacheSetAndGet(t *testing.T) {
	c := NewCache(10 * time.Second)
	ips := []net.IP{net.ParseIP("1.2.3.4")}
	c.Set("example.com", ips)

	got, ok := c.Get("example.com")
	if !ok {
		t.Fatal("expected cache hit")
	}
	if len(got) != 1 || !got[0].Equal(net.ParseIP("1.2.3.4")) {
		t.Errorf("unexpected IPs: %v", got)
	}
}

func TestCacheMiss(t *testing.T) {
	c := NewCache(10 * time.Second)
	_, ok := c.Get("notfound.com")
	if ok {
		t.Error("expected cache miss")
	}
}

func TestCacheExpiry(t *testing.T) {
	c := NewCache(50 * time.Millisecond)
	ips := []net.IP{net.ParseIP("9.9.9.9")}
	c.Set("expire.com", ips)

	_, ok := c.Get("expire.com")
	if !ok {
		t.Fatal("expected cache hit before expiry")
	}

	time.Sleep(100 * time.Millisecond)

	_, ok = c.Get("expire.com")
	if ok {
		t.Error("expected cache miss after expiry")
	}
}

func TestCacheFlush(t *testing.T) {
	c := NewCache(10 * time.Second)
	c.Set("a.com", []net.IP{net.ParseIP("1.1.1.1")})
	c.Set("b.com", []net.IP{net.ParseIP("2.2.2.2")})

	if c.Size() != 2 {
		t.Errorf("expected size 2, got %d", c.Size())
	}

	c.Flush()
	if c.Size() != 0 {
		t.Errorf("expected size 0 after flush, got %d", c.Size())
	}
}

func TestCacheConcurrency(t *testing.T) {
	c := NewCache(10 * time.Second)
	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func(i int) {
			c.Set("host", []net.IP{net.ParseIP("1.2.3.4")})
			c.Get("host")
			done <- struct{}{}
		}(i)
	}
	for i := 0; i < 10; i++ {
		<-done
	}
}

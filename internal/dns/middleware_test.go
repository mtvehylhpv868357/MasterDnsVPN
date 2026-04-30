package dns

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

// mockResponseWriter is a minimal dns.ResponseWriter for testing.
type mockResponseWriter struct {
	written *dns.Msg
}

func (m *mockResponseWriter) LocalAddr() net.Addr         { return &net.UDPAddr{} }
func (m *mockResponseWriter) RemoteAddr() net.Addr        { return &net.UDPAddr{} }
func (m *mockResponseWriter) WriteMsg(msg *dns.Msg) error { m.written = msg; return nil }
func (m *mockResponseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (m *mockResponseWriter) Close() error               { return nil }
func (m *mockResponseWriter) TsigStatus() error          { return nil }
func (m *mockResponseWriter) TsigTimersOnly(bool)        {}
func (m *mockResponseWriter) Hijack()                    {}

func newTestMsg() *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	return m
}

func TestHandlerFunc(t *testing.T) {
	called := false
	h := HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) { called = true })
	h.ServeDNS(&mockResponseWriter{}, newTestMsg())
	if !called {
		t.Fatal("handler was not called")
	}
}

func TestChain(t *testing.T) {
	order := []string{}
	mk := func(tag string) func(Handler) Handler {
		return func(next Handler) Handler {
			return HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
				order = append(order, tag)
				next.ServeDNS(w, r)
			})
		}
	}
	inner := HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) { order = append(order, "inner") })
	h := Chain(inner, mk("first"), mk("second"))
	h.ServeDNS(&mockResponseWriter{}, newTestMsg())
	// Middlewares should execute in the order they are passed to Chain,
	// with the inner handler running last.
	if len(order) != 3 {
		t.Fatalf("expected 3 entries in order, got %d: %v", len(order), order)
	}
	if order[0] != "first" || order[1] != "second" || order[2] != "inner" {
		t.Errorf("unexpected chain order: %v", order)
	}
}

func TestRecoveryMiddleware(t *testing.T) {
	panic_handler := HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		panic("intentional panic")
	})
	w := &mockResponseWriter{}
	RecoveryMiddleware(panic_handler).ServeDNS(w, newTestMsg())
	if w.written == nil {
		t.Fatal("expected SERVFAIL response after panic")
	}
	if w.written.Rcode != dns.RcodeServerFailure {
		t.Errorf("expected SERVFAIL, got rcode %d", w.written.Rcode)
	}
}

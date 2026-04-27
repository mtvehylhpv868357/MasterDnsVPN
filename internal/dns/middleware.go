package dns

import (
	"log"
	"time"

	"github.com/miekg/dns"
)

// Handler is the core interface for a DNS processing step.
type Handler interface {
	ServeDNS(w dns.ResponseWriter, r *dns.Msg)
}

// HandlerFunc is a function that implements Handler.
type HandlerFunc func(w dns.ResponseWriter, r *dns.Msg)

// ServeDNS implements Handler.
func (f HandlerFunc) ServeDNS(w dns.ResponseWriter, r *dns.Msg) { f(w, r) }

// Chain wraps inner with zero or more middleware layers (outermost first).
func Chain(inner Handler, mw ...func(Handler) Handler) Handler {
	for i := len(mw) - 1; i >= 0; i-- {
		inner = mw[i](inner)
	}
	return inner
}

// LoggingMiddleware logs every incoming query and the latency of the response.
func LoggingMiddleware(next Handler) Handler {
	return HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		start := time.Now()
		if len(r.Question) > 0 {
			q := r.Question[0]
			log.Printf("[dns] query name=%s type=%d class=%d",
				q.Name, q.Qtype, q.Qclass)
			defer func() {
				log.Printf("[dns] served name=%s latency=%s", q.Name, time.Since(start))
			}()
		}
		next.ServeDNS(w, r)
	})
}

// RecoveryMiddleware catches panics inside a handler and returns SERVFAIL.
func RecoveryMiddleware(next Handler) Handler {
	return HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("[dns] recovered from panic: %v", rec)
				m := new(dns.Msg)
				m.SetReply(r)
				m.Rcode = dns.RcodeServerFailure
				_ = w.WriteMsg(m)
			}
		}()
		next.ServeDNS(w, r)
	})
}

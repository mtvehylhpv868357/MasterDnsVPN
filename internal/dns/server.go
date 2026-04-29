// Package dns provides DNS resolution, caching, forwarding, and server functionality.
package dns

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

// ServerConfig holds configuration for the DNS server.
type ServerConfig struct {
	// ListenAddr is the address and port to listen on (e.g., "0.0.0.0:53").
	ListenAddr string
	// Network is the network type: "udp", "tcp", or "both".
	Network string
	// ReadTimeout is the timeout for reading a DNS message.
	ReadTimeout time.Duration
	// WriteTimeout is the timeout for writing a DNS response.
	WriteTimeout time.Duration
}

// DefaultServerConfig returns a ServerConfig with sensible defaults.
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		ListenAddr:   "0.0.0.0:53",
		Network:      "udp",
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}
}

// Server is a DNS server that handles incoming queries using a handler chain.
type Server struct {
	cfg        ServerConfig
	handler    dns.Handler
	udpServer  *dns.Server
	tcpServer  *dns.Server
}

// NewServer creates a new DNS Server with the given config and handler.
// If handler is nil, dns.DefaultServeMux is used.
func NewServer(cfg ServerConfig, handler dns.Handler) *Server {
	if handler == nil {
		handler = dns.DefaultServeMux
	}
	return &Server{
		cfg:     cfg,
		handler: handler,
	}
}

// Start begins listening for DNS queries.
// If cfg.Network is "both", both UDP and TCP servers are started.
// The method blocks until the context is cancelled or an error occurs.
func (s *Server) Start(ctx context.Context) error {
	errCh := make(chan error, 2)

	switch s.cfg.Network {
	case "udp", "":
		go s.serveNetwork(ctx, "udp", errCh)
	case "tcp":
		go s.serveNetwork(ctx, "tcp", errCh)
	case "both":
		go s.serveNetwork(ctx, "udp", errCh)
		go s.serveNetwork(ctx, "tcp", errCh)
	default:
		return fmt.Errorf("dns: unsupported network %q", s.cfg.Network)
	}

	select {
	case <-ctx.Done():
		return s.Shutdown()
	case err := <-errCh:
		_ = s.Shutdown()
		return err
	}
}

// serveNetwork starts a DNS server on the given network and sends any startup
// or runtime errors to errCh.
func (s *Server) serveNetwork(ctx context.Context, network string, errCh chan<- error) {
	srv := &dns.Server{
		Addr:         s.cfg.ListenAddr,
		Net:          network,
		Handler:      s.handler,
		ReadTimeout:  s.cfg.ReadTimeout,
		WriteTimeout: s.cfg.WriteTimeout,
	}

	if network == "udp" {
		s.udpServer = srv
	} else {
		s.tcpServer = srv
	}

	if err := srv.ListenAndServe(); err != nil {
		select {
		case <-ctx.Done():
			// Context cancelled; shutdown is expected.
		default:
			errCh <- fmt.Errorf("dns: %s server error: %w", network, err)
		}
	}
}

// Shutdown gracefully stops the DNS server(s).
func (s *Server) Shutdown() error {
	var firstErr error
	if s.udpServer != nil {
		if err := s.udpServer.Shutdown(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if s.tcpServer != nil {
		if err := s.tcpServer.Shutdown(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// ListenAddr returns the resolved listen address of the server.
// This is useful when the port was assigned dynamically (e.g., ":0").
func (s *Server) ListenAddr() string {
	if s.udpServer != nil && s.udpServer.PacketConn != nil {
		return s.udpServer.PacketConn.LocalAddr().String()
	}
	if s.tcpServer != nil && s.tcpServer.Listener != nil {
		return s.tcpServer.Listener.Addr().String()
	}
	return s.cfg.ListenAddr
}

// ParseListenAddr splits a listen address into host and port components.
func ParseListenAddr(addr string) (host, port string, err error) {
	return net.SplitHostPort(addr)
}

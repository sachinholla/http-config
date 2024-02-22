// Copyright 2024 Sachin Holla

package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"sync/atomic"
)

func logf(fmt string, args ...interface{}) {
	log.Printf("[DEBUG] "+fmt, args...)
}

// Server wraps a http.Server object and its configurations.
// Allows changing the server cert & CA cert dynamically.
// But all changes must be done from a single goroutine only.
type Server struct {
	serverCert atomic.Pointer[tls.Certificate]
	tlsConfig  atomic.Pointer[tls.Config]
	httpServer *http.Server
}

// NewServer creates a new Server object, without any cert configurations.
func NewServer() *Server {
	s := new(Server)
	s.tlsConfig.Store(&tls.Config{
		GetCertificate: s.getCert,
		ClientAuth:     tls.RequestClientCert,
		MinVersion:     tls.VersionTLS12,
	})
	return s
}

// GetCertificate impl to be set in the server tls.Config
func (s *Server) getCert(c *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert := s.serverCert.Load()
	logf("getCert: returning %p", cert)
	return cert, nil
}

// GetConfigForClient impl to be used in the server tls.Config
func (s *Server) getConf(c *tls.ClientHelloInfo) (*tls.Config, error) {
	config := s.tlsConfig.Load()
	logf("getConf: returning %p", config)
	return config, nil
}

// SetCert updates the server cert configuration from
// the given private key & cert PEM files.
// Subsequent connection requests will use this new server cert.
func (s *Server) SetCert(keyFile, crtFile string) error {
	logf("SetCert: keyFile=%s, crtFile=%s", keyFile, crtFile)
	cert, err := ParseKeyPair(keyFile, crtFile)
	if err != nil {
		return fmt.Errorf("SetCert error: %w", err)
	}

	logf("SetCert: store %p", &cert)
	s.serverCert.Store(&cert)
	return nil
}

// SetCA updates the CA cert configuration from the given cert PEM file.
// Passing an empty string will remove the CA cert configuration.
// Subsequent connection requests will be validated using this new CA cert.
func (s *Server) SetCA(caFile string) error {
	logf("SetCA: caFile=%s", caFile)
	var caPool *x509.CertPool
	if caFile != "" {
		cert, err := ParseCert(caFile)
		if err != nil {
			return fmt.Errorf("SetCA error: %w", err)
		}
		caPool = x509.NewCertPool()
		caPool.AddCert(cert.Leaf)
	}

	curConfig := s.tlsConfig.Load()
	newConfig := &tls.Config{
		ClientCAs:      caPool,
		GetCertificate: curConfig.GetCertificate,
		ClientAuth:     tls.RequestClientCert,
		MinVersion:     curConfig.MinVersion,
	}
	if caPool != nil {
		newConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	logf("SetCA: store %p", newConfig)
	s.tlsConfig.Store(newConfig)
	return nil
}

// Start the https server on given port.
// Server runs in a separate goroutine. Caller can use the returned
// channel object to monitor server stop/error status.
func (s *Server) Start(port int, handler http.Handler) chan error {
	cfg := &tls.Config{
		GetCertificate:     s.getCert,
		GetConfigForClient: s.getConf,
	}

	s.httpServer = &http.Server{
		Addr:      fmt.Sprintf(":%d", port),
		Handler:   withLogging(handler),
		TLSConfig: cfg,
	}

	stopChan := make(chan error, 1)
	go func() {
		logf("Starting server on %s ....", s.httpServer.Addr)
		stopChan <- s.httpServer.ListenAndServeTLS("", "")
	}()
	return stopChan
}

// Stop the https server if running.
func (s *Server) Stop() {
	if s.httpServer != nil {
		s.httpServer.Close()
		s.httpServer = nil
	}
}

// withLogging creates a request logging middleware
func withLogging(h http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logf("Received: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		h.ServeHTTP(w, r)
	}
}

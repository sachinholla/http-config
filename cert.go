// Copyright 2024 Sachin Holla

package main

// Certificate utilities

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// ParseCert parses the given peivate key and public certificate
// PEM files into a tls.Certificate object.
func ParseKeyPair(keyFile, crtFile string) (tls.Certificate, error) {
	if keyFile == "" || crtFile == "" {
		return tls.Certificate{}, nil
	}

	cert, err := tls.LoadX509KeyPair(crtFile, keyFile)
	if err != nil {
		return cert, fmt.Errorf("keypair load error: %w", err)
	}

	if len(cert.Certificate) == 0 {
		return cert, fmt.Errorf("cert file corrupted: %s", crtFile)
	}

	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return cert, fmt.Errorf("bad cert file %s: %w", crtFile, err)
	}

	return cert, nil
}

// ParseCert parses the given certificate PEM file into a
// tls.Certificate object (with Certificate and Leaf fields only).
func ParseCert(crtFile string) (tls.Certificate, error) {
	var cert tls.Certificate
	if crtFile == "" {
		return cert, nil
	}

	data, err := os.ReadFile(crtFile)
	if err != nil {
		return cert, fmt.Errorf("cert read error: %w", err)
	}

	for len(data) != 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" {
			continue
		}

		cert.Leaf, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return cert, fmt.Errorf("cert parse error: %w", err)
		}

		cert.Certificate = [][]byte{block.Bytes}
		return cert, nil
	}

	return cert, fmt.Errorf("not a cert file: %s", crtFile)
}

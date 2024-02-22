// Copyright 2024 Sachin Holla

package main_test

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	test "github.com/sachinholla/http-config"
)

var (
	serverPort = 12345
	messageGen = atomic.Uint64{}
)

func TestCertChange(t *testing.T) {
	x1 := parseCert(t, "testdata/x1_key.pem", "testdata/x1_crt.pem")
	x2 := parseCert(t, "testdata/x2_key.pem", "testdata/x2_crt.pem")
	y1 := parseCert(t, "testdata/y1_key.pem", "testdata/y1_crt.pem")
	y2 := parseCert(t, "testdata/y2_key.pem", "testdata/y2_crt.pem")

	// initialize server with x1 as server cert and no CA cert
	s := test.NewServer()
	if err := s.SetCert(x1.keyFile, x1.certFile); err != nil {
		t.Fatal("Failed to init ServerCert:", err)
	}

	startPingServer(t, s)
	c := certChangeTester{t: t}

	// Verify ping with default client cert
	c.verify(x1)
	c.verify(x1)

	// Change server cert to y1
	if err := s.SetCert(y1.keyFile, y1.certFile); err != nil {
		t.Fatal("Failed to change ServerCert:", err)
	}

	// Ping should continue to work and should see the new server cert
	c.verify(y1)

	// set caY as CA cert
	if err := s.SetCA("testdata/caY_crt.pem"); err != nil {
		t.Fatal(err)
	}

	// Ping should fail with default client cert
	c.verify(nil)

	// Use y2 as client cert, which is signed by caY; ping should work now
	c.setCert(y2)
	c.verify(y1)

	// Change CA cert to caX
	if err := s.SetCA("testdata/caX_crt.pem"); err != nil {
		t.Fatal("Failed to change CA cert:", err)
	}

	// Pings should fail again
	c.verify(nil)

	// Use x1 as client client.. Pings should work now
	c.setCert(x1)
	c.verify(y1)

	// Update the server cert to x2
	if err := s.SetCert(x2.keyFile, x2.certFile); err != nil {
		t.Fatal("Failed to update ServerCert 2nd time:", err)
	}

	// Pings should continue to work and see the new server cert
	c.verify(x2)
	c.verify(x2)

	// Change back the CA ceert to caY
	if err := s.SetCA("testdata/caY_crt.pem"); err != nil {
		t.Fatal("Failed to revert CA cert:", err)
	}

	// Pings should stop since due to client cert mismatch
	c.verify(nil)

	// Remove the CA cert
	if err := s.SetCA(""); err != nil {
		t.Fatal("Failed to remove CA cert:", err)
	}

	// Pings should start working now
	c.verify(x2)
}

func startPingServer(t *testing.T, s *test.Server) {
	t.Helper()
	pingHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(r.URL.Path))
	})
	stopChan := s.Start(serverPort, pingHandler)
	select {
	case <-time.After(2 * time.Second): //TODO have better way of ensuring server up
		t.Logf("Server started on port %d", serverPort)
	case err := <-stopChan:
		t.Fatalf("Server start failed: %T: %v", err, err)
	}
	t.Cleanup(s.Stop)
}

type certChangeTester struct {
	t *testing.T
	c []tls.Certificate
}

func (cw *certChangeTester) setCert(cert *Cert) {
	if cert != nil {
		cw.c = []tls.Certificate{cert.Certificate}
	} else {
		cw.c = nil
	}
}

func (cw *certChangeTester) verify(expServerCert *Cert) {
	cw.t.Helper()
	msg := fmt.Sprintf("msg%d", messageGen.Add(1))
	url := fmt.Sprintf("https://localhost:%d/%s", serverPort, msg)
	req, _ := http.NewRequest("GET", url, nil)

	cw.t.Logf("Request: GET %s", url)

	tx := http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates:       cw.c,
			InsecureSkipVerify: true,
		}}

	client := http.Client{Transport: &tx}
	res, err := client.Do(req)
	if err != nil {
		if expServerCert == nil {
			return
		}
		cw.t.Fatalf("Request error: %v", err)
	}

	peerCert := res.TLS.PeerCertificates[0]
	var data string
	if res.Body != nil {
		b, _ := io.ReadAll(res.Body)
		data = strings.TrimPrefix(string(b), "/")
	}

	cw.t.Logf(
		"Response: status=%d, data=%s, peer_cert=%v",
		res.StatusCode, data, certId(peerCert),
	)
	if expServerCert == nil || !expServerCert.Leaf.Equal(peerCert) {
		cw.t.Fatalf("Expecting cert: %v\nReceived: %v",
			certId(expServerCert.Leaf), certId(peerCert))
	}
	if res.StatusCode != http.StatusOK {
		cw.t.Fatalf("Http error: %d %s (%s)", res.StatusCode, res.Status, data)
	}
	if data != msg {
		cw.t.Fatalf("Expecting data: %s\nReceived: %s", msg, data)
	}
}

func certId(cert *x509.Certificate) string {
	if cert == nil || len(cert.Raw) == 0 {
		return "<null>"
	}
	return fmt.Sprint(cert.SerialNumber) // TODO use md5 hash of cert.Raw?
}

type Cert struct {
	keyFile  string
	certFile string
	tls.Certificate
}

func parseCert(t *testing.T, keyFile, certFile string) *Cert {
	cert, err := test.ParseKeyPair(keyFile, certFile)
	if err != nil || cert.Leaf == nil {
		t.Fatalf("Invalid cert {%s, %s}. err=%v", keyFile, certFile, err)
	}
	return &Cert{
		keyFile:     keyFile,
		certFile:    certFile,
		Certificate: cert,
	}
}

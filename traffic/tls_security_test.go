package traffic

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

// Local loopback fixtures only: no public test site or external network needed.
func TestLocalSecurityProxyRejectsUntrustedTLS(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil { t.Fatal(err) }
	addr := ln.Addr().String()
	_ = ln.Close()
	tr, err := Open(t.TempDir(), addr)
	if err != nil { t.Fatal(err) }
	defer tr.Close()
	started := make(chan error, 1)
	go func() { started <- tr.Start() }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, dialErr := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if dialErr == nil { _ = conn.Close(); break }
		select { case err := <-started: t.Fatalf("proxy start: %v", err); default: }
		if time.Now().After(deadline) { t.Fatal("proxy did not start") }
		time.Sleep(10 * time.Millisecond)
	}
	proxyURL, err := url.Parse("http://" + addr)
	if err != nil { t.Fatal(err) }
	roots := x509.NewCertPool()
	ca := tr.proxy.GetCertificate()
	roots.AddCert(&ca)
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		// Trust only ARTEX's local CA on the client side. This does NOT trust
		// the independently self-signed destination used below.
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "proxy-working") }))
	defer plain.Close()
	resp, err := client.Get(plain.URL)
	if err != nil { t.Fatalf("HTTP control failed: %v", err) }
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil || resp.StatusCode != 200 || string(body) != "proxy-working" {
		t.Fatalf("HTTP control: status=%d body=%q err=%v", resp.StatusCode, body, err)
	}
	var reached atomic.Int32
	untrusted := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		_, _ = io.WriteString(w, "must-not-reach")
	}))
	defer untrusted.Close()
	for range 2 {
		resp, err := client.Get(untrusted.URL)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode < 400 { t.Fatalf("untrusted HTTPS returned %d", resp.StatusCode) }
		}
		transport.CloseIdleConnections()
	}
	if reached.Load() != 0 { t.Fatalf("sent %d HTTP requests to an untrusted TLS server", reached.Load()) }
	if _, bypass := tr.pass.Load("127.0.0.1"); bypass { t.Fatal("certificate failure marked destination for passthrough") }
}

package traffic

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lqqyt2423/go-mitmproxy/cert"
)

// Local loopback fixtures only: no public test site or external network needed.
func TestLocalSecurityProxyRejectsUntrustedTLS(t *testing.T) {
	if trustedURL := os.Getenv("ARTEX_LOCAL_TLS_CONTROL"); trustedURL != "" {
		testLocalSecurityProxyTLS(t, trustedURL)
		return
	}
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		// Those platforms use the OS certificate store rather than this test's
		// SSL_CERT_FILE. Still exercise rejection without changing OS trust.
		testLocalSecurityProxyTLS(t, "")
		return
	}
	var reached atomic.Int32
	trusted := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		_, _ = io.WriteString(w, "trusted-control")
	}))
	defer trusted.Close()
	dir := t.TempDir()
	rootFile := filepath.Join(dir, "test-root.pem")
	if err := os.WriteFile(rootFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: trusted.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	// Go caches system roots process-wide. A fresh test subprocess makes this
	// trust fixture deterministic, independent of other tests, without adding
	// any CA to the host/runner OS certificate store.
	cmd := exec.Command(os.Args[0], "-test.run=^TestLocalSecurityProxyRejectsUntrustedTLS$")
	cmd.Env = append(os.Environ(), "ARTEX_LOCAL_TLS_CONTROL="+trusted.URL, "SSL_CERT_FILE="+rootFile, "SSL_CERT_DIR="+dir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("TLS controls failed: %v\n%s", err, out)
	}
	if reached.Load() != 1 {
		t.Fatalf("trusted TLS control received %d requests, want 1", reached.Load())
	}
}

func testLocalSecurityProxyTLS(t *testing.T, trustedURL string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	tr, err := Open(t.TempDir(), addr)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	started := make(chan error, 1)
	go func() { started <- tr.Start() }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, dialErr := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if dialErr == nil {
			_ = conn.Close()
			break
		}
		select {
		case err := <-started:
			t.Fatalf("proxy start: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("proxy did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	proxyURL, err := url.Parse("http://" + addr)
	if err != nil {
		t.Fatal(err)
	}
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
	if err != nil {
		t.Fatalf("HTTP control failed: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil || resp.StatusCode != 200 || string(body) != "proxy-working" {
		t.Fatalf("HTTP control: status=%d body=%q err=%v", resp.StatusCode, body, err)
	}
	if trustedURL != "" {
		resp, err := client.Get(trustedURL)
		if err != nil {
			t.Fatalf("trusted HTTPS control failed: %v", err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil || resp.StatusCode != 200 || string(body) != "trusted-control" {
			t.Fatalf("trusted HTTPS control: status=%d body=%q err=%v", resp.StatusCode, body, err)
		}
	}
	var reached atomic.Int32
	// Use an independent CA: httptest's default TLS certificate is shared by
	// test servers and is intentionally trusted for the positive control.
	unknownCA, err := cert.NewSelfSignCAMemory()
	if err != nil {
		t.Fatal(err)
	}
	unknownCert, err := unknownCA.GetCert("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	untrusted := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		_, _ = io.WriteString(w, "must-not-reach")
	}))
	untrusted.TLS = &tls.Config{Certificates: []tls.Certificate{*unknownCert}, MinVersion: tls.VersionTLS12}
	untrusted.StartTLS()
	defer untrusted.Close()
	for range 2 {
		resp, err := client.Get(untrusted.URL)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode < 400 {
				t.Fatalf("untrusted HTTPS returned %d", resp.StatusCode)
			}
		}
		transport.CloseIdleConnections()
	}
	if reached.Load() != 0 {
		t.Fatalf("sent %d HTTP requests to an untrusted TLS server", reached.Load())
	}
	if _, bypass := tr.pass.Load("127.0.0.1"); bypass {
		t.Fatal("certificate failure marked destination for passthrough")
	}
}

package egressauthd

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

// recordingAudit captures EgressEntry values for assertions.
type recordingAudit struct {
	mu      sync.Mutex
	entries []EgressEntry
}

func (r *recordingAudit) LogEgress(e EgressEntry) {
	r.mu.Lock()
	r.entries = append(r.entries, e)
	r.mu.Unlock()
}

func (r *recordingAudit) last() (EgressEntry, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.entries) == 0 {
		return EgressEntry{}, false
	}
	return r.entries[len(r.entries)-1], true
}

// startFakeUpstream returns a TLS test server that echoes the inbound
// Authorization header in a response header so the test can assert what
// the proxy injected. Its certificate is returned so the proxy can be
// told to trust it.
func startFakeUpstream(t *testing.T) (*httptest.Server, *x509.CertPool, string) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Seen-Authorization", r.Header.Get("Authorization"))
		w.Header().Set("X-Seen-Path", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "upstream-ok")
	}))
	t.Cleanup(srv.Close)

	pool := x509.NewCertPool()
	for _, c := range srv.TLS.Certificates {
		for _, der := range c.Certificate {
			if cert, err := x509.ParseCertificate(der); err == nil {
				pool.AddCert(cert)
			}
		}
	}
	host := mustHost(t, srv.URL)
	return srv, pool, host
}

// newEchoServer returns a plain-HTTP test server that echoes the inbound
// Authorization header and request path in response headers. It backs
// the loopback catch-all proxy test, where the upstream leg is plain
// HTTP so no upstream TLS trust is needed.
func newEchoServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Seen-Authorization", r.Header.Get("Authorization"))
		w.Header().Set("X-Seen-Path", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "upstream-ok")
	}))
}

func mustHost(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u.Host // host:port
}

// newProxyForTest builds and starts an actionProxy for the supplied
// config and action, returning the proxy and the action's HTTP client
// (configured to route through the proxy and trust its ephemeral CA).
func newProxyForTest(t *testing.T, cfg *Config, action *Action, broker BrokerClient, upstreamPool *x509.CertPool, audit AuditLogger) (*actionProxy, *http.Client) {
	t.Helper()
	cache := newTokenCache(broker, nil)
	proxy, err := newActionProxy(action, cfg, cache, audit, nil, &tls.Config{RootCAs: upstreamPool, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatalf("newActionProxy: %v", err)
	}
	// Bind on an OS-assigned port within a wide range by trying once;
	// the test only needs a single proxy so a direct net.Listen via
	// Start with port 0 is simplest.
	if err := proxy.Start(0); err != nil {
		t.Fatalf("proxy.Start: %v", err)
	}
	t.Cleanup(proxy.Close)

	proxyURL, err := url.Parse("http://" + proxy.listener.Addr().String())
	if err != nil {
		t.Fatalf("parse proxy url: %v", err)
	}

	// The action trusts the proxy's per-action ephemeral CA for the
	// MITM leaf certificates.
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(proxy.caCertPEM()) {
		t.Fatal("failed to add ephemeral CA to pool")
	}
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS12},
		},
	}
	return proxy, client
}

func TestProxy_AllowListedHostInjectsCredential(t *testing.T) {
	t.Parallel()
	_, upstreamPool, host := startFakeUpstream(t)

	cfg := &Config{EgressMode: EgressModeMITM, HostDestinationMap: map[string]string{
		hostnameOnly(host): "registry",
	}}
	action := &Action{ID: "a", Grant: "grant-1", ExpiresAt: time.Now().Add(time.Hour)}
	broker := &fakeBroker{tok: &MintedToken{Token: "minted-xyz", Scheme: "bearer", ExpiresAt: time.Now().Add(time.Hour)}}
	audit := &recordingAudit{}

	_, client := newProxyForTest(t, cfg, action, broker, upstreamPool, audit)

	resp, err := client.Get("https://" + host + "/v1/thing")
	if err != nil {
		t.Fatalf("GET via proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Seen-Authorization"); got != "Bearer minted-xyz" {
		t.Errorf("injected Authorization: got %q, want %q", got, "Bearer minted-xyz")
	}
	if e, ok := audit.last(); !ok || e.Decision != DecisionForwardedInjected {
		t.Errorf("audit decision: got %+v, want forwarded_injected", e)
	}
}

func TestProxy_NonAllowListedHostRejected(t *testing.T) {
	t.Parallel()
	_, upstreamPool, host := startFakeUpstream(t)

	// Map a DIFFERENT host so the upstream's host has no destination and
	// is failed closed.
	cfg := &Config{EgressMode: EgressModeMITM, HostDestinationMap: map[string]string{
		"some-other-host.example.com": "registry",
	}}
	action := &Action{ID: "a", Grant: "g", ExpiresAt: time.Now().Add(time.Hour)}
	broker := &fakeBroker{tok: &MintedToken{Token: "x", Scheme: "bearer"}}
	audit := &recordingAudit{}

	_, client := newProxyForTest(t, cfg, action, broker, upstreamPool, audit)

	resp, err := client.Get("https://" + host + "/denied")
	if err != nil {
		t.Fatalf("GET via proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status: got %d, want 403", resp.StatusCode)
	}
	if broker.callCount() != 0 {
		t.Errorf("broker should not be called for a denied host, got %d calls", broker.callCount())
	}
	if e, ok := audit.last(); !ok || e.Decision != DecisionDeniedHost {
		t.Errorf("audit decision: got %+v, want denied_host", e)
	}
}

func TestProxy_BrokerDownFailsClosed(t *testing.T) {
	t.Parallel()
	_, upstreamPool, host := startFakeUpstream(t)

	cfg := &Config{EgressMode: EgressModeMITM, HostDestinationMap: map[string]string{
		hostnameOnly(host): "registry",
	}}
	action := &Action{ID: "a", Grant: "g", ExpiresAt: time.Now().Add(time.Hour)}
	// Broker errors on every mint: the request must fail closed (no
	// forward), surfacing a 5xx rather than reaching the upstream.
	broker := &fakeBroker{err: fmt.Errorf("connection refused")}
	audit := &recordingAudit{}

	_, client := newProxyForTest(t, cfg, action, broker, upstreamPool, audit)

	resp, err := client.Get("https://" + host + "/needs-auth")
	if err != nil {
		t.Fatalf("GET via proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 500 {
		t.Fatalf("status: got %d, want 5xx (fail closed)", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Seen-Authorization"); got != "" {
		t.Errorf("request reached upstream despite broker failure (saw auth %q)", got)
	}
	if e, ok := audit.last(); !ok || e.Decision != DecisionFailClosedBroker {
		t.Errorf("audit decision: got %+v, want fail_closed_broker", e)
	}
}

func TestProxy_BrokerDeniedFailsClosedForbidden(t *testing.T) {
	t.Parallel()
	_, upstreamPool, host := startFakeUpstream(t)

	cfg := &Config{EgressMode: EgressModeMITM, HostDestinationMap: map[string]string{
		hostnameOnly(host): "registry",
	}}
	action := &Action{ID: "a", Grant: "g", ExpiresAt: time.Now().Add(time.Hour)}
	broker := &fakeBroker{err: ErrBrokerDenied}
	audit := &recordingAudit{}

	_, client := newProxyForTest(t, cfg, action, broker, upstreamPool, audit)

	resp, err := client.Get("https://" + host + "/needs-auth")
	if err != nil {
		t.Fatalf("GET via proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status: got %d, want 403 on broker deny", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Seen-Authorization"); got != "" {
		t.Errorf("request reached upstream despite broker deny (saw auth %q)", got)
	}
}

func TestProxy_TokenReusedAcrossRequests(t *testing.T) {
	t.Parallel()
	_, upstreamPool, host := startFakeUpstream(t)

	cfg := &Config{EgressMode: EgressModeMITM, HostDestinationMap: map[string]string{
		hostnameOnly(host): "registry",
	}}
	action := &Action{ID: "a", Grant: "g", ExpiresAt: time.Now().Add(time.Hour)}
	broker := &fakeBroker{tok: &MintedToken{Token: "reused", Scheme: "bearer", ExpiresAt: time.Now().Add(time.Hour)}}

	_, client := newProxyForTest(t, cfg, action, broker, upstreamPool, nil)

	for i := 0; i < 3; i++ {
		resp, err := client.Get("https://" + host + "/x")
		if err != nil {
			t.Fatalf("GET %d: %v", i, err)
		}
		_ = resp.Body.Close()
	}
	if broker.callCount() != 1 {
		t.Errorf("broker calls across 3 requests: got %d, want 1 (cache reuse)", broker.callCount())
	}
}

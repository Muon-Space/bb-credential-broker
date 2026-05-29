package egressauthd

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestControlServer_RegisterProxyAndTeardown drives the control API
// end to end over an in-memory handler: register an action, route a
// request through the returned proxy port (asserting the credential is
// injected), then deregister and confirm the proxy is gone.
func TestControlServer_RegisterProxyAndTeardown(t *testing.T) {
	t.Parallel()
	_, upstreamPool, host := startFakeUpstream(t)

	cfg := &Config{
		EgressMode: EgressModeMITM,
		// The port allocator iterates a [lo,hi] range; use a high
		// ephemeral range so binds succeed in CI.
		ProxyPortRange:     [2]int{20000, 20200},
		HostDestinationMap: map[string]string{hostnameOnly(host): "registry"},
	}

	broker := &fakeBroker{tok: &MintedToken{Token: "ctl-tok", Scheme: "bearer", ExpiresAt: time.Now().Add(time.Hour)}}
	cache := newTokenCache(broker, nil)
	cs := newControlServer(cfg, cache, &recordingAudit{}, nil, &tls.Config{RootCAs: upstreamPool, MinVersion: tls.VersionTLS12})
	handler := cs.Handler()

	// Register an action with its broker delegation grant.
	createBody, _ := json.Marshal(createActionRequest{
		Grant:     "grant-1",
		ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339),
	})
	rec := doRequest(t, handler, http.MethodPost, "/actions", createBody)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /actions: got %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	var created createActionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if created.ActionID == "" {
		t.Fatal("empty action_id")
	}
	if created.ProxyPort < 20000 || created.ProxyPort > 20200 {
		t.Fatalf("proxy_port %d outside configured range", created.ProxyPort)
	}
	// Contract C1: env carries HTTP(S)_PROXY pointing at the proxy port.
	wantProxy := fmt.Sprintf("http://127.0.0.1:%d", created.ProxyPort)
	if created.Env["HTTPS_PROXY"] != wantProxy || created.Env["HTTP_PROXY"] != wantProxy {
		t.Errorf("env proxy vars: got HTTP_PROXY=%q HTTPS_PROXY=%q, want %q",
			created.Env["HTTP_PROXY"], created.Env["HTTPS_PROXY"], wantProxy)
	}
	if !strings.Contains(created.Env["NO_PROXY"], "127.0.0.1") {
		t.Errorf("NO_PROXY should keep loopback direct, got %q", created.Env["NO_PROXY"])
	}
	if !strings.Contains(created.Env["EGRESS_AUTHD_CA_PEM"], "BEGIN CERTIFICATE") {
		t.Error("env should carry the per-action CA PEM for trust bootstrap")
	}

	// Route a request through the allocated proxy and confirm injection.
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM([]byte(created.Env["EGRESS_AUTHD_CA_PEM"])) {
		t.Fatal("failed to load CA PEM from env")
	}
	proxyURL := mustParseURL(t, wantProxy)
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS12},
		},
	}
	resp, err := client.Get("https://" + host + "/thing")
	if err != nil {
		t.Fatalf("GET via control-allocated proxy: %v", err)
	}
	if got := resp.Header.Get("X-Seen-Authorization"); got != "Bearer ctl-tok" {
		t.Errorf("injected auth: got %q, want %q", got, "Bearer ctl-tok")
	}
	_ = resp.Body.Close()

	// Deregister; the proxy listener must stop accepting.
	delRec := doRequest(t, handler, http.MethodDelete, "/actions/"+created.ActionID, nil)
	if delRec.Code != http.StatusOK {
		t.Fatalf("DELETE /actions/{id}: got %d, want 200", delRec.Code)
	}
	// Give the listener a moment to close, then a fresh dial should fail.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, derr := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", created.ProxyPort), 100*time.Millisecond)
		if derr != nil {
			return // success: proxy is gone
		}
		_ = c.Close()
		time.Sleep(50 * time.Millisecond)
	}
	t.Errorf("proxy port %d still accepting after DELETE", created.ProxyPort)
}

// TestControlServer_RejectsMissingGrant confirms registration fails fast
// when the worker does not supply a delegation grant: the sidecar has no
// authority to relay to /token without it.
func TestControlServer_RejectsMissingGrant(t *testing.T) {
	t.Parallel()
	cfg := &Config{
		ProxyPortRange:     [2]int{20300, 20400},
		HostDestinationMap: map[string]string{"x": "dest"},
	}
	cs := newControlServer(cfg, newTokenCache(&fakeBroker{}, nil), nil, nil, &tls.Config{MinVersion: tls.VersionTLS12})
	handler := cs.Handler()

	body, _ := json.Marshal(createActionRequest{ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)})
	rec := doRequest(t, handler, http.MethodPost, "/actions", body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400 for missing grant", rec.Code)
	}
}

// doRequest is a tiny helper that runs a request against a handler and
// returns the recorder.
func doRequest(t *testing.T, h http.Handler, method, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body != nil {
		r = httptest.NewRequest(method, path, bytes.NewReader(body))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

// mustParseURL parses raw or fails the test.
func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}

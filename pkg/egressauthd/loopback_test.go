package egressauthd

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// newLoopbackProxyForTest builds and starts a loopback-mode actionProxy
// and returns a plain-HTTP client that talks to the loopback listener
// directly (no proxy, no MITM CA). The upstream pool is the TLS trust
// the proxy uses to dial the real upstream.
func newLoopbackProxyForTest(t *testing.T, cfg *Config, action *Action, broker BrokerClient, upstreamPool *x509.CertPool, audit AuditLogger) (*actionProxy, *http.Client, string) {
	t.Helper()
	cfg.EgressMode = EgressModeLoopback
	cache := newTokenCache(broker, nil)
	proxy, err := newActionProxy(action, cfg, cache, audit, nil, &tls.Config{RootCAs: upstreamPool, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatalf("newActionProxy: %v", err)
	}
	if proxy.ca != nil {
		t.Fatal("loopback mode must not allocate an ephemeral CA")
	}
	if err := proxy.Start(0); err != nil {
		t.Fatalf("proxy.Start: %v", err)
	}
	t.Cleanup(proxy.Close)

	base := "http://" + proxy.listener.Addr().String()
	// Plain-HTTP client to the loopback listener; no proxy configured.
	client := &http.Client{Timeout: 10 * time.Second}
	return proxy, client, base
}

func TestLoopback_MappedDestinationInjectsAndForwards(t *testing.T) {
	t.Parallel()
	_, upstreamPool, host := startFakeUpstream(t)

	cfg := &Config{HostDestinationMap: map[string]string{host: "registry-pypi"}}
	action := &Action{ID: "a", Grant: "grant-1", ExpiresAt: time.Now().Add(time.Hour)}
	broker := &fakeBroker{tok: &MintedToken{Token: "minted-xyz", Scheme: "bearer", ExpiresAt: time.Now().Add(time.Hour)}}
	audit := &recordingAudit{}

	_, client, base := newLoopbackProxyForTest(t, cfg, action, broker, upstreamPool, audit)

	// Request the destination route; the proxy strips the destination
	// prefix and forwards the remainder over TLS to the upstream.
	resp, err := client.Get(base + "/registry-pypi/simple/foo/")
	if err != nil {
		t.Fatalf("GET via loopback: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Seen-Authorization"); got != "Bearer minted-xyz" {
		t.Errorf("injected Authorization: got %q, want %q", got, "Bearer minted-xyz")
	}
	if got := resp.Header.Get("X-Seen-Path"); got != "/simple/foo/" {
		t.Errorf("forwarded path: got %q, want /simple/foo/ (destination prefix stripped)", got)
	}
	if e, ok := audit.last(); !ok || e.Decision != DecisionForwardedInjected {
		t.Errorf("audit decision: got %+v, want forwarded_injected", e)
	}
}

func TestLoopback_BasePathPrependedToUpstream(t *testing.T) {
	t.Parallel()
	_, upstreamPool, host := startFakeUpstream(t)

	cfg := &Config{
		HostDestinationMap: map[string]string{host: "registry-pypi"},
		HostToolMap:        map[string]string{host: ToolPyPI},
		// A registry's virtual PyPI repo base path; the reverse-proxy
		// must prepend it to the (prefix-stripped) request path.
		HostBasePathMap: map[string]string{host: "/api/pypi/index/simple"},
	}
	action := &Action{ID: "a", Grant: "g", ExpiresAt: time.Now().Add(time.Hour)}
	broker := &fakeBroker{tok: &MintedToken{Token: "t", Scheme: "bearer", ExpiresAt: time.Now().Add(time.Hour)}}
	audit := &recordingAudit{}

	_, client, base := newLoopbackProxyForTest(t, cfg, action, broker, upstreamPool, audit)

	// uv would request <route>/<pkg>/; the proxy strips /registry-pypi
	// and prepends the base path.
	resp, err := client.Get(base + "/registry-pypi/requests/")
	if err != nil {
		t.Fatalf("GET via loopback: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if got, want := resp.Header.Get("X-Seen-Path"), "/api/pypi/index/simple/requests/"; got != want {
		t.Errorf("forwarded path: got %q, want %q", got, want)
	}
	if got := resp.Header.Get("X-Seen-Authorization"); got != "Bearer t" {
		t.Errorf("injected auth: got %q, want Bearer t", got)
	}
}

// TestLoopback_SharedBrokerDestinationMintsOnceAndUsesBrokerDestination
// drives two distinct loopback prefixes (registry-pypi and
// registry-cargo) that share one broker destination ("registry")
// through the reverse-proxy. It asserts the mint is keyed on the broker
// destination: the broker is called exactly once (the second tool reuses
// the cached token) and the MintRequest carried the broker destination,
// not the per-tool loopback prefix.
func TestLoopback_SharedBrokerDestinationMintsOnceAndUsesBrokerDestination(t *testing.T) {
	t.Parallel()
	_, upstreamPool, host := startFakeUpstream(t)

	cfg := &Config{
		Routes: []Route{
			{Host: host, Destination: "registry-pypi", BrokerDestination: "registry", Tool: ToolPyPI},
			{Host: host, Destination: "registry-cargo", BrokerDestination: "registry", Tool: ToolCargo},
		},
	}
	action := &Action{ID: "a", Grant: "grant-1", ExpiresAt: time.Now().Add(time.Hour)}
	broker := &fakeBroker{tok: &MintedToken{Token: "shared-tok", Scheme: "bearer", ExpiresAt: time.Now().Add(time.Hour)}}
	audit := &recordingAudit{}

	_, client, base := newLoopbackProxyForTest(t, cfg, action, broker, upstreamPool, audit)

	// First tool route: mints for the broker destination.
	resp, err := client.Get(base + "/registry-pypi/simple/foo/")
	if err != nil {
		t.Fatalf("GET pypi route: %v", err)
	}
	if got := resp.Header.Get("X-Seen-Authorization"); got != "Bearer shared-tok" {
		t.Errorf("pypi injected auth: got %q, want Bearer shared-tok", got)
	}
	_ = resp.Body.Close()

	// Second, DIFFERENT loopback prefix sharing the broker destination:
	// must reuse the cached token (no second mint).
	resp, err = client.Get(base + "/registry-cargo/crates/bar")
	if err != nil {
		t.Fatalf("GET cargo route: %v", err)
	}
	if got := resp.Header.Get("X-Seen-Authorization"); got != "Bearer shared-tok" {
		t.Errorf("cargo injected auth: got %q, want Bearer shared-tok", got)
	}
	_ = resp.Body.Close()

	if broker.callCount() != 1 {
		t.Errorf("broker mints across two tool routes sharing a broker destination: got %d, want 1", broker.callCount())
	}
	// The mint was keyed on the broker destination, not the loopback prefix.
	if got := broker.lastRequest(); got.Destination != "registry" {
		t.Errorf("mint destination: got %q, want registry (the broker destination, not a loopback prefix)", got.Destination)
	}
	// Audit/metrics label is the broker destination.
	if e, ok := audit.last(); !ok || e.Destination != "registry" {
		t.Errorf("audit destination label: got %+v, want registry", e)
	}
}

func TestLoopback_UnknownDestinationRejected(t *testing.T) {
	t.Parallel()
	_, upstreamPool, host := startFakeUpstream(t)

	cfg := &Config{HostDestinationMap: map[string]string{host: "registry-pypi"}}
	action := &Action{ID: "a", Grant: "g", ExpiresAt: time.Now().Add(time.Hour)}
	broker := &fakeBroker{tok: &MintedToken{Token: "x", Scheme: "bearer"}}
	audit := &recordingAudit{}

	_, client, base := newLoopbackProxyForTest(t, cfg, action, broker, upstreamPool, audit)

	// A destination prefix that is not mapped must be refused with 403
	// and never reach the broker or upstream.
	resp, err := client.Get(base + "/some-other-dest/v1/thing")
	if err != nil {
		t.Fatalf("GET via loopback: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status: got %d, want 403", resp.StatusCode)
	}
	if broker.callCount() != 0 {
		t.Errorf("broker should not be called for an unmapped destination, got %d", broker.callCount())
	}
	if e, ok := audit.last(); !ok || e.Decision != DecisionDeniedHost {
		t.Errorf("audit decision: got %+v, want denied_host", e)
	}
}

func TestLoopback_BrokerDownFailsClosed(t *testing.T) {
	t.Parallel()
	_, upstreamPool, host := startFakeUpstream(t)

	cfg := &Config{HostDestinationMap: map[string]string{host: "registry-pypi"}}
	action := &Action{ID: "a", Grant: "g", ExpiresAt: time.Now().Add(time.Hour)}
	broker := &fakeBroker{err: fmt.Errorf("connection refused")}
	audit := &recordingAudit{}

	_, client, base := newLoopbackProxyForTest(t, cfg, action, broker, upstreamPool, audit)

	resp, err := client.Get(base + "/registry-pypi/needs-auth")
	if err != nil {
		t.Fatalf("GET via loopback: %v", err)
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

func TestLoopback_BrokerDeniedFailsClosedForbidden(t *testing.T) {
	t.Parallel()
	_, upstreamPool, host := startFakeUpstream(t)

	cfg := &Config{HostDestinationMap: map[string]string{host: "registry-pypi"}}
	action := &Action{ID: "a", Grant: "g", ExpiresAt: time.Now().Add(time.Hour)}
	broker := &fakeBroker{err: ErrBrokerDenied}
	audit := &recordingAudit{}

	_, client, base := newLoopbackProxyForTest(t, cfg, action, broker, upstreamPool, audit)

	resp, err := client.Get(base + "/registry-pypi/needs-auth")
	if err != nil {
		t.Fatalf("GET via loopback: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status: got %d, want 403 on broker deny", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Seen-Authorization"); got != "" {
		t.Errorf("request reached upstream despite broker deny (saw auth %q)", got)
	}
}

// TestLoopback_ControlEnvReturnsLoopbackURLs drives the control API in
// loopback mode and asserts the returned env points the pip/uv tools at
// the per-destination loopback route, sets the catch-all proxy, and
// drops the MITM CA PEM.
func TestLoopback_ControlEnvReturnsLoopbackURLs(t *testing.T) {
	t.Parallel()
	cfg := &Config{
		EgressMode:         EgressModeLoopback,
		ProxyPortRange:     [2]int{21000, 21200},
		HostDestinationMap: map[string]string{"registry.example.com": "registry-pypi"},
		HostToolMap:        map[string]string{"registry.example.com": ToolPyPI},
	}
	broker := &fakeBroker{tok: &MintedToken{Token: "t", Scheme: "bearer", ExpiresAt: time.Now().Add(time.Hour)}}
	cs := newControlServer(cfg, newTokenCache(broker, nil), &recordingAudit{}, nil, &tls.Config{MinVersion: tls.VersionTLS12})
	handler := cs.Handler()

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

	base := fmt.Sprintf("http://127.0.0.1:%d", created.ProxyPort)
	wantRoute := base + "/registry-pypi"

	// Catch-all proxy points at the loopback base.
	if created.Env["HTTP_PROXY"] != base || created.Env["HTTPS_PROXY"] != base {
		t.Errorf("catch-all proxy: got HTTP_PROXY=%q HTTPS_PROXY=%q, want %q",
			created.Env["HTTP_PROXY"], created.Env["HTTPS_PROXY"], base)
	}
	// Per-tool index overrides point at the per-destination route.
	for _, key := range []string{"UV_DEFAULT_INDEX", "UV_INDEX", "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL"} {
		if created.Env[key] != wantRoute {
			t.Errorf("%s: got %q, want %q", key, created.Env[key], wantRoute)
		}
	}
	// The MITM CA PEM must be absent in loopback mode.
	if _, ok := created.Env["EGRESS_AUTHD_CA_PEM"]; ok {
		t.Error("EGRESS_AUTHD_CA_PEM must not be set in loopback mode")
	}
	// No files for a pure-pypi mapping (pypi is env-only).
	if len(created.Files) != 0 {
		t.Errorf("files: got %v, want none for pypi-only mapping", created.Files)
	}
}

// TestLoopback_ControlEnvReturnsConfigFiles asserts that cargo, docker
// and git tags produce written config files (env alone is insufficient)
// while pypi stays env-only.
func TestLoopback_ControlEnvReturnsConfigFiles(t *testing.T) {
	t.Parallel()
	cfg := &Config{
		EgressMode:     EgressModeLoopback,
		ProxyPortRange: [2]int{21300, 21500},
		HostDestinationMap: map[string]string{
			"cargo.example.com":    "registry-cargo",
			"registry.example.com": "registry-docker",
			"git.example.com":      "git-host",
		},
		HostToolMap: map[string]string{
			"cargo.example.com":    ToolCargo,
			"registry.example.com": ToolDocker,
			"git.example.com":      ToolGit,
		},
	}
	broker := &fakeBroker{tok: &MintedToken{Token: "t", Scheme: "bearer", ExpiresAt: time.Now().Add(time.Hour)}}
	cs := newControlServer(cfg, newTokenCache(broker, nil), &recordingAudit{}, nil, &tls.Config{MinVersion: tls.VersionTLS12})
	handler := cs.Handler()

	createBody, _ := json.Marshal(createActionRequest{Grant: "g"})
	rec := doRequest(t, handler, http.MethodPost, "/actions", createBody)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /actions: got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var created createActionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode: %v", err)
	}

	byPath := map[string]string{}
	for _, f := range created.Files {
		byPath[f.Path] = f.Contents
	}
	cargo, ok := byPath[".cargo/config.toml"]
	if !ok {
		t.Fatalf("expected a cargo config file; got files %v", keysOf(byPath))
	}
	if !strings.Contains(cargo, "replace-with") || !strings.Contains(cargo, "/registry-cargo") {
		t.Errorf("cargo config does not redirect to the loopback route: %s", cargo)
	}
	docker, ok := byPath[".config/containers/registries.conf"]
	if !ok {
		t.Fatalf("expected a docker registries.conf; got files %v", keysOf(byPath))
	}
	if !strings.Contains(docker, "registry.example.com") || !strings.Contains(docker, "/registry-docker") {
		t.Errorf("docker config does not mirror the upstream to the loopback route: %s", docker)
	}
	git, ok := byPath[".gitconfig"]
	if !ok {
		t.Fatalf("expected a gitconfig; got files %v", keysOf(byPath))
	}
	if !strings.Contains(git, "insteadOf") || !strings.Contains(git, "https://git.example.com/") {
		t.Errorf("gitconfig does not rewrite the upstream: %s", git)
	}
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestLoopback_CatchAllPlainHTTPProxy confirms that an absolute-form
// request through the catch-all HTTP_PROXY (a tool not pointed at a
// per-tool override) is still gated by the host mapping and injected by
// host.
func TestLoopback_CatchAllPlainHTTPProxy(t *testing.T) {
	t.Parallel()
	// A plain-HTTP upstream so the catch-all proxy path (which dials the
	// absolute-URL host) can be exercised without TLS on the upstream.
	upstream, host := startFakePlainUpstream(t)
	_ = upstream

	cfg := &Config{EgressMode: EgressModeLoopback, HostDestinationMap: map[string]string{
		hostnameOnly(host): "registry",
	}}
	action := &Action{ID: "a", Grant: "g", ExpiresAt: time.Now().Add(time.Hour)}
	broker := &fakeBroker{tok: &MintedToken{Token: "catchall", Scheme: "bearer", ExpiresAt: time.Now().Add(time.Hour)}}
	audit := &recordingAudit{}

	proxy, _, _ := newLoopbackProxyForTest(t, cfg, action, broker, x509.NewCertPool(), audit)

	proxyURL := mustParseURL(t, "http://"+proxy.listener.Addr().String())
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}
	resp, err := client.Get("http://" + host + "/thing")
	if err != nil {
		t.Fatalf("GET via catch-all proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if got := resp.Header.Get("X-Seen-Authorization"); got != "Bearer catchall" {
		t.Errorf("injected auth via catch-all: got %q, want %q", got, "Bearer catchall")
	}
}

// startFakePlainUpstream returns a plain-HTTP test server that echoes
// the inbound Authorization and path, for the catch-all proxy test.
func startFakePlainUpstream(t *testing.T) (string, string) {
	t.Helper()
	srv := newEchoServer()
	t.Cleanup(srv.Close)
	return srv.URL, mustHost(t, srv.URL)
}

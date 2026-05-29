package egressauthd

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// fakeBroker is a BrokerClient that records calls and returns a
// configured token or error. It backs the token-cache and proxy tests.
type fakeBroker struct {
	mu    sync.Mutex
	calls int
	tok   *MintedToken
	err   error
	// lastReq records the most recent MintRequest so tests can assert
	// the grant was relayed.
	lastReq MintRequest
}

func (b *fakeBroker) Mint(_ context.Context, req MintRequest) (*MintedToken, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls++
	b.lastReq = req
	if b.err != nil {
		return nil, b.err
	}
	return b.tok, nil
}

func (b *fakeBroker) callCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.calls
}

func (b *fakeBroker) lastRequest() MintRequest {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.lastReq
}

func TestConfig_Validate(t *testing.T) {
	t.Parallel()
	base := func() *Config {
		//nolint:gosec // G101: these are file paths and URLs, not credential literals.
		return &Config{
			BrokerTokenURL: "https://broker.example.com",
			ListenSocket:   "/var/run/egress-authd/control.sock",
			ProxyPortRange: [2]int{15000, 15100},
			HostDestinationMap: map[string]string{
				"registry.example.com": "registry",
			},
			HostToolMap:     map[string]string{},
			HostBasePathMap: map[string]string{},
		}
	}

	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{name: "valid", mutate: func(*Config) {}},
		{name: "explicit loopback mode", mutate: func(c *Config) { c.EgressMode = EgressModeLoopback }},
		{name: "explicit mitm mode", mutate: func(c *Config) { c.EgressMode = EgressModeMITM }},
		{name: "invalid egress mode", mutate: func(c *Config) { c.EgressMode = "transparent" }, wantErr: true},
		{
			name: "valid host_tool_map",
			mutate: func(c *Config) {
				c.HostToolMap["registry.example.com"] = ToolPyPI
			},
		},
		{
			name: "unknown tool tag",
			mutate: func(c *Config) {
				c.HostToolMap["registry.example.com"] = "conda"
			},
			wantErr: true,
		},
		{
			name: "tool tag for unmapped host",
			mutate: func(c *Config) {
				c.HostToolMap["mirror.example.com"] = ToolPyPI
			},
			wantErr: true,
		},
		{
			name: "valid base path",
			mutate: func(c *Config) {
				c.HostBasePathMap["registry.example.com"] = "/api/pypi/index/simple"
			},
		},
		{
			name: "base path for unmapped host",
			mutate: func(c *Config) {
				c.HostBasePathMap["nope.example.com"] = "/x"
			},
			wantErr: true,
		},
		{
			name: "multi-tool routes on one host",
			mutate: func(c *Config) {
				// A registry serving pypi + cargo + docker: three
				// routes share the host AND one broker destination, with
				// distinct loopback prefixes (Destination).
				c.HostDestinationMap = nil
				c.HostToolMap = nil
				c.HostBasePathMap = nil
				c.Routes = []Route{
					{Host: "registry.example.com", Destination: "registry-pypi", BrokerDestination: "registry", Tool: ToolPyPI, BasePath: "/api/pypi/index/simple"},
					{Host: "registry.example.com", Destination: "registry-cargo", BrokerDestination: "registry", Tool: ToolCargo},
					{Host: "registry.example.com", Destination: "registry-docker", BrokerDestination: "registry", Tool: ToolDocker},
				}
			},
		},
		{
			name: "shared broker_destination across distinct destinations is allowed",
			mutate: func(c *Config) {
				// BrokerDestination repeats ("registry") while Destination
				// (the loopback prefix) stays unique: this MUST validate, it
				// is the whole point of the split.
				c.HostDestinationMap = nil
				c.HostToolMap = nil
				c.HostBasePathMap = nil
				c.Routes = []Route{
					{Host: "a.example.com", Destination: "reg-pypi", BrokerDestination: "registry", Tool: ToolPyPI},
					{Host: "a.example.com", Destination: "reg-cargo", BrokerDestination: "registry", Tool: ToolCargo},
				}
			},
		},
		{
			name: "duplicate destination rejected even with distinct broker_destination",
			mutate: func(c *Config) {
				// Destination (loopback prefix) collides; broker destinations
				// differ. Still rejected: the prefix lookup would be
				// ambiguous.
				c.HostDestinationMap = nil
				c.Routes = []Route{
					{Host: "a.example.com", Destination: "dup", BrokerDestination: "registry", Tool: ToolPyPI},
					{Host: "b.example.com", Destination: "dup", BrokerDestination: "git-host", Tool: ToolGit},
				}
			},
			wantErr: true,
		},
		{
			name: "route missing destination",
			mutate: func(c *Config) {
				c.Routes = []Route{{Host: "x.example.com", Tool: ToolPyPI}}
			},
			wantErr: true,
		},
		{
			name: "route unknown tool",
			mutate: func(c *Config) {
				c.Routes = []Route{{Host: "x.example.com", Destination: "x", Tool: "conda"}}
			},
			wantErr: true,
		},
		{
			name: "duplicate destination across routes",
			mutate: func(c *Config) {
				// Same destination on two routes makes the loopback
				// path-prefix lookup ambiguous; reject it.
				c.HostDestinationMap = map[string]string{"a.example.com": "dup"}
				c.Routes = []Route{{Host: "b.example.com", Destination: "dup", Tool: ToolPyPI}}
			},
			wantErr: true,
		},
		{name: "missing broker token url", mutate: func(c *Config) { c.BrokerTokenURL = "" }, wantErr: true},
		{name: "relative broker token url", mutate: func(c *Config) { c.BrokerTokenURL = "broker" }, wantErr: true},
		{name: "missing socket", mutate: func(c *Config) { c.ListenSocket = "" }, wantErr: true},
		{name: "inverted port range", mutate: func(c *Config) { c.ProxyPortRange = [2]int{200, 100} }, wantErr: true},
		{name: "port out of range", mutate: func(c *Config) { c.ProxyPortRange = [2]int{1, 70000} }, wantErr: true},
		{
			name: "no host mapped at all",
			mutate: func(c *Config) {
				c.HostDestinationMap = nil
				c.Routes = nil
			},
			wantErr: true,
		},
		{
			name: "empty destination in map",
			mutate: func(c *Config) {
				c.HostDestinationMap["x"] = ""
			},
			wantErr: true,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := base()
			tc.mutate(c)
			err := c.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("err: got %v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestConfig_AllowedHostAndDestination(t *testing.T) {
	t.Parallel()
	c := &Config{
		HostDestinationMap: map[string]string{"registry.example.com": "registry"},
	}

	if !c.allowedHost("registry.example.com") {
		t.Error("expected registry host to be allowed")
	}
	if c.allowedHost("evil.example.com") {
		t.Error("expected non-mapped host to be denied")
	}

	dest, ok := c.destinationForHost("registry.example.com")
	if !ok || dest != "registry" {
		t.Errorf("destinationForHost: got (%q,%v), want (registry,true)", dest, ok)
	}
	// A host with no route reports no destination (fail closed).
	if _, ok := c.destinationForHost("mirror.example.com"); ok {
		t.Error("expected unmapped host to report no destination")
	}
}

// TestConfig_MultiToolRoutesResolveDistinctly confirms a host serving
// several tools yields one upstream per loopback prefix (Destination),
// each with its own tool tag and base path, all sharing one broker
// destination, and that the host-level default broker destination is the
// shared value.
func TestConfig_MultiToolRoutesResolveDistinctly(t *testing.T) {
	t.Parallel()
	c := &Config{
		Routes: []Route{
			{Host: "registry.example.com", Destination: "reg-pypi", BrokerDestination: "registry", Tool: ToolPyPI, BasePath: "/api/pypi/pypi/simple"},
			{Host: "registry.example.com", Destination: "reg-cargo", BrokerDestination: "registry", Tool: ToolCargo, BasePath: "/api/cargo/cargo"},
			{Host: "registry.example.com", Destination: "reg-docker", BrokerDestination: "registry", Tool: ToolDocker},
		},
	}

	if !c.allowedHost("registry.example.com") {
		t.Fatal("multi-tool host should be allowed")
	}
	// Each loopback prefix resolves to the same host but its own tool/base
	// path, and all share the one broker destination.
	pypi, ok := c.upstreamForDestination("reg-pypi")
	if !ok || pypi.Tool != ToolPyPI || pypi.BasePath != "/api/pypi/pypi/simple" || pypi.BrokerDestination != "registry" {
		t.Errorf("reg-pypi route: got %+v", pypi)
	}
	cargo, ok := c.upstreamForDestination("reg-cargo")
	if !ok || cargo.Tool != ToolCargo || cargo.BasePath != "/api/cargo/cargo" || cargo.BrokerDestination != "registry" {
		t.Errorf("reg-cargo route: got %+v", cargo)
	}
	docker, ok := c.upstreamForDestination("reg-docker")
	if !ok || docker.Tool != ToolDocker || docker.BrokerDestination != "registry" {
		t.Errorf("reg-docker route: got %+v", docker)
	}
	// Host-level default (catch-all path) is the shared broker destination,
	// not a loopback prefix.
	if dest, ok := c.destinationForHost("registry.example.com"); !ok || dest != "registry" {
		t.Errorf("host default broker destination: got (%q,%v), want (registry,true)", dest, ok)
	}
	if n := len(c.mappedUpstreams()); n != 3 {
		t.Errorf("mappedUpstreams: got %d, want 3", n)
	}
}

// TestConfig_BrokerDestinationDefaultsToDestination confirms a route (or
// flat host map entry) with no explicit broker_destination falls back to
// using Destination as the broker destination — the single-tool case
// where the loopback prefix and broker destination coincide.
func TestConfig_BrokerDestinationDefaultsToDestination(t *testing.T) {
	t.Parallel()
	c := &Config{
		Routes: []Route{
			{Host: "git.example.com", Destination: "git-host", Tool: ToolGit}, // no broker_destination
		},
		HostDestinationMap: map[string]string{"pkg.example.com": "registry"},
	}
	// Route with no broker_destination: defaults to Destination.
	if dest, ok := c.destinationForHost("git.example.com"); !ok || dest != "git-host" {
		t.Errorf("route default: got (%q,%v), want (git-host,true)", dest, ok)
	}
	gitHost, ok := c.upstreamForDestination("git-host")
	if !ok || gitHost.BrokerDestination != "git-host" {
		t.Errorf("route upstream broker destination: got %+v, want BrokerDestination=git-host", gitHost)
	}
	// Flat map entry: loopback prefix and broker destination coincide.
	if dest, ok := c.destinationForHost("pkg.example.com"); !ok || dest != "registry" {
		t.Errorf("flat-map default: got (%q,%v), want (registry,true)", dest, ok)
	}
	reg, ok := c.upstreamForDestination("registry")
	if !ok || reg.BrokerDestination != "registry" || reg.Destination != "registry" {
		t.Errorf("flat-map upstream: got %+v", reg)
	}
}

func TestActionRegistry_TTLEviction(t *testing.T) {
	t.Parallel()
	var evicted []string
	var mu sync.Mutex
	reg := newActionRegistry(func(a *Action) {
		mu.Lock()
		evicted = append(evicted, a.ID)
		mu.Unlock()
	})

	now := time.Now()
	reg.now = func() time.Time { return now }

	live := &Action{ID: "live", ExpiresAt: now.Add(time.Hour)}
	expiring := &Action{ID: "expiring", ExpiresAt: now.Add(time.Minute)}
	reg.Add(live)
	reg.Add(expiring)

	// Before expiry both are gettable.
	if _, ok := reg.Get("expiring"); !ok {
		t.Fatal("expiring action should be live before TTL")
	}

	// Advance past the expiring action's TTL: Get fails closed even
	// before the sweeper runs.
	now = now.Add(2 * time.Minute)
	if _, ok := reg.Get("expiring"); ok {
		t.Error("expired action should not be gettable")
	}
	if _, ok := reg.Get("live"); !ok {
		t.Error("live action should still be gettable")
	}

	// Sweep removes and evicts the expired one only.
	swept := reg.sweepExpired()
	if swept != 1 {
		t.Errorf("swept: got %d, want 1", swept)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(evicted) != 1 || evicted[0] != "expiring" {
		t.Errorf("evicted: got %v, want [expiring]", evicted)
	}
}

func TestActionRegistry_DeleteEvicts(t *testing.T) {
	t.Parallel()
	var evicted []string
	reg := newActionRegistry(func(a *Action) { evicted = append(evicted, a.ID) })
	reg.Add(&Action{ID: "a", ExpiresAt: time.Now().Add(time.Hour)})

	if !reg.Delete("a") {
		t.Fatal("Delete should report the action was present")
	}
	if reg.Delete("a") {
		t.Error("second Delete should report absent")
	}
	if len(evicted) != 1 || evicted[0] != "a" {
		t.Errorf("evicted: got %v, want [a]", evicted)
	}
}

func TestTokenCache_ReuseAndRefresh(t *testing.T) {
	t.Parallel()
	now := time.Now()
	broker := &fakeBroker{tok: &MintedToken{Token: "t1", Scheme: "bearer", ExpiresAt: now.Add(time.Hour)}}
	cache := newTokenCache(broker, nil)
	cache.now = func() time.Time { return now }

	action := &Action{ID: "a", Grant: "grant-1", ExpiresAt: now.Add(2 * time.Hour)}

	// First call mints.
	tok, err := cache.Get(context.Background(), action, "registry")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if tok.Token != "t1" {
		t.Fatalf("token: got %q, want t1", tok.Token)
	}
	if broker.callCount() != 1 {
		t.Fatalf("broker calls: got %d, want 1", broker.callCount())
	}
	// The cache must relay the action's grant (as the MintRequest grant)
	// and the requested destination.
	if got := broker.lastRequest(); got.Grant != "grant-1" || got.Destination != "registry" {
		t.Errorf("mint request: got %+v, want grant=grant-1 destination=registry", got)
	}

	// Second call within the refresh window reuses the cached token.
	if _, err := cache.Get(context.Background(), action, "registry"); err != nil {
		t.Fatalf("Get(reuse): %v", err)
	}
	if broker.callCount() != 1 {
		t.Errorf("broker calls after reuse: got %d, want 1 (cache miss)", broker.callCount())
	}

	// Advance to within refreshSkew of expiry: the next call re-mints.
	broker.tok = &MintedToken{Token: "t2", Scheme: "bearer", ExpiresAt: now.Add(3 * time.Hour)}
	now = now.Add(time.Hour - refreshSkew/2)
	tok, err = cache.Get(context.Background(), action, "registry")
	if err != nil {
		t.Fatalf("Get(refresh): %v", err)
	}
	if tok.Token != "t2" {
		t.Errorf("token after refresh: got %q, want t2", tok.Token)
	}
	if broker.callCount() != 2 {
		t.Errorf("broker calls after refresh: got %d, want 2", broker.callCount())
	}
}

func TestTokenCache_DistinctPerActionAndDestination(t *testing.T) {
	t.Parallel()
	now := time.Now()
	broker := &fakeBroker{tok: &MintedToken{Token: "t", ExpiresAt: now.Add(time.Hour)}}
	cache := newTokenCache(broker, nil)
	cache.now = func() time.Time { return now }

	a1 := &Action{ID: "a1", Grant: "g1", ExpiresAt: now.Add(time.Hour)}
	a2 := &Action{ID: "a2", Grant: "g2", ExpiresAt: now.Add(time.Hour)}

	_, _ = cache.Get(context.Background(), a1, "registry")
	_, _ = cache.Get(context.Background(), a1, "git-host") // different destination
	_, _ = cache.Get(context.Background(), a2, "registry") // different action
	if broker.callCount() != 3 {
		t.Errorf("broker calls: got %d, want 3 (one per distinct key)", broker.callCount())
	}

	// Evicting a1 drops its entries; re-fetching for a1 re-mints, a2 stays cached.
	cache.evictAction("a1")
	_, _ = cache.Get(context.Background(), a1, "registry")
	_, _ = cache.Get(context.Background(), a2, "registry")
	if broker.callCount() != 4 {
		t.Errorf("broker calls after evict: got %d, want 4", broker.callCount())
	}
}

func TestTokenCache_PropagatesBrokerError(t *testing.T) {
	t.Parallel()
	broker := &fakeBroker{err: ErrBrokerDenied}
	cache := newTokenCache(broker, nil)
	_, err := cache.Get(context.Background(), &Action{ID: "a", Grant: "g"}, "registry")
	if !errors.Is(err, ErrBrokerDenied) {
		t.Errorf("err: got %v, want ErrBrokerDenied", err)
	}
}

// TestTokenCache_MetricsCountRealMintsAndLookups asserts the cache records
// one miss plus one successful broker mint on the cold call, and one hit
// (no second mint) on the warm call. This locks in that mints_total
// counts real /token calls to the broker rather than per-request cache
// lookups, and that lookups_total is wired at all.
func TestTokenCache_MetricsCountRealMintsAndLookups(t *testing.T) {
	t.Parallel()
	now := time.Now()
	broker := &fakeBroker{tok: &MintedToken{Token: "t", ExpiresAt: now.Add(time.Hour)}}
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)
	cache := newTokenCache(broker, m)
	cache.now = func() time.Time { return now }
	action := &Action{ID: "a", Grant: "g", ExpiresAt: now.Add(time.Hour)}

	// Cold call: one miss, one real broker mint.
	if _, err := cache.Get(context.Background(), action, "registry"); err != nil {
		t.Fatalf("Get(cold): %v", err)
	}
	// Warm call within the refresh window: one hit, no second mint.
	if _, err := cache.Get(context.Background(), action, "registry"); err != nil {
		t.Fatalf("Get(warm): %v", err)
	}

	if got := testutil.ToFloat64(m.tokenCacheHits.WithLabelValues("miss")); got != 1 {
		t.Errorf("lookups miss: got %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.tokenCacheHits.WithLabelValues("hit")); got != 1 {
		t.Errorf("lookups hit: got %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.brokerMints.WithLabelValues("registry", "success")); got != 1 {
		t.Errorf("broker mints success: got %v, want 1 (one real mint, not one per request)", got)
	}
	if broker.callCount() != 1 {
		t.Errorf("broker calls: got %d, want 1", broker.callCount())
	}
}

package registrytokenexchange_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Muon-Space/bb-credential-broker/pkg/auth"
	"github.com/Muon-Space/bb-credential-broker/pkg/destinations/registrytokenexchange"
)

// writeSecret stages a secret file with the supplied bytes and
// returns its path.
func writeSecret(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	return path
}

// tokenEndpoint captures the requests it receives and returns a
// canned status/body for each. respond is consulted per-request so
// tests can vary the response across calls (e.g. to exercise
// refresh-after-expiry).
type tokenEndpoint struct {
	server *httptest.Server

	mu       sync.Mutex
	requests []*http.Request
	calls    int32

	respond func(call int) (int, string)
}

func newTokenEndpoint(t *testing.T, respond func(call int) (int, string)) *tokenEndpoint {
	t.Helper()
	e := &tokenEndpoint{respond: respond}
	e.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		// Clone the essentials we need; the request body is empty
		// for a GET so no need to drain/restore it.
		clone := r.Clone(context.Background())
		e.requests = append(e.requests, clone)
		e.mu.Unlock()

		call := int(atomic.AddInt32(&e.calls, 1))
		status, body := e.respond(call)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(e.server.Close)
	return e
}

func (e *tokenEndpoint) URL() string { return e.server.URL }

func (e *tokenEndpoint) callCount() int {
	return int(atomic.LoadInt32(&e.calls))
}

func (e *tokenEndpoint) lastRequest() *http.Request {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.requests) == 0 {
		return nil
	}
	return e.requests[len(e.requests)-1]
}

func newTestIdentity() *auth.Identity {
	return &auth.Identity{Type: auth.IdentityTypeCI, Principal: "p"}
}

func TestNew_RejectsNilConfig(t *testing.T) {
	t.Parallel()
	if _, err := registrytokenexchange.New("d", nil); err == nil {
		t.Fatal("New(nil): expected error, got nil")
	}
}

func TestNew_RejectsMissingTokenURL(t *testing.T) {
	t.Parallel()
	cfg := &registrytokenexchange.Config{Username: "u", File: writeSecret(t, "s")}
	if _, err := registrytokenexchange.New("d", cfg); err == nil {
		t.Fatal("New with empty tokenUrl: expected error, got nil")
	}
}

func TestNew_RejectsRelativeTokenURL(t *testing.T) {
	t.Parallel()
	cfg := &registrytokenexchange.Config{TokenURL: "/v2/token", Username: "u", File: writeSecret(t, "s")}
	if _, err := registrytokenexchange.New("d", cfg); err == nil {
		t.Fatal("New with relative tokenUrl: expected error, got nil")
	}
}

func TestNew_RejectsMissingUsername(t *testing.T) {
	t.Parallel()
	cfg := &registrytokenexchange.Config{TokenURL: "https://example.com/v2/token", File: writeSecret(t, "s")} //nolint:gosec // G101: false positive; tokenUrl literal, not a credential
	if _, err := registrytokenexchange.New("d", cfg); err == nil {
		t.Fatal("New with empty username: expected error, got nil")
	}
}

func TestNew_RejectsMissingFile(t *testing.T) {
	t.Parallel()
	cfg := &registrytokenexchange.Config{TokenURL: "https://example.com/v2/token", Username: "u"} //nolint:gosec // G101: false positive; test placeholder username, not a credential
	if _, err := registrytokenexchange.New("d", cfg); err == nil {
		t.Fatal("New with empty file: expected error, got nil")
	}
}

func TestNew_RejectsUnreadableFile(t *testing.T) {
	t.Parallel()
	cfg := &registrytokenexchange.Config{ //nolint:gosec // G101: false positive; test placeholder username, not a credential
		TokenURL: "https://example.com/v2/token",
		Username: "u",
		File:     filepath.Join(t.TempDir(), "missing"),
	}
	if _, err := registrytokenexchange.New("d", cfg); err == nil {
		t.Fatal("New with missing secret file: expected error, got nil")
	}
}

func TestNew_RejectsBadCacheTTL(t *testing.T) {
	t.Parallel()
	cfg := &registrytokenexchange.Config{ //nolint:gosec // G101: false positive; test placeholder username, not a credential
		TokenURL: "https://example.com/v2/token",
		Username: "u",
		File:     writeSecret(t, "s"),
		CacheTTL: "not-a-duration",
	}
	if _, err := registrytokenexchange.New("d", cfg); err == nil {
		t.Fatal("New with bad cacheTtl: expected error, got nil")
	}
}

func TestNew_RejectsZeroCacheTTL(t *testing.T) {
	t.Parallel()
	cfg := &registrytokenexchange.Config{ //nolint:gosec // G101: false positive; test placeholder username, not a credential
		TokenURL: "https://example.com/v2/token",
		Username: "u",
		File:     writeSecret(t, "s"),
		CacheTTL: "0s",
	}
	if _, err := registrytokenexchange.New("d", cfg); err == nil {
		t.Fatal("New with zero cacheTtl: expected error, got nil")
	}
}

// TestMint_HappyPath exercises the full two-legged exchange: the
// broker GETs the configured token endpoint with service/scope query
// params and a Basic-auth header, and dispenses the extracted token
// reformatted as a complete "Bearer <token>" Authorization value with
// no separate scheme or username.
func TestMint_HappyPath(t *testing.T) {
	t.Parallel()
	endpoint := newTokenEndpoint(t, func(int) (int, string) {
		return http.StatusOK, `{"token":"opaque-bearer-token","expires_in":300}`
	})

	cfg := &registrytokenexchange.Config{
		TokenURL: endpoint.URL() + "/v2/token",
		Service:  "registry.example.com",
		Scope:    "repository:my-repo:pull",
		Username: "robot",
		File:     writeSecret(t, "s3cr3t"),
	}
	d, err := registrytokenexchange.New("registry", cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	tok, err := d.Mint(context.Background(), newTestIdentity())
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if tok.Value != "Bearer opaque-bearer-token" {
		t.Errorf("Value: got %q, want %q", tok.Value, "Bearer opaque-bearer-token")
	}

	req := endpoint.lastRequest()
	if req == nil {
		t.Fatal("token endpoint received no request")
	}
	if req.Method != http.MethodGet {
		t.Errorf("Method: got %q, want GET", req.Method)
	}
	q := req.URL.Query()
	if got := q.Get("service"); got != "registry.example.com" {
		t.Errorf("service query param: got %q, want %q", got, "registry.example.com")
	}
	if got := q.Get("scope"); got != "repository:my-repo:pull" {
		t.Errorf("scope query param: got %q, want %q", got, "repository:my-repo:pull")
	}
}

// TestMint_SendsCorrectBasicAuthHeader pins the exact wire encoding:
// standard (padded) base64 of "username:secret" per RFC 7617, not
// the broker's ${b64:...} template function's base64url-without-
// padding encoding, which a spec-compliant server would reject.
func TestMint_SendsCorrectBasicAuthHeader(t *testing.T) {
	t.Parallel()
	endpoint := newTokenEndpoint(t, func(int) (int, string) {
		return http.StatusOK, `{"token":"t","expires_in":300}`
	})

	cfg := &registrytokenexchange.Config{
		TokenURL: endpoint.URL() + "/v2/token",
		Username: "robot",
		File:     writeSecret(t, "s3cr3t"),
	}
	d, err := registrytokenexchange.New("registry", cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := d.Mint(context.Background(), newTestIdentity()); err != nil {
		t.Fatalf("Mint: %v", err)
	}

	req := endpoint.lastRequest()
	if req == nil {
		t.Fatal("token endpoint received no request")
	}
	gotUser, gotPass, ok := req.BasicAuth()
	if !ok {
		t.Fatalf("Authorization header %q did not parse as Basic auth", req.Header.Get("Authorization"))
	}
	if gotUser != "robot" || gotPass != "s3cr3t" {
		t.Errorf("BasicAuth: got (%q, %q), want (%q, %q)", gotUser, gotPass, "robot", "s3cr3t")
	}

	// Independently confirm the header is standard base64 (padded,
	// '+'/'/' alphabet), not base64url-without-padding.
	header := req.Header.Get("Authorization")
	encoded := strings.TrimPrefix(header, "Basic ")
	want := base64.StdEncoding.EncodeToString([]byte("robot:s3cr3t"))
	if encoded != want {
		t.Errorf("Authorization encoding: got %q, want %q (standard base64)", encoded, want)
	}
}

// TestMint_AcceptsAccessTokenAlias covers registries that return
// access_token instead of the spec-mandated token field.
func TestMint_AcceptsAccessTokenAlias(t *testing.T) {
	t.Parallel()
	endpoint := newTokenEndpoint(t, func(int) (int, string) {
		return http.StatusOK, `{"access_token":"aliased-token","expires_in":300}`
	})
	cfg := &registrytokenexchange.Config{
		TokenURL: endpoint.URL() + "/v2/token",
		Username: "u",
		File:     writeSecret(t, "s"),
	}
	d, err := registrytokenexchange.New("d", cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	tok, err := d.Mint(context.Background(), newTestIdentity())
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if tok.Value != "Bearer aliased-token" {
		t.Errorf("Value: got %q, want %q", tok.Value, "Bearer aliased-token")
	}
}

// TestMint_CachesWithinTokenLifetime confirms that a second Mint call
// issued before the cached token's refresh instant reuses the cached
// value instead of re-exchanging.
func TestMint_CachesWithinTokenLifetime(t *testing.T) {
	t.Parallel()
	endpoint := newTokenEndpoint(t, func(call int) (int, string) {
		return http.StatusOK, fmt.Sprintf(`{"token":"tok-%d","expires_in":300}`, call)
	})
	cfg := &registrytokenexchange.Config{
		TokenURL: endpoint.URL() + "/v2/token",
		Username: "u",
		File:     writeSecret(t, "s"),
	}
	d, err := registrytokenexchange.New("d", cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	frozen := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	d.SetNow(func() time.Time { return frozen })

	first, err := d.Mint(context.Background(), newTestIdentity())
	if err != nil {
		t.Fatalf("Mint #1: %v", err)
	}
	second, err := d.Mint(context.Background(), newTestIdentity())
	if err != nil {
		t.Fatalf("Mint #2: %v", err)
	}
	if first.Value != second.Value {
		t.Errorf("expected cached value to be reused: got %q then %q", first.Value, second.Value)
	}
	if got := endpoint.callCount(); got != 1 {
		t.Errorf("token endpoint call count: got %d, want 1 (second Mint should have hit the cache)", got)
	}
}

// TestMint_RefreshesAfterExpiry confirms that once the clock passes
// the cached token's refresh instant (reported expiry minus the
// safety margin), the next Mint re-exchanges.
func TestMint_RefreshesAfterExpiry(t *testing.T) {
	t.Parallel()
	endpoint := newTokenEndpoint(t, func(call int) (int, string) {
		return http.StatusOK, fmt.Sprintf(`{"token":"tok-%d","expires_in":60}`, call)
	})
	cfg := &registrytokenexchange.Config{
		TokenURL: endpoint.URL() + "/v2/token",
		Username: "u",
		File:     writeSecret(t, "s"),
	}
	d, err := registrytokenexchange.New("d", cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	d.SetNow(func() time.Time { return now })

	first, err := d.Mint(context.Background(), newTestIdentity())
	if err != nil {
		t.Fatalf("Mint #1: %v", err)
	}
	if first.Value != "Bearer tok-1" {
		t.Fatalf("Value #1: got %q, want %q", first.Value, "Bearer tok-1")
	}

	// Advance past expiry (60s) minus the refresh skew.
	now = now.Add(56 * time.Second)

	second, err := d.Mint(context.Background(), newTestIdentity())
	if err != nil {
		t.Fatalf("Mint #2: %v", err)
	}
	if second.Value != "Bearer tok-2" {
		t.Errorf("Value #2: got %q, want %q (expected re-exchange after expiry)", second.Value, "Bearer tok-2")
	}
	if got := endpoint.callCount(); got != 2 {
		t.Errorf("token endpoint call count: got %d, want 2", got)
	}
}

// TestMint_DefaultsTTLWhenExpiresInAbsent covers registries that omit
// expires_in entirely, which the Docker Registry v2 token-auth spec
// permits. The destination must still succeed and fall back to
// DefaultCacheTTL rather than failing the mint.
func TestMint_DefaultsTTLWhenExpiresInAbsent(t *testing.T) {
	t.Parallel()
	endpoint := newTokenEndpoint(t, func(call int) (int, string) {
		return http.StatusOK, fmt.Sprintf(`{"token":"tok-%d"}`, call)
	})
	cfg := &registrytokenexchange.Config{
		TokenURL: endpoint.URL() + "/v2/token",
		Username: "u",
		File:     writeSecret(t, "s"),
	}
	d, err := registrytokenexchange.New("d", cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// ExpiresAt reflects the real registry-side deadline, computed
	// by httptokenexchange from the real clock (it has no injectable
	// clock of its own), so assert it against a real-time window
	// rather than a frozen SetNow value.
	before := time.Now()
	first, err := d.Mint(context.Background(), newTestIdentity())
	after := time.Now()
	if err != nil {
		t.Fatalf("Mint #1: %v", err)
	}
	minExpiry := before.Add(registrytokenexchange.DefaultCacheTTL)
	maxExpiry := after.Add(registrytokenexchange.DefaultCacheTTL)
	if first.ExpiresAt.Before(minExpiry) || first.ExpiresAt.After(maxExpiry) {
		t.Errorf("ExpiresAt: got %v, want within [%v, %v]", first.ExpiresAt, minExpiry, maxExpiry)
	}

	// Still within the default TTL: cached, no second call.
	if _, err := d.Mint(context.Background(), newTestIdentity()); err != nil {
		t.Fatalf("Mint #2: %v", err)
	}
	if got := endpoint.callCount(); got != 1 {
		t.Errorf("token endpoint call count: got %d, want 1 (default TTL should still be cached)", got)
	}
}

// TestMint_HonoursConfiguredDefaultTTL confirms that a configured
// cacheTtl (not the package default) is used as the fallback when
// expires_in is absent.
func TestMint_HonoursConfiguredDefaultTTL(t *testing.T) {
	t.Parallel()
	endpoint := newTokenEndpoint(t, func(int) (int, string) {
		return http.StatusOK, `{"token":"tok"}`
	})
	cfg := &registrytokenexchange.Config{
		TokenURL: endpoint.URL() + "/v2/token",
		Username: "u",
		File:     writeSecret(t, "s"),
		CacheTTL: "10s",
	}
	d, err := registrytokenexchange.New("d", cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	before := time.Now()
	tok, err := d.Mint(context.Background(), newTestIdentity())
	after := time.Now()
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	minExpiry := before.Add(10 * time.Second)
	maxExpiry := after.Add(10 * time.Second)
	if tok.ExpiresAt.Before(minExpiry) || tok.ExpiresAt.After(maxExpiry) {
		t.Errorf("ExpiresAt: got %v, want within [%v, %v]", tok.ExpiresAt, minExpiry, maxExpiry)
	}
}

// TestMint_UpstreamFailureSurfacesAsError confirms that a non-2xx
// response from the token endpoint fails the mint through the normal
// destination-error path rather than a bespoke error convention.
func TestMint_UpstreamFailureSurfacesAsError(t *testing.T) {
	t.Parallel()
	endpoint := newTokenEndpoint(t, func(int) (int, string) {
		return http.StatusUnauthorized, `{"error":"invalid credentials"}`
	})
	cfg := &registrytokenexchange.Config{
		TokenURL: endpoint.URL() + "/v2/token",
		Username: "u",
		File:     writeSecret(t, "s"),
	}
	d, err := registrytokenexchange.New("d", cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := d.Mint(context.Background(), newTestIdentity()); err == nil {
		t.Fatal("Mint against a 401 upstream: expected error, got nil")
	}
}

// TestMint_UpstreamFailureIsNotCached confirms that a failed exchange
// does not poison the cache: the next Mint call retries rather than
// replaying the failure indefinitely.
func TestMint_UpstreamFailureIsNotCached(t *testing.T) {
	t.Parallel()
	endpoint := newTokenEndpoint(t, func(call int) (int, string) {
		if call == 1 {
			return http.StatusServiceUnavailable, `{"error":"try again"}`
		}
		return http.StatusOK, `{"token":"recovered","expires_in":300}`
	})
	cfg := &registrytokenexchange.Config{
		TokenURL: endpoint.URL() + "/v2/token",
		Username: "u",
		File:     writeSecret(t, "s"),
	}
	d, err := registrytokenexchange.New("d", cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := d.Mint(context.Background(), newTestIdentity()); err == nil {
		t.Fatal("Mint #1: expected error, got nil")
	}
	tok, err := d.Mint(context.Background(), newTestIdentity())
	if err != nil {
		t.Fatalf("Mint #2: %v", err)
	}
	if tok.Value != "Bearer recovered" {
		t.Errorf("Value: got %q, want %q", tok.Value, "Bearer recovered")
	}
}

// TestMint_ConcurrentMissesDedup pins the singleflight behaviour:
// a burst of concurrent Mint calls against a cold cache must produce
// exactly one exchange call to the token endpoint.
func TestMint_ConcurrentMissesDedup(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	var inFlight int32
	endpoint := newTokenEndpoint(t, func(call int) (int, string) {
		atomic.AddInt32(&inFlight, 1)
		<-release
		return http.StatusOK, fmt.Sprintf(`{"token":"tok-%d","expires_in":300}`, call)
	})
	cfg := &registrytokenexchange.Config{
		TokenURL: endpoint.URL() + "/v2/token",
		Username: "u",
		File:     writeSecret(t, "s"),
	}
	d, err := registrytokenexchange.New("d", cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const n = 10
	var wg sync.WaitGroup
	results := make([]*registrytokenexchange.Token, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = d.Mint(context.Background(), newTestIdentity())
		}(i)
	}
	// Let every goroutine reach the handler before releasing it, so
	// this actually exercises the concurrent-miss path rather than
	// racing goroutine scheduling.
	deadline := time.Now().Add(2 * time.Second)
	for atomic.LoadInt32(&inFlight) < 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	close(release)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("Mint #%d: %v", i, err)
		}
	}
	for i, r := range results {
		if r.Value != results[0].Value {
			t.Errorf("result #%d: got %q, want %q (all concurrent callers should share one exchange)", i, r.Value, results[0].Value)
		}
	}
	if got := endpoint.callCount(); got != 1 {
		t.Errorf("token endpoint call count: got %d, want 1", got)
	}
}

// TestMint_RereadsSecretFileOnRotation confirms that a secret
// rotated on disk between exchanges takes effect on the next
// exchange, without a broker restart. This can only be observed
// across a real cache miss, so the test forces one via SetNow.
func TestMint_RereadsSecretFileOnRotation(t *testing.T) {
	t.Parallel()
	var gotPasswords []string
	endpoint := newTokenEndpoint(t, func(call int) (int, string) {
		return http.StatusOK, fmt.Sprintf(`{"token":"tok-%d","expires_in":60}`, call)
	})
	path := writeSecret(t, "v1")
	cfg := &registrytokenexchange.Config{
		TokenURL: endpoint.URL() + "/v2/token",
		Username: "u",
		File:     path,
	}
	d, err := registrytokenexchange.New("d", cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	d.SetNow(func() time.Time { return now })

	if _, err := d.Mint(context.Background(), newTestIdentity()); err != nil {
		t.Fatalf("Mint #1: %v", err)
	}
	if _, _, ok := endpoint.lastRequest().BasicAuth(); !ok {
		t.Fatal("expected Basic auth on request #1")
	}
	_, pass, _ := endpoint.lastRequest().BasicAuth()
	gotPasswords = append(gotPasswords, pass)

	if err := os.WriteFile(path, []byte("v2"), 0o600); err != nil {
		t.Fatalf("rewrite secret: %v", err)
	}
	now = now.Add(56 * time.Second) // force a cache miss

	if _, err := d.Mint(context.Background(), newTestIdentity()); err != nil {
		t.Fatalf("Mint #2: %v", err)
	}
	_, pass, _ = endpoint.lastRequest().BasicAuth()
	gotPasswords = append(gotPasswords, pass)

	if gotPasswords[0] != "v1" || gotPasswords[1] != "v2" {
		t.Errorf("passwords across rotation: got %v, want [v1 v2]", gotPasswords)
	}
}

// TestRenderRequest_ShowsResolvedURLWithoutLeakingSecret confirms the
// render path surfaces the exact URL the broker would GET while never
// reading the real secret file into the rendered output.
func TestRenderRequest_ShowsResolvedURLWithoutLeakingSecret(t *testing.T) {
	t.Parallel()
	cfg := &registrytokenexchange.Config{ //nolint:gosec // G101: false positive; test placeholder username, not a credential
		TokenURL: "https://registry.example.com/v2/token",
		Service:  "registry.example.com",
		Scope:    "repository:my-repo:pull",
		Username: "robot",
		File:     writeSecret(t, "s3cr3t"),
	}
	d, err := registrytokenexchange.New("d", cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req, err := d.RenderRequest(context.Background(), newTestIdentity())
	if err != nil {
		t.Fatalf("RenderRequest: %v", err)
	}
	if req.Method != http.MethodGet {
		t.Errorf("Method: got %q, want GET", req.Method)
	}
	u, err := url.Parse(req.URL.String())
	if err != nil {
		t.Fatalf("parse rendered URL: %v", err)
	}
	if u.Query().Get("scope") != "repository:my-repo:pull" {
		t.Errorf("rendered URL missing scope: %s", req.URL.String())
	}
	if strings.Contains(req.Header.Get("Authorization"), "s3cr3t") {
		t.Error("rendered request must not leak the real secret")
	}
}

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
// params and a Basic-auth header, and dispenses the extracted opaque
// bearer token verbatim.
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
	if tok.Value != "opaque-bearer-token" {
		t.Errorf("Value: got %q, want %q", tok.Value, "opaque-bearer-token")
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
	if tok.Value != "aliased-token" {
		t.Errorf("Value: got %q, want %q", tok.Value, "aliased-token")
	}
}

// TestMint_ExchangesOnEveryCall pins the division of responsibility
// between this type and the destinations package: Impl performs no
// caching of its own, so every Mint call reaches the registry's
// token endpoint. The identity-invariant cache that keeps /token
// bursts from repeating the exchange is applied by BuildRegistry in
// the parent package and is tested there.
func TestMint_ExchangesOnEveryCall(t *testing.T) {
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

	first, err := d.Mint(context.Background(), newTestIdentity())
	if err != nil {
		t.Fatalf("Mint #1: %v", err)
	}
	second, err := d.Mint(context.Background(), newTestIdentity())
	if err != nil {
		t.Fatalf("Mint #2: %v", err)
	}
	if first.Value != "tok-1" || second.Value != "tok-2" {
		t.Errorf("Values: got %q, %q; want tok-1, tok-2", first.Value, second.Value)
	}
	if got := endpoint.callCount(); got != 2 {
		t.Errorf("token endpoint call count: got %d, want 2", got)
	}
}

// TestMint_DefaultsTTLWhenExpiresInAbsent covers registries that omit
// expires_in entirely, which the Docker Registry v2 token-auth spec
// permits. The destination must still succeed and stamp an expiry of
// now plus DefaultCacheTTL rather than failing the mint or returning
// a zero expiry (which would defeat the parent package's cache).
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
	frozen := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	d.SetNow(func() time.Time { return frozen })

	tok, err := d.Mint(context.Background(), newTestIdentity())
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if want := frozen.Add(registrytokenexchange.DefaultCacheTTL); !tok.ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt: got %v, want %v", tok.ExpiresAt, want)
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
	frozen := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	d.SetNow(func() time.Time { return frozen })

	tok, err := d.Mint(context.Background(), newTestIdentity())
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if want := frozen.Add(10 * time.Second); !tok.ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt: got %v, want %v", tok.ExpiresAt, want)
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

// TestMint_RereadsSecretFileOnRotation confirms that a secret
// rotated on disk between exchanges takes effect on the next
// exchange, without a broker restart.
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

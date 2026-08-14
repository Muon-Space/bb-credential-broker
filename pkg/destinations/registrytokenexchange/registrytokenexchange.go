// Package registrytokenexchange implements a destination type for
// registries that implement the Docker Registry v2 / OCI
// Distribution Spec bearer-token authentication flow: a GET against
// a dedicated token endpoint, authenticated with HTTP Basic auth,
// returns a short-lived opaque bearer token that must then be
// presented as `Authorization: Bearer <token>` on the actual
// resource request. Such registries reject Basic auth on resource
// endpoints outright; only the token endpoint accepts it.
//
// A staticSecret destination cannot serve this flow: a static
// credential is rejected by the registry's resource endpoints
// regardless of validity, because those endpoints never accept
// Basic auth at all, and the bearer token they do accept does not
// exist until exchange time. registryTokenExchange performs the
// two-legged exchange itself and dispenses the resulting bearer
// token through the standard response shape (scheme "bearer"), so
// consumers present it exactly as they would any other
// bearer-token destination's credential.
//
// Implementation: the destination compiles its configuration down to
// an httpTokenExchange config at construction time — the same
// technique oidcTokenExchange uses — so the actual HTTP request,
// response-size limiting, status validation, JSON decoding, JMESPath
// extraction and audit-log population are all the existing,
// already-tested httptokenexchange machinery. The only genuinely new
// pieces are:
//
//   - A RoundTripper that injects a fresh, correctly RFC 7617-encoded
//     HTTP Basic Authorization header (username plus a secret read
//     from disk) into the outbound request. The broker's own
//     ${b64:...} template function base64url-encodes without
//     padding for an unrelated use case and would produce a header
//     most registries reject, so this type does not route the
//     credential through the shared template engine.
//   - A short-lived, singleflight-guarded cache in front of the
//     exchange, because the opaque bearer token this flow returns is
//     typically valid for as little as 60 seconds and the exchange
//     is not identity-scoped: every caller of a given destination
//     gets the same token, so sharing one cached value across
//     concurrent /token requests produces a single exchange call
//     against the registry's token endpoint rather than one per
//     request.
package registrytokenexchange

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/Muon-Space/bb-credential-broker/pkg/auth"
	"github.com/Muon-Space/bb-credential-broker/pkg/destinations/httptokenexchange"
)

// requestTimeout bounds the outbound exchange request. Mirrors
// httptokenexchange's own requestTimeout constant; duplicated here
// because this type supplies its own http.Client (to install the
// Basic-auth transport) rather than taking httptokenexchange's
// default.
const requestTimeout = 30 * time.Second

// DefaultCacheTTL is the token lifetime assumed when the token
// endpoint's response carries no expires_in field. The Docker
// Registry v2 / OCI Distribution Spec token-authentication flow
// permits omitting expires_in; 60 seconds is the commonly used
// default lifetime in that case.
const DefaultCacheTTL = 60 * time.Second

// refreshSkew is how long before the cached token's reported expiry
// the cache treats it as stale and re-exchanges. Mirrors the
// refreshSkew convention in pkg/egressauthd's client-side token
// cache, sized down from that cache's 30s because the tokens this
// destination caches are themselves often as short-lived as 60s
// total; a 30s skew would halve the usable window.
const refreshSkew = 5 * time.Second

// Config configures a single named registryTokenExchange
// destination.
type Config struct {
	// TokenURL is the absolute URL of the registry's token endpoint
	// (the `realm` advertised in the registry's
	// `WWW-Authenticate: Bearer realm="...",service="...",...`
	// challenge). Required.
	TokenURL string `json:"tokenUrl"`

	// Service is sent as the token endpoint's `service` query
	// parameter, matching the `service` value from the registry's
	// challenge.
	Service string `json:"service,omitempty"`

	// Scope is sent as the token endpoint's `scope` query
	// parameter, matching the `scope` value from the registry's
	// challenge (for example "repository:my-repo:pull").
	Scope string `json:"scope,omitempty"`

	// Username is the HTTP Basic-auth username sent to TokenURL.
	// Required.
	Username string `json:"username"`

	// File is the absolute path to the file holding the Basic-auth
	// secret paired with Username (a password or personal access
	// token). Mirrors staticSecret's File convention: the file is
	// read fresh on every exchange (not merely at construction) so
	// that an operator rotating the underlying Secret does not need
	// to restart the broker. Required.
	File string `json:"file"`

	// CacheTTL is the token lifetime assumed when the token
	// endpoint's response omits expires_in. Empty means
	// DefaultCacheTTL. Ignored when the response does carry
	// expires_in; that value is always used instead.
	CacheTTL string `json:"cacheTtl,omitempty"`
}

// Token is the credential returned by Mint. The destinations parent
// package wraps Impl in an adapter that translates between the two
// so that this child package avoids an import cycle on its parent.
type Token struct {
	// Value is the opaque bearer token returned by the registry's
	// token endpoint, dispensed verbatim. The adapter that projects
	// this onto the parent package's Token sets the scheme to
	// "bearer", so the /token response is shaped identically to an
	// httpTokenExchange destination's.
	Value     string
	ExpiresAt time.Time
}

// cachedToken is a stored Token plus the absolute time at which the
// cache should re-exchange.
type cachedToken struct {
	token     *Token
	refreshAt time.Time
}

// Impl is a single instance of the registryTokenExchange destination
// type. Exchanges are delegated to an inner httptokenexchange.Impl;
// Impl itself owns only the response cache and the singleflight
// guard in front of it.
type Impl struct {
	name  string
	inner *httptokenexchange.Impl
	now   func() time.Time

	mu       sync.Mutex
	cached   *cachedToken
	inflight *sync.WaitGroup
}

// New constructs an Impl from cfg. The secret file's readability is
// checked once here (mirroring staticSecret) so a misconfigured path
// fails the broker's load step rather than the first /token request;
// the file's contents are then re-read on every subsequent exchange.
func New(name string, cfg *Config) (*Impl, error) {
	if cfg == nil {
		return nil, fmt.Errorf("registryTokenExchange: config is nil")
	}
	if cfg.TokenURL == "" {
		return nil, fmt.Errorf("registryTokenExchange: tokenUrl is required")
	}
	if cfg.Username == "" {
		return nil, fmt.Errorf("registryTokenExchange: username is required")
	}
	if cfg.File == "" {
		return nil, fmt.Errorf("registryTokenExchange: file is required")
	}
	if _, err := readSecretFile(cfg.File); err != nil {
		return nil, fmt.Errorf("registryTokenExchange: %w", err)
	}

	cacheTTL := DefaultCacheTTL
	if cfg.CacheTTL != "" {
		d, err := time.ParseDuration(cfg.CacheTTL)
		if err != nil {
			return nil, fmt.Errorf("registryTokenExchange: cacheTtl: %w", err)
		}
		if d <= 0 {
			return nil, fmt.Errorf("registryTokenExchange: cacheTtl must be positive")
		}
		cacheTTL = d
	}

	tokenURL, err := buildTokenURL(cfg)
	if err != nil {
		return nil, fmt.Errorf("registryTokenExchange: %w", err)
	}

	// The request has no per-identity variability at all — the
	// exchange authenticates with a fixed operator-supplied
	// credential, not the caller's Identity — so the compiled
	// httpTokenExchange config is fully static. tokenJsonPath
	// accepts either "token" (the spec-mandated field) or
	// "access_token" (the alias some implementations use instead).
	// expiresInJsonPath falls back to the configured cacheTTL, in
	// seconds, whenever the response omits expires_in, so a missing
	// field never fails the exchange.
	httpCfg := &httptokenexchange.Config{
		Request: httptokenexchange.RequestConfig{
			Method: http.MethodGet,
			URL:    tokenURL,
		},
		Response: httptokenexchange.ResponseConfig{
			TokenJSONPath:     "token || access_token",
			ExpiresInJSONPath: fmt.Sprintf("expires_in || `%d`", int64(cacheTTL.Seconds())),
		},
	}

	client := &http.Client{
		Timeout: requestTimeout,
		Transport: &basicAuthTransport{
			username: cfg.Username,
			file:     cfg.File,
			base:     http.DefaultTransport,
		},
	}

	inner, err := httptokenexchange.New(name, httpCfg, httptokenexchange.Dependencies{HTTPClient: client})
	if err != nil {
		return nil, fmt.Errorf("registryTokenExchange: %w", err)
	}

	return &Impl{
		name:  name,
		inner: inner,
		now:   time.Now,
	}, nil
}

// buildTokenURL appends the configured service/scope query
// parameters to cfg.TokenURL, properly URL-encoded, and validates
// that the result is an absolute http(s) URL.
func buildTokenURL(cfg *Config) (string, error) {
	u, err := url.Parse(cfg.TokenURL)
	if err != nil {
		return "", fmt.Errorf("tokenUrl: %w", err)
	}
	if !u.IsAbs() || (u.Scheme != "http" && u.Scheme != "https") {
		return "", fmt.Errorf("tokenUrl must be an absolute http or https URL")
	}
	q := u.Query()
	if cfg.Service != "" {
		q.Set("service", cfg.Service)
	}
	if cfg.Scope != "" {
		q.Set("scope", cfg.Scope)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// Name returns the operator-chosen name of this destination
// instance.
func (i *Impl) Name() string { return i.name }

// SetNow overrides the function used to read the current time. It
// exists so tests can assert cache behaviour at specific instants;
// production callers should not invoke it.
func (i *Impl) SetNow(f func() time.Time) { i.now = f }

// Mint returns the cached bearer token when one is fresh, otherwise
// performs the two-legged exchange via the inner httpTokenExchange
// destination and caches the result.
//
// Concurrent misses for this destination are de-duplicated with the
// same mutex-plus-WaitGroup pattern pkg/egressauthd's client-side
// token cache uses: the first caller to observe a stale cache
// performs the exchange while later callers wait on it and then
// re-read the cache, so a burst of /token requests for this
// destination produces a single upstream exchange call.
func (i *Impl) Mint(ctx context.Context, identity *auth.Identity) (*Token, error) {
	i.mu.Lock()
	if tok, ok := i.freshLocked(); ok {
		i.mu.Unlock()
		return tok, nil
	}
	if wg := i.inflight; wg != nil {
		i.mu.Unlock()
		wg.Wait()
		i.mu.Lock()
		if tok, ok := i.freshLocked(); ok {
			i.mu.Unlock()
			return tok, nil
		}
		// The in-flight exchange failed or produced a still-stale
		// entry; fall through and exchange ourselves.
	}
	wg := &sync.WaitGroup{}
	wg.Add(1)
	i.inflight = wg
	i.mu.Unlock()

	defer func() {
		i.mu.Lock()
		i.inflight = nil
		i.mu.Unlock()
		wg.Done()
	}()

	// wallNow anchors the TTL calculation below to the real clock:
	// httptokenexchange's expiresInJsonPath extraction stamps
	// ExpiresAt from time.Now() internally (it has no injectable
	// clock of its own), so the only portable way to recover "how
	// long is this token valid for" is to diff against the real
	// time observed on this side of the same call.
	wallNow := time.Now()
	innerTok, err := i.inner.Mint(ctx, identity)
	if err != nil {
		return nil, err
	}
	if innerTok.Value == "" {
		return nil, fmt.Errorf("registryTokenExchange: %s: token endpoint response carried no token", i.name)
	}

	tok := &Token{
		Value:     innerTok.Value,
		ExpiresAt: innerTok.ExpiresAt,
	}

	// ttl is the token's validity window, derived from two
	// real-clock readings taken around the same exchange call. Once
	// known, the cache's refresh instant is re-anchored to i.now()
	// rather than to the real clock, so that (a) tests can control
	// cache staleness deterministically via SetNow and (b) the
	// cache logic is entirely self-consistent even if i.now ever
	// diverges from wall time for reasons other than testing.
	ttl := tok.ExpiresAt.Sub(wallNow)
	if ttl < 0 {
		ttl = 0
	}
	refreshAt := i.now().Add(ttl - refreshSkew)

	i.mu.Lock()
	i.cached = &cachedToken{token: tok, refreshAt: refreshAt}
	i.mu.Unlock()
	return tok, nil
}

// freshLocked returns the cached token and true when one exists and
// has not yet reached its refresh instant. Callers must hold i.mu.
func (i *Impl) freshLocked() (*Token, bool) {
	if i.cached != nil && i.now().Before(i.cached.refreshAt) {
		return i.cached.token, true
	}
	return nil, false
}

// RenderRequest builds the outbound GET request the destination
// would exchange, without dispatching it or performing the caching
// wrapper's dedup logic. The Authorization header is never resolved
// for real here: the credential is injected by the RoundTripper at
// dispatch time, not by request construction, so a redacted
// placeholder is set instead of reading the real secret file.
func (i *Impl) RenderRequest(ctx context.Context, identity *auth.Identity) (*http.Request, error) {
	req, err := i.inner.RenderRequest(ctx, identity)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Basic <redacted; computed at dispatch time from username + file>")
	return req, nil
}

// basicAuthTransport injects a fresh HTTP Basic Authorization header
// into every outbound request immediately before it is sent, reading
// the paired secret from disk on each round trip. This mirrors
// staticSecret's read-on-every-Mint convention — an operator rotating
// the underlying Secret does not need to restart the broker — applied
// at exchange frequency rather than dispense frequency, since Impl's
// cache means the inner httpTokenExchange Mint (and therefore this
// transport) only runs on a cache miss.
//
// Standard net/http Basic-auth encoding (base64.StdEncoding per RFC
// 7617, via http.Request.SetBasicAuth) is used rather than the
// broker's ${b64:...} template function, which base64url-encodes
// without padding for a different use case and would produce a
// header most registries reject.
type basicAuthTransport struct {
	username string
	file     string
	base     http.RoundTripper
}

// RoundTrip implements http.RoundTripper.
func (t *basicAuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	secret, err := readSecretFile(t.file)
	if err != nil {
		return nil, fmt.Errorf("registryTokenExchange: read %s: %w", t.file, err)
	}
	req.SetBasicAuth(t.username, secret)
	return t.base.RoundTrip(req)
}

// readSecretFile reads path from disk and returns its contents with
// trailing whitespace removed. Mirrors staticSecret's readSecret: the
// trim handles the common gotcha of operators piping credentials
// into files via shell tools, and stripping it has no security
// consequence because no real credential carries trailing whitespace
// as a significant byte.
func readSecretFile(path string) (string, error) {
	// #nosec G304 G703 -- the path is operator-supplied configuration,
	// equivalent to staticSecret's File and the SigningKeyFile/
	// JWKSFile paths used elsewhere in the broker.
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	trimmed := bytes.TrimRight(data, " \t\r\n")
	if len(trimmed) == 0 {
		return "", fmt.Errorf("%s is empty", path)
	}
	return string(trimmed), nil
}

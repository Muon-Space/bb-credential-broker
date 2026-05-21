package handlers_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/audit"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/auth"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/destinations"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/handlers"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/store"
)

// stubDestination returns the configured token (or error) on Mint.
type stubDestination struct {
	token *destinations.Token
	err   error
}

func (s *stubDestination) Mint(context.Context, *auth.Identity) (*destinations.Token, error) {
	return s.token, s.err
}

func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("ParseCIDR %q: %v", s, err)
	}
	return n
}

// newTestStore returns a SignedStore with the supplied TTL and a
// deterministic key. The concrete type is returned so tests can
// call SetNow when they need to assert time-dependent behaviour.
func newTestStore(t *testing.T, ttl time.Duration) *store.SignedStore {
	t.Helper()
	key := bytes.Repeat([]byte{0x42}, store.MinSignedKeyBytes)
	s, err := store.NewSignedStore(key, ttl, "")
	if err != nil {
		t.Fatalf("NewSignedStore: %v", err)
	}
	return s
}

func mintNonce(t *testing.T, s store.NonceStore, dests ...string) string {
	t.Helper()
	nonce, err := s.Mint(&store.Record{
		Identity:            &auth.Identity{Type: auth.IdentityTypeCI, Principal: "p"},
		AllowedDestinations: dests,
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	return nonce
}

func newTokenHandler(t *testing.T, s store.NonceStore, registry destinations.Registry) *handlers.TokenHandler {
	t.Helper()
	return handlers.NewTokenHandler(
		[]*net.IPNet{mustCIDR(t, "10.0.0.0/8")},
		s,
		registry,
		nil,
		nil,
	)
}

func TestToken_RejectsForeignSourceIP(t *testing.T) {
	t.Parallel()
	h := newTokenHandler(t, newTestStore(t, time.Minute), destinations.Registry{})
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(`{"nonce":"x","destination":"y"}`))
	r.RemoteAddr = "8.8.8.8:12345"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestToken_RejectsUnknownNonce(t *testing.T) {
	t.Parallel()
	h := newTokenHandler(t, newTestStore(t, time.Minute), destinations.Registry{})
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(`{"nonce":"never","destination":"y"}`))
	r.RemoteAddr = "10.0.0.42:12345"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusGone {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusGone)
	}
}

// TestToken_RejectsExpiredNonce covers the second path through the
// handler that returns 410 Gone: a token whose exp has passed. The
// signed backend collapses every validation failure (expired,
// malformed, bad signature) into ErrNotFound, which the handler
// surfaces as 410.
func TestToken_RejectsExpiredNonce(t *testing.T) {
	t.Parallel()
	s := newTestStore(t, time.Minute)
	nonce := mintNonce(t, s, "alpha")
	// Fast-forward the verifier's clock so the signed token's exp
	// claim is in the past.
	s.SetNow(func() time.Time { return time.Now().Add(time.Hour) })

	h := newTokenHandler(t, s, destinations.Registry{})
	r := httptest.NewRequest(http.MethodPost, "/token",
		strings.NewReader(`{"nonce":"`+nonce+`","destination":"alpha"}`))
	r.RemoteAddr = "10.0.0.42:12345"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusGone {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusGone)
	}
}

func TestToken_RejectsDestinationOutsideGrant(t *testing.T) {
	t.Parallel()
	s := newTestStore(t, time.Minute)
	nonce := mintNonce(t, s, "alpha")

	h := newTokenHandler(t, s, destinations.Registry{})
	r := httptest.NewRequest(http.MethodPost, "/token",
		strings.NewReader(`{"nonce":"`+nonce+`","destination":"beta"}`))
	r.RemoteAddr = "10.0.0.42:12345"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestToken_RejectsUnknownDestinationName(t *testing.T) {
	t.Parallel()
	s := newTestStore(t, time.Minute)
	nonce := mintNonce(t, s, "alpha")

	h := newTokenHandler(t, s, destinations.Registry{})
	r := httptest.NewRequest(http.MethodPost, "/token",
		strings.NewReader(`{"nonce":"`+nonce+`","destination":"alpha"}`))
	r.RemoteAddr = "10.0.0.42:12345"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestToken_MintFailureReturns502(t *testing.T) {
	t.Parallel()
	s := newTestStore(t, time.Minute)
	nonce := mintNonce(t, s, "alpha")

	h := newTokenHandler(t, s, destinations.Registry{
		"alpha": &stubDestination{err: errors.New("upstream broke")},
	})
	r := httptest.NewRequest(http.MethodPost, "/token",
		strings.NewReader(`{"nonce":"`+nonce+`","destination":"alpha"}`))
	r.RemoteAddr = "10.0.0.42:12345"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusBadGateway {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusBadGateway)
	}
}

func TestToken_HappyPath(t *testing.T) {
	t.Parallel()
	s := newTestStore(t, time.Minute)
	nonce := mintNonce(t, s, "alpha")

	h := newTokenHandler(t, s, destinations.Registry{
		"alpha": &stubDestination{token: &destinations.Token{
			Value:     "abc123",
			Scheme:    "bearer",
			ExpiresAt: time.Unix(1700000000, 0),
		}},
	})
	r := httptest.NewRequest(http.MethodPost, "/token",
		strings.NewReader(`{"nonce":"`+nonce+`","destination":"alpha"}`))
	r.RemoteAddr = "10.0.0.42:12345"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("status: got %d, want %d. body: %s", w.Code, http.StatusOK, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"abc123"`) {
		t.Errorf("response body missing token: %s", w.Body.String())
	}
}

// TestToken_ClaimFailureAuditCarriesReason proves that when Claim
// rejects a token, the underlying reason (expired, bad signature,
// etc.) is preserved in the audit-log Error field while the HTTP
// response body remains opaque. Operators rely on this distinction
// to triage routine token expiry from active forgery attempts.
func TestToken_ClaimFailureAuditCarriesReason(t *testing.T) {
	t.Parallel()
	s := newTestStore(t, time.Minute)
	nonce := mintNonce(t, s, "alpha")
	s.SetNow(func() time.Time { return time.Now().Add(time.Hour) })

	var buf bytes.Buffer
	auditLog := audit.NewLogger(&buf)
	h := handlers.NewTokenHandler(
		[]*net.IPNet{mustCIDR(t, "10.0.0.0/8")},
		s,
		destinations.Registry{},
		auditLog,
		nil,
	)

	r := httptest.NewRequest(http.MethodPost, "/token",
		strings.NewReader(`{"nonce":"`+nonce+`","destination":"alpha"}`))
	r.RemoteAddr = "10.0.0.42:12345"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusGone {
		t.Fatalf("status: got %d, want %d", w.Code, http.StatusGone)
	}
	if strings.Contains(w.Body.String(), "expired") {
		t.Errorf("client response body must not leak the underlying reason: %s", w.Body.String())
	}
	if !strings.Contains(buf.String(), "expired") {
		t.Errorf("audit log must carry the underlying reason: %s", buf.String())
	}
}

func TestToken_RejectsMalformedBody(t *testing.T) {
	t.Parallel()
	h := newTokenHandler(t, newTestStore(t, time.Minute), destinations.Registry{})
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(`not-json`))
	r.RemoteAddr = "10.0.0.42:12345"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// TestToken_SuccessEntryCarriesUpstreamFields confirms that the
// audit record for a successful /token mint folds in whatever
// MintAudit the destination implementation populated. The test
// uses a stubDestination that pre-populates the MintAudit value
// in its Mint method via a callback that mirrors what
// httptokenexchange.Mint does in production.
func TestToken_SuccessEntryCarriesUpstreamFields(t *testing.T) {
	t.Parallel()
	s := newTestStore(t, time.Minute)
	nonce := mintNonce(t, s, "alpha")

	stub := &auditingStub{
		token: &destinations.Token{Value: "abc", Scheme: "bearer", ExpiresAt: time.Unix(1700000900, 0).UTC()},
		populate: func(a *audit.MintAudit) {
			a.UpstreamURL = "https://upstream.example.com/token"
			a.UpstreamStatusCode = 200
			a.UpstreamDuration = 12 * time.Millisecond
		},
	}
	rec := &recordingLogger{}
	h := handlers.NewTokenHandler(
		[]*net.IPNet{mustCIDR(t, "10.0.0.0/8")},
		s,
		destinations.Registry{"alpha": stub},
		rec,
		nil,
	)
	r := httptest.NewRequest(http.MethodPost, "/token",
		strings.NewReader(`{"nonce":"`+nonce+`","destination":"alpha"}`))
	r.RemoteAddr = "10.0.0.42:12345"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want %d (body=%s)", w.Code, http.StatusOK, w.Body.String())
	}
	if len(rec.token) != 1 {
		t.Fatalf("audit calls: got %d, want 1", len(rec.token))
	}
	entry := rec.token[0]
	if entry.Result != audit.ResultSuccess {
		t.Errorf("Result: got %q, want success", entry.Result)
	}
	if entry.UpstreamURL != "https://upstream.example.com/token" {
		t.Errorf("UpstreamURL: got %q", entry.UpstreamURL)
	}
	if entry.UpstreamStatus != 200 {
		t.Errorf("UpstreamStatus: got %d", entry.UpstreamStatus)
	}
	if entry.UpstreamDurationMS != 12 {
		t.Errorf("UpstreamDurationMS: got %d", entry.UpstreamDurationMS)
	}
	if entry.TokenExpiresAt == nil {
		t.Errorf("TokenExpiresAt: got nil, want populated")
	}
}

// TestToken_FailureEntryPopulatesExcerpt covers the failure path:
// an upstream rejection that populates UpstreamResponseExcerpt
// must surface that excerpt in the audit log under the documented
// schema key.
func TestToken_FailureEntryPopulatesExcerpt(t *testing.T) {
	t.Parallel()
	s := newTestStore(t, time.Minute)
	nonce := mintNonce(t, s, "alpha")

	stub := &auditingStub{
		err: errors.New("upstream said no"),
		populate: func(a *audit.MintAudit) {
			a.UpstreamURL = "https://upstream/token"
			a.UpstreamStatusCode = http.StatusUnauthorized
			a.UpstreamDuration = 4 * time.Millisecond
			a.UpstreamResponseExcerpt = `{"error":"unauthorized"}`
		},
	}
	rec := &recordingLogger{}
	h := handlers.NewTokenHandler(
		[]*net.IPNet{mustCIDR(t, "10.0.0.0/8")},
		s,
		destinations.Registry{"alpha": stub},
		rec,
		nil,
	)
	r := httptest.NewRequest(http.MethodPost, "/token",
		strings.NewReader(`{"nonce":"`+nonce+`","destination":"alpha"}`))
	r.RemoteAddr = "10.0.0.42:12345"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("status: got %d, want %d", w.Code, http.StatusBadGateway)
	}
	if len(rec.token) != 1 {
		t.Fatalf("audit calls: got %d, want 1", len(rec.token))
	}
	entry := rec.token[0]
	if entry.Result != audit.ResultFailure {
		t.Errorf("Result: got %q, want failure", entry.Result)
	}
	if entry.UpstreamResponseExcerpt != `{"error":"unauthorized"}` {
		t.Errorf("UpstreamResponseExcerpt: got %q", entry.UpstreamResponseExcerpt)
	}
	if !strings.Contains(entry.DenialReason, "upstream said no") {
		t.Errorf("DenialReason: got %q", entry.DenialReason)
	}
}

// TestToken_StaticSecretLikeDestinationOmitsUpstream covers the
// staticSecret case: a destination that performs no upstream HTTP
// call leaves MintAudit zero, and the resulting TokenEntry has
// upstream_* fields at their zero values so the JSON output drops
// them entirely.
func TestToken_StaticSecretLikeDestinationOmitsUpstream(t *testing.T) {
	t.Parallel()
	s := newTestStore(t, time.Minute)
	nonce := mintNonce(t, s, "static")

	stub := &auditingStub{
		token: &destinations.Token{Value: "pat-value", Scheme: "basic", Username: "x-access-token"},
		// No populate callback: simulates a destination that
		// mints locally without an upstream call.
	}
	rec := &recordingLogger{}
	h := handlers.NewTokenHandler(
		[]*net.IPNet{mustCIDR(t, "10.0.0.0/8")},
		s,
		destinations.Registry{"static": stub},
		rec,
		nil,
	)
	r := httptest.NewRequest(http.MethodPost, "/token",
		strings.NewReader(`{"nonce":"`+nonce+`","destination":"static"}`))
	r.RemoteAddr = "10.0.0.42:12345"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d (body=%s)", w.Code, w.Body.String())
	}
	if len(rec.token) != 1 {
		t.Fatalf("audit calls: got %d, want 1", len(rec.token))
	}
	entry := rec.token[0]
	if entry.UpstreamURL != "" || entry.UpstreamStatus != 0 || entry.UpstreamDurationMS != 0 {
		t.Errorf("upstream_* fields should be zero for local mints, got URL=%q status=%d duration=%d",
			entry.UpstreamURL, entry.UpstreamStatus, entry.UpstreamDurationMS)
	}
}

// TestToken_AuditPrecedesResponseWrite is the /token counterpart
// of the /delegate ordering test.
func TestToken_AuditPrecedesResponseWrite(t *testing.T) {
	t.Parallel()
	s := newTestStore(t, time.Minute)
	nonce := mintNonce(t, s, "alpha")

	var auditFired bool
	rec := &recordingLogger{onLog: func() { auditFired = true }}
	stub := &auditingStub{token: &destinations.Token{Value: "abc", Scheme: "bearer"}}
	h := handlers.NewTokenHandler(
		[]*net.IPNet{mustCIDR(t, "10.0.0.0/8")},
		s,
		destinations.Registry{"alpha": stub},
		rec,
		nil,
	)
	r := httptest.NewRequest(http.MethodPost, "/token",
		strings.NewReader(`{"nonce":"`+nonce+`","destination":"alpha"}`))
	r.RemoteAddr = "10.0.0.42:12345"
	w := &orderingResponseWriter{inner: httptest.NewRecorder(), auditFired: &auditFired, t: t}
	h.ServeHTTP(w, r)

	if !auditFired {
		t.Errorf("audit hook never fired")
	}
}

// auditingStub is a stubDestination variant that also runs a
// populate callback against the MintAudit installed in the
// context, mimicking what httptokenexchange.Mint does in
// production. It lets handler-level tests assert audit-log
// content without standing up a real upstream HTTPS server.
type auditingStub struct {
	token    *destinations.Token
	err      error
	populate func(*audit.MintAudit)
}

func (s *auditingStub) Mint(ctx context.Context, _ *auth.Identity) (*destinations.Token, error) {
	if s.populate != nil {
		if a := audit.MintAuditFromContext(ctx); a != nil {
			s.populate(a)
		}
	}
	return s.token, s.err
}

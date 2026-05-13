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

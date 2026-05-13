package handlers_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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
	h := newTokenHandler(t, store.NewInMemoryStore(time.Minute, 0), destinations.Registry{})
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
	h := newTokenHandler(t, store.NewInMemoryStore(time.Minute, 0), destinations.Registry{})
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(`{"nonce":"never","destination":"y"}`))
	r.RemoteAddr = "10.0.0.42:12345"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusGone {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusGone)
	}
}

func TestToken_RejectsAlreadyClaimedNonce(t *testing.T) {
	t.Parallel()
	s := store.NewInMemoryStore(time.Minute, 0)
	nonce := mintNonce(t, s, "alpha")
	if _, err := s.Claim(nonce); err != nil {
		t.Fatalf("first claim: %v", err)
	}

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
	s := store.NewInMemoryStore(time.Minute, 0)
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
	s := store.NewInMemoryStore(time.Minute, 0)
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
	s := store.NewInMemoryStore(time.Minute, 0)
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
	s := store.NewInMemoryStore(time.Minute, 0)
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

func TestToken_RejectsMalformedBody(t *testing.T) {
	t.Parallel()
	h := newTokenHandler(t, store.NewInMemoryStore(time.Minute, 0), destinations.Registry{})
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(`not-json`))
	r.RemoteAddr = "10.0.0.42:12345"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusBadRequest)
	}
}

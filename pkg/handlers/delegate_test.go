package handlers_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/auth"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/handlers"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/policy"
)

// fakeValidator is a BearerValidator that returns the configured
// Identity when token == "good", and an error otherwise.
type fakeValidator struct {
	identity *auth.Identity
}

func (f *fakeValidator) ValidateBearer(token string) (*auth.Identity, error) {
	if token == "good" {
		return f.identity, nil
	}
	return nil, errors.New("invalid token")
}

// fakePolicy returns a fixed list of allowed destinations regardless
// of the supplied Identity.
type fakePolicy struct{ allowed []string }

func (f *fakePolicy) Resolve(*auth.Identity) ([]string, error) { return f.allowed, nil }

func newDelegateHandler(t *testing.T, allowed []string) *handlers.DelegateHandler {
	t.Helper()
	id := &auth.Identity{Type: auth.IdentityTypeCI, Principal: "repo:owner/repo:ref:refs/heads/main"}
	return handlers.NewDelegateHandler(
		&fakeValidator{identity: id},
		&fakePolicy{allowed: allowed},
		newTestStore(t, 15*time.Minute),
		nil,
		nil,
	)
}

func TestDelegate_RejectsNonPostMethod(t *testing.T) {
	t.Parallel()
	h := newDelegateHandler(t, nil)
	r := httptest.NewRequest(http.MethodGet, "/delegate", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestDelegate_RejectsMissingAuthHeader(t *testing.T) {
	t.Parallel()
	h := newDelegateHandler(t, nil)
	r := httptest.NewRequest(http.MethodPost, "/delegate", strings.NewReader(`{"requested_destinations":["x"]}`))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestDelegate_RejectsInvalidBearerToken(t *testing.T) {
	t.Parallel()
	h := newDelegateHandler(t, nil)
	r := httptest.NewRequest(http.MethodPost, "/delegate", strings.NewReader(`{"requested_destinations":["x"]}`))
	r.Header.Set("Authorization", "Bearer bad")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestDelegate_RejectsEmptyRequestedDestinations(t *testing.T) {
	t.Parallel()
	h := newDelegateHandler(t, []string{"x"})
	r := httptest.NewRequest(http.MethodPost, "/delegate", strings.NewReader(`{"requested_destinations":[]}`))
	r.Header.Set("Authorization", "Bearer good")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestDelegate_RejectsRequestedOutsideAllowed(t *testing.T) {
	t.Parallel()
	h := newDelegateHandler(t, []string{"alpha"})
	r := httptest.NewRequest(http.MethodPost, "/delegate", strings.NewReader(`{"requested_destinations":["alpha","beta"]}`))
	r.Header.Set("Authorization", "Bearer good")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestDelegate_HappyPath(t *testing.T) {
	t.Parallel()
	h := newDelegateHandler(t, []string{"alpha", "beta"})
	r := httptest.NewRequest(http.MethodPost, "/delegate", strings.NewReader(`{"requested_destinations":["alpha","beta"]}`))
	r.Header.Set("Authorization", "Bearer good")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, `"nonce"`) {
		t.Errorf("response body missing nonce: %s", body)
	}
}

// TestDelegate_EmptyPolicyDeniesByDefault verifies that an empty
// policy configuration resolves every identity to the empty allowed
// set, so any non-empty requested_destinations list is rejected
// with 403. This is the operator's safety net when the policy file
// is misconfigured or absent.
func TestDelegate_EmptyPolicyDeniesByDefault(t *testing.T) {
	t.Parallel()
	id := &auth.Identity{Type: auth.IdentityTypeCI, Principal: "p"}
	eng, err := policy.New(policy.Config{})
	if err != nil {
		t.Fatalf("policy.New: %v", err)
	}
	h := handlers.NewDelegateHandler(&fakeValidator{identity: id}, eng,
		newTestStore(t, time.Minute), nil, nil)

	r := httptest.NewRequest(http.MethodPost, "/delegate",
		strings.NewReader(`{"requested_destinations":["alpha"]}`))
	r.Header.Set("Authorization", "Bearer good")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusForbidden)
	}
}

// TestDelegate_HonoursStoreTTL asserts that the operator-configured
// nonce-store TTL flows through to the expires_at field returned to
// callers. The handler must not impose its own TTL.
func TestDelegate_HonoursStoreTTL(t *testing.T) {
	t.Parallel()
	const configuredTTL = 7 * time.Minute
	id := &auth.Identity{Type: auth.IdentityTypeCI, Principal: "p"}
	h := handlers.NewDelegateHandler(
		&fakeValidator{identity: id},
		&fakePolicy{allowed: []string{"alpha"}},
		newTestStore(t, configuredTTL),
		nil,
		nil,
	)

	before := time.Now()
	r := httptest.NewRequest(http.MethodPost, "/delegate",
		strings.NewReader(`{"requested_destinations":["alpha"]}`))
	r.Header.Set("Authorization", "Bearer good")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	after := time.Now()

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want %d (body=%s)", w.Code, http.StatusOK, w.Body.String())
	}
	var resp struct {
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	earliest := before.Add(configuredTTL)
	latest := after.Add(configuredTTL)
	if resp.ExpiresAt.Before(earliest) || resp.ExpiresAt.After(latest) {
		t.Errorf("expires_at %v not within expected window [%v, %v] for TTL %v",
			resp.ExpiresAt, earliest, latest, configuredTTL)
	}
}

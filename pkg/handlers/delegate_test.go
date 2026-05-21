package handlers_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/audit"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/auth"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/handlers"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/policy"
)

// recordingLogger captures the order and content of audit-log
// calls so tests can assert both what was logged and the ordering
// of logging relative to HTTP response writes. Tests that care
// about ordering install an onLog hook that flips a flag also
// observed by an orderingResponseWriter; the writer asserts the
// flag is true before it allows a WriteHeader through, so an
// out-of-order handler fails the test rather than silently
// swapping the documented invariant.
type recordingLogger struct {
	mu       sync.Mutex
	delegate []audit.DelegateEntry
	token    []audit.TokenEntry
	onLog    func()
}

func (r *recordingLogger) LogDelegate(_ context.Context, e audit.DelegateEntry) {
	r.mu.Lock()
	r.delegate = append(r.delegate, e)
	r.mu.Unlock()
	if r.onLog != nil {
		r.onLog()
	}
}

func (r *recordingLogger) LogToken(_ context.Context, e audit.TokenEntry) {
	r.mu.Lock()
	r.token = append(r.token, e)
	r.mu.Unlock()
	if r.onLog != nil {
		r.onLog()
	}
}

// orderingResponseWriter wraps an inner http.ResponseWriter and
// fails the test the moment WriteHeader fires if the supplied
// auditFired flag is still false. The pairing with recordingLogger
// makes the audit-before-response invariant observable at the
// exact moment the handler tries to write a response.
type orderingResponseWriter struct {
	inner      http.ResponseWriter
	auditFired *bool
	t          *testing.T
}

func (o *orderingResponseWriter) Header() http.Header { return o.inner.Header() }

func (o *orderingResponseWriter) Write(b []byte) (int, error) {
	if o.auditFired != nil && !*o.auditFired {
		o.t.Errorf("response body written before audit log entry was emitted")
	}
	return o.inner.Write(b)
}

func (o *orderingResponseWriter) WriteHeader(code int) {
	if o.auditFired != nil && !*o.auditFired {
		o.t.Errorf("response WriteHeader(%d) called before audit log entry was emitted", code)
	}
	o.inner.WriteHeader(code)
}

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

// TestDelegate_GrantedEntryCarriesJTIAndExp confirms the audit
// record for a successful /delegate names the issued token by JTI
// and absolute expiry. These fields are the join key the audit
// pipeline uses to correlate /delegate decisions with the
// subsequent /token mints.
func TestDelegate_GrantedEntryCarriesJTIAndExp(t *testing.T) {
	t.Parallel()
	id := &auth.Identity{
		Type:      auth.IdentityTypeCI,
		Principal: "repo:owner/repo:ref:refs/heads/main",
		Claims:    map[string]any{"repository": "owner/repo"},
	}
	rec := &recordingLogger{}
	h := handlers.NewDelegateHandler(
		&fakeValidator{identity: id},
		&fakePolicy{allowed: []string{"alpha"}},
		newTestStore(t, time.Minute),
		rec,
		nil,
	)

	r := httptest.NewRequest(http.MethodPost, "/delegate",
		strings.NewReader(`{"requested_destinations":["alpha"]}`))
	r.Header.Set("Authorization", "Bearer good")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200 (body=%s)", w.Code, w.Body.String())
	}
	if len(rec.delegate) != 1 {
		t.Fatalf("audit calls: got %d, want 1", len(rec.delegate))
	}
	entry := rec.delegate[0]
	if entry.Result != audit.ResultGranted {
		t.Errorf("Result: got %q, want %q", entry.Result, audit.ResultGranted)
	}
	if entry.DelegationTokenJTI == "" {
		t.Errorf("DelegationTokenJTI: got empty, want populated")
	}
	if entry.DelegationTokenExp == nil {
		t.Errorf("DelegationTokenExp: got nil, want populated")
	}
	if entry.Identity == nil || entry.Identity.Claims["repository"] != "owner/repo" {
		t.Errorf("Identity claims missing repository: %+v", entry.Identity)
	}
}

// TestDelegate_DenialPreIdentityHasNilIdentity covers the
// pre-resolution rejection paths: a missing or invalid bearer
// token yields a denial entry whose Identity is nil so consumers
// can distinguish authenticated-but-denied from authentication
// failures.
func TestDelegate_DenialPreIdentityHasNilIdentity(t *testing.T) {
	t.Parallel()
	id := &auth.Identity{Type: auth.IdentityTypeCI, Principal: "p"}
	rec := &recordingLogger{}
	h := handlers.NewDelegateHandler(
		&fakeValidator{identity: id},
		&fakePolicy{allowed: []string{"alpha"}},
		newTestStore(t, time.Minute),
		rec,
		nil,
	)

	r := httptest.NewRequest(http.MethodPost, "/delegate", strings.NewReader(`{}`))
	// No Authorization header.
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if len(rec.delegate) != 1 {
		t.Fatalf("audit calls: got %d, want 1", len(rec.delegate))
	}
	if rec.delegate[0].Identity != nil {
		t.Errorf("Identity: got %+v, want nil", rec.delegate[0].Identity)
	}
	if rec.delegate[0].Result != audit.ResultDenied {
		t.Errorf("Result: got %q, want denied", rec.delegate[0].Result)
	}
	if !strings.Contains(rec.delegate[0].DenialReason, "Authorization") {
		t.Errorf("DenialReason: got %q", rec.delegate[0].DenialReason)
	}
}

// TestDelegate_AuditPrecedesResponseWrite locks in the contract
// that the handler emits its audit-log entry before writing the
// HTTP response. The orderingResponseWriter fails the test the
// moment WriteHeader fires before the audit hook has run, so any
// future refactor that swaps the order shows up here.
func TestDelegate_AuditPrecedesResponseWrite(t *testing.T) {
	t.Parallel()
	id := &auth.Identity{Type: auth.IdentityTypeCI, Principal: "p"}
	var auditFired bool
	rec := &recordingLogger{onLog: func() { auditFired = true }}
	h := handlers.NewDelegateHandler(
		&fakeValidator{identity: id},
		&fakePolicy{allowed: []string{"alpha"}},
		newTestStore(t, time.Minute),
		rec,
		nil,
	)

	r := httptest.NewRequest(http.MethodPost, "/delegate",
		strings.NewReader(`{"requested_destinations":["alpha"]}`))
	r.Header.Set("Authorization", "Bearer good")
	w := &orderingResponseWriter{inner: httptest.NewRecorder(), auditFired: &auditFired, t: t}
	h.ServeHTTP(w, r)

	if !auditFired {
		t.Errorf("audit hook never fired")
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

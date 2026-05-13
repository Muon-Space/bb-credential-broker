// Package handlers contains the HTTP handlers for /delegate, /token,
// /-/healthy and /metrics. The handlers are intentionally small;
// most of the work happens in their direct dependencies (the JWT
// parser, the policy engine, the nonce store and the destinations
// registry).
package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"time"

	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/audit"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/auth"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/metrics"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/policy"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/store"
)

// BearerValidator is the contract /delegate requires of the
// upstream JWT parser. Defining it as an interface keeps the
// handler testable without standing up a real JWKS file and
// signed-test-token plumbing.
type BearerValidator interface {
	ValidateBearer(token string) (*auth.Identity, error)
}

// DelegateHandler implements POST /delegate.
//
// The handler validates the caller's bearer JWT, resolves the
// caller's Identity, asks the policy engine which destinations the
// caller is allowed to mint tokens for, and mints a single-use
// nonce that the caller can subsequently exchange via /token.
type DelegateHandler struct {
	parser  BearerValidator
	policy  policy.Engine
	nonces  store.NonceStore
	audit   *audit.Logger
	metrics *metrics.Metrics
	now     func() time.Time
}

// NewDelegateHandler constructs a DelegateHandler from its
// dependencies. metrics may be nil when the caller does not need
// instrumentation (typically in unit tests).
func NewDelegateHandler(parser BearerValidator, p policy.Engine, n store.NonceStore, a *audit.Logger, m *metrics.Metrics) *DelegateHandler {
	return &DelegateHandler{
		parser:  parser,
		policy:  p,
		nonces:  n,
		audit:   a,
		metrics: m,
		now:     time.Now,
	}
}

// delegateRequest is the JSON body the caller POSTs to /delegate.
type delegateRequest struct {
	// RequestedDestinations is the list of destination names the
	// caller intends to mint tokens for. The handler intersects
	// this list with the policy-allowed set and rejects the
	// request if any requested destination is outside the
	// allowed set.
	RequestedDestinations []string `json:"requested_destinations"`
}

// delegateResponse is the JSON body /delegate returns on success.
type delegateResponse struct {
	Nonce               string    `json:"nonce"`
	ExpiresAt           time.Time `json:"expires_at"`
	GrantedDestinations []string  `json:"granted_destinations"`
}

// ServeHTTP implements http.Handler. The bulk of the request flow
// lives in serve so that the outer can record duration and outcome
// metrics without threading them through every early return.
func (h *DelegateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := h.now()
	status, identityType := h.serve(w, r)
	h.metrics.RecordDelegate(status, identityType, h.now().Sub(start))
}

// serve runs the request handler and returns the HTTP status it
// emitted along with the resolved identity type. identityType is
// empty when the request was rejected before identity resolution.
func (h *DelegateHandler) serve(w http.ResponseWriter, r *http.Request) (int, string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return http.StatusMethodNotAllowed, ""
	}
	header := r.Header.Get("Authorization")
	const bearerPrefix = "Bearer "
	if !strings.HasPrefix(header, bearerPrefix) {
		h.recordFailure("", "", http.StatusUnauthorized)
		http.Error(w, "missing or malformed Authorization header", http.StatusUnauthorized)
		return http.StatusUnauthorized, ""
	}
	identity, err := h.parser.ValidateBearer(strings.TrimPrefix(header, bearerPrefix))
	if err != nil {
		h.recordFailure("", "", http.StatusUnauthorized)
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return http.StatusUnauthorized, ""
	}
	identityType := string(identity.Type)

	var req delegateRequest
	if r.Body != nil {
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil && err.Error() != "EOF" {
			h.recordFailure(identityType, identity.Principal, http.StatusBadRequest)
			http.Error(w, "malformed request body", http.StatusBadRequest)
			return http.StatusBadRequest, identityType
		}
	}
	if len(req.RequestedDestinations) == 0 {
		h.recordFailure(identityType, identity.Principal, http.StatusBadRequest)
		http.Error(w, "requested_destinations must not be empty", http.StatusBadRequest)
		return http.StatusBadRequest, identityType
	}

	allowed, err := h.policy.Resolve(identity)
	if err != nil {
		h.recordFailure(identityType, identity.Principal, http.StatusInternalServerError)
		http.Error(w, "policy resolution failed", http.StatusInternalServerError)
		return http.StatusInternalServerError, identityType
	}
	for _, d := range req.RequestedDestinations {
		if !slices.Contains(allowed, d) {
			h.recordFailure(identityType, identity.Principal, http.StatusForbidden)
			http.Error(w, "requested destination is not allowed for this identity", http.StatusForbidden)
			return http.StatusForbidden, identityType
		}
	}

	// The handler intentionally leaves Record.ExpiresAt zero so
	// the nonce store applies its own configured TTL. The store
	// mutates the supplied record to record the absolute expiry
	// it assigned; that value is what the response advertises to
	// the caller.
	rec := &store.Record{
		Identity:            identity,
		AllowedDestinations: req.RequestedDestinations,
	}
	nonce, err := h.nonces.Mint(rec)
	if err != nil {
		h.recordFailure(identityType, identity.Principal, http.StatusInternalServerError)
		http.Error(w, "could not mint nonce", http.StatusInternalServerError)
		return http.StatusInternalServerError, identityType
	}

	if h.audit != nil {
		h.audit.Log(r.Context(), audit.Event{
			Time:                h.now(),
			Op:                  audit.OperationDelegate,
			IdentityType:        identityType,
			IdentityPrincipal:   identity.Principal,
			GrantedDestinations: req.RequestedDestinations,
			Success:             true,
		})
	}
	writeJSON(w, http.StatusOK, delegateResponse{
		Nonce:               nonce,
		ExpiresAt:           rec.ExpiresAt,
		GrantedDestinations: req.RequestedDestinations,
	})
	return http.StatusOK, identityType
}

func (h *DelegateHandler) recordFailure(identityType, principal string, status int) {
	if h.audit == nil {
		return
	}
	h.audit.Log(context.Background(), audit.Event{
		Time:              h.now(),
		Op:                audit.OperationDelegate,
		IdentityType:      identityType,
		IdentityPrincipal: principal,
		Success:           false,
		Error:             http.StatusText(status),
	})
}

// writeJSON serialises v to w with the supplied status code. Errors
// from the underlying writer are not surfaced; the standard library
// already records them in the server's error log.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// Package handlers contains the HTTP handlers for /delegate, /token,
// /-/healthy and /metrics. The handlers are intentionally small;
// most of the work happens in their direct dependencies (the JWT
// parser, the policy engine, the nonce store and the destinations
// registry).
package handlers

import (
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
// caller is allowed to mint tokens for, and mints a short-lived
// delegation token that the caller can subsequently exchange via
// /token. The token's exact form (opaque nonce, signed JWT, etc.)
// depends on the configured NonceStore backend.
type DelegateHandler struct {
	parser  BearerValidator
	policy  policy.Engine
	nonces  store.NonceStore
	audit   audit.Logger
	metrics *metrics.Metrics
	now     func() time.Time
}

// NewDelegateHandler constructs a DelegateHandler from its
// dependencies. metrics may be nil when the caller does not need
// instrumentation (typically in unit tests).
func NewDelegateHandler(parser BearerValidator, p policy.Engine, n store.NonceStore, a audit.Logger, m *metrics.Metrics) *DelegateHandler {
	return &DelegateHandler{
		parser:  parser,
		policy:  p,
		nonces:  n,
		audit:   a,
		metrics: m,
		now:     time.Now,
	}
}

// Denial reasons emitted under the audit-log's denial_reason field.
// They are part of the published log schema; downstream queries
// pivot on them.
const (
	denialMissingAuthorization     = "missing or malformed Authorization header"
	denialJWTValidationFailed      = "jwt validation failed"
	denialMalformedRequestBody     = "malformed request body"
	denialEmptyRequestedSet        = "requested_destinations must not be empty"
	denialPolicyResolutionError    = "policy resolution error"
	denialNoPolicyEntryMatched     = "no policy entry matched identity"
	denialDestinationNotInGrantSet = "requested destination not in granted set"
	denialNonceMintFailed          = "nonce mint failed"
)

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
//
// Every code path emits exactly one audit-log entry before writing
// the HTTP response, so the audit record is durable even when the
// caller subsequently disconnects. Failure reasons surfaced to the
// caller stay opaque; the audit log retains the operator-readable
// detail under denial_reason.
func (h *DelegateHandler) serve(w http.ResponseWriter, r *http.Request) (int, string) {
	if r.Method != http.MethodPost {
		// Method-not-allowed is the only path that does not
		// emit an audit-log entry: it is a malformed request
		// at the routing layer and the broker has no Identity
		// or intent to record.
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return http.StatusMethodNotAllowed, ""
	}
	header := r.Header.Get("Authorization")
	const bearerPrefix = "Bearer "
	if !strings.HasPrefix(header, bearerPrefix) {
		h.recordDenial(r, nil, denialMissingAuthorization)
		http.Error(w, "missing or malformed Authorization header", http.StatusUnauthorized)
		return http.StatusUnauthorized, ""
	}
	identity, err := h.parser.ValidateBearer(strings.TrimPrefix(header, bearerPrefix))
	if err != nil {
		h.recordDenial(r, nil, denialJWTValidationFailed+": "+err.Error())
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return http.StatusUnauthorized, ""
	}
	identityType := string(identity.Type)

	var req delegateRequest
	if r.Body != nil {
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil && err.Error() != "EOF" {
			h.recordDenial(r, identity, denialMalformedRequestBody)
			http.Error(w, "malformed request body", http.StatusBadRequest)
			return http.StatusBadRequest, identityType
		}
	}
	if len(req.RequestedDestinations) == 0 {
		h.recordDenial(r, identity, denialEmptyRequestedSet)
		http.Error(w, "requested_destinations must not be empty", http.StatusBadRequest)
		return http.StatusBadRequest, identityType
	}

	allowed, err := h.policy.Resolve(identity)
	if err != nil {
		h.recordDenial(r, identity, denialPolicyResolutionError+": "+err.Error())
		http.Error(w, "policy resolution failed", http.StatusInternalServerError)
		return http.StatusInternalServerError, identityType
	}
	if len(allowed) == 0 {
		h.recordDenial(r, identity, denialNoPolicyEntryMatched)
		http.Error(w, "requested destination is not allowed for this identity", http.StatusForbidden)
		return http.StatusForbidden, identityType
	}
	for _, d := range req.RequestedDestinations {
		if !slices.Contains(allowed, d) {
			h.recordDenial(r, identity, denialDestinationNotInGrantSet+": "+d)
			http.Error(w, "requested destination is not allowed for this identity", http.StatusForbidden)
			return http.StatusForbidden, identityType
		}
	}

	// The handler intentionally leaves Record.ExpiresAt zero so
	// the nonce store applies its own configured TTL. The store
	// mutates the supplied record to record the absolute expiry
	// and the JTI it assigned; those values are what the
	// response advertises to the caller and what the audit log
	// names the issued token by.
	rec := &store.Record{
		Identity:            identity,
		AllowedDestinations: req.RequestedDestinations,
	}
	nonce, err := h.nonces.Mint(rec)
	if err != nil {
		h.recordDenial(r, identity, denialNonceMintFailed+": "+err.Error())
		http.Error(w, "could not mint nonce", http.StatusInternalServerError)
		return http.StatusInternalServerError, identityType
	}

	h.recordGrant(r, identity, req.RequestedDestinations, rec)
	writeJSON(w, http.StatusOK, delegateResponse{
		Nonce:               nonce,
		ExpiresAt:           rec.ExpiresAt,
		GrantedDestinations: req.RequestedDestinations,
	})
	return http.StatusOK, identityType
}

// recordDenial emits one DelegateEntry with result="denied" and the
// supplied reason. The Identity may be nil for requests rejected
// before identity resolution.
func (h *DelegateHandler) recordDenial(r *http.Request, identity *auth.Identity, reason string) {
	if h.audit == nil {
		return
	}
	h.audit.LogDelegate(r.Context(), audit.DelegateEntry{
		Time:         h.now(),
		Identity:     toIdentityRecord(identity),
		Result:       audit.ResultDenied,
		DenialReason: reason,
	})
}

// recordGrant emits one DelegateEntry with result="granted" and
// the issued delegation token's identifying metadata.
func (h *DelegateHandler) recordGrant(r *http.Request, identity *auth.Identity, granted []string, rec *store.Record) {
	if h.audit == nil {
		return
	}
	exp := rec.ExpiresAt
	h.audit.LogDelegate(r.Context(), audit.DelegateEntry{
		Time:                h.now(),
		Identity:            toIdentityRecord(identity),
		Result:              audit.ResultGranted,
		GrantedDestinations: granted,
		DelegationTokenJTI:  rec.JTI,
		DelegationTokenExp:  &exp,
	})
}

// toIdentityRecord projects an auth.Identity into the audit log's
// IdentityRecord shape. A nil Identity yields a nil record so the
// resulting JSON renders "identity": null for pre-identity-resolution
// rejections.
func toIdentityRecord(id *auth.Identity) *audit.IdentityRecord {
	if id == nil {
		return nil
	}
	return &audit.IdentityRecord{
		Type:      string(id.Type),
		Principal: id.Principal,
		Claims:    id.Claims,
	}
}

// writeJSON serialises v to w with the supplied status code. Errors
// from the underlying writer are not surfaced; the standard library
// already records them in the server's error log.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

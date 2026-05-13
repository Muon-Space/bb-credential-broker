package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/audit"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/destinations"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/metrics"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/store"
)

// TokenHandler implements POST /token.
//
// The handler enforces the source-IP gate, claims the supplied
// nonce from the store, dispatches to the named destination's mint
// flow and returns the resulting Token to the caller. Every
// validation failure returns a HTTP status that allows the worker
// to distinguish between configuration errors (which it should
// surface to the user) and transient errors (which it may retry).
type TokenHandler struct {
	allowedNets []*net.IPNet
	store       store.NonceStore
	registry    destinations.Registry
	audit       *audit.Logger
	metrics     *metrics.Metrics
	now         func() time.Time
}

// NewTokenHandler constructs a TokenHandler from its dependencies.
// Nets enumerate the source CIDRs from which /token requests are
// accepted; any request from a source outside the union of these
// CIDRs is rejected with HTTP 401 before the body is read. metrics
// may be nil when the caller does not need instrumentation.
func NewTokenHandler(nets []*net.IPNet, s store.NonceStore, r destinations.Registry, a *audit.Logger, m *metrics.Metrics) *TokenHandler {
	return &TokenHandler{
		allowedNets: nets,
		store:       s,
		registry:    r,
		audit:       a,
		metrics:     m,
		now:         time.Now,
	}
}

// tokenRequest is the JSON body the caller POSTs to /token.
type tokenRequest struct {
	Nonce       string `json:"nonce"`
	Destination string `json:"destination"`
}

// tokenResponse is the JSON body /token returns on success.
type tokenResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	Scheme    string    `json:"scheme"`
}

// ServeHTTP implements http.Handler. The bulk of the request flow
// lives in serve so that the outer can record duration and outcome
// metrics without threading them through every early return.
func (h *TokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := h.now()
	status, identityType, destination := h.serve(w, r)
	h.metrics.RecordToken(status, identityType, destination, h.now().Sub(start))
}

// serve runs the request handler and returns the HTTP status it
// emitted, the resolved identity type and the requested destination
// name. identityType is empty when the request was rejected before
// nonce claim; destination is empty when the request was rejected
// before the body was parsed.
func (h *TokenHandler) serve(w http.ResponseWriter, r *http.Request) (int, string, string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return http.StatusMethodNotAllowed, "", ""
	}
	if !h.sourceAllowed(r) {
		h.recordFailure("", "", http.StatusUnauthorized)
		http.Error(w, "source address is not permitted", http.StatusUnauthorized)
		return http.StatusUnauthorized, "", ""
	}

	var req tokenRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		h.recordFailure("", "", http.StatusBadRequest)
		http.Error(w, "malformed request body", http.StatusBadRequest)
		return http.StatusBadRequest, "", ""
	}
	if req.Nonce == "" || req.Destination == "" {
		h.recordFailure("", req.Destination, http.StatusBadRequest)
		http.Error(w, "nonce and destination are required", http.StatusBadRequest)
		return http.StatusBadRequest, "", req.Destination
	}

	rec, err := h.store.Claim(req.Nonce)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// Audit log carries the underlying reason (expired,
			// bad signature, wrong issuer, etc.) so that
			// operators can distinguish routine token expiry
			// from active forgery attempts. The HTTP response
			// stays opaque so callers cannot probe.
			h.recordClaimFailure(req.Destination, http.StatusGone, err)
			http.Error(w, "nonce is not valid", http.StatusGone)
			return http.StatusGone, "", req.Destination
		}
		h.recordFailure("", req.Destination, http.StatusInternalServerError)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return http.StatusInternalServerError, "", req.Destination
	}
	identityType := string(rec.Identity.Type)
	if !rec.AllowsDestination(req.Destination) {
		h.recordFailure(identityType, rec.Identity.Principal, http.StatusForbidden)
		http.Error(w, "destination is not granted by this nonce", http.StatusForbidden)
		return http.StatusForbidden, identityType, req.Destination
	}

	dest := h.registry.Lookup(req.Destination)
	if dest == nil {
		h.recordFailure(identityType, rec.Identity.Principal, http.StatusNotFound)
		http.Error(w, "destination is not configured", http.StatusNotFound)
		return http.StatusNotFound, identityType, req.Destination
	}

	tok, err := dest.Mint(r.Context(), rec.Identity)
	if err != nil {
		h.recordMintFailure(rec, req.Destination, http.StatusBadGateway, err)
		http.Error(w, "destination mint failed", http.StatusBadGateway)
		return http.StatusBadGateway, identityType, req.Destination
	}

	if h.audit != nil {
		h.audit.Log(r.Context(), audit.Event{
			Time:              h.now(),
			Op:                audit.OperationToken,
			IdentityType:      identityType,
			IdentityPrincipal: rec.Identity.Principal,
			Destination:       req.Destination,
			Success:           true,
		})
	}
	writeJSON(w, http.StatusOK, tokenResponse{
		Token:     tok.Value,
		ExpiresAt: tok.ExpiresAt,
		Scheme:    tok.Scheme,
	})
	return http.StatusOK, identityType, req.Destination
}

// sourceAllowed reports whether the caller's source address falls
// inside one of the configured allowed networks.
func (h *TokenHandler) sourceAllowed(r *http.Request) bool {
	if len(h.allowedNets) == 0 {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range h.allowedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (h *TokenHandler) recordFailure(identityType, destination string, status int) {
	if h.audit == nil {
		return
	}
	h.audit.Log(context.Background(), audit.Event{
		Time:         h.now(),
		Op:           audit.OperationToken,
		IdentityType: identityType,
		Destination:  destination,
		Success:      false,
		Error:        http.StatusText(status),
	})
}

func (h *TokenHandler) recordClaimFailure(destination string, status int, err error) {
	if h.audit == nil {
		return
	}
	msg := http.StatusText(status)
	if err != nil {
		msg = msg + ": " + err.Error()
	}
	h.audit.Log(context.Background(), audit.Event{
		Time:        h.now(),
		Op:          audit.OperationToken,
		Destination: destination,
		Success:     false,
		Error:       msg,
	})
}

func (h *TokenHandler) recordMintFailure(rec *store.Record, destination string, status int, err error) {
	if h.audit == nil {
		return
	}
	h.audit.Log(context.Background(), audit.Event{
		Time:              h.now(),
		Op:                audit.OperationToken,
		IdentityType:      string(rec.Identity.Type),
		IdentityPrincipal: rec.Identity.Principal,
		Destination:       destination,
		Success:           false,
		Error:             http.StatusText(status) + ": " + err.Error(),
	})
}

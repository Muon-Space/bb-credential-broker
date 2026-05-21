package handlers

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/audit"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/auth"
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
	audit       audit.Logger
	metrics     *metrics.Metrics
	now         func() time.Time
}

// NewTokenHandler constructs a TokenHandler from its dependencies.
// Nets enumerate the source CIDRs from which /token requests are
// accepted; any request from a source outside the union of these
// CIDRs is rejected with HTTP 401 before the body is read. metrics
// may be nil when the caller does not need instrumentation.
func NewTokenHandler(nets []*net.IPNet, s store.NonceStore, r destinations.Registry, a audit.Logger, m *metrics.Metrics) *TokenHandler {
	return &TokenHandler{
		allowedNets: nets,
		store:       s,
		registry:    r,
		audit:       a,
		metrics:     m,
		now:         time.Now,
	}
}

// Denial reasons emitted under the audit-log's denial_reason field
// on the /token side. They are part of the published log schema.
//
//nolint:gosec // G101: these are denial-reason strings written to the audit log, not credentials
const (
	denialSourceNotPermitted    = "source address is not permitted"
	denialTokenMalformedBody    = "malformed request body"
	denialNonceOrDestEmpty      = "nonce and destination are required"
	denialNonceInvalid          = "nonce is not valid"
	denialDestinationNotInNonce = "destination is not granted by this nonce"
	denialDestinationNotKnown   = "destination is not configured"
	denialDestinationMintFailed = "destination mint failed"
)

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

	// Username is set only by destinations that pair the token
	// with a basic-auth username (typically the static-secret
	// type when dispensing a personal access token to git or an
	// OCI registry). Bearer-token destinations leave it empty.
	Username string `json:"username,omitempty"`
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
//
// Every code path emits exactly one audit-log entry before writing
// the HTTP response. The handler installs a MintAudit value in the
// context handed to the destination's Mint call so the destination
// can populate upstream metadata that the audit-log entry surfaces
// uniformly across success and failure paths.
func (h *TokenHandler) serve(w http.ResponseWriter, r *http.Request) (int, string, string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return http.StatusMethodNotAllowed, "", ""
	}
	if !h.sourceAllowed(r) {
		h.recordTokenFailure(r, nil, "", "", denialSourceNotPermitted, nil)
		http.Error(w, "source address is not permitted", http.StatusUnauthorized)
		return http.StatusUnauthorized, "", ""
	}

	var req tokenRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		h.recordTokenFailure(r, nil, "", "", denialTokenMalformedBody, nil)
		http.Error(w, "malformed request body", http.StatusBadRequest)
		return http.StatusBadRequest, "", ""
	}
	if req.Nonce == "" || req.Destination == "" {
		h.recordTokenFailure(r, nil, "", req.Destination, denialNonceOrDestEmpty, nil)
		http.Error(w, "nonce and destination are required", http.StatusBadRequest)
		return http.StatusBadRequest, "", req.Destination
	}

	rec, err := h.store.Claim(req.Nonce)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// Audit log retains the underlying reason
			// (expired, bad signature, wrong issuer, etc.)
			// so operators can distinguish routine token
			// expiry from active forgery attempts. The
			// HTTP response stays opaque so callers cannot
			// probe.
			h.recordTokenFailure(r, nil, "", req.Destination, denialNonceInvalid+": "+err.Error(), nil)
			http.Error(w, "nonce is not valid", http.StatusGone)
			return http.StatusGone, "", req.Destination
		}
		h.recordTokenFailure(r, nil, "", req.Destination, "claim error: "+err.Error(), nil)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return http.StatusInternalServerError, "", req.Destination
	}
	identityType := string(rec.Identity.Type)
	if !rec.AllowsDestination(req.Destination) {
		h.recordTokenFailure(r, rec.Identity, identityType, req.Destination, denialDestinationNotInNonce, nil)
		http.Error(w, "destination is not granted by this nonce", http.StatusForbidden)
		return http.StatusForbidden, identityType, req.Destination
	}

	dest := h.registry.Lookup(req.Destination)
	if dest == nil {
		h.recordTokenFailure(r, rec.Identity, identityType, req.Destination, denialDestinationNotKnown, nil)
		http.Error(w, "destination is not configured", http.StatusNotFound)
		return http.StatusNotFound, identityType, req.Destination
	}

	// Install the MintAudit so the destination implementation
	// can populate upstream-call metadata that this handler
	// folds into the TokenEntry regardless of mint outcome.
	mintAudit := &audit.MintAudit{}
	ctx := audit.ContextWithMintAudit(r.Context(), mintAudit)

	tok, err := dest.Mint(ctx, rec.Identity)
	if err != nil {
		h.recordTokenFailure(r, rec.Identity, identityType, req.Destination, denialDestinationMintFailed+": "+err.Error(), mintAudit)
		http.Error(w, "destination mint failed", http.StatusBadGateway)
		return http.StatusBadGateway, identityType, req.Destination
	}

	h.recordTokenSuccess(r, rec.Identity, req.Destination, tok, mintAudit)
	writeJSON(w, http.StatusOK, tokenResponse{
		Token:     tok.Value,
		ExpiresAt: tok.ExpiresAt,
		Scheme:    tok.Scheme,
		Username:  tok.Username,
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

// recordTokenFailure emits one TokenEntry with result="failure"
// and the supplied denial reason. The mintAudit argument may be
// nil for failures that occur before destination dispatch (source
// gate, malformed body, etc.); when non-nil its populated fields
// are propagated into the entry.
//
//nolint:revive // argument count mirrors the shape of the entry
func (h *TokenHandler) recordTokenFailure(r *http.Request, identity *auth.Identity, identityType, destination, reason string, mintAudit *audit.MintAudit) {
	if h.audit == nil {
		return
	}
	_ = identityType // recorded via the metrics layer at ServeHTTP; preserved in the signature for symmetry with recordTokenSuccess.
	entry := audit.TokenEntry{
		Time:         h.now(),
		Identity:     toIdentityRecord(identity),
		Destination:  destination,
		Result:       audit.ResultFailure,
		DenialReason: reason,
	}
	applyMintAudit(&entry, mintAudit)
	h.audit.LogToken(r.Context(), entry)
}

// recordTokenSuccess emits one TokenEntry with result="success"
// and the minted token's expiry, along with whatever upstream
// metadata the destination populated.
func (h *TokenHandler) recordTokenSuccess(r *http.Request, identity *auth.Identity, destination string, tok *destinations.Token, mintAudit *audit.MintAudit) {
	if h.audit == nil {
		return
	}
	entry := audit.TokenEntry{
		Time:        h.now(),
		Identity:    toIdentityRecord(identity),
		Destination: destination,
		Result:      audit.ResultSuccess,
	}
	if !tok.ExpiresAt.IsZero() {
		exp := tok.ExpiresAt
		entry.TokenExpiresAt = &exp
	}
	applyMintAudit(&entry, mintAudit)
	h.audit.LogToken(r.Context(), entry)
}

// applyMintAudit folds the upstream-call metadata produced by the
// destination's Mint call into entry. The function tolerates a nil
// mintAudit: failures before destination dispatch leave entry's
// upstream_* fields zero, and the omitempty tags drop them from
// the JSON output.
func applyMintAudit(entry *audit.TokenEntry, mintAudit *audit.MintAudit) {
	if mintAudit == nil {
		return
	}
	entry.UpstreamURL = mintAudit.UpstreamURL
	entry.UpstreamStatus = mintAudit.UpstreamStatusCode
	if mintAudit.UpstreamDuration > 0 {
		entry.UpstreamDurationMS = mintAudit.UpstreamDuration.Milliseconds()
	}
	entry.UpstreamResponseExcerpt = mintAudit.UpstreamResponseExcerpt
}

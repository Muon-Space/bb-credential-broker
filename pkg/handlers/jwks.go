package handlers

import (
	"net/http"
	"strconv"
)

// jwksCacheSeconds is the value the JWKS handler advertises in
// Cache-Control: max-age. Downstream verifiers (JFrog and any
// other generic-OIDC consumer) typically poll the JWKS endpoint
// when their cached key expires; 300 seconds is short enough that
// a key rotation propagates within a few minutes and long enough
// that the broker's API listener is not hit on every mint.
const jwksCacheSeconds = 300

// JWKSHandler implements GET /.well-known/jwks.json. The response
// body is precomputed once at construction time so the per-request
// path performs no JSON marshaling, no key serialisation, and no
// allocation beyond the response write.
//
// The handler is registered on the API listener (the same listener
// /delegate and /token sit behind) so the operator's existing
// ingress reaches it without any further networking work. The
// endpoint is unauthenticated by design: a JSON Web Key Set is
// intentionally public information.
type JWKSHandler struct {
	body []byte
}

// NewJWKSHandler constructs a JWKSHandler that serves body
// verbatim. body must be a valid JSON Web Key Set encoding (RFC
// 7517 §5); production callers obtain it from
// signer.Signer.JWKSBytes(), tests may supply any byte slice.
func NewJWKSHandler(body []byte) *JWKSHandler {
	return &JWKSHandler{body: body}
}

// ServeHTTP implements http.Handler. GET and HEAD requests
// receive the precomputed JWKS body; other methods receive 405.
func (h *JWKSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/jwk-set+json")
	w.Header().Set("Cache-Control", "max-age="+strconv.Itoa(jwksCacheSeconds))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(h.body)
}

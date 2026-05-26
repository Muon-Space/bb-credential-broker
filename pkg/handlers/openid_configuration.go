package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
)

// openIDConfigurationCacheSeconds is the value the discovery
// handler advertises in Cache-Control: max-age. Discovery
// documents are intended to be very static — operators publish a
// new one only when the broker's issuer URL changes — so the
// cache window can be longer than the JWKS endpoint's. One hour
// is a common default for OIDC discovery and matches what
// Auth0 / Okta / Keycloak publish.
const openIDConfigurationCacheSeconds = 3600

// OpenIDConfigurationHandler implements
// GET /.well-known/openid-configuration. The response body is
// precomputed once at construction so the per-request path
// performs no JSON marshalling and no allocation beyond the
// response write.
//
// The handler is registered on the API listener (the same
// listener /delegate, /token and /.well-known/jwks.json sit
// behind) so an operator's existing ingress reaches it without
// further networking configuration. The endpoint is
// unauthenticated by design: a discovery document is intended to
// be public information.
//
// Registration is conditional on the operator supplying an issuer
// URL via brokerSigner.issuer. Without one the broker has no way
// to know what to advertise as its own issuer, and the handler is
// not installed at all.
type OpenIDConfigurationHandler struct {
	body []byte
}

// OpenIDConfigurationParams collects the broker-published values
// the handler returns. Issuer is required; JWKSURI defaults to
// Issuer + "/.well-known/jwks.json" when empty.
type OpenIDConfigurationParams struct {
	Issuer  string
	JWKSURI string
}

// NewOpenIDConfigurationHandler constructs a handler from the
// supplied issuer metadata. The body is marshalled once at
// construction time; subsequent requests serve the precomputed
// bytes.
func NewOpenIDConfigurationHandler(p OpenIDConfigurationParams) (*OpenIDConfigurationHandler, error) {
	jwksURI := p.JWKSURI
	if jwksURI == "" {
		jwksURI = p.Issuer + "/.well-known/jwks.json"
	}
	doc := openIDConfigurationDocument{
		Issuer:                           p.Issuer,
		JWKSURI:                          jwksURI,
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
		ResponseTypesSupported:           []string{"token"},
		SubjectTypesSupported:            []string{"public"},
	}
	body, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	return &OpenIDConfigurationHandler{body: body}, nil
}

// openIDConfigurationDocument is the JSON shape RFC 8414 defines
// for an OAuth 2.0 Authorization Server Metadata response and that
// the OIDC Discovery 1.0 spec extends. The broker advertises only
// the minimum the spec requires plus what generic-OIDC consumers
// (JFrog, Keycloak, Auth0) need to bootstrap the JWKS lookup.
type openIDConfigurationDocument struct {
	Issuer                           string   `json:"issuer"`
	JWKSURI                          string   `json:"jwks_uri"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
}

// ServeHTTP implements http.Handler. GET and HEAD requests
// receive the precomputed discovery document; other methods
// receive 405.
func (h *OpenIDConfigurationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "max-age="+strconv.Itoa(openIDConfigurationCacheSeconds))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(h.body)
}

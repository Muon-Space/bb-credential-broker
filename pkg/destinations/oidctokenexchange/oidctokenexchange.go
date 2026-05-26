// Package oidctokenexchange implements a higher-level destination
// type for the canonical OAuth 2.0 Token Exchange (RFC 8693) flow
// where the broker mints its own JWT, uses it as subject_token, and
// the downstream service validates the signature against the
// broker's published JWKS.
//
// The type exists because the lower-level httpTokenExchange shape
// — every field a template, body shape and header set the
// operator's responsibility — is a footgun for this very common
// case: operators have to remember to use body.form (because
// body.json is incompatible with templated JSON, see the README
// "Body encoding gotcha"), compose the JWT claims via
// ${signjwt:...} + ${json:...} + ${default:...} by hand, and
// match the kid published in /.well-known/jwks.json. The
// oidcTokenExchange type packages all of that into a type-safe
// config block whose fields are exactly the operator-meaningful
// knobs.
//
// Implementation: oidcTokenExchange compiles its config down to an
// equivalent httpTokenExchange config at broker start-up and
// delegates request execution to the existing httptokenexchange
// machinery. This keeps zero new HTTP, JMESPath, or mint code in
// the broker; bug fixes to httptokenexchange benefit both types.
package oidctokenexchange

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/destinations/httptokenexchange"
)

// Default values that operators can omit from their configuration.
const (
	defaultAlgorithm        = "RS256"
	defaultTTL              = "5m"
	defaultSubjectTokenType = "urn:ietf:params:oauth:token-type:id_token"
)

// Config is the configuration shape for a single named
// oidcTokenExchange destination.
type Config struct {
	// URL is the absolute HTTP URL of the downstream
	// token-exchange endpoint. The broker POSTs the form-encoded
	// exchange request here.
	URL string `json:"url"`

	// ProviderName is the value sent in the request body's
	// provider_name field. Downstream services use this to look
	// up the OIDC provider configuration that names the broker's
	// JWKS and issuer.
	ProviderName string `json:"providerName"`

	// SubjectToken describes how the broker constructs the JWT
	// it sends as the request's subject_token. Exactly one
	// subject-token shape (currently only signedJWT) must be
	// configured.
	SubjectToken SubjectTokenConfig `json:"subjectToken"`

	// SubjectTokenType is the value sent in the request body's
	// subject_token_type field. Empty defaults to the OIDC ID
	// Token type (defaultSubjectTokenType), which is the shape
	// most downstreams accept even though a broker-signed JWT is
	// technically the generic JWT type per RFC 8693 §3.
	SubjectTokenType string `json:"subjectTokenType,omitempty"`

	// Response describes how the broker extracts the resulting
	// access token from the downstream response. Passed through
	// to httpTokenExchange verbatim.
	Response httptokenexchange.ResponseConfig `json:"response"`
}

// SubjectTokenConfig is the discriminated union over supported
// subject-token shapes. Today only signedJWT is implemented; the
// shape leaves room for future additions (a static reference
// token, a chain-of-trust shape, etc.) without changing the
// surrounding destination schema.
type SubjectTokenConfig struct {
	SignedJWT *SignedJWTConfig `json:"signedJWT,omitempty"`
}

// SignedJWTConfig configures the broker-minted JWT the
// destination sends as subject_token.
type SignedJWTConfig struct {
	// SigningKey names an entry in the broker's top-level
	// secrets map whose resolved value is the PEM-encoded RSA
	// private key the broker uses to sign the JWT. The
	// corresponding public key is published via the JWKS
	// endpoint; the kid embedded in the JWT header is the RFC
	// 7638 thumbprint of the public key.
	SigningKey string `json:"signingKey"`

	// Algorithm is the JWA signing algorithm. Empty defaults to
	// RS256, which is the only algorithm the broker's JWKS
	// endpoint advertises today.
	Algorithm string `json:"algorithm,omitempty"`

	// Issuer is the value the broker stamps into the JWT's iss
	// claim. Operators typically set this to the same URL the
	// broker advertises via brokerSigner.issuer so downstream
	// verifiers can correlate the JWT to the discovery document.
	Issuer string `json:"issuer"`

	// Subject is the value the broker stamps into the JWT's sub
	// claim. The field is a template expression; common choices
	// are a fixed broker service-account principal (when
	// existing downstream mappings expect a single subject) or
	// ${identity.principal} (when mappings pivot per-build on
	// the originating CI identity).
	Subject string `json:"subject"`

	// Audience, when non-empty, becomes the JWT's aud claim.
	// Match what the downstream OIDC provider configuration
	// validates, or omit if the provider does not validate
	// audience.
	Audience string `json:"audience,omitempty"`

	// TTL is the time-to-live for the issued JWT. Empty
	// defaults to defaultTTL. Must parse as a Go-style
	// time.Duration ("5m", "300s", etc.).
	TTL string `json:"ttl,omitempty"`

	// Claims forwards additional claims into the JWT. Keys are
	// the JSON object keys; values are template expressions
	// evaluated per request. Each value is auto-typed via the
	// ${json:...} template function: number-shaped templates
	// land as JSON numbers, string-shaped templates land as
	// JSON-escaped strings.
	Claims map[string]string `json:"claims,omitempty"`
}

// New constructs the httpTokenExchange.Impl backing this
// destination type. The Impl is what the destinations registry
// returns to the /token handler; from there execution is
// indistinguishable from a hand-rolled httpTokenExchange
// destination, so the broker reuses every existing code path
// (template eval, JMESPath response extraction, MintAudit
// plumbing, metrics middleware).
//
// Errors are returned wrapped with the destination name so the
// registry-build error surface stays consistent.
func New(name string, cfg *Config, deps httptokenexchange.Dependencies) (*httptokenexchange.Impl, error) {
	if cfg == nil {
		return nil, fmt.Errorf("nil config")
	}
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	transformed, err := cfg.toHTTPTokenExchange()
	if err != nil {
		return nil, err
	}
	return httptokenexchange.New(name, transformed, deps)
}

// validateConfig enforces the required-field invariants that
// would otherwise surface as template-construction errors deep in
// httptokenexchange.New. Errors point at the operator-visible
// field path.
func validateConfig(cfg *Config) error {
	if cfg.URL == "" {
		return fmt.Errorf("url is required")
	}
	if cfg.ProviderName == "" {
		return fmt.Errorf("providerName is required")
	}
	if cfg.SubjectToken.SignedJWT == nil {
		return fmt.Errorf("subjectToken.signedJWT is required (the only supported subject-token shape today)")
	}
	sj := cfg.SubjectToken.SignedJWT
	if sj.SigningKey == "" {
		return fmt.Errorf("subjectToken.signedJWT.signingKey is required")
	}
	if sj.Issuer == "" {
		return fmt.Errorf("subjectToken.signedJWT.issuer is required")
	}
	if sj.Subject == "" {
		return fmt.Errorf("subjectToken.signedJWT.subject is required")
	}
	ttl := sj.TTL
	if ttl == "" {
		ttl = defaultTTL
	}
	if _, err := time.ParseDuration(ttl); err != nil {
		return fmt.Errorf("subjectToken.signedJWT.ttl: %w", err)
	}
	if alg := sj.Algorithm; alg != "" && alg != defaultAlgorithm {
		return fmt.Errorf("subjectToken.signedJWT.algorithm: %q is not supported; broker advertises %s only", alg, defaultAlgorithm)
	}
	return nil
}

// toHTTPTokenExchange compiles the high-level configuration down
// to the lower-level httpTokenExchange shape the existing
// destination machinery already knows how to execute.
//
// The transform builds a form-encoded RFC 8693 request body and a
// subject_token template that wraps the operator-supplied claims
// in ${signjwt:RS256:${secret:KEY}:${json:...}}. Each claim
// VALUE is passed verbatim to ${json:...}, which auto-types it at
// evaluation time (number-shaped templates land as JSON numbers,
// string-shaped templates land as JSON-escaped strings).
//
// The transform is deterministic and runs once at broker
// start-up; any error here surfaces in app.New / validate
// alongside the rest of the configuration-load checks.
func (c *Config) toHTTPTokenExchange() (*httptokenexchange.Config, error) {
	sj := c.SubjectToken.SignedJWT

	ttl := sj.TTL
	if ttl == "" {
		ttl = defaultTTL
	}
	alg := sj.Algorithm
	if alg == "" {
		alg = defaultAlgorithm
	}
	subjectTokenType := c.SubjectTokenType
	if subjectTokenType == "" {
		subjectTokenType = defaultSubjectTokenType
	}

	subjectToken := buildSubjectTokenTemplate(sj, alg, ttl)

	return &httptokenexchange.Config{
		Request: httptokenexchange.RequestConfig{
			Method: "POST",
			URL:    c.URL,
			Headers: map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
			},
			Body: &httptokenexchange.BodyConfig{
				Form: map[string]string{
					"grant_type":         "urn:ietf:params:oauth:grant-type:token-exchange",
					"subject_token_type": subjectTokenType,
					"subject_token":      subjectToken,
					"provider_name":      c.ProviderName,
				},
			},
		},
		Response: c.Response,
	}, nil
}

// buildSubjectTokenTemplate assembles the ${signjwt:...:${json:...}}
// template string the broker evaluates at /token time. Claim keys
// are sorted lexicographically so a given configuration produces
// the same template at every broker boot (the operator's
// `bb-credential-broker render` output is then byte-identical
// across runs, which makes diff review tractable).
func buildSubjectTokenTemplate(sj *SignedJWTConfig, alg, ttl string) string {
	// Build the ${json:...} argument list. iss/sub/iat/exp/aud
	// are emitted in this fixed order so the resulting JWT
	// claims body is deterministic; user-supplied claims follow
	// in lexicographic order.
	jsonArgs := []string{
		"iss", quotedJSONString(sj.Issuer),
		"sub", sj.Subject,
		"iat", "${now}",
		"exp", "${now+" + ttl + "}",
	}
	if sj.Audience != "" {
		jsonArgs = append(jsonArgs, "aud", quotedJSONString(sj.Audience))
	}
	keys := make([]string, 0, len(sj.Claims))
	for k := range sj.Claims {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		jsonArgs = append(jsonArgs, k, sj.Claims[k])
	}

	jsonExpr := "${json:" + strings.Join(jsonArgs, ":") + "}"
	return "${signjwt:" + alg + ":${secret:" + sj.SigningKey + "}:" + jsonExpr + "}"
}

// quotedJSONString wraps s as a JSON string literal so the
// emitted form is what an operator would have hand-written for a
// fixed string claim: with surrounding double quotes and proper
// escaping. The ${json:...} function's auto-typing rule then
// recognises the result as a valid JSON literal and passes it
// through verbatim.
func quotedJSONString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

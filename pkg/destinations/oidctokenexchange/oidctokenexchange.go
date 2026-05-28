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
//
//nolint:gosec // G101: the subject_token_type URN is an IANA-registered identifier, not a credential
const (
	defaultAlgorithm        = "RS256"
	defaultTTL              = "5m"
	defaultSubjectTokenType = "urn:ietf:params:oauth:token-type:id_token"
	defaultBodyFormat       = BodyFormatForm
)

// BodyFormat values for the destination's request body shape.
// "form" is RFC 8693's canonical x-www-form-urlencoded payload
// and the default. "json" emits the same fields as a JSON object
// with Content-Type: application/json — required for downstreams
// (Artifactory among them) that reject form-encoded bodies with
// HTTP 415 Unsupported Media Type despite the spec.
const (
	BodyFormatForm = "form"
	BodyFormatJSON = "json"
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

	// BodyFormat controls the wire format of the request body.
	// Permitted values:
	//
	//   "form" — application/x-www-form-urlencoded (default;
	//            RFC 8693's canonical shape).
	//   "json" — application/json (required by Artifactory and
	//            other downstreams that reject form-encoded
	//            bodies with HTTP 415 Unsupported Media Type
	//            despite the spec).
	//
	// Empty defaults to "form". The choice is downstream-
	// specific; operators consult their target service's API
	// documentation before adoption.
	BodyFormat string `json:"bodyFormat,omitempty"`

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
	switch cfg.BodyFormat {
	case "", BodyFormatForm, BodyFormatJSON:
	default:
		return fmt.Errorf("bodyFormat: %q is not supported; want %q or %q", cfg.BodyFormat, BodyFormatForm, BodyFormatJSON)
	}
	return nil
}

// toHTTPTokenExchange compiles the high-level configuration down
// to the lower-level httpTokenExchange shape the existing
// destination machinery already knows how to execute.
//
// The transform builds an RFC 8693 request body (form-encoded by
// default, JSON when bodyFormat is "json") and a subject_token
// template that wraps the operator-supplied claims in
// ${signjwt:RS256:${secret:KEY}:${json:...}}. Each claim VALUE
// is passed verbatim to ${json:...}, which auto-types it at
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
	bodyFormat := c.BodyFormat
	if bodyFormat == "" {
		bodyFormat = defaultBodyFormat
	}

	subjectToken := buildSubjectTokenTemplate(sj, alg, ttl)

	headers, body := buildRequestBody(bodyFormat, c.ProviderName, subjectTokenType, subjectToken)
	return &httptokenexchange.Config{
		Request: httptokenexchange.RequestConfig{
			Method:  "POST",
			URL:     c.URL,
			Headers: headers,
			Body:    body,
		},
		Response: c.Response,
	}, nil
}

// buildRequestBody returns the Content-Type header set and the
// BodyConfig the destination should emit for the operator-chosen
// body format. The same four logical fields (grant_type,
// subject_token_type, subject_token, provider_name) are sent in
// both shapes; only the wire encoding differs.
//
// The JSON path uses body.raw with ${json:...} wrapping rather
// than body.json because the subject_token value contains the
// nested ${signjwt:...:${json:...}} template — body.json's
// footgun detector would correctly reject that pattern (the
// signjwt arg includes literal " chars that would break the
// template parser once JSON-encoded). body.raw skips the JSON
// re-encoding step and feeds the operator-supplied bytes
// through unchanged.
func buildRequestBody(format, providerName, subjectTokenType, subjectToken string) (map[string]string, *httptokenexchange.BodyConfig) {
	switch format {
	case BodyFormatJSON:
		headers := map[string]string{"Content-Type": "application/json"}
		// Quote each fixed-string field (grant_type, provider_name,
		// subject_token_type) and pass subject_token through
		// verbatim; the ${json:...} call auto-types its values.
		body := &httptokenexchange.BodyConfig{
			Raw: "${json:" +
				"grant_type:" + jsonArgValue("urn:ietf:params:oauth:grant-type:token-exchange") +
				":subject_token_type:" + jsonArgValue(subjectTokenType) +
				":subject_token:" + subjectToken +
				":provider_name:" + jsonArgValue(providerName) +
				"}",
		}
		return headers, body
	default: // BodyFormatForm
		headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
		body := &httptokenexchange.BodyConfig{
			Form: map[string]string{
				"grant_type":         "urn:ietf:params:oauth:grant-type:token-exchange",
				"subject_token_type": subjectTokenType,
				"subject_token":      subjectToken,
				"provider_name":      providerName,
			},
		}
		return headers, body
	}
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
		"iss", jsonArgValue(sj.Issuer),
		"sub", jsonArgValue(sj.Subject),
		"iat", "${now}",
		"exp", "${now+" + ttl + "}",
	}
	if sj.Audience != "" {
		jsonArgs = append(jsonArgs, "aud", jsonArgValue(sj.Audience))
	}
	keys := make([]string, 0, len(sj.Claims))
	for k := range sj.Claims {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		jsonArgs = append(jsonArgs, k, jsonArgValue(sj.Claims[k]))
	}

	jsonExpr := "${json:" + strings.Join(jsonArgs, ":") + "}"
	return "${signjwt:" + alg + ":${secret:" + sj.SigningKey + "}:" + jsonExpr + "}"
}

// jsonArgValue returns the form of v that should be passed as a
// ${json:...} value argument:
//
//   - Pure literals (strings containing no ${...} substitution
//     markers) are wrapped in JSON quotes so the literal can
//     safely contain colons and other arg-separator characters.
//     The canonical case is a fixed service-account subject like
//     "system:serviceaccount:NAMESPACE:NAME" whose colons would
//     otherwise be interpreted as ${json:...} arg separators and
//     misalign the entire argument list.
//   - Templated values pass through verbatim so their ${...}
//     expressions are evaluated per request. The ${json:...}
//     function's auto-typing rule then wraps the evaluated
//     result as a JSON string at runtime.
//
// The heuristic is "contains ${"; it deliberately does not try
// to parse the template at this layer. Mixed inputs like
// "prefix-${identity.principal}" pass through and evaluate
// correctly because ${json:...}'s auto-typer wraps the final
// concatenated string at runtime.
func jsonArgValue(v string) string {
	if strings.Contains(v, "${") {
		return v
	}
	b, _ := json.Marshal(v)
	return string(b)
}

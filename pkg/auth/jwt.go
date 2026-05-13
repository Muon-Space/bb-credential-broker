package auth

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// IssuerConfig describes one of the JWT issuers the broker accepts at
// /delegate. Each issuer is bound to a single JWKS file (typically
// kept fresh on disk by an out-of-process JWKS sidecar) and to a
// single IdentityType that determines how the validated claims are
// resolved into an Identity.
type IssuerConfig struct {
	// URL is the value the JWT's iss claim must match. Tokens
	// presented to /delegate are dispatched to the IssuerConfig
	// whose URL matches their iss claim; other tokens are
	// rejected.
	URL string `json:"url"`

	// JWKSFile is the path on disk to the JSON Web Key Set used
	// to verify signatures of tokens issued by this issuer.
	JWKSFile string `json:"jwksFile"`

	// Audience, when non-empty, is the value the JWT's aud claim
	// must contain. When empty, the audience is not checked.
	Audience string `json:"audience,omitempty"`

	// IdentityType selects the resolver applied to the validated
	// claims to build the caller's Identity.
	IdentityType IdentityType `json:"identityType"`
}

// JWTAuthConfig is the authentication section of the broker's
// top-level configuration.
type JWTAuthConfig struct {
	// Issuers enumerates every JWT issuer the broker will accept
	// at /delegate. Tokens whose iss claim does not match any
	// issuer in this list are rejected.
	Issuers []IssuerConfig `json:"issuers"`
}

// Errors returned by Parser.
var (
	// ErrUnknownIssuer is returned when a JWT's iss claim does
	// not match any configured IssuerConfig.
	ErrUnknownIssuer = errors.New("jwt: unknown issuer")

	// ErrUnknownKeyID is returned when a JWT's kid header refers
	// to a key that is not present in the configured JWKS.
	ErrUnknownKeyID = errors.New("jwt: unknown key id")

	// ErrAudienceMismatch is returned when a JWT's aud claim
	// does not contain the expected audience for its issuer.
	ErrAudienceMismatch = errors.New("jwt: audience mismatch")

	// ErrInvalidSignature is returned when a JWT's signature
	// fails verification against the resolved key.
	ErrInvalidSignature = errors.New("jwt: invalid signature")
)

// Parser validates incoming bearer tokens against the configured
// issuer set. A single Parser instance is safe for concurrent use.
type Parser struct {
	issuers map[string]*issuerEntry
}

type issuerEntry struct {
	cfg   IssuerConfig
	cache *JWKSCache
}

// NewParser constructs a Parser from cfg, loading every referenced
// JWKS file once before returning. Configuration errors and JWKS
// file load errors are surfaced synchronously so that a misconfigured
// broker fails fast on start-up.
func NewParser(cfg JWTAuthConfig) (*Parser, error) {
	if len(cfg.Issuers) == 0 {
		return nil, fmt.Errorf("jwt: no issuers configured")
	}
	p := &Parser{issuers: map[string]*issuerEntry{}}
	for i, ic := range cfg.Issuers {
		if ic.URL == "" {
			return nil, fmt.Errorf("jwt: issuers[%d].url is required", i)
		}
		if ic.JWKSFile == "" {
			return nil, fmt.Errorf("jwt: issuers[%d].jwksFile is required", i)
		}
		if ic.IdentityType == "" {
			return nil, fmt.Errorf("jwt: issuers[%d].identityType is required", i)
		}
		if _, ok := p.issuers[ic.URL]; ok {
			return nil, fmt.Errorf("jwt: duplicate issuer url %q", ic.URL)
		}
		cache, err := NewJWKSCache(ic.JWKSFile)
		if err != nil {
			return nil, fmt.Errorf("jwt: issuers[%d]: %w", i, err)
		}
		p.issuers[ic.URL] = &issuerEntry{cfg: ic, cache: cache}
	}
	return p, nil
}

// Caches returns the JWKSCache for each configured issuer. The
// caller is expected to spawn a refresh loop per cache during
// app start-up.
func (p *Parser) Caches() []*JWKSCache {
	out := make([]*JWKSCache, 0, len(p.issuers))
	for _, e := range p.issuers {
		out = append(out, e.cache)
	}
	return out
}

// ValidateBearer parses, verifies and resolves a single bearer token.
// The token argument is the raw value of the Authorization header
// minus the "Bearer " prefix. On success an Identity built from the
// validated claims is returned.
func (p *Parser) ValidateBearer(token string) (*Identity, error) {
	parsed, err := jwt.Parse(token, p.keyfunc, jwt.WithValidMethods(supportedMethods))
	if err != nil {
		return nil, fmt.Errorf("jwt: parse: %w", err)
	}
	if !parsed.Valid {
		return nil, ErrInvalidSignature
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("jwt: claims have unexpected shape")
	}
	iss, _ := claims["iss"].(string)
	entry, ok := p.issuers[iss]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownIssuer, iss)
	}
	if entry.cfg.Audience != "" {
		if !audienceContains(claims["aud"], entry.cfg.Audience) {
			return nil, ErrAudienceMismatch
		}
	}
	return ResolveIdentity(entry.cfg.IdentityType, map[string]any(claims))
}

// keyfunc is the jwt.Keyfunc that resolves a token's signing key by
// looking up the iss claim against the configured issuer set and
// then resolving the kid header inside that issuer's JWKS.
func (p *Parser) keyfunc(token *jwt.Token) (any, error) {
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("jwt: keyfunc: claims have unexpected shape")
	}
	iss, _ := claims["iss"].(string)
	entry, ok := p.issuers[iss]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownIssuer, iss)
	}
	kid, _ := token.Header["kid"].(string)
	if kid == "" {
		return nil, fmt.Errorf("jwt: keyfunc: token has no kid header")
	}
	key := entry.cache.Lookup(kid)
	if key == nil {
		return nil, fmt.Errorf("%w: kid=%s issuer=%s", ErrUnknownKeyID, kid, iss)
	}
	return key, nil
}

// supportedMethods enumerates the signing algorithms the broker
// accepts on inbound JWTs. The list is intentionally restrictive:
// adding an algorithm here is the deliberate decision to trust
// tokens signed with it.
var supportedMethods = []string{
	"RS256", "RS384", "RS512",
	"ES256", "ES384", "ES512",
	"EdDSA",
}

// audienceContains reports whether v, which holds the value of a
// JWT's aud claim and may be either a string or a slice of strings
// per RFC 7519, contains want.
func audienceContains(v any, want string) bool {
	switch a := v.(type) {
	case string:
		// RFC 7519 §4.1.3 permits a single audience value to
		// be encoded as either a string or a one-element
		// array. Treat space-separated audiences as multiple
		// values for compatibility with implementations that
		// follow the OAuth 2.0 convention.
		for _, s := range strings.Fields(a) {
			if s == want {
				return true
			}
		}
		return a == want
	case []any:
		for _, x := range a {
			if s, ok := x.(string); ok && s == want {
				return true
			}
		}
		return false
	case []string:
		return slices.Contains(a, want)
	default:
		return false
	}
}

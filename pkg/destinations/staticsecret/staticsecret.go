// Package staticsecret implements a destination type that returns a
// credential read verbatim from a file on disk. The intended source
// is a Kubernetes Secret mounted into the broker's pod; operators
// are free to populate the underlying Secret from any backend they
// already use (External Secrets Operator, CSI Secrets Store driver,
// Sealed Secrets, manual kubectl, etc.).
//
// The destination exists for credentials that genuinely cannot be
// minted on demand — long-lived personal access tokens for systems
// whose API does not expose an OIDC token-exchange flow. The broker
// still enforces per-identity policy at /delegate, so dispensing a
// stored secret remains gated on the caller's resolved Identity and
// recorded in the audit log.
package staticsecret

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"time"

	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/auth"
)

// DefaultCacheTTL is the value advertised in the response's
// expires_at field when the operator does not configure CacheTTL.
// The broker has no real expiry for a stored credential — operators
// rotate the underlying Secret out of band — so the value is purely
// a hint to clients about how often they should re-fetch.
const DefaultCacheTTL = time.Hour

// DefaultScheme is the value advertised in the response's scheme
// field when the operator does not configure Scheme.
const DefaultScheme = "bearer"

// Config configures a single named staticSecret destination.
type Config struct {
	// File is the absolute path to the file holding the credential
	// value. The file is read on every Mint so that an operator
	// rotating the underlying Secret does not need to restart the
	// broker for the new value to take effect.
	File string `json:"file"`

	// Scheme is the value advertised on the /token response's
	// scheme field. Empty means DefaultScheme. Typical values are
	// "bearer" (most APIs) and "basic" (git, npm registries, OCI
	// registries).
	Scheme string `json:"scheme,omitempty"`

	// Username is the value advertised on the /token response's
	// username field. It is meaningful only when Scheme is "basic"
	// and is ignored otherwise. Tools that authenticate with a
	// PAT against GitHub or GHE conventionally use the literal
	// string "x-access-token" here.
	Username string `json:"username,omitempty"`

	// CacheTTL is the validity hint published to clients via the
	// expires_at field. Empty means DefaultCacheTTL. The broker
	// itself does not enforce expiry — the underlying Secret may
	// be rotated at any time by the operator and the next Mint
	// will return the new value immediately.
	CacheTTL string `json:"cacheTtl,omitempty"`
}

// Token is the credential returned by Mint. The destinations parent
// package wraps Impl in an adapter that translates between the two
// so that this child package avoids an import cycle on its parent.
type Token struct {
	Value     string
	Scheme    string
	Username  string
	ExpiresAt time.Time
}

// Impl is a single instance of the staticSecret destination type.
type Impl struct {
	name     string
	file     string
	scheme   string
	username string
	cacheTTL time.Duration
	now      func() time.Time
}

// New constructs an Impl from cfg. The file is read once at
// construction time so that misconfigured paths fail the broker's
// load step rather than the first request.
func New(name string, cfg *Config) (*Impl, error) {
	if cfg == nil {
		return nil, fmt.Errorf("staticSecret: config is nil")
	}
	if cfg.File == "" {
		return nil, fmt.Errorf("staticSecret: file is required")
	}
	if _, err := readSecret(cfg.File); err != nil {
		return nil, err
	}
	scheme := cfg.Scheme
	if scheme == "" {
		scheme = DefaultScheme
	}
	cacheTTL := DefaultCacheTTL
	if cfg.CacheTTL != "" {
		d, err := time.ParseDuration(cfg.CacheTTL)
		if err != nil {
			return nil, fmt.Errorf("staticSecret: cacheTtl: %w", err)
		}
		if d <= 0 {
			return nil, fmt.Errorf("staticSecret: cacheTtl must be positive")
		}
		cacheTTL = d
	}
	return &Impl{
		name:     name,
		file:     cfg.File,
		scheme:   scheme,
		username: cfg.Username,
		cacheTTL: cacheTTL,
		now:      time.Now,
	}, nil
}

// Name returns the operator-chosen name of this destination instance.
func (i *Impl) Name() string { return i.name }

// SetNow overrides the function used to read the current time. It
// exists so tests can assert behaviour at a specific instant; production
// callers should not invoke it.
func (i *Impl) SetNow(f func() time.Time) { i.now = f }

// Mint reads the secret file and returns its contents as the token
// value. The identity argument is unused — policy gating happens at
// /delegate, before this code is reached — but is accepted to match
// the parent package's Destination interface.
func (i *Impl) Mint(_ context.Context, _ *auth.Identity) (*Token, error) {
	value, err := readSecret(i.file)
	if err != nil {
		return nil, err
	}
	return &Token{
		Value:     value,
		Scheme:    i.scheme,
		Username:  i.username,
		ExpiresAt: i.now().Add(i.cacheTTL),
	}, nil
}

// readSecret reads path from disk and returns its contents with
// trailing whitespace removed. Trailing whitespace is the most
// common gotcha when operators pipe credentials into files via
// shell tools, and stripping it has no security consequence
// because no real credential carries trailing whitespace as a
// significant byte.
func readSecret(path string) (string, error) {
	// #nosec G304 -- the path is operator-supplied configuration,
	// equivalent to the SigningKeyFile path used by pkg/store and
	// the JWKSFile path used by pkg/auth.
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("staticSecret: read %s: %w", path, err)
	}
	trimmed := bytes.TrimRight(data, " \t\r\n")
	if len(trimmed) == 0 {
		return "", fmt.Errorf("staticSecret: %s is empty", path)
	}
	return string(trimmed), nil
}

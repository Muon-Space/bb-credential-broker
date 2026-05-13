// Package store contains the broker's nonce store. A nonce is a
// short-lived token issued by /delegate and surrendered to /token in
// exchange for a destination-specific credential. Implementations
// vary in the backing storage strategy; see the SignedStore type for
// the production backend.
package store

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/auth"
)

// ErrNotFound is returned when the supplied token is not recognised
// or has expired. /token responds with 410 Gone. Implementations
// should also return ErrNotFound for any failure that the caller is
// not expected to be able to disambiguate (bad signature, malformed
// payload, wrong issuer); doing so prevents callers from probing the
// backend's internals.
var ErrNotFound = errors.New("nonce: not found or expired")

// Record is the payload stored against a nonce. It captures the
// caller's resolved Identity at the moment of /delegate, the set of
// destinations the policy engine permitted, and the nonce's expiry.
type Record struct {
	// Identity is a snapshot of the caller's Identity at the
	// moment /delegate was invoked. The /token handler passes
	// this identity to the destination's mint flow so that
	// downstream requests can carry per-build attribution.
	Identity *auth.Identity

	// AllowedDestinations is the set of destination names the
	// policy engine permitted at /delegate time. /token rejects
	// any destination outside this set.
	AllowedDestinations []string

	// ExpiresAt is the absolute time after which the nonce is no
	// longer valid. Implementations should treat ExpiresAt as
	// authoritative regardless of any other expiry tracking.
	ExpiresAt time.Time
}

// AllowsDestination reports whether the named destination appears in
// AllowedDestinations.
func (r *Record) AllowsDestination(name string) bool {
	return slices.Contains(r.AllowedDestinations, name)
}

// NonceStore is the interface implemented by every nonce-store
// backend. Implementations must be safe for concurrent use across
// multiple goroutines.
type NonceStore interface {
	// Mint allocates a new nonce, associates rec with it and
	// returns the freshly minted token string. The returned
	// string is opaque to the caller.
	Mint(rec *Record) (string, error)

	// Claim returns the Record associated with token. It returns
	// ErrNotFound if the token is unknown, expired or otherwise
	// invalid.
	Claim(token string) (*Record, error)
}

// Config selects a NonceStore backend. Exactly one of the
// type-specific fields must be set.
type Config struct {
	// Signed selects the stateless signed-token backend. Tokens
	// are JWTs signed with a shared HMAC key; any replica can
	// validate any other replica's tokens.
	Signed *SignedConfig `json:"signed,omitempty"`
}

// New constructs a NonceStore from cfg.
func New(cfg Config) (NonceStore, error) {
	switch {
	case cfg.Signed != nil:
		key, err := LoadSignedKey(cfg.Signed.SigningKeyFile)
		if err != nil {
			return nil, err
		}
		return NewSignedStore(key, time.Duration(cfg.Signed.TTL), cfg.Signed.Issuer)
	default:
		return nil, fmt.Errorf("nonce store has no recognised backend; expected one of: signed")
	}
}

// Duration is a time.Duration that round-trips through JSON as a
// Go-style duration string (for example "5m"). It exists so that
// configuration files can express durations naturally.
type Duration time.Duration

// UnmarshalJSON parses a JSON string of the form accepted by
// time.ParseDuration into a Duration.
func (d *Duration) UnmarshalJSON(data []byte) error {
	if len(data) >= 2 && data[0] == '"' && data[len(data)-1] == '"' {
		s := string(data[1 : len(data)-1])
		v, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("duration: %w", err)
		}
		*d = Duration(v)
		return nil
	}
	return fmt.Errorf("duration: expected JSON string, got %s", string(data))
}

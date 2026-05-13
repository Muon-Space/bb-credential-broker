// Package store contains the broker's nonce store. A nonce is a
// short-lived, single-use token issued by /delegate and surrendered
// to /token in exchange for a destination-specific credential.
package store

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/auth"
)

// Errors returned by NonceStore implementations.
var (
	// ErrNotFound is returned when the requested nonce is not
	// present in the store. /token responds with 410 Gone.
	ErrNotFound = errors.New("nonce: not found or expired")

	// ErrAlreadyClaimed is returned when a previously valid nonce
	// has already been consumed. /token responds with 410 Gone.
	ErrAlreadyClaimed = errors.New("nonce: already claimed")
)

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

// NonceStore is the interface implemented by both the production
// in-memory store and any future persistent backend.
//
// Implementations must guarantee that Claim returns ErrAlreadyClaimed
// for every concurrent or subsequent call after the first successful
// claim of a given nonce, even when calls race across goroutines.
type NonceStore interface {
	// Mint allocates a new nonce, stores rec under it, and
	// returns the freshly minted nonce string. The returned
	// string is opaque and contains enough entropy to resist
	// brute-force enumeration.
	Mint(rec *Record) (string, error)

	// Claim atomically marks the nonce as consumed and returns
	// the associated Record. It returns ErrNotFound if the nonce
	// is unknown or has already expired, and ErrAlreadyClaimed
	// if it has been previously consumed.
	Claim(nonce string) (*Record, error)
}

// Config selects a NonceStore implementation. Exactly one of the
// type-specific fields must be set.
type Config struct {
	// InMemory selects the process-local in-memory store.
	InMemory *InMemoryConfig `json:"inMemory,omitempty"`
}

// InMemoryConfig configures the in-memory NonceStore.
type InMemoryConfig struct {
	// TTL is the maximum lifetime of an unclaimed nonce. Mint
	// rejects requests with no TTL configured.
	TTL Duration `json:"ttl"`

	// MaxSize is an upper bound on the number of nonces held in
	// memory at any one time. When the store reaches MaxSize, the
	// oldest unclaimed nonce is discarded to make room. A
	// non-positive value disables the bound.
	MaxSize int `json:"maxSize,omitempty"`
}

// New constructs a NonceStore from cfg.
func New(cfg Config) (NonceStore, error) {
	switch {
	case cfg.InMemory != nil:
		if cfg.InMemory.TTL <= 0 {
			return nil, fmt.Errorf("inMemory.ttl must be a positive duration")
		}
		return NewInMemoryStore(time.Duration(cfg.InMemory.TTL), cfg.InMemory.MaxSize), nil
	default:
		return nil, fmt.Errorf("nonce store has no recognised backend; expected one of: inMemory")
	}
}

// Duration is a time.Duration that round-trips through JSON as a
// Go-style duration string (for example "15m"). It exists so that
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

// InMemoryStore is the default NonceStore. It holds nonces in a map
// guarded by a mutex and discards expired entries lazily on Claim
// and during Mint when MaxSize is reached.
type InMemoryStore struct {
	ttl     time.Duration
	maxSize int

	mu      sync.Mutex
	entries map[string]*entry
}

type entry struct {
	rec     *Record
	claimed atomic.Bool
}

// NewInMemoryStore constructs an InMemoryStore that retains unclaimed
// nonces for up to ttl. When maxSize is positive, the oldest expired
// entry is reaped on each Mint when the map exceeds the bound.
func NewInMemoryStore(ttl time.Duration, maxSize int) *InMemoryStore {
	return &InMemoryStore{
		ttl:     ttl,
		maxSize: maxSize,
		entries: map[string]*entry{},
	}
}

// nonceLength is the number of random bytes that back a nonce string.
// 24 bytes encodes to 32 base64-url characters and yields 192 bits of
// entropy, which is more than enough to render brute-force enumeration
// infeasible regardless of /token rate-limiting.
const nonceLength = 24

// Mint implements NonceStore.
func (s *InMemoryStore) Mint(rec *Record) (string, error) {
	if rec == nil {
		return "", fmt.Errorf("nonce: cannot mint a nil record")
	}
	if rec.ExpiresAt.IsZero() {
		rec.ExpiresAt = time.Now().Add(s.ttl)
	}

	buf := make([]byte, nonceLength)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("nonce: read random: %w", err)
	}
	nonce := base64.RawURLEncoding.EncodeToString(buf)

	s.mu.Lock()
	defer s.mu.Unlock()

	s.reapExpiredLocked()
	if s.maxSize > 0 && len(s.entries) >= s.maxSize {
		return "", fmt.Errorf("nonce: store is at capacity")
	}
	s.entries[nonce] = &entry{rec: rec}
	return nonce, nil
}

// Claim implements NonceStore.
func (s *InMemoryStore) Claim(nonce string) (*Record, error) {
	s.mu.Lock()
	e, ok := s.entries[nonce]
	s.mu.Unlock()
	if !ok {
		return nil, ErrNotFound
	}
	if time.Now().After(e.rec.ExpiresAt) {
		s.mu.Lock()
		delete(s.entries, nonce)
		s.mu.Unlock()
		return nil, ErrNotFound
	}
	if !e.claimed.CompareAndSwap(false, true) {
		return nil, ErrAlreadyClaimed
	}
	return e.rec, nil
}

func (s *InMemoryStore) reapExpiredLocked() {
	now := time.Now()
	for k, e := range s.entries {
		if now.After(e.rec.ExpiresAt) {
			delete(s.entries, k)
		}
	}
}

package auth

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"sync/atomic"
	"time"
)

// jwks is the on-disk JSON Web Key Set schema, stripped to the
// fields the broker uses. Fields that are not relevant to signature
// verification are intentionally omitted.
type jwks struct {
	Keys []jwksKey `json:"keys"`
}

type jwksKey struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg,omitempty"`
	Use string `json:"use,omitempty"`

	// RSA parameters.
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`

	// ECDSA / Ed25519 parameters.
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

// JWKSCache holds the parsed contents of a single JWKS file. The
// cache is refreshed periodically by reading the file from disk and
// atomically swapping the in-memory key set.
//
// JWKSCache is safe for concurrent use by multiple goroutines.
type JWKSCache struct {
	path string

	// keys holds a *map[string]any whose values are one of:
	// *rsa.PublicKey, *ecdsa.PublicKey or ed25519.PublicKey. The
	// pointer is replaced atomically on each successful refresh.
	keys atomic.Pointer[map[string]any]
}

// NewJWKSCache constructs a JWKSCache backed by the file at path and
// performs one synchronous load so that subsequent Lookup calls
// return values from a populated cache.
func NewJWKSCache(path string) (*JWKSCache, error) {
	c := &JWKSCache{path: path}
	if err := c.Refresh(); err != nil {
		return nil, fmt.Errorf("jwks: initial load of %s: %w", path, err)
	}
	return c, nil
}

// Refresh reads the JWKS file from disk and atomically replaces the
// in-memory key set on success. On failure the previous key set is
// retained.
func (c *JWKSCache) Refresh() error {
	raw, err := os.ReadFile(c.path)
	if err != nil {
		return err
	}
	var doc jwks
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("parse jwks: %w", err)
	}
	parsed := make(map[string]any, len(doc.Keys))
	for i, k := range doc.Keys {
		key, err := parseJWKSKey(k)
		if err != nil {
			return fmt.Errorf("jwks key index %d (kid=%q): %w", i, k.Kid, err)
		}
		parsed[k.Kid] = key
	}
	c.keys.Store(&parsed)
	return nil
}

// Lookup returns the verification key associated with kid, or nil
// when no such key is present.
func (c *JWKSCache) Lookup(kid string) any {
	m := c.keys.Load()
	if m == nil {
		return nil
	}
	return (*m)[kid]
}

// RunRefreshLoop periodically refreshes the cache at the supplied
// interval. The loop exits when ctx is cancelled. Refresh failures
// are logged via the supplied error sink; the cache continues to
// serve the previously loaded key set.
//
// The function is intended to be invoked as a long-running routine.
// Refresh failures are common during normal operation (the JWKS file
// is replaced atomically, but partial writes occasionally race with
// the reader); they should not be treated as fatal.
func (c *JWKSCache) RunRefreshLoop(ctx <-chan struct{}, interval time.Duration, onError func(error)) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx:
			return
		case <-ticker.C:
			if err := c.Refresh(); err != nil && onError != nil {
				onError(err)
			}
		}
	}
}

// parseJWKSKey converts a single JWKS key entry into the
// crypto-package public key type appropriate for its kty field.
func parseJWKSKey(k jwksKey) (any, error) {
	switch k.Kty {
	case "RSA":
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, fmt.Errorf("rsa: decode n: %w", err)
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, fmt.Errorf("rsa: decode e: %w", err)
		}
		e := new(big.Int).SetBytes(eBytes)
		if !e.IsInt64() || e.Int64() > int64(^uint32(0)) {
			return nil, fmt.Errorf("rsa: exponent out of range")
		}
		return &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: int(e.Int64()),
		}, nil
	case "EC":
		var curve elliptic.Curve
		switch k.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("ec: unsupported curve %q", k.Crv)
		}
		xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, fmt.Errorf("ec: decode x: %w", err)
		}
		yBytes, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			return nil, fmt.Errorf("ec: decode y: %w", err)
		}
		return &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(xBytes),
			Y:     new(big.Int).SetBytes(yBytes),
		}, nil
	case "OKP":
		if k.Crv != "Ed25519" {
			return nil, fmt.Errorf("okp: unsupported curve %q", k.Crv)
		}
		xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, fmt.Errorf("okp: decode x: %w", err)
		}
		if l := len(xBytes); l != ed25519.PublicKeySize {
			return nil, fmt.Errorf("okp: ed25519 key must be %d bytes, got %d", ed25519.PublicKeySize, l)
		}
		return ed25519.PublicKey(xBytes), nil
	default:
		return nil, fmt.Errorf("unsupported kty %q", k.Kty)
	}
}

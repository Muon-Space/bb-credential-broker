package store

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/auth"
)

// MinSignedKeyBytes is the minimum length of the HMAC signing key.
// 32 bytes (256 bits) matches the output size of SHA-256 and is the
// minimum recommended for HS256 by RFC 7518 section 3.2.
const MinSignedKeyBytes = 32

// DefaultSignedIssuer is the value used for the JWT iss claim when
// SignedConfig.Issuer is empty.
const DefaultSignedIssuer = "bb-credential-broker"

// JWT claim names used by SignedStore in addition to the standard
// RFC 7519 claims (iss, sub, iat, exp, jti). Defined as constants so
// that Mint and Claim cannot drift independently.
const (
	claimIdentityType        = "identity_type"
	claimIdentityClaims      = "claims"
	claimGrantedDestinations = "granted_destinations"
)

// SignedConfig configures the SignedStore backend.
type SignedConfig struct {
	// SigningKeyFile is the absolute path to the file holding the
	// raw HMAC signing key. The file must contain at least
	// MinSignedKeyBytes of key material. Operators are expected to
	// mount the file from a Kubernetes Secret, CSI Secrets Store
	// driver or similar; the broker only needs read access at
	// startup.
	SigningKeyFile string `json:"signingKeyFile"`

	// TTL is the validity period of an issued token. A token may
	// be claimed any number of times within this window before its
	// exp claim makes it invalid; see SignedStore for the
	// rationale.
	TTL Duration `json:"ttl"`

	// Issuer overrides the JWT iss claim. Empty means
	// DefaultSignedIssuer. Operators that run multiple brokers
	// distinguished by environment may set distinct issuer
	// strings to keep audit logs disambiguated.
	Issuer string `json:"issuer,omitempty"`
}

// SignedStore is a stateless NonceStore backend. Mint returns a JWT
// signed with an HMAC key all replicas hold; Claim validates the
// signature and parses the claims back into a Record.
//
// Because the token carries its own authorization, any replica can
// validate any other replica's tokens without coordination, allowing
// the broker to scale horizontally without a shared backend. The
// trade-off is that the strict single-use guarantee of an in-memory
// store is downgraded to limited-use within the configured TTL
// window: a token is valid for repeated Claim calls until its exp
// claim makes it invalid. For threat models where the destination
// credentials minted by the broker are themselves short-lived, this
// downgrade is acceptable.
//
// All token-validation failures (expired, malformed, bad signature,
// wrong issuer) collapse to ErrNotFound so that callers cannot
// distinguish them. The audit log records the underlying reason.
type SignedStore struct {
	key    []byte
	ttl    time.Duration
	issuer string
	now    func() time.Time
	parser *jwt.Parser
}

// NewSignedStore constructs a SignedStore from raw key bytes. The
// key must be at least MinSignedKeyBytes long. Use LoadSignedKey to
// read the key from a file on disk.
func NewSignedStore(key []byte, ttl time.Duration, issuer string) (*SignedStore, error) {
	if len(key) < MinSignedKeyBytes {
		return nil, fmt.Errorf("signed: key must be at least %d bytes, got %d", MinSignedKeyBytes, len(key))
	}
	if ttl <= 0 {
		return nil, fmt.Errorf("signed: ttl must be a positive duration")
	}
	if issuer == "" {
		issuer = DefaultSignedIssuer
	}
	s := &SignedStore{
		key:    append([]byte(nil), key...),
		ttl:    ttl,
		issuer: issuer,
		now:    time.Now,
	}
	// The parser is invariant per store instance; constructing it
	// once at startup avoids rebuilding the option chain on every
	// Claim. The WithTimeFunc closure captures s by reference so
	// SetNow continues to take effect after construction.
	s.parser = jwt.NewParser(
		jwt.WithIssuer(s.issuer),
		jwt.WithExpirationRequired(),
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithTimeFunc(func() time.Time { return s.now() }),
	)
	return s, nil
}

// SetNow overrides the function used to read the current time. It
// exists so that tests can assert behaviour at a specific instant
// without sleeping on the real clock; production callers should not
// invoke it.
func (s *SignedStore) SetNow(f func() time.Time) {
	s.now = f
}

// LoadSignedKey reads the HMAC signing key from path and returns
// its bytes. The file must contain at least MinSignedKeyBytes of
// raw key material; trailing whitespace is preserved. Operators
// generate the file with a tool such as openssl rand 32 > key.
func LoadSignedKey(path string) ([]byte, error) {
	// #nosec G304 -- the path is operator-supplied configuration,
	// equivalent to the IssuerConfig.JWKSFile path in pkg/auth.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("signed: read key file %s: %w", path, err)
	}
	if len(data) < MinSignedKeyBytes {
		return nil, fmt.Errorf("signed: key file %s contains %d bytes, want at least %d", path, len(data), MinSignedKeyBytes)
	}
	return data, nil
}

// Mint implements NonceStore. The returned string is a JWT signed
// with HS256 over the broker's HMAC key. The token encodes the
// caller's resolved Identity, the granted destinations and an
// absolute expiry derived from rec.ExpiresAt or the configured TTL.
func (s *SignedStore) Mint(rec *Record) (string, error) {
	if rec == nil {
		return "", fmt.Errorf("signed: cannot mint a nil record")
	}
	if rec.Identity == nil {
		return "", fmt.Errorf("signed: record has no identity")
	}

	now := s.now()
	if rec.ExpiresAt.IsZero() {
		rec.ExpiresAt = now.Add(s.ttl)
	}

	jti, err := newJTI()
	if err != nil {
		return "", err
	}

	claims := jwt.MapClaims{
		"iss":                    s.issuer,
		"sub":                    rec.Identity.Principal,
		"iat":                    now.Unix(),
		"exp":                    rec.ExpiresAt.Unix(),
		"jti":                    jti,
		claimIdentityType:        string(rec.Identity.Type),
		claimIdentityClaims:      rec.Identity.Claims,
		claimGrantedDestinations: rec.AllowedDestinations,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString(s.key)
	if err != nil {
		return "", fmt.Errorf("signed: sign token: %w", err)
	}
	return signed, nil
}

// Claim implements NonceStore. The supplied token is parsed and
// validated against the broker's HMAC key, expected issuer and the
// expiry encoded in the token itself. On success the encoded
// Identity, granted destinations and expiry are returned in a
// Record. On any validation failure ErrNotFound is returned so that
// callers cannot distinguish failure modes.
func (s *SignedStore) Claim(token string) (*Record, error) {
	parsed, err := s.parser.Parse(token, func(_ *jwt.Token) (any, error) {
		return s.key, nil
	})
	if err != nil || !parsed.Valid {
		return nil, ErrNotFound
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrNotFound
	}

	principal, err := claims.GetSubject()
	if err != nil {
		return nil, ErrNotFound
	}
	exp, err := claims.GetExpirationTime()
	if err != nil || exp == nil {
		return nil, ErrNotFound
	}

	identityType, _ := claims[claimIdentityType].(string)
	rawClaims, _ := claims[claimIdentityClaims].(map[string]any)

	rawDestinations, _ := claims[claimGrantedDestinations].([]any)
	destinations := make([]string, 0, len(rawDestinations))
	for _, d := range rawDestinations {
		if str, ok := d.(string); ok {
			destinations = append(destinations, str)
		}
	}

	return &Record{
		Identity: &auth.Identity{
			Type:      auth.IdentityType(identityType),
			Principal: principal,
			Claims:    rawClaims,
		},
		AllowedDestinations: destinations,
		ExpiresAt:           exp.Time,
	}, nil
}

// newJTI returns a fresh 128-bit random identifier suitable for use
// as a JWT jti claim.
func newJTI() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("signed: read random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

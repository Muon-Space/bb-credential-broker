package signer

import (
	"context"
	"crypto"
	"crypto/rsa"
	"encoding/json"
	"fmt"

	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/secrets"
)

// algRS256 is the JWA algorithm identifier the broker advertises
// in the JWKS for its RSA signing key. The broker uses RS256
// exclusively for its own JWTs; the constant exists so the JWKS
// alg field and the signjwt expected algorithm stay aligned.
const algRS256 = "RS256"

// Signer holds the broker's RSA signing key together with the
// precomputed metadata needed by the JWKS handler: the public
// half, the RFC 7638 thumbprint that becomes the JWT header kid,
// and the canonical JWKS body bytes.
//
// All public methods are safe for concurrent use; the underlying
// state is immutable after construction. Key rotation is a pod
// restart with a new key in place, mirroring the lifecycle of the
// existing HMAC signing key for the nonce store.
type Signer struct {
	private   crypto.PrivateKey
	public    crypto.PublicKey
	kid       string
	jwksBytes []byte
}

// Load fetches the PEM-encoded private key named by ref via the
// supplied secrets.Loader, parses it, derives the public half,
// computes the kid, and pre-marshals the JWKS body. Errors are
// wrapped with the operation that failed so a misconfigured
// broker fails its boot step with an actionable message.
//
// Load uses the loader rather than reading the file directly so
// the same code path serves both the AWS Secrets Manager and
// in-memory test loaders without further plumbing.
func Load(ctx context.Context, loader secrets.Loader, ref secrets.SecretRef) (*Signer, error) {
	pemBytes, err := loader.Load(ctx, ref)
	if err != nil {
		return nil, fmt.Errorf("load: %w", err)
	}
	return FromPEM(pemBytes)
}

// FromPEM constructs a Signer directly from the raw PEM bytes of
// the private key. It is the test-friendly entry point and the
// implementation Load delegates to.
//
// The broker currently advertises only RSA keys via JWKS; FromPEM
// rejects ECDSA and Ed25519 keys here so a misconfigured key type
// surfaces at boot rather than at the first downstream verifier
// that cannot fetch a usable kid.
func FromPEM(pemBytes []byte) (*Signer, error) {
	priv, err := ParsePrivateKey(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	if _, ok := priv.(*rsa.PrivateKey); !ok {
		return nil, fmt.Errorf("broker signing key must be RSA; got %T", priv)
	}
	pub, err := PublicKey(priv)
	if err != nil {
		return nil, fmt.Errorf("extract public key: %w", err)
	}
	kid, err := Thumbprint(pub)
	if err != nil {
		return nil, fmt.Errorf("compute kid: %w", err)
	}
	jwksBytes, err := marshalJWKS(pub, kid)
	if err != nil {
		return nil, fmt.Errorf("marshal jwks: %w", err)
	}
	return &Signer{
		private:   priv,
		public:    pub,
		kid:       kid,
		jwksBytes: jwksBytes,
	}, nil
}

// PrivateKey returns the parsed private-key value. The result is
// shared with the Signer; callers must not mutate it.
func (s *Signer) PrivateKey() crypto.PrivateKey { return s.private }

// PublicKey returns the derived public-key value. The result is
// shared with the Signer; callers must not mutate it.
func (s *Signer) PublicKey() crypto.PublicKey { return s.public }

// KID returns the RFC 7638 JWK thumbprint of the public key. It
// is the value the broker stamps into every JWT header it signs
// and that downstream verifiers use to look up the matching key
// in the published JWKS.
func (s *Signer) KID() string { return s.kid }

// JWKSBytes returns the canonical JSON Web Key Set body the JWKS
// handler serves. The bytes are pre-marshaled once at construction
// so the per-request handler does no allocation beyond the write
// to the response body.
func (s *Signer) JWKSBytes() []byte { return s.jwksBytes }

// jwkSet is the on-the-wire JSON Web Key Set shape. The encoding
// matches the structure RFC 7517 §5 mandates.
type jwkSet struct {
	Keys []map[string]string `json:"keys"`
}

// marshalJWKS produces the JWKS body bytes for a single-key set.
// The key entry carries the kty-specific required members, the
// caller-chosen kid, and the standard use/alg metadata so
// downstream verifiers do not have to infer them.
func marshalJWKS(pub crypto.PublicKey, kid string) ([]byte, error) {
	members, err := publicJWKRequiredMembers(pub)
	if err != nil {
		return nil, err
	}
	members["use"] = "sig"
	members["alg"] = algRS256
	members["kid"] = kid
	return json.Marshal(jwkSet{Keys: []map[string]string{members}})
}

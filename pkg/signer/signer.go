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
// in the JWKS for its RSA signing keys. The broker uses RS256
// exclusively for its own JWTs.
const algRS256 = "RS256"

// Signer holds the broker's ordered list of RSA signing keys
// together with the precomputed JWKS body that publishes them all.
// The first key in the list is the active signer — the one
// signjwt uses when minting a new JWT — while every key remains
// in the JWKS so downstream verifiers can validate JWTs signed
// with any of them.
//
// The list shape is what enables zero-downtime key rotation: the
// operator stages a new key as a second entry, restarts pods so
// both keys land in the JWKS, waits the JWKS cache window
// (Cache-Control: max-age=300) for downstream verifiers to
// re-fetch, swaps the order so the broker signs with the new
// key, waits the cache window again, then drops the old key.
// Without the overlap, downstream caches reject newly-signed
// JWTs for up to 300 seconds after a rotation.
//
// All public methods are safe for concurrent use; the underlying
// state is immutable after construction.
type Signer struct {
	keys      []*keyEntry
	jwksBytes []byte
}

// keyEntry is the per-key state Signer keeps for each entry in
// privateKeySecrets. Each key has its own RFC 7638 thumbprint
// (kid) and contributes one JWK to the published set.
type keyEntry struct {
	private crypto.PrivateKey
	public  crypto.PublicKey
	kid     string
}

// Load fetches the PEM-encoded private key named by ref via the
// supplied secrets.Loader and returns a single-key Signer. The
// function is preserved for backwards compatibility with
// configurations that name a single brokerSigner.privateKeySecret;
// operators wanting rotation overlap use the LoadMulti / list
// shape instead.
func Load(ctx context.Context, loader secrets.Loader, ref secrets.SecretRef) (*Signer, error) {
	return LoadMulti(ctx, loader, []secrets.SecretRef{ref})
}

// LoadMulti fetches multiple PEM-encoded private keys via the
// supplied loader and assembles a Signer whose first key is the
// active signer and whose remaining keys are kept in the JWKS so
// downstream verifiers can validate JWTs signed with them
// previously. The order of refs is significant: rotation
// procedures rely on operators controlling which key signs by
// putting it first.
//
// Errors at any per-key load step are wrapped with the index of
// the failing ref so operators can localise misconfiguration.
func LoadMulti(ctx context.Context, loader secrets.Loader, refs []secrets.SecretRef) (*Signer, error) {
	if len(refs) == 0 {
		return nil, fmt.Errorf("at least one signing key is required")
	}
	pems := make([][]byte, len(refs))
	for i, ref := range refs {
		b, err := loader.Load(ctx, ref)
		if err != nil {
			return nil, fmt.Errorf("load key %d: %w", i, err)
		}
		pems[i] = b
	}
	return FromPEMs(pems)
}

// FromPEM is the single-key entry point preserved for tests and
// for any caller wiring a Signer outside the loader path. It is
// equivalent to FromPEMs with a one-element slice.
func FromPEM(pemBytes []byte) (*Signer, error) {
	return FromPEMs([][]byte{pemBytes})
}

// FromPEMs constructs a Signer from a list of PEM-encoded RSA
// private keys. The order is significant: the first entry is the
// active signer. All keys are parsed, all derive a public half,
// and all contribute one JWK to the precomputed JWKS body.
//
// FromPEMs rejects non-RSA keys here so a misconfigured key type
// surfaces at boot rather than at the first downstream verifier
// that cannot fetch a usable kid for an unexpected kty.
func FromPEMs(pems [][]byte) (*Signer, error) {
	if len(pems) == 0 {
		return nil, fmt.Errorf("at least one signing key is required")
	}
	entries := make([]*keyEntry, len(pems))
	seenKIDs := make(map[string]int, len(pems))
	for i, pemBytes := range pems {
		priv, err := ParsePrivateKey(pemBytes)
		if err != nil {
			return nil, fmt.Errorf("key %d: parse private key: %w", i, err)
		}
		if _, ok := priv.(*rsa.PrivateKey); !ok {
			return nil, fmt.Errorf("key %d: broker signing key must be RSA; got %T", i, priv)
		}
		pub, err := PublicKey(priv)
		if err != nil {
			return nil, fmt.Errorf("key %d: extract public key: %w", i, err)
		}
		kid, err := Thumbprint(pub)
		if err != nil {
			return nil, fmt.Errorf("key %d: compute kid: %w", i, err)
		}
		if prev, dup := seenKIDs[kid]; dup {
			return nil, fmt.Errorf("key %d duplicates the kid of key %d; rotation requires distinct keys", i, prev)
		}
		seenKIDs[kid] = i
		entries[i] = &keyEntry{private: priv, public: pub, kid: kid}
	}
	jwksBytes, err := marshalJWKS(entries)
	if err != nil {
		return nil, fmt.Errorf("marshal jwks: %w", err)
	}
	return &Signer{keys: entries, jwksBytes: jwksBytes}, nil
}

// ActivePrivateKey returns the first key's private half — the
// one new JWTs should be signed with. The result is shared with
// the Signer; callers must not mutate it.
func (s *Signer) ActivePrivateKey() crypto.PrivateKey { return s.keys[0].private }

// ActivePublicKey returns the first key's public half. Operators
// who need the public key directly (rare; almost everyone reaches
// for JWKSBytes instead) reach for this.
func (s *Signer) ActivePublicKey() crypto.PublicKey { return s.keys[0].public }

// ActiveKID returns the RFC 7638 JWK thumbprint of the active
// (first) key. It is the value the broker stamps into every JWT
// it signs.
func (s *Signer) ActiveKID() string { return s.keys[0].kid }

// PrivateKey returns the active key's private half. Preserved
// for backwards compatibility with callers written against the
// single-key Signer; new callers should use ActivePrivateKey.
func (s *Signer) PrivateKey() crypto.PrivateKey { return s.ActivePrivateKey() }

// PublicKey returns the active key's public half. Preserved for
// backwards compatibility with callers written against the
// single-key Signer; new callers should use ActivePublicKey.
func (s *Signer) PublicKey() crypto.PublicKey { return s.ActivePublicKey() }

// KID returns the active key's RFC 7638 thumbprint. Preserved
// for backwards compatibility with callers written against the
// single-key Signer; new callers should use ActiveKID.
func (s *Signer) KID() string { return s.ActiveKID() }

// JWKSBytes returns the canonical JSON Web Key Set body the JWKS
// handler serves. The set contains an entry for every key in the
// Signer's list so downstream verifiers can validate JWTs signed
// with any of them — the mechanism that enables rotation
// overlap.
func (s *Signer) JWKSBytes() []byte { return s.jwksBytes }

// KIDs returns the ordered list of kids the Signer holds. The
// first entry is the active kid; subsequent entries are kept in
// the JWKS for rotation overlap. Useful for tests and for
// operator-facing diagnostics.
func (s *Signer) KIDs() []string {
	out := make([]string, len(s.keys))
	for i, k := range s.keys {
		out[i] = k.kid
	}
	return out
}

// jwkSet is the on-the-wire JSON Web Key Set shape. The encoding
// matches the structure RFC 7517 §5 mandates.
type jwkSet struct {
	Keys []map[string]string `json:"keys"`
}

// marshalJWKS produces the JWKS body bytes for the supplied
// ordered list of keys. Each entry carries the kty-specific
// required members, the per-key kid, and the standard use/alg
// metadata so downstream verifiers do not have to infer them.
// The keys appear in the same order as in entries — operators
// reading the JWKS body during a rotation can confirm which key
// is active at a glance.
func marshalJWKS(entries []*keyEntry) ([]byte, error) {
	out := jwkSet{Keys: make([]map[string]string, 0, len(entries))}
	for _, e := range entries {
		members, err := publicJWKRequiredMembers(e.public)
		if err != nil {
			return nil, err
		}
		members["use"] = "sig"
		members["alg"] = algRS256
		members["kid"] = e.kid
		out.Keys = append(out.Keys, members)
	}
	return json.Marshal(out)
}

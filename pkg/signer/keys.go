// Package signer holds the broker's optional RSA signing key and
// the small set of crypto helpers shared between the JWT-signing
// template function and the JWKS endpoint. The package is
// imported by both pkg/destinations/httptokenexchange/template (for
// kid derivation when signing) and pkg/handlers (for JWKS
// publication), so it stays free of either consumer's specific
// concerns.
package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
)

// ParsePrivateKey accepts a PEM-encoded private key in any of the
// common forms used for JWT signing — PKCS#1 RSA, SEC1 EC, or
// PKCS#8 wrapping any of RSA, ECDSA, Ed25519 — and returns the
// crypto-package private key value appropriate for the encoded
// algorithm.
//
// Operators stage signing keys produced by tools such as
// `openssl genrsa`, `openssl ecparam -genkey`, or `openssl genpkey`.
// All three of those write one of the supported PEM block types.
func ParsePrivateKey(pemBytes []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		switch k := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
			return k, nil
		default:
			return nil, fmt.Errorf("PKCS#8 key has unsupported type %T", key)
		}
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q", block.Type)
	}
}

// PublicKey returns the public half of priv. The supplied value
// must be one of the private-key types ParsePrivateKey returns; an
// unrecognised type yields an error rather than a panic so callers
// that forward arbitrary crypto.PrivateKey values surface the
// mismatch loudly.
func PublicKey(priv crypto.PrivateKey) (crypto.PublicKey, error) {
	type publicKeyer interface {
		Public() crypto.PublicKey
	}
	if pk, ok := priv.(publicKeyer); ok {
		return pk.Public(), nil
	}
	return nil, fmt.Errorf("private key of type %T has no .Public() method", priv)
}

// Thumbprint returns the RFC 7638 JSON Web Key thumbprint of pub.
// The hash is SHA-256 over the canonical JWK form (only the
// required members for the key's kty, encoded as a JSON object
// with keys in lexicographic order and no whitespace); the output
// is base64url without padding.
//
// The thumbprint is the natural choice of kid: it is deterministic
// from the key alone, stable across processes that hold the same
// key, and cannot be made to collide with the thumbprint of any
// other key. The broker stamps this kid into every JWT it signs
// with an asymmetric algorithm and publishes the same kid in the
// JWKS so downstream verifiers can resolve the right key without
// operator coordination.
func Thumbprint(pub crypto.PublicKey) (string, error) {
	canonical, err := canonicalJWK(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// canonicalJWK encodes pub in the canonical JWK form RFC 7638
// requires for thumbprint computation: a JSON object containing
// only the required members for the key's kty (no use/alg/kid), in
// the lexicographic key order encoding/json produces for
// map[string]string, with no whitespace.
//
// json.Marshal of map[string]string emits keys alphabetically, so
// the canonical order falls out of the standard library's behaviour
// rather than being constructed by hand.
func canonicalJWK(pub crypto.PublicKey) ([]byte, error) {
	m, err := publicJWKRequiredMembers(pub)
	if err != nil {
		return nil, err
	}
	return json.Marshal(m)
}

// publicJWKRequiredMembers returns the kty-specific required-member
// set of a JWK for pub. RFC 7518 §6 enumerates them:
//
//	RSA      e, kty, n
//	EC       crv, kty, x, y
//	Ed25519  crv, kty, x
//
// The map is owned by the caller and may be extended (with use,
// alg, kid, etc.) before serialisation when callers need the full
// JWK form rather than the thumbprint-canonical form.
func publicJWKRequiredMembers(pub crypto.PublicKey) (map[string]string, error) {
	switch p := pub.(type) {
	case *rsa.PublicKey:
		return map[string]string{
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(p.E)).Bytes()),
			"kty": "RSA",
			"n":   base64.RawURLEncoding.EncodeToString(p.N.Bytes()),
		}, nil
	case *ecdsa.PublicKey:
		crv := ecCurveName(p.Curve.Params().Name)
		if crv == "" {
			return nil, fmt.Errorf("unsupported EC curve %q", p.Curve.Params().Name)
		}
		size := (p.Curve.Params().BitSize + 7) / 8
		return map[string]string{
			"crv": crv,
			"kty": "EC",
			"x":   base64.RawURLEncoding.EncodeToString(leftPad(p.X.Bytes(), size)),
			"y":   base64.RawURLEncoding.EncodeToString(leftPad(p.Y.Bytes(), size)),
		}, nil
	case ed25519.PublicKey:
		return map[string]string{
			"crv": "Ed25519",
			"kty": "OKP",
			"x":   base64.RawURLEncoding.EncodeToString(p),
		}, nil
	default:
		return nil, fmt.Errorf("unsupported public key type %T", pub)
	}
}

// ecCurveName maps Go's elliptic.Curve.Params().Name strings to
// the JWA crv names. Unsupported curves yield "".
func ecCurveName(name string) string {
	switch name {
	case "P-256":
		return "P-256"
	case "P-384":
		return "P-384"
	case "P-521":
		return "P-521"
	default:
		return ""
	}
}

// leftPad returns b left-padded with zero bytes to reach length n.
// EC coordinate encoding requires fixed-width big-endian unsigned
// integers; big.Int.Bytes strips leading zeros and would otherwise
// produce a thumbprint that differs from canonical implementations
// (Auth0, Okta, jose libraries) for keys whose X or Y coordinate
// happens to have a high bit of zero.
func leftPad(b []byte, n int) []byte {
	if len(b) >= n {
		return b
	}
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}

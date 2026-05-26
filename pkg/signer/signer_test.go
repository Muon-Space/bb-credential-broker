package signer_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"

	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/secrets"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/signer"
)

// generateRSAPEM returns a PEM-encoded PKCS#1 RSA private key for
// use in tests. A 2048-bit key is the smallest commonly accepted
// modulus for production RS256 and is fast enough for the
// per-test cost.
func generateRSAPEM(t *testing.T) ([]byte, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	return pemBytes, key
}

func TestFromPEM_HappyPath(t *testing.T) {
	t.Parallel()
	pemBytes, _ := generateRSAPEM(t)
	s, err := signer.FromPEM(pemBytes)
	if err != nil {
		t.Fatalf("FromPEM: %v", err)
	}
	if s.KID() == "" {
		t.Errorf("KID: got empty, want populated")
	}
	if len(s.JWKSBytes()) == 0 {
		t.Errorf("JWKSBytes: got empty, want populated")
	}
}

func TestFromPEM_RejectsMalformedPEM(t *testing.T) {
	t.Parallel()
	if _, err := signer.FromPEM([]byte("not a PEM block")); err == nil {
		t.Fatal("expected error for malformed PEM, got nil")
	}
}

// TestFromPEM_RejectsNonRSAKey pins the v1 constraint that the
// broker's JWKS endpoint advertises RSA only; an operator handing
// the broker an EC or Ed25519 key sees the rejection at boot,
// not at the first downstream verifier that cannot fetch a usable
// kid for an unexpected kty.
func TestFromPEM_RejectsNonRSAKey(t *testing.T) {
	t.Parallel()
	// Generate an Ed25519 key in PKCS#8 PEM form, freshly each
	// time, rather than embedding a static EC PEM string — gosec
	// flags any in-source PEM block as a suspected credential.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}
	_ = pub
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal ed25519: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	_, err = signer.FromPEM(pemBytes)
	if err == nil {
		t.Fatal("expected error for non-RSA key, got nil")
	}
	if !strings.Contains(err.Error(), "RSA") {
		t.Errorf("error %q should mention RSA constraint", err.Error())
	}
}

// TestFromPEM_KIDIsDeterministic confirms two Signers loaded from
// the same PEM bytes produce the same kid. The downstream verifier
// caches by kid, so any non-determinism across broker replicas
// would silently break verification.
func TestFromPEM_KIDIsDeterministic(t *testing.T) {
	t.Parallel()
	pemBytes, _ := generateRSAPEM(t)
	a, err := signer.FromPEM(pemBytes)
	if err != nil {
		t.Fatalf("FromPEM #1: %v", err)
	}
	b, err := signer.FromPEM(pemBytes)
	if err != nil {
		t.Fatalf("FromPEM #2: %v", err)
	}
	if a.KID() != b.KID() {
		t.Errorf("KID mismatch: %q vs %q", a.KID(), b.KID())
	}
}

// TestThumbprint_RFC7638Vector pins the implementation against the
// worked example in RFC 7638 §3.1. Any future change to the
// canonical-JWK construction or the hash that drifts away from
// the spec's worked answer fails this test.
func TestThumbprint_RFC7638Vector(t *testing.T) {
	t.Parallel()
	// Modulus and exponent from RFC 7638 §3.1.
	const nB64 = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx" +
		"4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCi" +
		"FV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6" +
		"Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb" +
		"9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFT" +
		"WhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls" +
		"1jF44-csFCur-kEgU8awapJzKnqDKgw"
	const eB64 = "AQAB"
	const wantKID = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"

	nBytes, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		t.Fatalf("decode n: %v", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		t.Fatalf("decode e: %v", err)
	}
	pub := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}
	got, err := signer.Thumbprint(pub)
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	if got != wantKID {
		t.Errorf("Thumbprint: got %q, want %q", got, wantKID)
	}
}

// TestJWKSBytes_Shape ensures the JWKS body the handler will serve
// is a single-key set carrying the kty-specific required members
// plus the broker-published metadata. Downstream verifiers expect
// this exact shape — RFC 7517 §5 with §4.2/§4.3/§4.5 fields.
func TestJWKSBytes_Shape(t *testing.T) {
	t.Parallel()
	pemBytes, _ := generateRSAPEM(t)
	s, err := signer.FromPEM(pemBytes)
	if err != nil {
		t.Fatalf("FromPEM: %v", err)
	}
	var parsed struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.Unmarshal(s.JWKSBytes(), &parsed); err != nil {
		t.Fatalf("unmarshal jwks: %v", err)
	}
	if got := len(parsed.Keys); got != 1 {
		t.Fatalf("keys length: got %d, want 1", got)
	}
	k := parsed.Keys[0]
	for _, field := range []string{"kty", "n", "e", "alg", "use", "kid"} {
		if k[field] == "" {
			t.Errorf("missing or empty key field %q in %+v", field, k)
		}
	}
	if k["kty"] != "RSA" {
		t.Errorf("kty: got %q, want RSA", k["kty"])
	}
	if k["alg"] != "RS256" {
		t.Errorf("alg: got %q, want RS256", k["alg"])
	}
	if k["use"] != "sig" {
		t.Errorf("use: got %q, want sig", k["use"])
	}
	if k["kid"] != s.KID() {
		t.Errorf("kid: got %q, want %q (from Signer.KID)", k["kid"], s.KID())
	}
}

// TestThumbprint_MatchesIndependentSHA256 cross-checks the
// thumbprint against an independently computed SHA-256 of the
// canonical-JWK form. This guards against any future refactor
// that accidentally introduces whitespace or a different key
// ordering into the canonical form.
func TestThumbprint_MatchesIndependentSHA256(t *testing.T) {
	t.Parallel()
	_, priv := generateRSAPEM(t)
	pub := &priv.PublicKey
	gotThumb, err := signer.Thumbprint(pub)
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	// Hand-construct the canonical JWK form and hash it.
	canonical := []byte(`{"e":"` +
		base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()) +
		`","kty":"RSA","n":"` +
		base64.RawURLEncoding.EncodeToString(pub.N.Bytes()) +
		`"}`)
	sum := sha256.Sum256(canonical)
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if gotThumb != want {
		t.Errorf("Thumbprint: got %q, want %q (canonical=%s)", gotThumb, want, canonical)
	}
}

// TestLoad_PropagatesLoaderError verifies that a loader error
// surfaces from Signer construction. Operators see this as a
// startup failure that names the underlying retrieval problem.
func TestLoad_PropagatesLoaderError(t *testing.T) {
	t.Parallel()
	loader := &erroringLoader{err: errors.New("test loader failure")}
	_, err := signer.Load(context.Background(), loader, secrets.SecretRef{
		AWSSecretsManager: &secrets.AWSSecretsManagerRef{ARN: "arn:x"},
	})
	if err == nil {
		t.Fatal("expected error from loader, got nil")
	}
	if !strings.Contains(err.Error(), "test loader failure") {
		t.Errorf("error %q should wrap the underlying loader error", err.Error())
	}
}

// TestLoad_HappyPath end-to-ends through the loader to confirm
// the same FromPEM kid emerges when bytes arrive via Loader.
func TestLoad_HappyPath(t *testing.T) {
	t.Parallel()
	pemBytes, _ := generateRSAPEM(t)
	loader := secrets.NewMapLoader()
	ref := secrets.SecretRef{
		AWSSecretsManager: &secrets.AWSSecretsManagerRef{ARN: "arn:test"},
	}
	loader.Set("aws:arn:test#", pemBytes)

	viaLoad, err := signer.Load(context.Background(), loader, ref)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	viaFromPEM, err := signer.FromPEM(pemBytes)
	if err != nil {
		t.Fatalf("FromPEM: %v", err)
	}
	if viaLoad.KID() != viaFromPEM.KID() {
		t.Errorf("KID mismatch: load=%q fromPEM=%q", viaLoad.KID(), viaFromPEM.KID())
	}
	if !bytes.Equal(viaLoad.JWKSBytes(), viaFromPEM.JWKSBytes()) {
		t.Errorf("JWKSBytes mismatch")
	}
}

// erroringLoader implements secrets.Loader and always returns the
// configured error. Used to drive Load's error path without
// standing up a real backend.
type erroringLoader struct{ err error }

func (l *erroringLoader) Load(_ context.Context, _ secrets.SecretRef) ([]byte, error) {
	return nil, l.err
}

// TestFromPEMs_MultiKey covers the rotation-overlap shape: a
// Signer constructed from N keys must (a) publish every key in
// the JWKS so downstream verifiers can validate any of them,
// (b) name the first key as active so signjwt uses it for new
// JWTs, and (c) preserve the operator-supplied order in the
// JWKS body so an operator inspecting it can see which key is
// active.
func TestFromPEMs_MultiKey(t *testing.T) {
	t.Parallel()
	pemA, _ := generateRSAPEM(t)
	pemB, _ := generateRSAPEM(t)
	s, err := signer.FromPEMs([][]byte{pemA, pemB})
	if err != nil {
		t.Fatalf("FromPEMs: %v", err)
	}

	kids := s.KIDs()
	if len(kids) != 2 {
		t.Fatalf("KIDs length: got %d, want 2", len(kids))
	}
	if s.ActiveKID() != kids[0] {
		t.Errorf("ActiveKID: got %q, want %q (first kid)", s.ActiveKID(), kids[0])
	}

	var parsed struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.Unmarshal(s.JWKSBytes(), &parsed); err != nil {
		t.Fatalf("unmarshal jwks: %v", err)
	}
	if len(parsed.Keys) != 2 {
		t.Fatalf("jwks keys length: got %d, want 2", len(parsed.Keys))
	}
	if parsed.Keys[0]["kid"] != kids[0] {
		t.Errorf("jwks order: first key kid mismatch")
	}
	if parsed.Keys[1]["kid"] != kids[1] {
		t.Errorf("jwks order: second key kid mismatch")
	}
}

// TestFromPEMs_RejectsDuplicateKey pins the documented invariant
// that rotation requires distinct keys. Catching a duplicate at
// configuration load prevents a confusing JWKS where two
// entries collide on kid (the downstream verifier would see a
// single de-duplicated key).
func TestFromPEMs_RejectsDuplicateKey(t *testing.T) {
	t.Parallel()
	pemA, _ := generateRSAPEM(t)
	_, err := signer.FromPEMs([][]byte{pemA, pemA})
	if err == nil {
		t.Fatal("expected duplicate-kid error, got nil")
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("error %q should mention duplicate", err.Error())
	}
}

// TestLoadMulti_PreservesRefOrder is the loader-path analogue of
// TestFromPEMs_MultiKey: it confirms that the order of refs
// supplied to LoadMulti is the order of keys the Signer holds
// (the active key is refs[0]).
func TestLoadMulti_PreservesRefOrder(t *testing.T) {
	t.Parallel()
	pemA, _ := generateRSAPEM(t)
	pemB, _ := generateRSAPEM(t)
	loader := secrets.NewMapLoader()
	loader.Set("aws:arn:test:a#", pemA)
	loader.Set("aws:arn:test:b#", pemB)

	refs := []secrets.SecretRef{
		{AWSSecretsManager: &secrets.AWSSecretsManagerRef{ARN: "arn:test:a"}},
		{AWSSecretsManager: &secrets.AWSSecretsManagerRef{ARN: "arn:test:b"}},
	}
	s, err := signer.LoadMulti(context.Background(), loader, refs)
	if err != nil {
		t.Fatalf("LoadMulti: %v", err)
	}
	if len(s.KIDs()) != 2 {
		t.Errorf("KIDs length: got %d, want 2", len(s.KIDs()))
	}

	// Sanity-check that swapping ref order swaps the active kid.
	swapped, err := signer.LoadMulti(context.Background(), loader,
		[]secrets.SecretRef{refs[1], refs[0]})
	if err != nil {
		t.Fatalf("LoadMulti (swapped): %v", err)
	}
	if swapped.ActiveKID() == s.ActiveKID() {
		t.Errorf("expected swapped ref order to change the active kid")
	}
}

// TestLoadMulti_EmptyRefs surfaces an operator misconfiguration
// (an empty privateKeySecrets list) at the same point in the
// boot path as every other signer error.
func TestLoadMulti_EmptyRefs(t *testing.T) {
	t.Parallel()
	_, err := signer.LoadMulti(context.Background(), secrets.NewMapLoader(), nil)
	if err == nil {
		t.Fatal("expected error for empty refs, got nil")
	}
}

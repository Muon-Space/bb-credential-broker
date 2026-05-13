package store_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/auth"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/store"
)

// signedKey returns a deterministic key suitable for tests. It is
// long enough to satisfy MinSignedKeyBytes but predictable so that
// independent SignedStore instances can be constructed with the same
// material.
func signedKey() []byte {
	return bytes.Repeat([]byte{0x42}, store.MinSignedKeyBytes)
}

func newSignedStore(t *testing.T) *store.SignedStore {
	t.Helper()
	s, err := store.NewSignedStore(signedKey(), 5*time.Minute, "")
	if err != nil {
		t.Fatalf("NewSignedStore: %v", err)
	}
	return s
}

func TestSignedStore_NewRejectsShortKey(t *testing.T) {
	t.Parallel()
	short := bytes.Repeat([]byte{0x01}, store.MinSignedKeyBytes-1)
	if _, err := store.NewSignedStore(short, time.Minute, ""); err == nil {
		t.Fatal("NewSignedStore with short key: expected error, got nil")
	}
}

func TestSignedStore_NewRejectsZeroTTL(t *testing.T) {
	t.Parallel()
	if _, err := store.NewSignedStore(signedKey(), 0, ""); err == nil {
		t.Fatal("NewSignedStore with zero TTL: expected error, got nil")
	}
}

func TestSignedStore_NewDefaultsIssuer(t *testing.T) {
	t.Parallel()
	s, err := store.NewSignedStore(signedKey(), time.Minute, "")
	if err != nil {
		t.Fatalf("NewSignedStore: %v", err)
	}
	tok, err := s.Mint(newRecord(t))
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	// A token Mint-ed with the default issuer must be Claim-able by
	// a store explicitly configured with the same default issuer.
	verify, err := store.NewSignedStore(signedKey(), time.Minute, store.DefaultSignedIssuer)
	if err != nil {
		t.Fatalf("NewSignedStore (verify): %v", err)
	}
	if _, err := verify.Claim(tok); err != nil {
		t.Errorf("Claim with explicit default issuer: %v", err)
	}
}

func TestLoadSignedKey_FileNotFound(t *testing.T) {
	t.Parallel()
	if _, err := store.LoadSignedKey(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("LoadSignedKey on missing file: expected error, got nil")
	}
}

func TestLoadSignedKey_TooShort(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, []byte("short"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	if _, err := store.LoadSignedKey(path); err == nil {
		t.Fatal("LoadSignedKey on short file: expected error, got nil")
	}
}

func TestLoadSignedKey_Roundtrip(t *testing.T) {
	t.Parallel()
	want := signedKey()
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	got, err := store.LoadSignedKey(path)
	if err != nil {
		t.Fatalf("LoadSignedKey: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("LoadSignedKey returned different bytes than written")
	}
}

func TestSignedStore_MintRejectsNil(t *testing.T) {
	t.Parallel()
	s := newSignedStore(t)
	if _, err := s.Mint(nil); err == nil {
		t.Fatal("Mint(nil): expected error, got nil")
	}
}

func TestSignedStore_MintRejectsRecordWithNoIdentity(t *testing.T) {
	t.Parallel()
	s := newSignedStore(t)
	if _, err := s.Mint(&store.Record{AllowedDestinations: []string{"x"}}); err == nil {
		t.Fatal("Mint(record without Identity): expected error, got nil")
	}
}

func TestSignedStore_MintClaim(t *testing.T) {
	t.Parallel()
	s := newSignedStore(t)
	rec := newRecord(t)

	tok, err := s.Mint(rec)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if tok == "" {
		t.Fatal("Mint returned empty token")
	}

	got, err := s.Claim(tok)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if got.Identity == nil {
		t.Fatal("Claim returned record without Identity")
	}
	if got.Identity.Type != rec.Identity.Type {
		t.Errorf("Identity.Type: got %q, want %q", got.Identity.Type, rec.Identity.Type)
	}
	if got.Identity.Principal != rec.Identity.Principal {
		t.Errorf("Identity.Principal: got %q, want %q", got.Identity.Principal, rec.Identity.Principal)
	}
	if len(got.AllowedDestinations) != len(rec.AllowedDestinations) {
		t.Errorf("AllowedDestinations length: got %d, want %d", len(got.AllowedDestinations), len(rec.AllowedDestinations))
	}
	for i, d := range rec.AllowedDestinations {
		if got.AllowedDestinations[i] != d {
			t.Errorf("AllowedDestinations[%d]: got %q, want %q", i, got.AllowedDestinations[i], d)
		}
	}
}

func TestSignedStore_RoundTripsClaims(t *testing.T) {
	t.Parallel()
	s := newSignedStore(t)
	rec := &store.Record{
		Identity: &auth.Identity{
			Type:      auth.IdentityTypeCI,
			Principal: "repo:owner/repo:ref:refs/heads/main",
			Claims: map[string]any{
				"repository": "owner/repo",
				"actor":      "octocat",
				"ref":        "refs/heads/main",
				"workflow":   "deploy",
				"run_id":     "12345",
			},
		},
		AllowedDestinations: []string{"alpha", "beta", "gamma"},
	}

	tok, err := s.Mint(rec)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	got, err := s.Claim(tok)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}

	for k, want := range rec.Identity.Claims {
		gotV, ok := got.Identity.Claims[k]
		if !ok {
			t.Errorf("claim %q missing from round-tripped Identity", k)
			continue
		}
		if gotV != want {
			t.Errorf("claim %q: got %v, want %v", k, gotV, want)
		}
	}
}

func TestSignedStore_Expired(t *testing.T) {
	t.Parallel()
	s := newSignedStore(t)
	tok, err := s.Mint(newRecord(t))
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	// Fast-forward the clock past the TTL so the parser rejects the
	// token on its exp claim.
	s.SetNow(func() time.Time { return time.Now().Add(time.Hour) })
	_, err = s.Claim(tok)
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Claim of expired token: got err %v, want ErrNotFound", err)
	}
}

func TestSignedStore_BadSignature(t *testing.T) {
	t.Parallel()
	signer := newSignedStore(t)
	tok, err := signer.Mint(newRecord(t))
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	// A verifier holding a different key must reject the token.
	otherKey := bytes.Repeat([]byte{0xFF}, store.MinSignedKeyBytes)
	verifier, err := store.NewSignedStore(otherKey, 5*time.Minute, "")
	if err != nil {
		t.Fatalf("NewSignedStore (verifier): %v", err)
	}
	if _, err := verifier.Claim(tok); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Claim with bad signature: got err %v, want ErrNotFound", err)
	}
}

func TestSignedStore_WrongIssuer(t *testing.T) {
	t.Parallel()
	signer, err := store.NewSignedStore(signedKey(), 5*time.Minute, "issuer-a")
	if err != nil {
		t.Fatalf("NewSignedStore (signer): %v", err)
	}
	tok, err := signer.Mint(newRecord(t))
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	verifier, err := store.NewSignedStore(signedKey(), 5*time.Minute, "issuer-b")
	if err != nil {
		t.Fatalf("NewSignedStore (verifier): %v", err)
	}
	if _, err := verifier.Claim(tok); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Claim with wrong issuer: got err %v, want ErrNotFound", err)
	}
}

func TestSignedStore_TamperedToken(t *testing.T) {
	t.Parallel()
	s := newSignedStore(t)
	tok, err := s.Mint(newRecord(t))
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	// Flip a character in the payload segment to invalidate the
	// signature.
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT segments, got %d", len(parts))
	}
	payload := []byte(parts[1])
	payload[0] ^= 0x01
	parts[1] = string(payload)
	tampered := strings.Join(parts, ".")
	if _, err := s.Claim(tampered); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Claim of tampered token: got err %v, want ErrNotFound", err)
	}
}

func TestSignedStore_ClaimRejectsGarbage(t *testing.T) {
	t.Parallel()
	s := newSignedStore(t)
	if _, err := s.Claim("not.a.jwt"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Claim of garbage: got err %v, want ErrNotFound", err)
	}
	if _, err := s.Claim(""); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Claim of empty string: got err %v, want ErrNotFound", err)
	}
}

// TestSignedStore_CrossInstance is the headline test for the Path 2
// design: a token minted by one SignedStore is valid for any other
// SignedStore that holds the same key. This is the property that
// allows the broker to be deployed at replica_count > 1 without a
// shared backend.
func TestSignedStore_CrossInstance(t *testing.T) {
	t.Parallel()
	signer, err := store.NewSignedStore(signedKey(), 5*time.Minute, "")
	if err != nil {
		t.Fatalf("NewSignedStore (signer): %v", err)
	}
	verifier, err := store.NewSignedStore(signedKey(), 5*time.Minute, "")
	if err != nil {
		t.Fatalf("NewSignedStore (verifier): %v", err)
	}

	rec := newRecord(t)
	tok, err := signer.Mint(rec)
	if err != nil {
		t.Fatalf("Mint on signer: %v", err)
	}
	got, err := verifier.Claim(tok)
	if err != nil {
		t.Fatalf("Claim on verifier: %v", err)
	}
	if got.Identity.Principal != rec.Identity.Principal {
		t.Errorf("cross-instance Claim returned wrong identity: got %q, want %q",
			got.Identity.Principal, rec.Identity.Principal)
	}
	if !got.AllowsDestination("alpha") {
		t.Error("cross-instance Claim lost the AllowedDestinations")
	}
}

// TestSignedStore_LimitedUseSemantics documents the trade-off of the
// stateless design: the same token may be Claimed multiple times
// within its TTL window. Future operators considering strict
// single-use semantics should add a per-replica jti cache or a
// shared dedup store; this test exists to make the current
// behaviour explicit and to flag any regression that silently
// reintroduces single-use enforcement.
func TestSignedStore_LimitedUseSemantics(t *testing.T) {
	t.Parallel()
	s := newSignedStore(t)
	tok, err := s.Mint(newRecord(t))
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	for i := range 3 {
		if _, err := s.Claim(tok); err != nil {
			t.Fatalf("Claim attempt %d: got err %v, want nil", i, err)
		}
	}
}

// TestSignedStore_NewFromConfig exercises the New() dispatch path
// using a key written to disk, end-to-end.
func TestSignedStore_NewFromConfig(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, signedKey(), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	cfg := store.Config{
		Signed: &store.SignedConfig{
			SigningKeyFile: path,
			TTL:            store.Duration(5 * time.Minute),
		},
	}
	s, err := store.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	tok, err := s.Mint(newRecord(t))
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if _, err := s.Claim(tok); err != nil {
		t.Fatalf("Claim: %v", err)
	}
}

func TestSignedStore_NewRejectsMissingKeyFile(t *testing.T) {
	t.Parallel()
	cfg := store.Config{
		Signed: &store.SignedConfig{
			SigningKeyFile: filepath.Join(t.TempDir(), "missing"),
			TTL:            store.Duration(5 * time.Minute),
		},
	}
	if _, err := store.New(cfg); err == nil {
		t.Fatal("New with missing key file: expected error, got nil")
	}
}

// signWithMethod produces a JWT signed with the given method using
// the test signing key. Tests use it to construct tokens whose
// header doesn't match what the SignedStore parser is configured to
// accept, so the parser's WithValidMethods constraint can be
// exercised directly.
func signWithMethod(t *testing.T, method jwt.SigningMethod, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(method, claims)
	signed, err := tok.SignedString(signedKey())
	if err != nil {
		t.Fatalf("sign with %s: %v", method.Alg(), err)
	}
	return signed
}

// TestSignedStore_RejectsWrongAlgorithm pins the WithValidMethods
// constraint. A token signed with the same key but a different HMAC
// algorithm (HS512) must be rejected; otherwise an attacker who
// could induce the broker to accept tokens of an algorithm chosen by
// the header would be able to bypass downgrade protections.
func TestSignedStore_RejectsWrongAlgorithm(t *testing.T) {
	t.Parallel()
	s := newSignedStore(t)
	now := time.Now()
	tok := signWithMethod(t, jwt.SigningMethodHS512, jwt.MapClaims{
		"iss":           store.DefaultSignedIssuer,
		"sub":           "test",
		"iat":           now.Unix(),
		"exp":           now.Add(5 * time.Minute).Unix(),
		"identity_type": string(auth.IdentityTypeCI),
	})
	if _, err := s.Claim(tok); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Claim of HS512-signed token: got err %v, want ErrNotFound", err)
	}
}

// TestSignedStore_RejectsInvalidIdentityType pins the defence-in-
// depth check that the identity_type claim, even when it is covered
// by a valid signature, must be one of the known IdentityType values.
func TestSignedStore_RejectsInvalidIdentityType(t *testing.T) {
	t.Parallel()
	s := newSignedStore(t)
	now := time.Now()
	tok := signWithMethod(t, jwt.SigningMethodHS256, jwt.MapClaims{
		"iss":           store.DefaultSignedIssuer,
		"sub":           "test",
		"iat":           now.Unix(),
		"exp":           now.Add(5 * time.Minute).Unix(),
		"identity_type": "robot",
	})
	if _, err := s.Claim(tok); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Claim of token with unknown identity_type: got err %v, want ErrNotFound", err)
	}
}

// TestSignedStore_ClaimErrorCarriesReason verifies that the failure
// path returns an error whose string includes a human-readable
// reason in addition to wrapping ErrNotFound. Operators rely on the
// reason to triage in audit logs.
func TestSignedStore_ClaimErrorCarriesReason(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		token       func(t *testing.T, s *store.SignedStore) string
		wantSubstr  string
		fastForward time.Duration
	}{
		{
			name: "expired",
			token: func(t *testing.T, s *store.SignedStore) string {
				tok, err := s.Mint(newRecord(t))
				if err != nil {
					t.Fatalf("Mint: %v", err)
				}
				return tok
			},
			wantSubstr:  "expired",
			fastForward: time.Hour,
		},
		{
			name: "wrong issuer",
			token: func(t *testing.T, _ *store.SignedStore) string {
				other, err := store.NewSignedStore(signedKey(), 5*time.Minute, "other-issuer")
				if err != nil {
					t.Fatalf("NewSignedStore: %v", err)
				}
				tok, err := other.Mint(newRecord(t))
				if err != nil {
					t.Fatalf("Mint: %v", err)
				}
				return tok
			},
			wantSubstr: "issuer",
		},
		{
			name: "bad signature",
			token: func(t *testing.T, _ *store.SignedStore) string {
				other, err := store.NewSignedStore(bytes.Repeat([]byte{0xFF}, store.MinSignedKeyBytes), 5*time.Minute, "")
				if err != nil {
					t.Fatalf("NewSignedStore: %v", err)
				}
				tok, err := other.Mint(newRecord(t))
				if err != nil {
					t.Fatalf("Mint: %v", err)
				}
				return tok
			},
			wantSubstr: "signature",
		},
		{
			name: "malformed",
			token: func(_ *testing.T, _ *store.SignedStore) string {
				return "not.a.jwt"
			},
			wantSubstr: "malformed",
		},
		{
			name: "wrong algorithm",
			token: func(t *testing.T, _ *store.SignedStore) string {
				now := time.Now()
				return signWithMethod(t, jwt.SigningMethodHS512, jwt.MapClaims{
					"iss": store.DefaultSignedIssuer,
					"sub": "test",
					"iat": now.Unix(),
					"exp": now.Add(5 * time.Minute).Unix(),
				})
			},
			wantSubstr: "signing method",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := newSignedStore(t)
			tok := tc.token(t, s)
			if tc.fastForward > 0 {
				s.SetNow(func() time.Time { return time.Now().Add(tc.fastForward) })
			}
			_, err := s.Claim(tok)
			if !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("Claim: got err %v, want wrapped ErrNotFound", err)
			}
			if !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Errorf("Claim error %q: want substring %q", err.Error(), tc.wantSubstr)
			}
		})
	}
}

// TestSignedStore_Concurrent fans out N concurrent Mint+Claim pairs
// against a single SignedStore. The race detector catches any
// shared-state bug; the assertion catches any misuse of the parser
// that produces incorrect results under load. The store is supposed
// to be safe for concurrent use because every per-call value is
// derived from immutable receiver state plus call-local data.
func TestSignedStore_Concurrent(t *testing.T) {
	t.Parallel()
	const goroutines = 64

	s := newSignedStore(t)
	var (
		wg     sync.WaitGroup
		failed atomic.Int32
	)
	wg.Add(goroutines)
	start := make(chan struct{})
	for range goroutines {
		go func() {
			defer wg.Done()
			<-start
			tok, err := s.Mint(newRecord(t))
			if err != nil {
				t.Errorf("Mint: %v", err)
				failed.Add(1)
				return
			}
			rec, err := s.Claim(tok)
			if err != nil {
				t.Errorf("Claim: %v", err)
				failed.Add(1)
				return
			}
			if rec.Identity.Principal != "repo:owner/repo:ref:refs/heads/main" {
				t.Errorf("Claim returned wrong principal: %q", rec.Identity.Principal)
				failed.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if got := failed.Load(); got != 0 {
		t.Fatalf("%d/%d concurrent Mint+Claim pairs failed", got, goroutines)
	}
}

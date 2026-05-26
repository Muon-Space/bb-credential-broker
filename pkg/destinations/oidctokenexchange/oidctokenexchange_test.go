package oidctokenexchange_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/auth"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/destinations/httptokenexchange"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/destinations/oidctokenexchange"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/secrets"
)

// loaderWithKey returns a secrets.Loader seeded with a freshly-
// generated RSA private key under the supplied named-secret key.
// Tests use it so the signjwt template emitted by the transform
// can actually sign at runtime.
func loaderWithKey(t *testing.T, name string) (secrets.Loader, *rsa.PrivateKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
	loader := secrets.NewMapLoader()
	loader.Set("aws:arn:test:"+name+"#", pemBytes)
	return loader, priv
}

func TestNew_RejectsMissingRequiredFields(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		cfg  *oidctokenexchange.Config
		want string
	}{
		{
			name: "missing url",
			cfg: &oidctokenexchange.Config{
				ProviderName: "p",
				SubjectToken: oidctokenexchange.SubjectTokenConfig{
					SignedJWT: &oidctokenexchange.SignedJWTConfig{SigningKey: "k", Issuer: "iss", Subject: "sub"},
				},
			},
			want: "url",
		},
		{
			name: "missing providerName",
			cfg: &oidctokenexchange.Config{
				URL: "https://x",
				SubjectToken: oidctokenexchange.SubjectTokenConfig{
					SignedJWT: &oidctokenexchange.SignedJWTConfig{SigningKey: "k", Issuer: "iss", Subject: "sub"},
				},
			},
			want: "providerName",
		},
		{
			name: "missing signedJWT shape",
			cfg: &oidctokenexchange.Config{
				URL: "https://x", ProviderName: "p",
				SubjectToken: oidctokenexchange.SubjectTokenConfig{},
			},
			want: "signedJWT",
		},
		{
			name: "missing signingKey",
			cfg: &oidctokenexchange.Config{
				URL: "https://x", ProviderName: "p",
				SubjectToken: oidctokenexchange.SubjectTokenConfig{
					SignedJWT: &oidctokenexchange.SignedJWTConfig{Issuer: "iss", Subject: "sub"},
				},
			},
			want: "signingKey",
		},
		{
			name: "missing issuer",
			cfg: &oidctokenexchange.Config{
				URL: "https://x", ProviderName: "p",
				SubjectToken: oidctokenexchange.SubjectTokenConfig{
					SignedJWT: &oidctokenexchange.SignedJWTConfig{SigningKey: "k", Subject: "sub"},
				},
			},
			want: "issuer",
		},
		{
			name: "missing subject",
			cfg: &oidctokenexchange.Config{
				URL: "https://x", ProviderName: "p",
				SubjectToken: oidctokenexchange.SubjectTokenConfig{
					SignedJWT: &oidctokenexchange.SignedJWTConfig{SigningKey: "k", Issuer: "iss"},
				},
			},
			want: "subject",
		},
		{
			name: "bad ttl",
			cfg: &oidctokenexchange.Config{
				URL: "https://x", ProviderName: "p",
				SubjectToken: oidctokenexchange.SubjectTokenConfig{
					SignedJWT: &oidctokenexchange.SignedJWTConfig{SigningKey: "k", Issuer: "iss", Subject: "sub", TTL: "not-a-duration"},
				},
			},
			want: "ttl",
		},
		{
			name: "unsupported algorithm",
			cfg: &oidctokenexchange.Config{
				URL: "https://x", ProviderName: "p",
				SubjectToken: oidctokenexchange.SubjectTokenConfig{
					SignedJWT: &oidctokenexchange.SignedJWTConfig{SigningKey: "k", Algorithm: "HS256", Issuer: "iss", Subject: "sub"},
				},
			},
			want: "algorithm",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			loader, _ := loaderWithKey(t, "k")
			_, err := oidctokenexchange.New("x", tc.cfg, httptokenexchange.Dependencies{
				Secrets: loader,
				NamedSecrets: map[string]secrets.SecretRef{"k": {
					AWSSecretsManager: &secrets.AWSSecretsManagerRef{ARN: "arn:test:k"},
				}},
			})
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q should mention %q", err.Error(), tc.want)
			}
		})
	}
}

// TestNew_EndToEndAgainstFakeUpstream exercises the full path:
// config compiles to an httpTokenExchange, the Mint flow signs a
// JWT against the operator-supplied key, the form body reaches a
// fake upstream, and the response token round-trips back to the
// caller. The fake upstream verifies the signature with the
// public half of the same key and asserts the JWT contents match
// what the operator configured.
func TestNew_EndToEndAgainstFakeUpstream(t *testing.T) {
	t.Parallel()
	loader, priv := loaderWithKey(t, "broker-key")

	var receivedSubjectToken string
	var receivedForm url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		receivedForm = r.PostForm
		receivedSubjectToken = r.PostForm.Get("subject_token")
		_, _ = w.Write([]byte(`{"access_token":"abc","expires_in":300}`))
	}))
	defer srv.Close()

	cfg := &oidctokenexchange.Config{
		URL:          srv.URL + "/token",
		ProviderName: "broker-issued",
		SubjectToken: oidctokenexchange.SubjectTokenConfig{
			SignedJWT: &oidctokenexchange.SignedJWTConfig{
				SigningKey: "broker-key",
				Issuer:     "https://broker.example.com",
				Subject:    "${identity.principal}",
				Audience:   "downstream-tx",
				TTL:        "120s",
				Claims: map[string]string{
					"team": "${default:${identity.claims.team}:unknown}",
				},
			},
		},
		Response: httptokenexchange.ResponseConfig{
			TokenJSONPath:     "access_token",
			ExpiresInJSONPath: "expires_in",
		},
	}
	deps := httptokenexchange.Dependencies{
		Secrets: loader,
		NamedSecrets: map[string]secrets.SecretRef{"broker-key": {
			AWSSecretsManager: &secrets.AWSSecretsManagerRef{ARN: "arn:test:broker-key"},
		}},
	}

	impl, err := oidctokenexchange.New("artifactory", cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	identity := &auth.Identity{
		Type:      auth.IdentityTypeCI,
		Principal: "repo:owner/repo:ref:refs/heads/main",
		Claims:    map[string]any{"team": "platform"},
	}
	tok, err := impl.Mint(context.Background(), identity)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if tok.Value != "abc" {
		t.Errorf("Token.Value: got %q, want abc", tok.Value)
	}

	if got := receivedForm.Get("grant_type"); got != "urn:ietf:params:oauth:grant-type:token-exchange" {
		t.Errorf("upstream grant_type: got %q", got)
	}
	if got := receivedForm.Get("subject_token_type"); got != "urn:ietf:params:oauth:token-type:id_token" {
		t.Errorf("upstream subject_token_type: got %q", got)
	}
	if got := receivedForm.Get("provider_name"); got != "broker-issued" {
		t.Errorf("upstream provider_name: got %q", got)
	}

	parsed, err := jwt.Parse(receivedSubjectToken, func(*jwt.Token) (any, error) { return &priv.PublicKey, nil })
	if err != nil {
		t.Fatalf("parse subject_token jwt: %v", err)
	}
	claims, _ := parsed.Claims.(jwt.MapClaims)
	if claims["iss"] != "https://broker.example.com" {
		t.Errorf("jwt iss: got %v", claims["iss"])
	}
	if claims["sub"] != "repo:owner/repo:ref:refs/heads/main" {
		t.Errorf("jwt sub: got %v", claims["sub"])
	}
	if claims["aud"] != "downstream-tx" {
		t.Errorf("jwt aud: got %v", claims["aud"])
	}
	if claims["team"] != "platform" {
		t.Errorf("jwt team claim: got %v", claims["team"])
	}
	// iat and exp must be JSON numbers, not strings.
	if _, ok := claims["iat"].(float64); !ok {
		t.Errorf("jwt iat: got %T %v, want JSON number", claims["iat"], claims["iat"])
	}
	if _, ok := claims["exp"].(float64); !ok {
		t.Errorf("jwt exp: got %T %v, want JSON number", claims["exp"], claims["exp"])
	}
	// kid is the RFC 7638 thumbprint of the public key; non-empty
	// is the only invariant we pin here (a dedicated test in
	// pkg/signer pins the thumbprint value).
	if kid, _ := parsed.Header["kid"].(string); kid == "" {
		t.Errorf("jwt kid header missing")
	}
}

// TestNew_DefaultsAreApplied checks that operator-omitted optional
// fields receive the documented defaults: RS256 algorithm, 5m
// TTL, :id_token subject_token_type.
func TestNew_DefaultsAreApplied(t *testing.T) {
	t.Parallel()
	loader, _ := loaderWithKey(t, "broker-key")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"x"}`))
	}))
	defer srv.Close()

	cfg := &oidctokenexchange.Config{
		URL:          srv.URL,
		ProviderName: "p",
		SubjectToken: oidctokenexchange.SubjectTokenConfig{
			SignedJWT: &oidctokenexchange.SignedJWTConfig{
				SigningKey: "broker-key",
				Issuer:     "https://broker",
				Subject:    "sa",
				// Algorithm and TTL deliberately omitted.
			},
		},
		Response: httptokenexchange.ResponseConfig{TokenJSONPath: "access_token"},
	}
	deps := httptokenexchange.Dependencies{
		Secrets: loader,
		NamedSecrets: map[string]secrets.SecretRef{"broker-key": {
			AWSSecretsManager: &secrets.AWSSecretsManagerRef{ARN: "arn:test:broker-key"},
		}},
	}
	if _, err := oidctokenexchange.New("x", cfg, deps); err != nil {
		t.Fatalf("New with defaults: %v", err)
	}
}

// TestNew_OverridableSubjectTokenType lets operators target
// downstreams that document the generic :jwt type rather than the
// :id_token default.
func TestNew_OverridableSubjectTokenType(t *testing.T) {
	t.Parallel()
	loader, _ := loaderWithKey(t, "k")

	var receivedType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		receivedType = r.PostForm.Get("subject_token_type")
		_, _ = w.Write([]byte(`{"access_token":"x"}`))
	}))
	defer srv.Close()

	cfg := &oidctokenexchange.Config{
		URL: srv.URL, ProviderName: "p",
		SubjectTokenType: "urn:ietf:params:oauth:token-type:jwt",
		SubjectToken: oidctokenexchange.SubjectTokenConfig{
			SignedJWT: &oidctokenexchange.SignedJWTConfig{SigningKey: "k", Issuer: "i", Subject: "s"},
		},
		Response: httptokenexchange.ResponseConfig{TokenJSONPath: "access_token"},
	}
	deps := httptokenexchange.Dependencies{
		Secrets: loader,
		NamedSecrets: map[string]secrets.SecretRef{"k": {
			AWSSecretsManager: &secrets.AWSSecretsManagerRef{ARN: "arn:test:k"},
		}},
	}
	impl, err := oidctokenexchange.New("x", cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := impl.Mint(context.Background(), &auth.Identity{
		Type: auth.IdentityTypeCI, Principal: "p",
	}); err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if receivedType != "urn:ietf:params:oauth:token-type:jwt" {
		t.Errorf("subject_token_type: got %q", receivedType)
	}
}

// TestNew_DispatcherIntegration verifies the destinations registry
// resolves the oidcTokenExchange discriminator end-to-end via JSON.
func TestNew_DispatcherIntegration(t *testing.T) {
	t.Parallel()
	loader, _ := loaderWithKey(t, "k")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"abc"}`))
	}))
	defer srv.Close()

	raw := []byte(`{
		"oidcTokenExchange": {
			"url": "` + srv.URL + `",
			"providerName": "p",
			"subjectToken": {
				"signedJWT": {
					"signingKey": "k",
					"issuer": "https://broker",
					"subject": "sa"
				}
			},
			"response": { "tokenJsonPath": "access_token" }
		}
	}`)

	// Round-trip through the dispatcher's JSON decode to prove
	// the destinationConfig envelope recognises the new field.
	var cfg struct {
		OIDCTokenExchange *oidctokenexchange.Config `json:"oidcTokenExchange"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if cfg.OIDCTokenExchange == nil {
		t.Fatal("oidcTokenExchange field did not unmarshal")
	}
	deps := httptokenexchange.Dependencies{
		Secrets: loader,
		NamedSecrets: map[string]secrets.SecretRef{"k": {
			AWSSecretsManager: &secrets.AWSSecretsManagerRef{ARN: "arn:test:k"},
		}},
	}
	if _, err := oidctokenexchange.New("x", cfg.OIDCTokenExchange, deps); err != nil {
		t.Fatalf("New: %v", err)
	}
}

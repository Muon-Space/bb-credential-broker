package template_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/destinations/httptokenexchange/template"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/secrets"
)

func TestFile_ReadsFromDisk(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	if err := os.WriteFile(path, []byte("hello"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	tmpl := template.MustParse("${file:" + path + "}")
	got, err := tmpl.Eval(context.Background(), newScope(t, nil))
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if got != "hello" {
		t.Errorf("got %q, want %q", got, "hello")
	}
}

func TestFile_MissingFileSurfacesError(t *testing.T) {
	t.Parallel()
	tmpl := template.MustParse("${file:/no/such/path/at/all}")
	_, err := tmpl.Eval(context.Background(), newScope(t, nil))
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestSecret_LoadsByName(t *testing.T) {
	t.Parallel()
	loader := secrets.NewMapLoader()
	ref := secrets.SecretRef{
		AWSSecretsManager: &secrets.AWSSecretsManagerRef{
			ARN:   "arn:aws:secretsmanager:us-east-1:0:secret:k",
			Field: "f",
		},
	}
	loader.Set("aws:arn:aws:secretsmanager:us-east-1:0:secret:k#f", []byte("super-secret"))

	scope := template.DefaultScope(nil, loader, map[string]secrets.SecretRef{"my-key": ref})
	scope.Now = fixedTime
	tmpl := template.MustParse("${secret:my-key}")

	got, err := tmpl.Eval(context.Background(), scope)
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if got != "super-secret" {
		t.Errorf("got %q, want %q", got, "super-secret")
	}
}

func TestSecret_UnknownNameSurfacesError(t *testing.T) {
	t.Parallel()
	scope := template.DefaultScope(nil, secrets.NewMapLoader(), map[string]secrets.SecretRef{})
	tmpl := template.MustParse("${secret:nope}")
	_, err := tmpl.Eval(context.Background(), scope)
	if err == nil {
		t.Fatal("expected error for unknown secret, got nil")
	}
	if !strings.Contains(err.Error(), `no secret named "nope"`) {
		t.Errorf("error %q lacks expected text", err.Error())
	}
}

func TestJSONString_QuotesAndEscapes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input string
		want  string
	}{
		{input: `simple`, want: `"simple"`},
		{input: `with "quotes"`, want: `"with \"quotes\""`},
		{input: `with\backslash`, want: `"with\\backslash"`},
		{input: ``, want: `""`},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			tmpl := template.MustParse(`${jsonString:` + tc.input + `}`)
			got, err := tmpl.Eval(context.Background(), newScope(t, nil))
			if err != nil {
				t.Fatalf("Eval: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestB64_Encodes(t *testing.T) {
	t.Parallel()
	tmpl := template.MustParse(`${b64:hello}`)
	got, err := tmpl.Eval(context.Background(), newScope(t, nil))
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if got != "aGVsbG8" {
		t.Errorf("got %q, want %q", got, "aGVsbG8")
	}
}

func TestEnv_ReadsVar(t *testing.T) {
	// Note: cannot mark parallel — t.Setenv is incompatible with t.Parallel.
	t.Setenv("BB_CREDENTIAL_BROKER_TEST_VAR", "value-from-env")
	tmpl := template.MustParse(`${env:BB_CREDENTIAL_BROKER_TEST_VAR}`)
	got, err := tmpl.Eval(context.Background(), newScope(t, nil))
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if got != "value-from-env" {
		t.Errorf("got %q, want %q", got, "value-from-env")
	}
}

func TestEnv_MissingReturnsEmpty(t *testing.T) {
	t.Parallel()
	tmpl := template.MustParse(`${env:DEFINITELY_NOT_SET_BB_BROKER_VAR_42}`)
	got, err := tmpl.Eval(context.Background(), newScope(t, nil))
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if got != "" {
		t.Errorf("got %q, want empty string", got)
	}
}

func TestSignJWT_RoundTrip(t *testing.T) {
	t.Parallel()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})

	loader := secrets.NewMapLoader()
	ref := secrets.SecretRef{
		AWSSecretsManager: &secrets.AWSSecretsManagerRef{ARN: "arn:test:key"},
	}
	loader.Set("aws:arn:test:key#", pemBytes)

	scope := template.DefaultScope(nil, loader, map[string]secrets.SecretRef{"k": ref})
	scope.Now = fixedTime
	// jsonString wraps the principal substitution; here we
	// hand-build the claims object since there's no identity in
	// scope.
	tmpl := template.MustParse(`${signjwt:RS256:${secret:k}:{"iss":"app","sub":"sub","iat":${now}}}`)
	signed, err := tmpl.Eval(context.Background(), scope)
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}

	parsed, err := jwt.Parse(signed, func(*jwt.Token) (any, error) { return &priv.PublicKey, nil })
	if err != nil {
		t.Fatalf("parse signed jwt: %v", err)
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatalf("claims have wrong shape: %T", parsed.Claims)
	}
	if claims["iss"] != "app" {
		t.Errorf("iss: got %v, want %q", claims["iss"], "app")
	}
}

func TestSignJWT_UnsupportedAlg(t *testing.T) {
	t.Parallel()
	scope := template.DefaultScope(nil, secrets.NewMapLoader(), map[string]secrets.SecretRef{})
	tmpl := template.MustParse(`${signjwt:NOTANALG:key:{}}`)
	_, err := tmpl.Eval(context.Background(), scope)
	if err == nil {
		t.Fatal("expected error from unsupported algorithm, got nil")
	}
}

package template_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/auth"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/destinations/httptokenexchange/template"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/secrets"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/signer"
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
	// The signed JWT must carry a kid header so downstream
	// verifiers that look up signing keys in a JWKS by kid (the
	// broker's own JWKS endpoint, JFrog's generic-OIDC provider,
	// any other PKIX consumer) resolve the right entry without
	// operator coordination.
	if _, ok := parsed.Header["kid"].(string); !ok {
		t.Errorf("kid header missing or non-string: %+v", parsed.Header)
	}
}

// TestSignJWT_KIDIsRFC7638Thumbprint asserts the kid the signer
// embeds matches the RFC 7638 JWK thumbprint of the public key.
// The check pairs with pkg/signer's thumbprint vector test: a
// future refactor that changes one half of the kid-derivation
// chain without changing the other surfaces here.
func TestSignJWT_KIDIsRFC7638Thumbprint(t *testing.T) {
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
		AWSSecretsManager: &secrets.AWSSecretsManagerRef{ARN: "arn:test:k"},
	}
	loader.Set("aws:arn:test:k#", pemBytes)

	scope := template.DefaultScope(nil, loader, map[string]secrets.SecretRef{"k": ref})
	scope.Now = fixedTime
	tmpl := template.MustParse(`${signjwt:RS256:${secret:k}:{"iss":"app","iat":${now}}}`)
	signed, err := tmpl.Eval(context.Background(), scope)
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	parsed, err := jwt.Parse(signed, func(*jwt.Token) (any, error) { return &priv.PublicKey, nil })
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	gotKID, _ := parsed.Header["kid"].(string)
	wantKID, err := signer.Thumbprint(&priv.PublicKey)
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	if gotKID != wantKID {
		t.Errorf("kid: got %q, want %q (RFC 7638 thumbprint)", gotKID, wantKID)
	}
}

// TestJSON_AutoTypesValues exercises the auto-typing rule that
// distinguishes JSON literals from bare strings. A number that
// resolves to a numeric string is emitted unquoted; a string
// substitution is wrapped in quotes; a pre-quoted JSON string is
// passed through verbatim; bools and null are recognised.
func TestJSON_AutoTypesValues(t *testing.T) {
	t.Parallel()
	id := &auth.Identity{
		Type:      auth.IdentityTypeCI,
		Principal: "repo:owner/repo:ref:refs/heads/main",
		Claims:    map[string]any{"team": "platform"},
	}
	cases := []struct {
		name string
		tmpl string
		want string
	}{
		{
			name: "empty object",
			tmpl: `${json}`,
			want: `{}`,
		},
		{
			name: "string value gets quoted",
			tmpl: `${json:sub:${identity.principal}}`,
			want: `{"sub":"repo:owner/repo:ref:refs/heads/main"}`,
		},
		{
			name: "numeric template stays unquoted",
			tmpl: `${json:iat:${now}}`,
			// fixedTime in the test scope returns 1700000000.
			want: `{"iat":1700000000}`,
		},
		{
			name: "pre-quoted string passes verbatim",
			tmpl: `${json:iss:"https://broker.example.com"}`,
			want: `{"iss":"https://broker.example.com"}`,
		},
		{
			name: "boolean literal",
			tmpl: `${json:active:true}`,
			want: `{"active":true}`,
		},
		{
			name: "null literal",
			tmpl: `${json:tenant:null}`,
			want: `{"tenant":null}`,
		},
		{
			name: "string with characters json would escape",
			tmpl: `${json:msg:hello "world"}`,
			want: `{"msg":"hello \"world\""}`,
		},
		{
			name: "key order follows operator-supplied order, not lexicographic",
			tmpl: `${json:z:1:a:2:m:3}`,
			want: `{"z":1,"a":2,"m":3}`,
		},
		{
			name: "mixed types in one object",
			tmpl: `${json:sub:${identity.principal}:iat:${now}:active:true}`,
			want: `{"sub":"repo:owner/repo:ref:refs/heads/main","iat":1700000000,"active":true}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tmpl := template.MustParse(tc.tmpl)
			got, err := tmpl.Eval(context.Background(), newScope(t, id))
			if err != nil {
				t.Fatalf("Eval: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestJSON_OutputIsValidJSON cross-checks the auto-typing logic
// by parsing the function output back through encoding/json. Any
// future change that emits a malformed JSON document for a
// representative claims body will trip this test before reaching
// the destination service.
func TestJSON_OutputIsValidJSON(t *testing.T) {
	t.Parallel()
	id := &auth.Identity{Type: auth.IdentityTypeCI, Principal: "p"}
	tmpl := template.MustParse(
		`${json:iss:"https://broker":sub:${identity.principal}:iat:${now}:active:true:tenant:null}`)
	got, err := tmpl.Eval(context.Background(), newScope(t, id))
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(got), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v (got=%s)", err, got)
	}
	if parsed["iss"] != "https://broker" {
		t.Errorf("iss: got %v", parsed["iss"])
	}
	if _, ok := parsed["iat"].(float64); !ok {
		t.Errorf("iat: got %T %v, want JSON number", parsed["iat"], parsed["iat"])
	}
	if parsed["active"] != true {
		t.Errorf("active: got %v", parsed["active"])
	}
	if parsed["tenant"] != nil {
		t.Errorf("tenant: got %v, want JSON null", parsed["tenant"])
	}
}

// TestJSON_OddArityRejectedAtNew covers the documented arity
// invariant that surfaces at broker startup via the Validator
// registry. Without the validator the error would surface only
// at the first /token request that exercises the template.
func TestJSON_OddArityRejectedAtNew(t *testing.T) {
	t.Parallel()
	// Three arguments — one key, one value, and a stray third
	// item. Validation should reject this when the template is
	// run through Template.Validate(template.DefaultValidators()).
	tmpl := template.MustParse(`${json:k1:v1:k2}`)
	err := tmpl.Validate(template.DefaultValidators())
	if err == nil {
		t.Fatal("expected odd-arity error from validator, got nil")
	}
	if !strings.Contains(err.Error(), "json") {
		t.Errorf("error %q should mention json", err.Error())
	}
	if !strings.Contains(err.Error(), "even") {
		t.Errorf("error %q should describe the even-pairs requirement", err.Error())
	}
}

// TestJSON_IntegratesWithSignJWT confirms the canonical operator
// use case: ${json:...} as the third argument to signjwt produces
// a verifiable JWT whose decoded claims match the operator-
// supplied key/value pairs.
func TestJSON_IntegratesWithSignJWT(t *testing.T) {
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
		AWSSecretsManager: &secrets.AWSSecretsManagerRef{ARN: "arn:test:k"},
	}
	loader.Set("aws:arn:test:k#", pemBytes)
	id := &auth.Identity{Type: auth.IdentityTypeCI, Principal: "repo:foo/bar"}
	scope := template.DefaultScope(id, loader, map[string]secrets.SecretRef{"k": ref})
	scope.Now = fixedTime

	tmpl := template.MustParse(
		`${signjwt:RS256:${secret:k}:${json:iss:"https://broker":sub:${identity.principal}:iat:${now}}}`)
	signed, err := tmpl.Eval(context.Background(), scope)
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	parsed, err := jwt.Parse(signed, func(*jwt.Token) (any, error) { return &priv.PublicKey, nil })
	if err != nil {
		t.Fatalf("parse signed jwt: %v", err)
	}
	claims, _ := parsed.Claims.(jwt.MapClaims)
	if claims["iss"] != "https://broker" {
		t.Errorf("iss: got %v", claims["iss"])
	}
	if claims["sub"] != "repo:foo/bar" {
		t.Errorf("sub: got %v", claims["sub"])
	}
	// iat must be a JSON number.
	if iat, ok := claims["iat"].(float64); !ok || iat != 1700000000 {
		t.Errorf("iat: got %T %v, want 1700000000", claims["iat"], claims["iat"])
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

// TestDefault_PrimaryExpressionWins exercises the success path: the
// first argument evaluates without error and its value is returned;
// the fallback is not consulted.
func TestDefault_PrimaryExpressionWins(t *testing.T) {
	t.Parallel()
	id := &auth.Identity{
		Type:      auth.IdentityTypeCI,
		Principal: "the-principal",
		Claims:    map[string]any{"present": "yes"},
	}
	tmpl := template.MustParse("${default:${identity.claims.present}:fallback}")
	got, err := tmpl.Eval(context.Background(), newScope(t, id))
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if got != "yes" {
		t.Errorf("got %q, want %q", got, "yes")
	}
}

// TestDefault_FallbackOnMissingClaim verifies the headline use
// case: a destination template that references a claim a newly
// created repository has not yet been classified against returns
// the operator-supplied fallback rather than erroring at /token
// time.
func TestDefault_FallbackOnMissingClaim(t *testing.T) {
	t.Parallel()
	id := &auth.Identity{
		Type:      auth.IdentityTypeCI,
		Principal: "the-principal",
		Claims:    map[string]any{},
	}
	tmpl := template.MustParse("${default:${identity.claims.absent}:fallback}")
	got, err := tmpl.Eval(context.Background(), newScope(t, id))
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if got != "fallback" {
		t.Errorf("got %q, want %q", got, "fallback")
	}
}

// TestDefault_NestedFallbackIsTemplated confirms that the fallback
// argument is itself a template: a missing claim falls through to
// an expression that itself substitutes a different identity field.
func TestDefault_NestedFallbackIsTemplated(t *testing.T) {
	t.Parallel()
	id := &auth.Identity{
		Type:      auth.IdentityTypeCI,
		Principal: "the-principal",
		Claims:    map[string]any{},
	}
	tmpl := template.MustParse("${default:${identity.claims.absent}:${identity.principal}}")
	got, err := tmpl.Eval(context.Background(), newScope(t, id))
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if got != "the-principal" {
		t.Errorf("got %q, want %q", got, "the-principal")
	}
}

// TestDefault_EmptyFallbackIsValid demonstrates that the empty
// string is a legal fallback value — useful when downstream callers
// distinguish absent from empty themselves.
func TestDefault_EmptyFallbackIsValid(t *testing.T) {
	t.Parallel()
	id := &auth.Identity{Type: auth.IdentityTypeCI, Principal: "p", Claims: map[string]any{}}
	tmpl := template.MustParse("${default:${identity.claims.absent}:}")
	got, err := tmpl.Eval(context.Background(), newScope(t, id))
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

// TestDefault_FallbackCoversNonVariableErrors verifies the
// error-tolerance is not specific to missing-variable failures: a
// failed ${secret:...} lookup (a different error class) also
// triggers the fallback.
func TestDefault_FallbackCoversNonVariableErrors(t *testing.T) {
	t.Parallel()
	scope := template.DefaultScope(nil, secrets.NewMapLoader(), map[string]secrets.SecretRef{})
	scope.Now = fixedTime
	tmpl := template.MustParse("${default:${secret:does-not-exist}:fallback}")
	got, err := tmpl.Eval(context.Background(), scope)
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if got != "fallback" {
		t.Errorf("got %q, want %q", got, "fallback")
	}
}

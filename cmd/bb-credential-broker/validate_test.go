package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// minimalJWKS is a single-key JSON Web Key Set parseable by the
// broker's JWKS loader. The key material is intentionally trivial:
// the validate path checks only that the file parses and that every
// key declares a supported kty, not that the resulting public key
// can verify a real signature.
const minimalJWKS = `{"keys":[{"kid":"k1","kty":"RSA","n":"AQAB","e":"AQAB"}]}`

// fixture writes the file tree the example configurations expect:
// JWKS files for each configured issuer, the HMAC signing key for
// the nonce store, and the operator-supplied destination files
// referenced by the staticSecret destination type. The returned
// directory is the root under which paths are anchored; the test
// uses it to write per-case configurations that reference the
// fixture files by absolute path.
func fixture(t *testing.T) (root, jwks, signingKey, destFile, oidcToken string) {
	t.Helper()
	root = t.TempDir()

	jwks = filepath.Join(root, "jwks.json")
	if err := os.WriteFile(jwks, []byte(minimalJWKS), 0o600); err != nil {
		t.Fatalf("write jwks: %v", err)
	}

	signingKey = filepath.Join(root, "signing-key")
	if err := os.WriteFile(signingKey, bytes.Repeat([]byte{0x42}, 32), 0o600); err != nil {
		t.Fatalf("write signing key: %v", err)
	}

	destFile = filepath.Join(root, "dest-pat")
	if err := os.WriteFile(destFile, []byte("pat-value\n"), 0o600); err != nil {
		t.Fatalf("write dest file: %v", err)
	}

	oidcToken = filepath.Join(root, "sa-token")
	if err := os.WriteFile(oidcToken, []byte("dummy-oidc-token"), 0o600); err != nil {
		t.Fatalf("write sa token: %v", err)
	}
	return root, jwks, signingKey, destFile, oidcToken
}

// writeConfig writes body to a fresh config.jsonnet under root and
// returns its absolute path. The helper centralises the small
// boilerplate around table-driven tests below.
func writeConfig(t *testing.T, root, body string) string {
	t.Helper()
	path := filepath.Join(root, "config.jsonnet")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// validate runs the validate subcommand against path with a
// per-test stderr buffer so parallel tests do not race over the
// process-global os.Stderr. Returns the dispatcher's exit code and
// whatever stderr text was produced.
func validate(_ *testing.T, path string) (int, string) {
	var buf bytes.Buffer
	code := run([]string{"bb-credential-broker", "validate", path}, &buf)
	return code, buf.String()
}

// validJsonnet returns a configuration that exercises every
// subsystem the validate path checks. Tests mutate this body to
// introduce a single defect per case so the assertions stay focused.
func validJsonnet(jwks, signingKey, destFile, oidcToken string) string {
	return fmt.Sprintf(`{
  apiServer: { listenAddress: ':8080' },
  diagnosticsServer: { listenAddress: ':9980' },
  tokenAllowedCIDRs: ['10.0.0.0/8'],
  jwtAuth: {
    issuers: [
      { url: 'https://issuer.example.com', jwksFile: '%s', identityType: 'ci' },
    ],
  },
  nonceStore: { signed: { signingKeyFile: '%s', ttl: '5m' } },
  secrets: {
    'gh-app-key': {
      awsSecretsManager: { arn: 'arn:aws:secretsmanager:us-east-1:000000000000:secret:k', field: 'private_key' },
    },
  },
  destinations: {
    'artifactory': {
      httpTokenExchange: {
        request: {
          method: 'POST',
          url: 'https://artifactory.example.com/token',
          headers: { 'Authorization': 'Bearer ${file:%s}' },
        },
        response: { tokenJsonPath: 'access_token' },
      },
    },
    'pat-static': {
      staticSecret: { file: '%s', scheme: 'bearer' },
    },
  },
  policy: {
    ci: [
      { match: { 'claims.repository': { glob: 'owner/*' } }, allowedDestinations: ['artifactory'] },
    ],
  },
}`, jwks, signingKey, oidcToken, destFile)
}

func TestValidate_HappyPath(t *testing.T) {
	t.Parallel()
	root, jwks, signingKey, destFile, oidcToken := fixture(t)
	path := writeConfig(t, root, validJsonnet(jwks, signingKey, destFile, oidcToken))
	code, out := validate(t, path)
	if code != 0 {
		t.Fatalf("exit code: got %d, want 0; stderr=%q", code, out)
	}
	if out != "" {
		t.Errorf("expected empty stderr, got %q", out)
	}
}

func TestValidate_RejectsMalformedJsonnet(t *testing.T) {
	t.Parallel()
	root, _, _, _, _ := fixture(t)
	path := writeConfig(t, root, `{ this is not valid jsonnet `)
	code, out := validate(t, path)
	if code == 0 {
		t.Fatalf("expected non-zero exit, got 0")
	}
	if !strings.Contains(out, "evaluate") {
		t.Errorf("stderr should mention jsonnet evaluation, got %q", out)
	}
}

func TestValidate_RejectsMissingIssuerURL(t *testing.T) {
	t.Parallel()
	root, jwks, signingKey, destFile, oidcToken := fixture(t)
	body := strings.Replace(
		validJsonnet(jwks, signingKey, destFile, oidcToken),
		"url: 'https://issuer.example.com'",
		"url: ''",
		1,
	)
	path := writeConfig(t, root, body)
	code, out := validate(t, path)
	if code == 0 {
		t.Fatalf("expected non-zero exit, got 0; stderr=%q", out)
	}
	if !strings.Contains(out, "url") {
		t.Errorf("stderr should mention issuer url, got %q", out)
	}
}

func TestValidate_RejectsMissingJWKSFile(t *testing.T) {
	t.Parallel()
	root, jwks, signingKey, destFile, oidcToken := fixture(t)
	body := strings.Replace(
		validJsonnet(jwks, signingKey, destFile, oidcToken),
		jwks,
		filepath.Join(root, "does-not-exist.json"),
		1,
	)
	path := writeConfig(t, root, body)
	code, out := validate(t, path)
	if code == 0 {
		t.Fatalf("expected non-zero exit, got 0; stderr=%q", out)
	}
	if !strings.Contains(out, "jwtAuth") {
		t.Errorf("stderr should mention jwtAuth, got %q", out)
	}
}

func TestValidate_RejectsMissingSigningKey(t *testing.T) {
	t.Parallel()
	root, jwks, signingKey, destFile, oidcToken := fixture(t)
	body := strings.Replace(
		validJsonnet(jwks, signingKey, destFile, oidcToken),
		signingKey,
		filepath.Join(root, "does-not-exist"),
		1,
	)
	path := writeConfig(t, root, body)
	code, out := validate(t, path)
	if code == 0 {
		t.Fatalf("expected non-zero exit, got 0; stderr=%q", out)
	}
	if !strings.Contains(out, "nonceStore") {
		t.Errorf("stderr should mention nonceStore, got %q", out)
	}
}

func TestValidate_RejectsShortSigningKey(t *testing.T) {
	t.Parallel()
	root, jwks, _, destFile, oidcToken := fixture(t)
	short := filepath.Join(root, "short-key")
	if err := os.WriteFile(short, []byte("too-short"), 0o600); err != nil {
		t.Fatalf("write short key: %v", err)
	}
	body := validJsonnet(jwks, short, destFile, oidcToken)
	path := writeConfig(t, root, body)
	code, out := validate(t, path)
	if code == 0 {
		t.Fatalf("expected non-zero exit, got 0; stderr=%q", out)
	}
	if !strings.Contains(out, "nonceStore") {
		t.Errorf("stderr should mention nonceStore, got %q", out)
	}
}

func TestValidate_RejectsBadGlobPattern(t *testing.T) {
	t.Parallel()
	root, jwks, signingKey, destFile, oidcToken := fixture(t)
	body := strings.Replace(
		validJsonnet(jwks, signingKey, destFile, oidcToken),
		"glob: 'owner/*'",
		"glob: 'owner/[unterminated'",
		1,
	)
	path := writeConfig(t, root, body)
	code, out := validate(t, path)
	if code == 0 {
		t.Fatalf("expected non-zero exit, got 0; stderr=%q", out)
	}
	if !strings.Contains(out, "policy") {
		t.Errorf("stderr should mention policy, got %q", out)
	}
}

func TestValidate_RejectsUndefinedSecretReference(t *testing.T) {
	t.Parallel()
	root, jwks, signingKey, destFile, oidcToken := fixture(t)
	// Reference a secret name that is not registered in the
	// top-level secrets map. The check fires inside
	// httptokenexchange.New, surfaced through BuildRegistry.
	body := strings.Replace(
		validJsonnet(jwks, signingKey, destFile, oidcToken),
		"'Authorization': 'Bearer ${file:"+oidcToken+"}'",
		"'Authorization': 'Bearer ${secret:not-registered}'",
		1,
	)
	path := writeConfig(t, root, body)
	code, out := validate(t, path)
	if code == 0 {
		t.Fatalf("expected non-zero exit, got 0; stderr=%q", out)
	}
	if !strings.Contains(out, "not-registered") {
		t.Errorf("stderr should mention the missing secret name, got %q", out)
	}
}

func TestValidate_RejectsMalformedCIDR(t *testing.T) {
	t.Parallel()
	root, jwks, signingKey, destFile, oidcToken := fixture(t)
	body := strings.Replace(
		validJsonnet(jwks, signingKey, destFile, oidcToken),
		"['10.0.0.0/8']",
		"['not-a-cidr']",
		1,
	)
	path := writeConfig(t, root, body)
	code, out := validate(t, path)
	if code == 0 {
		t.Fatalf("expected non-zero exit, got 0; stderr=%q", out)
	}
	if !strings.Contains(out, "tokenAllowedCIDRs") {
		t.Errorf("stderr should mention tokenAllowedCIDRs, got %q", out)
	}
}

func TestValidate_RejectsMissingSecretARN(t *testing.T) {
	t.Parallel()
	root, jwks, signingKey, destFile, oidcToken := fixture(t)
	body := strings.Replace(
		validJsonnet(jwks, signingKey, destFile, oidcToken),
		"arn: 'arn:aws:secretsmanager:us-east-1:000000000000:secret:k'",
		"arn: ''",
		1,
	)
	path := writeConfig(t, root, body)
	code, out := validate(t, path)
	if code == 0 {
		t.Fatalf("expected non-zero exit, got 0; stderr=%q", out)
	}
	if !strings.Contains(out, "secret") && !strings.Contains(out, "arn") {
		t.Errorf("stderr should mention the missing arn, got %q", out)
	}
}

// TestValidate_AggregatesMultipleErrors verifies that an operator
// running the validate path against a configuration with several
// problems sees every problem in a single invocation rather than
// having to fix them one at a time across successive runs.
func TestValidate_AggregatesMultipleErrors(t *testing.T) {
	t.Parallel()
	root, jwks, signingKey, destFile, oidcToken := fixture(t)
	body := validJsonnet(jwks, signingKey, destFile, oidcToken)
	body = strings.Replace(body, "glob: 'owner/*'", "glob: 'owner/[unterminated'", 1)
	body = strings.Replace(body, jwks, filepath.Join(root, "missing.json"), 1)
	path := writeConfig(t, root, body)
	code, out := validate(t, path)
	if code == 0 {
		t.Fatalf("expected non-zero exit, got 0; stderr=%q", out)
	}
	if !strings.Contains(out, "policy") {
		t.Errorf("stderr should mention policy, got %q", out)
	}
	if !strings.Contains(out, "jwtAuth") {
		t.Errorf("stderr should mention jwtAuth, got %q", out)
	}
}

// TestRun_UsageOnMissingArguments asserts that the dispatcher
// surfaces a usage line and a non-zero exit code when the operator
// invokes the binary with no positional arguments. This is the
// first message a new operator sees and must mention the validate
// subcommand so they discover the lightweight CI path.
func TestRun_UsageOnMissingArguments(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	code := run([]string{"bb-credential-broker"}, &buf)
	if code != 2 {
		t.Errorf("exit code: got %d, want 2", code)
	}
	if !strings.Contains(buf.String(), "validate") {
		t.Errorf("usage should mention the validate subcommand, got %q", buf.String())
	}
}

func TestRun_UsageOnValidateWithoutPath(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	code := run([]string{"bb-credential-broker", "validate"}, &buf)
	if code != 2 {
		t.Errorf("exit code: got %d, want 2", code)
	}
	if !strings.Contains(buf.String(), "validate") {
		t.Errorf("usage should mention the validate subcommand, got %q", buf.String())
	}
}

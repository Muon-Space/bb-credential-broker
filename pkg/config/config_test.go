package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/config"
)

const validJsonnet = `
{
  apiServer:         { listenAddress: ':8080' },
  diagnosticsServer: { listenAddress: ':9980' },
  tokenAllowedCIDRs: ['10.0.0.0/8'],
  jwtAuth: {
    issuers: [
      {
        url:          'https://token.actions.githubusercontent.com',
        jwksFile:     '/etc/jwks/github-jwks.json',
        audience:     'bb-credential-broker',
        identityType: 'ci',
      },
    ],
  },
  nonceStore: {
    signed: { signingKeyFile: '/etc/broker/key', ttl: '5m' },
  },
  secrets: {
    'github-app-key': {
      awsSecretsManager: { arn: 'arn:aws:secretsmanager:us-east-1:000000000000:secret:k', field: 'private_key' },
    },
  },
  destinations: {
    'example': {
      httpTokenExchange: {
        request: { method: 'POST', url: 'https://example.com/token' },
        response: { tokenJsonPath: 'access_token' },
      },
    },
  },
  policy: {
    ci: [
      {
        match: { 'claims.repository': { glob: 'owner/*' } },
        allowedDestinations: ['example'],
      },
    ],
  },
}
`

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.jsonnet")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestLoad_HappyPath(t *testing.T) {
	t.Parallel()
	cfg, err := config.Load(writeConfig(t, validJsonnet))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.APIServer.ListenAddress; got != ":8080" {
		t.Errorf("APIServer.ListenAddress: got %q, want \":8080\"", got)
	}
	if len(cfg.JWTAuth.Issuers) != 1 {
		t.Fatalf("JWTAuth.Issuers: got %d, want 1", len(cfg.JWTAuth.Issuers))
	}
	if cfg.NonceStore.Signed == nil {
		t.Fatal("NonceStore.Signed: got nil")
	}
	if _, ok := cfg.Destinations["example"]; !ok {
		t.Errorf("Destinations: missing key %q", "example")
	}
	if _, ok := cfg.Secrets["github-app-key"]; !ok {
		t.Errorf("Secrets: missing key %q", "github-app-key")
	}
}

func TestLoad_RejectsMissingAPIServer(t *testing.T) {
	t.Parallel()
	body := `{
  diagnosticsServer: { listenAddress: ':9980' },
  tokenAllowedCIDRs: ['10.0.0.0/8'],
  jwtAuth: { issuers: [{ url: 'x', jwksFile: '/etc/jwks/x.json', identityType: 'ci' }] },
  nonceStore: { signed: { signingKeyFile: '/etc/broker/key', ttl: '5m' } },
}`
	_, err := config.Load(writeConfig(t, body))
	if err == nil {
		t.Fatal("expected error for missing apiServer, got nil")
	}
}

func TestLoad_RejectsBadCIDR(t *testing.T) {
	t.Parallel()
	body := `{
  apiServer:         { listenAddress: ':8080' },
  diagnosticsServer: { listenAddress: ':9980' },
  tokenAllowedCIDRs: ['not-a-cidr'],
  jwtAuth: { issuers: [{ url: 'x', jwksFile: '/etc/jwks/x.json', identityType: 'ci' }] },
  nonceStore: { signed: { signingKeyFile: '/etc/broker/key', ttl: '5m' } },
}`
	_, err := config.Load(writeConfig(t, body))
	if err == nil {
		t.Fatal("expected CIDR validation error, got nil")
	}
}

func TestLoad_RejectsUnknownTopLevelField(t *testing.T) {
	t.Parallel()
	body := `{
  apiServer:         { listenAddress: ':8080' },
  diagnosticsServer: { listenAddress: ':9980' },
  tokenAllowedCIDRs: ['10.0.0.0/8'],
  jwtAuth: { issuers: [{ url: 'x', jwksFile: '/etc/jwks/x.json', identityType: 'ci' }] },
  nonceStore: { signed: { signingKeyFile: '/etc/broker/key', ttl: '5m' } },
  unknownField: 'hello',
}`
	_, err := config.Load(writeConfig(t, body))
	if err == nil {
		t.Fatal("expected unknown-field error, got nil")
	}
}

// TestLoad_RejectsTypoInSecretRef pins the invariant for
// SecretRef.UnmarshalJSON: typos inside a SecretRef's backend
// block must not be silently ignored. The custom UnmarshalJSON
// installs its own strict decoder because json.Unmarshal does not
// propagate the outer Decoder's DisallowUnknownFields setting.
func TestLoad_RejectsTypoInSecretRef(t *testing.T) {
	t.Parallel()
	body := `{
  apiServer:         { listenAddress: ':8080' },
  diagnosticsServer: { listenAddress: ':9980' },
  tokenAllowedCIDRs: ['10.0.0.0/8'],
  jwtAuth: { issuers: [{ url: 'x', jwksFile: '/etc/jwks/x.json', identityType: 'ci' }] },
  nonceStore: { signed: { signingKeyFile: '/etc/broker/key', ttl: '5m' } },
  secrets: {
    'k': {
      // 'feild' is a typo of 'field' — must be rejected.
      awsSecretsManager: { arn: 'arn:x', feild: 'private_key' },
    },
  },
}`
	_, err := config.Load(writeConfig(t, body))
	if err == nil {
		t.Fatal("expected typo in awsSecretsManager.feild to be rejected, got nil")
	}
	if !strings.Contains(err.Error(), "feild") && !strings.Contains(err.Error(), "unknown field") {
		t.Errorf("error %q should name the unknown field", err.Error())
	}
}

func TestLoad_RejectsBadIdentityType(t *testing.T) {
	t.Parallel()
	body := `{
  apiServer:         { listenAddress: ':8080' },
  diagnosticsServer: { listenAddress: ':9980' },
  tokenAllowedCIDRs: ['10.0.0.0/8'],
  jwtAuth: { issuers: [{ url: 'x', jwksFile: '/etc/jwks/x.json', identityType: 'frog' }] },
  nonceStore: { signed: { signingKeyFile: '/etc/broker/key', ttl: '5m' } },
}`
	_, err := config.Load(writeConfig(t, body))
	if err == nil {
		t.Fatal("expected identityType validation error, got nil")
	}
}

func TestServerConfig_HTTPServerTimeoutsDefaults(t *testing.T) {
	t.Parallel()
	r, w := config.ServerConfig{}.HTTPServerTimeouts()
	if r == 0 || w == 0 {
		t.Errorf("expected non-zero defaults, got read=%v write=%v", r, w)
	}
}

// TestLoad_ExampleConfigParses doubles as a regression test for the
// shipped example: any change that breaks the example also breaks
// the build.
func TestLoad_ExampleConfigParses(t *testing.T) {
	t.Parallel()
	cfg, err := config.Load("../../examples/config.jsonnet")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Destinations) != 4 {
		t.Errorf("Destinations: got %d, want 4", len(cfg.Destinations))
	}
	if len(cfg.Secrets) != 2 {
		t.Errorf("Secrets: got %d, want 2", len(cfg.Secrets))
	}
	if cfg.BrokerSigner == nil {
		t.Errorf("BrokerSigner: got nil, want populated")
	}
}

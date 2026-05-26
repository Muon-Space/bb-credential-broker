package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeUpstream stands up an httptest server that records nothing
// and returns a token-shaped body. It lets the render test build
// a real destination registry without putting an unreachable URL
// in the config (which would surface in the test as a build-time
// template error rather than a runtime networking failure).
func fakeUpstream(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"x","expires_in":60}`))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// renderFixture writes a minimal valid config + identity file and
// returns their paths. The destination is an httpTokenExchange
// with a templated form body so the render output exercises the
// non-trivial templating path.
func renderFixture(t *testing.T, upstream string) (configPath, identityPath string) {
	t.Helper()
	root, jwks, signingKey, _, oidcToken := fixture(t)

	body := fmt.Sprintf(`{
  apiServer:         { listenAddress: ':8080' },
  diagnosticsServer: { listenAddress: ':9980' },
  tokenAllowedCIDRs: ['10.0.0.0/8'],
  jwtAuth: { issuers: [{ url: 'https://x', jwksFile: '%s', identityType: 'ci' }] },
  nonceStore: { signed: { signingKeyFile: '%s', ttl: '5m' } },
  destinations: {
    'artifactory': {
      httpTokenExchange: {
        request: {
          method: 'POST',
          url:    '%s/access/api/v1/oidc/token',
          headers: { 'X-Originator': '${identity.principal}' },
          body: { form: {
            grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
            sa_token:   '${file:%s}',
            subject:    '${identity.principal}',
          } },
        },
        response: { tokenJsonPath: 'access_token', expiresInJsonPath: 'expires_in' },
      },
    },
  },
}`, jwks, signingKey, upstream, oidcToken)
	configPath = filepath.Join(root, "config.jsonnet")
	if err := os.WriteFile(configPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	identityPath = filepath.Join(root, "identity.json")
	if err := os.WriteFile(identityPath, []byte(`{
  "type": "ci",
  "principal": "repo:owner/repo:ref:refs/heads/main",
  "claims": {"actor": "alice"}
}`), 0o600); err != nil {
		t.Fatalf("write identity: %v", err)
	}
	return configPath, identityPath
}

func TestRender_OutputRequest(t *testing.T) {
	t.Parallel()
	upstream := fakeUpstream(t)
	configPath, identityPath := renderFixture(t, upstream)

	var stdout, stderr bytes.Buffer
	code := runRender([]string{"--identity", identityPath, configPath, "artifactory"}, &stderr, &stdout)
	if code != 0 {
		t.Fatalf("exit code: got %d (stderr=%s)", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "POST "+upstream+"/access/api/v1/oidc/token HTTP/1.1") {
		t.Errorf("request line not in output:\n%s", out)
	}
	if !strings.Contains(out, "X-Originator: repo:owner/repo:ref:refs/heads/main") {
		t.Errorf("templated header not in output:\n%s", out)
	}
	if !strings.Contains(out, "Content-Type: application/x-www-form-urlencoded") {
		t.Errorf("Content-Type for form body not in output:\n%s", out)
	}
	if !strings.Contains(out, "subject=repo") {
		t.Errorf("form body field not in output (expected subject= form param):\n%s", out)
	}
}

func TestRender_OutputURL(t *testing.T) {
	t.Parallel()
	upstream := fakeUpstream(t)
	configPath, identityPath := renderFixture(t, upstream)
	var stdout, stderr bytes.Buffer
	code := runRender([]string{"--identity", identityPath, "--output", "url", configPath, "artifactory"}, &stderr, &stdout)
	if code != 0 {
		t.Fatalf("exit code: got %d (stderr=%s)", code, stderr.String())
	}
	want := upstream + "/access/api/v1/oidc/token"
	if got := strings.TrimSpace(stdout.String()); got != want {
		t.Errorf("url output: got %q, want %q", got, want)
	}
}

func TestRender_OutputUnknownIsRejected(t *testing.T) {
	t.Parallel()
	upstream := fakeUpstream(t)
	configPath, identityPath := renderFixture(t, upstream)
	var stdout, stderr bytes.Buffer
	code := runRender([]string{"--identity", identityPath, "--output", "frog", configPath, "artifactory"}, &stderr, &stdout)
	if code != 2 {
		t.Errorf("exit code: got %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "unknown --output") {
		t.Errorf("stderr: %s", stderr.String())
	}
}

func TestRender_DestinationNotConfigured(t *testing.T) {
	t.Parallel()
	upstream := fakeUpstream(t)
	configPath, identityPath := renderFixture(t, upstream)
	var stdout, stderr bytes.Buffer
	code := runRender([]string{"--identity", identityPath, configPath, "missing"}, &stderr, &stdout)
	if code != 1 {
		t.Errorf("exit code: got %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "missing") {
		t.Errorf("stderr should name the missing destination: %s", stderr.String())
	}
}

func TestRender_MissingIdentityFlag(t *testing.T) {
	t.Parallel()
	upstream := fakeUpstream(t)
	configPath, _ := renderFixture(t, upstream)
	var stdout, stderr bytes.Buffer
	code := runRender([]string{configPath, "artifactory"}, &stderr, &stdout)
	if code != 2 {
		t.Errorf("exit code: got %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "--identity is required") {
		t.Errorf("stderr: %s", stderr.String())
	}
}

func TestRender_StaticSecretIsNotRenderable(t *testing.T) {
	t.Parallel()
	root, jwks, signingKey, destFile, _ := fixture(t)
	configPath := filepath.Join(root, "config.jsonnet")
	body := fmt.Sprintf(`{
  apiServer:         { listenAddress: ':8080' },
  diagnosticsServer: { listenAddress: ':9980' },
  tokenAllowedCIDRs: ['10.0.0.0/8'],
  jwtAuth: { issuers: [{ url: 'https://x', jwksFile: '%s', identityType: 'ci' }] },
  nonceStore: { signed: { signingKeyFile: '%s', ttl: '5m' } },
  destinations: {
    'pat': { staticSecret: { file: '%s' } },
  },
}`, jwks, signingKey, destFile)
	if err := os.WriteFile(configPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	identityPath := filepath.Join(root, "id.json")
	_ = os.WriteFile(identityPath, []byte(`{"type":"ci","principal":"p","claims":{}}`), 0o600)

	var stdout, stderr bytes.Buffer
	code := runRender([]string{"--identity", identityPath, configPath, "pat"}, &stderr, &stdout)
	if code != 1 {
		t.Errorf("exit code: got %d, want 1\nstderr=%s\nstdout=%s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stderr.String(), "no HTTP request") {
		t.Errorf("stderr should explain staticSecret: %s", stderr.String())
	}
}

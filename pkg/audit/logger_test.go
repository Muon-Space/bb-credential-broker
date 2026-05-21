package audit_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/audit"
)

func TestLogger_DelegateGranted(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	l := audit.NewLogger(&buf)
	exp := time.Unix(1700000300, 0).UTC()
	l.LogDelegate(context.Background(), audit.DelegateEntry{
		Time: time.Unix(1700000000, 0).UTC(),
		Identity: &audit.IdentityRecord{
			Type:      "ci",
			Principal: "repo:owner/repo:ref:refs/heads/main",
			Claims: map[string]any{
				"repository": "owner/repo",
				"actor":      "octocat",
			},
		},
		Result:              audit.ResultGranted,
		GrantedDestinations: []string{"alpha", "beta"},
		DelegationTokenJTI:  "the-jti",
		DelegationTokenExp:  &exp,
	})

	var got map[string]any
	if err := json.NewDecoder(strings.NewReader(buf.String())).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["event"] != "delegate" {
		t.Errorf("event: got %v, want %q", got["event"], "delegate")
	}
	if got["result"] != "granted" {
		t.Errorf("result: got %v, want %q", got["result"], "granted")
	}
	if got["delegation_token_jti"] != "the-jti" {
		t.Errorf("delegation_token_jti: got %v", got["delegation_token_jti"])
	}
	id, ok := got["identity"].(map[string]any)
	if !ok {
		t.Fatalf("identity: got %T, want map", got["identity"])
	}
	if id["type"] != "ci" {
		t.Errorf("identity.type: got %v", id["type"])
	}
	claims, ok := id["claims"].(map[string]any)
	if !ok {
		t.Fatalf("identity.claims: got %T, want map", id["claims"])
	}
	if claims["repository"] != "owner/repo" {
		t.Errorf("claims.repository: got %v", claims["repository"])
	}
}

func TestLogger_DelegateDeniedPreIdentity(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	l := audit.NewLogger(&buf)
	l.LogDelegate(context.Background(), audit.DelegateEntry{
		Time:         time.Unix(1700000000, 0).UTC(),
		Identity:     nil, // request rejected before bearer-token validation
		Result:       audit.ResultDenied,
		DenialReason: "missing or malformed Authorization header",
	})

	var got map[string]any
	if err := json.NewDecoder(strings.NewReader(buf.String())).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["result"] != "denied" {
		t.Errorf("result: got %v", got["result"])
	}
	if got["denial_reason"] != "missing or malformed Authorization header" {
		t.Errorf("denial_reason: got %v", got["denial_reason"])
	}
	// Identity must serialise as JSON null when no Identity is
	// available, rather than being omitted: downstream queries
	// can then assert presence of the key without branching on
	// existence.
	id, ok := got["identity"]
	if !ok {
		t.Fatalf("identity key absent; expected JSON null")
	}
	if id != nil {
		t.Errorf("identity: got %v, want nil", id)
	}
}

func TestLogger_TokenSuccessHTTP(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	l := audit.NewLogger(&buf)
	exp := time.Unix(1700000900, 0).UTC()
	l.LogToken(context.Background(), audit.TokenEntry{
		Time: time.Unix(1700000000, 0).UTC(),
		Identity: &audit.IdentityRecord{
			Type:      "ci",
			Principal: "repo:owner/repo:ref:refs/heads/main",
			Claims:    map[string]any{"repository": "owner/repo"},
		},
		Destination:        "artifactory",
		Result:             audit.ResultSuccess,
		UpstreamURL:        "https://artifactory.example.com/access/api/v1/oidc/token",
		UpstreamStatus:     200,
		UpstreamDurationMS: 123,
		TokenExpiresAt:     &exp,
	})

	var got map[string]any
	if err := json.NewDecoder(strings.NewReader(buf.String())).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["event"] != "token" {
		t.Errorf("event: got %v", got["event"])
	}
	if got["upstream_status"].(float64) != 200 {
		t.Errorf("upstream_status: got %v", got["upstream_status"])
	}
	if got["upstream_duration_ms"].(float64) != 123 {
		t.Errorf("upstream_duration_ms: got %v", got["upstream_duration_ms"])
	}
}

// TestLogger_TokenSuccessStaticSecret confirms that destinations
// with no upstream call (the staticSecret type) leave the
// upstream_* fields omitted entirely from the JSON output rather
// than emitting zero values that would confuse downstream queries.
func TestLogger_TokenSuccessStaticSecret(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	l := audit.NewLogger(&buf)
	exp := time.Unix(1700003600, 0).UTC()
	l.LogToken(context.Background(), audit.TokenEntry{
		Time:           time.Unix(1700000000, 0).UTC(),
		Identity:       &audit.IdentityRecord{Type: "ci", Principal: "p", Claims: map[string]any{}},
		Destination:    "ghe-packages-pat",
		Result:         audit.ResultSuccess,
		TokenExpiresAt: &exp,
	})

	var got map[string]any
	if err := json.NewDecoder(strings.NewReader(buf.String())).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, key := range []string{"upstream_url", "upstream_status", "upstream_duration_ms", "upstream_response_excerpt"} {
		if _, ok := got[key]; ok {
			t.Errorf("expected key %q to be omitted, got %v", key, got[key])
		}
	}
}

// TestLogger_TokenFailureWithExcerpt verifies that an upstream
// rejection surfaces the response excerpt under
// upstream_response_excerpt so an audit-log reader can diagnose
// the failure without rerunning the request.
func TestLogger_TokenFailureWithExcerpt(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	l := audit.NewLogger(&buf)
	l.LogToken(context.Background(), audit.TokenEntry{
		Time:                    time.Unix(1700000000, 0).UTC(),
		Identity:                &audit.IdentityRecord{Type: "ci", Principal: "p", Claims: map[string]any{}},
		Destination:             "artifactory",
		Result:                  audit.ResultFailure,
		DenialReason:            "destination mint failed: response status 401",
		UpstreamURL:             "https://artifactory.example.com/token",
		UpstreamStatus:          401,
		UpstreamDurationMS:      45,
		UpstreamResponseExcerpt: `{"error":"unauthorized"}`,
	})

	var got map[string]any
	if err := json.NewDecoder(strings.NewReader(buf.String())).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["result"] != "failure" {
		t.Errorf("result: got %v", got["result"])
	}
	if got["upstream_response_excerpt"] != `{"error":"unauthorized"}` {
		t.Errorf("upstream_response_excerpt: got %v", got["upstream_response_excerpt"])
	}
}

// TestLogger_NilClaimsRendersEmptyObject covers the documented
// invariant that the identity.claims key is always a JSON object,
// never JSON null. This keeps downstream queries from having to
// special-case "absent" versus "no claims".
func TestLogger_NilClaimsRendersEmptyObject(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	l := audit.NewLogger(&buf)
	l.LogDelegate(context.Background(), audit.DelegateEntry{
		Time:     time.Unix(1700000000, 0).UTC(),
		Identity: &audit.IdentityRecord{Type: "ci", Principal: "p", Claims: nil},
		Result:   audit.ResultGranted,
	})
	// Inspect the raw JSON; a nil map without the materialising
	// step in the logger would marshal as JSON null.
	if !strings.Contains(buf.String(), `"claims":{}`) {
		t.Errorf("expected claims to render as empty object, got %s", buf.String())
	}
}

// TestLogger_OutputIsDeterministic guards against accidental
// reliance on map iteration order in the entry types. A schema
// change that introduces non-deterministic ordering would surface
// here as a divergence between two consecutive marshalings of the
// same input.
func TestLogger_OutputIsDeterministic(t *testing.T) {
	t.Parallel()
	entry := audit.DelegateEntry{
		Time: time.Unix(1700000000, 0).UTC(),
		Identity: &audit.IdentityRecord{
			Type:      "ci",
			Principal: "p",
			Claims: map[string]any{
				"a": "alpha", "b": "bravo", "c": "charlie",
				"d": "delta", "e": "echo",
			},
		},
		Result:              audit.ResultGranted,
		GrantedDestinations: []string{"alpha", "beta"},
	}
	const runs = 8
	var first string
	for i := 0; i < runs; i++ {
		var buf bytes.Buffer
		audit.NewLogger(&buf).LogDelegate(context.Background(), entry)
		if i == 0 {
			first = buf.String()
			continue
		}
		if buf.String() != first {
			t.Fatalf("run %d differs:\n  %s\nfirst:\n  %s", i, buf.String(), first)
		}
	}
}

// TestLogger_NilContextDoesNotPanic protects the handlers' habit
// of calling Log* with the request context unmodified: even
// pathological callers passing nil must not crash the broker.
func TestLogger_NilContextDoesNotPanic(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	l := audit.NewLogger(&buf)
	//nolint:staticcheck // SA1012: passing nil context is the behaviour under test
	l.LogDelegate(nil, audit.DelegateEntry{
		Time:     time.Unix(1700000000, 0).UTC(),
		Identity: &audit.IdentityRecord{Type: "ci", Principal: "p", Claims: map[string]any{}},
		Result:   audit.ResultGranted,
	})
	//nolint:staticcheck // SA1012
	l.LogToken(nil, audit.TokenEntry{
		Time:        time.Unix(1700000000, 0).UTC(),
		Identity:    &audit.IdentityRecord{Type: "ci", Principal: "p", Claims: map[string]any{}},
		Destination: "alpha",
		Result:      audit.ResultSuccess,
	})
	if buf.Len() == 0 {
		t.Errorf("expected two JSON lines, got nothing")
	}
}

// TestMintAuditContext exercises the context-installed MintAudit
// channel that destination implementations populate. The test is
// in the audit package's external test file rather than next to
// the destination because the audit package owns the type.
func TestMintAuditContext(t *testing.T) {
	t.Parallel()
	a := &audit.MintAudit{}
	ctx := audit.ContextWithMintAudit(context.Background(), a)
	if got := audit.MintAuditFromContext(ctx); got != a {
		t.Errorf("MintAuditFromContext: got %v, want %v", got, a)
	}
	// Nil context and a context without the value installed
	// must yield nil, not panic.
	if got := audit.MintAuditFromContext(context.Background()); got != nil {
		t.Errorf("absent value: got %v, want nil", got)
	}
	if got := audit.MintAuditFromContext(nil); got != nil { //nolint:staticcheck // SA1012
		t.Errorf("nil context: got %v, want nil", got)
	}
}

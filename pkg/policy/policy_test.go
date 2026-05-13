package policy_test

import (
	"maps"
	"slices"
	"strings"
	"testing"

	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/auth"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/policy"
)

// strp returns a pointer to its argument; it shortens otherwise
// repetitive Match-construction code in the table-driven tests.
func strp(s string) *string { return &s }

// ciIdentity returns an Identity that mimics what auth.ResolveIdentity
// would produce for a CI OIDC token, with the supplied claims map.
// Tests construct identities directly rather than going through
// ResolveIdentity to keep the test surface small.
func ciIdentity(principal string, claims map[string]any) *auth.Identity {
	enriched := map[string]any{}
	maps.Copy(enriched, claims)
	return &auth.Identity{
		Type:      auth.IdentityTypeCI,
		Principal: principal,
		Claims:    enriched,
	}
}

func userIdentity(principal string, claims map[string]any) *auth.Identity {
	enriched := map[string]any{}
	maps.Copy(enriched, claims)
	return &auth.Identity{
		Type:      auth.IdentityTypeUser,
		Principal: principal,
		Claims:    enriched,
	}
}

func TestNew_AcceptsValidConfig(t *testing.T) {
	t.Parallel()
	cfg := policy.Config{
		CI: []policy.Entry{
			{
				Match:               map[string]policy.Match{"claims.repository": {Glob: strp("owner/*")}},
				AllowedDestinations: []string{"alpha"},
			},
		},
		Users: []policy.Entry{
			{
				Match:               map[string]policy.Match{"claims.tier": {Equals: strp("internal")}},
				AllowedDestinations: []string{"alpha", "beta"},
			},
		},
	}
	if _, err := policy.New(cfg); err != nil {
		t.Fatalf("New: %v", err)
	}
}

func TestNew_RejectsEmptyEntry(t *testing.T) {
	t.Parallel()
	if _, err := policy.New(policy.Config{CI: []policy.Entry{{}}}); err == nil {
		t.Fatal("expected error for empty entry, got nil")
	}
}

func TestNew_RejectsUnknownFieldPathRoot(t *testing.T) {
	t.Parallel()
	cfg := policy.Config{
		CI: []policy.Entry{
			{
				Match:               map[string]policy.Match{"identity.principal": {Equals: strp("x")}},
				AllowedDestinations: []string{"alpha"},
			},
		},
	}
	_, err := policy.New(cfg)
	if err == nil {
		t.Fatal("expected error for unknown field path root, got nil")
	}
	if !strings.Contains(err.Error(), "principal, type, claims") {
		t.Errorf("error %q should hint at the supported roots", err.Error())
	}
}

func TestNew_RejectsClaimsWithoutSubField(t *testing.T) {
	t.Parallel()
	cfg := policy.Config{
		CI: []policy.Entry{
			{
				Match:               map[string]policy.Match{"claims": {Equals: strp("x")}},
				AllowedDestinations: []string{"alpha"},
			},
		},
	}
	if _, err := policy.New(cfg); err == nil {
		t.Fatal("expected error for bare 'claims' path, got nil")
	}
}

func TestNew_RejectsPrincipalWithSubField(t *testing.T) {
	t.Parallel()
	cfg := policy.Config{
		CI: []policy.Entry{
			{
				Match:               map[string]policy.Match{"principal.foo": {Equals: strp("x")}},
				AllowedDestinations: []string{"alpha"},
			},
		},
	}
	if _, err := policy.New(cfg); err == nil {
		t.Fatal("expected error for 'principal.foo' path, got nil")
	}
}

func TestNew_RejectsNoOperator(t *testing.T) {
	t.Parallel()
	cfg := policy.Config{
		CI: []policy.Entry{
			{
				Match:               map[string]policy.Match{"principal": {}},
				AllowedDestinations: []string{"alpha"},
			},
		},
	}
	_, err := policy.New(cfg)
	if err == nil {
		t.Fatal("expected error for missing operator, got nil")
	}
	if !strings.Contains(err.Error(), "no operator set") {
		t.Errorf("error %q lacks expected wording", err.Error())
	}
}

func TestNew_RejectsMultipleOperators(t *testing.T) {
	t.Parallel()
	cfg := policy.Config{
		CI: []policy.Entry{
			{
				Match: map[string]policy.Match{
					"claims.foo": {Equals: strp("x"), Glob: strp("y/*")},
				},
				AllowedDestinations: []string{"alpha"},
			},
		},
	}
	_, err := policy.New(cfg)
	if err == nil {
		t.Fatal("expected error for multiple operators, got nil")
	}
	if !strings.Contains(err.Error(), "multiple operators") {
		t.Errorf("error %q lacks expected wording", err.Error())
	}
}

func TestNew_RejectsMalformedGlob(t *testing.T) {
	t.Parallel()
	cfg := policy.Config{
		CI: []policy.Entry{
			{
				Match:               map[string]policy.Match{"claims.repository": {Glob: strp("[unterminated")}},
				AllowedDestinations: []string{"alpha"},
			},
		},
	}
	if _, err := policy.New(cfg); err == nil {
		t.Fatal("expected error for malformed glob, got nil")
	}
}

func TestEngine_EqualsOperator(t *testing.T) {
	t.Parallel()
	eng := mustEngine(t, policy.Config{
		Users: []policy.Entry{
			{
				Match:               map[string]policy.Match{"principal": {Equals: strp("user@example.com")}},
				AllowedDestinations: []string{"alpha"},
			},
		},
	})

	if got, _ := eng.Resolve(userIdentity("user@example.com", nil)); !slices.Equal(got, []string{"alpha"}) {
		t.Errorf("matching principal: got %v, want [alpha]", got)
	}
	if got, _ := eng.Resolve(userIdentity("other@example.com", nil)); len(got) != 0 {
		t.Errorf("non-matching principal: got %v, want empty", got)
	}
}

func TestEngine_GlobOperator(t *testing.T) {
	t.Parallel()
	eng := mustEngine(t, policy.Config{
		CI: []policy.Entry{
			{
				Match:               map[string]policy.Match{"claims.repository": {Glob: strp("owner/*")}},
				AllowedDestinations: []string{"alpha"},
			},
		},
	})

	for _, repo := range []string{"owner/repo", "owner/another", "owner/x"} {
		got, _ := eng.Resolve(ciIdentity("p", map[string]any{"repository": repo}))
		if !slices.Equal(got, []string{"alpha"}) {
			t.Errorf("repo=%q: got %v, want [alpha]", repo, got)
		}
	}
	got, _ := eng.Resolve(ciIdentity("p", map[string]any{"repository": "other/repo"}))
	if len(got) != 0 {
		t.Errorf("non-matching repo: got %v, want empty", got)
	}
}

func TestEngine_InOperator(t *testing.T) {
	t.Parallel()
	eng := mustEngine(t, policy.Config{
		CI: []policy.Entry{
			{
				Match: map[string]policy.Match{
					"claims.environment": {In: []string{"prod", "staging"}},
				},
				AllowedDestinations: []string{"alpha"},
			},
		},
	})

	for _, env := range []string{"prod", "staging"} {
		got, _ := eng.Resolve(ciIdentity("p", map[string]any{"environment": env}))
		if !slices.Equal(got, []string{"alpha"}) {
			t.Errorf("env=%q: got %v, want [alpha]", env, got)
		}
	}
	got, _ := eng.Resolve(ciIdentity("p", map[string]any{"environment": "dev"}))
	if len(got) != 0 {
		t.Errorf("env=dev: got %v, want empty", got)
	}
}

func TestEngine_FirstMatchWins(t *testing.T) {
	t.Parallel()
	// The specific entry for owner/repo appears before the
	// wildcard catch-all; owner/repo must receive the more
	// permissive grant rather than the catch-all's grant.
	eng := mustEngine(t, policy.Config{
		CI: []policy.Entry{
			{
				Match:               map[string]policy.Match{"claims.repository": {Equals: strp("owner/repo")}},
				AllowedDestinations: []string{"alpha", "beta"},
			},
			{
				Match:               map[string]policy.Match{"claims.repository": {Glob: strp("owner/*")}},
				AllowedDestinations: []string{"alpha"},
			},
		},
	})

	got, _ := eng.Resolve(ciIdentity("p", map[string]any{"repository": "owner/repo"}))
	if !slices.Equal(got, []string{"alpha", "beta"}) {
		t.Errorf("specific match: got %v, want [alpha beta]", got)
	}
	got, _ = eng.Resolve(ciIdentity("p", map[string]any{"repository": "owner/another"}))
	if !slices.Equal(got, []string{"alpha"}) {
		t.Errorf("catch-all: got %v, want [alpha]", got)
	}
}

func TestEngine_AllChecksInEntryMustPass(t *testing.T) {
	t.Parallel()
	// An entry with two checks requires both to pass.
	eng := mustEngine(t, policy.Config{
		CI: []policy.Entry{
			{
				Match: map[string]policy.Match{
					"claims.repository": {Glob: strp("owner/*")},
					"principal":         {Equals: strp("svc-account-alpha")},
				},
				AllowedDestinations: []string{"alpha"},
			},
		},
	})

	matching := ciIdentity("svc-account-alpha", map[string]any{"repository": "owner/repo"})
	if got, _ := eng.Resolve(matching); !slices.Equal(got, []string{"alpha"}) {
		t.Errorf("both checks pass: got %v, want [alpha]", got)
	}

	repoOnly := ciIdentity("different-account", map[string]any{"repository": "owner/repo"})
	if got, _ := eng.Resolve(repoOnly); len(got) != 0 {
		t.Errorf("only repository matches: got %v, want empty", got)
	}
}

func TestEngine_EmptyMatchIsCatchAll(t *testing.T) {
	t.Parallel()
	eng := mustEngine(t, policy.Config{
		CI: []policy.Entry{
			{
				Match:               map[string]policy.Match{"claims.repository": {Equals: strp("owner/repo")}},
				AllowedDestinations: []string{"alpha", "beta"},
			},
			{AllowedDestinations: []string{"alpha"}},
		},
	})

	if got, _ := eng.Resolve(ciIdentity("p", map[string]any{"repository": "owner/repo"})); !slices.Equal(got, []string{"alpha", "beta"}) {
		t.Errorf("specific match: got %v, want [alpha beta]", got)
	}
	if got, _ := eng.Resolve(ciIdentity("p", map[string]any{"repository": "anyone/anything"})); !slices.Equal(got, []string{"alpha"}) {
		t.Errorf("catch-all: got %v, want [alpha]", got)
	}
}

func TestEngine_EmptyEqualsIsValidOperand(t *testing.T) {
	t.Parallel()
	// An empty string is a valid operand: it matches an
	// identity whose claim is empty (or absent, treated as
	// missing rather than empty by ResolvePath).
	empty := ""
	eng := mustEngine(t, policy.Config{
		Users: []policy.Entry{
			{
				Match:               map[string]policy.Match{"claims.tier": {Equals: &empty}},
				AllowedDestinations: []string{"alpha"},
			},
		},
	})

	got, _ := eng.Resolve(userIdentity("u@e.com", map[string]any{"tier": ""}))
	if !slices.Equal(got, []string{"alpha"}) {
		t.Errorf("empty equals empty: got %v, want [alpha]", got)
	}
	// A missing claim is not equal to the empty string; the
	// path resolution returns ok=false and the check fails.
	if got, _ := eng.Resolve(userIdentity("u@e.com", nil)); len(got) != 0 {
		t.Errorf("missing claim: got %v, want empty", got)
	}
}

func TestEngine_IdentityTypeIsolation(t *testing.T) {
	t.Parallel()
	eng := mustEngine(t, policy.Config{
		CI: []policy.Entry{
			{
				Match:               map[string]policy.Match{"claims.repository": {Glob: strp("owner/*")}},
				AllowedDestinations: []string{"alpha"},
			},
		},
		Users: []policy.Entry{
			{
				Match:               map[string]policy.Match{"claims.tier": {Equals: strp("internal")}},
				AllowedDestinations: []string{"beta"},
			},
		},
	})

	if got, _ := eng.Resolve(ciIdentity("p", map[string]any{"repository": "owner/repo"})); !slices.Equal(got, []string{"alpha"}) {
		t.Errorf("ci identity: got %v, want [alpha]", got)
	}
	if got, _ := eng.Resolve(userIdentity("u@e.com", map[string]any{"tier": "internal"})); !slices.Equal(got, []string{"beta"}) {
		t.Errorf("user identity: got %v, want [beta]", got)
	}
}

func TestEngine_MissingClaimDoesNotMatch(t *testing.T) {
	t.Parallel()
	eng := mustEngine(t, policy.Config{
		CI: []policy.Entry{
			{
				Match:               map[string]policy.Match{"claims.absent": {Equals: strp("anything")}},
				AllowedDestinations: []string{"alpha"},
			},
		},
	})
	if got, _ := eng.Resolve(ciIdentity("p", nil)); len(got) != 0 {
		t.Errorf("missing claim: got %v, want empty", got)
	}
}

func TestEngine_RejectsNilIdentity(t *testing.T) {
	t.Parallel()
	eng := mustEngine(t, policy.Config{})
	if _, err := eng.Resolve(nil); err == nil {
		t.Fatal("expected error for nil identity, got nil")
	}
}

func TestEngine_RejectsUnknownIdentityType(t *testing.T) {
	t.Parallel()
	eng := mustEngine(t, policy.Config{})
	id := &auth.Identity{Type: auth.IdentityType("alien"), Principal: "x"}
	if _, err := eng.Resolve(id); err == nil {
		t.Fatal("expected error for unknown identity type, got nil")
	}
}

func TestEngine_DefaultDenyOnNoMatch(t *testing.T) {
	t.Parallel()
	eng := mustEngine(t, policy.Config{
		CI: []policy.Entry{
			{
				Match:               map[string]policy.Match{"claims.repository": {Glob: strp("owner/*")}},
				AllowedDestinations: []string{"alpha"},
			},
		},
	})
	got, _ := eng.Resolve(ciIdentity("p", map[string]any{"repository": "other/repo"}))
	if len(got) != 0 {
		t.Errorf("got %v, want empty", got)
	}
}

func TestResolvePath_AllForms(t *testing.T) {
	t.Parallel()
	id := &auth.Identity{
		Type:      auth.IdentityTypeCI,
		Principal: "the-principal",
		Claims: map[string]any{
			"repository": "owner/repo",
			"nested":     map[string]any{"key": "deep-value"},
			"non_string": 42,
		},
	}
	tests := []struct {
		path string
		want string
		ok   bool
	}{
		{path: "principal", want: "the-principal", ok: true},
		{path: "type", want: "ci", ok: true},
		{path: "claims.repository", want: "owner/repo", ok: true},
		{path: "claims.nested.key", want: "deep-value", ok: true},
		{path: "claims.absent", ok: false},
		{path: "claims.non_string", ok: false}, // non-string value does not resolve
		{path: "claims.repository.too.deep", ok: false},
		{path: "unknown_root", ok: false},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			t.Parallel()
			got, ok := policy.ResolvePath(id, tc.path)
			if ok != tc.ok {
				t.Fatalf("ok: got %v, want %v", ok, tc.ok)
			}
			if ok && got != tc.want {
				t.Errorf("value: got %q, want %q", got, tc.want)
			}
		})
	}
}

// mustEngine constructs an Engine from cfg, failing the test on
// configuration errors.
func mustEngine(t *testing.T, cfg policy.Config) policy.Engine {
	t.Helper()
	eng, err := policy.New(cfg)
	if err != nil {
		t.Fatalf("policy.New: %v", err)
	}
	return eng
}

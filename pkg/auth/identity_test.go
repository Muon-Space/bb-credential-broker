package auth_test

import (
	"strings"
	"testing"

	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/auth"
)

func TestResolveIdentity_CI(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		claims            map[string]any
		wantPrincipal     string
		wantErrorContains string
	}{
		{
			name: "uses sub as principal",
			claims: map[string]any{
				"sub": "repo:owner/repo:ref:refs/heads/main",
				"iss": "https://token.actions.example.com",
			},
			wantPrincipal: "repo:owner/repo:ref:refs/heads/main",
		},
		{
			name: "preserves arbitrary claims",
			claims: map[string]any{
				"sub":        "service-account-name@example.com",
				"repository": "owner/repo",
				"ref":        "refs/heads/main",
			},
			wantPrincipal: "service-account-name@example.com",
		},
		{
			name:              "missing sub is rejected",
			claims:            map[string]any{},
			wantErrorContains: "no string sub claim",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			id, err := auth.ResolveIdentity(auth.IdentityTypeCI, tc.claims)
			if tc.wantErrorContains != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.wantErrorContains)
				}
				if !strings.Contains(err.Error(), tc.wantErrorContains) {
					t.Fatalf("expected error containing %q, got %q", tc.wantErrorContains, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if id.Principal != tc.wantPrincipal {
				t.Errorf("principal: got %q, want %q", id.Principal, tc.wantPrincipal)
			}
		})
	}
}

func TestResolveIdentity_PreservesAllClaimsVerbatim(t *testing.T) {
	t.Parallel()
	in := map[string]any{
		"sub":        "service",
		"repository": "owner/repo",
		"actor":      "alice",
		"any":        "value",
	}
	id, err := auth.ResolveIdentity(auth.IdentityTypeCI, in)
	if err != nil {
		t.Fatalf("ResolveIdentity: %v", err)
	}
	for k, v := range in {
		if id.Claims[k] != v {
			t.Errorf("claim %q: got %v, want %v", k, id.Claims[k], v)
		}
	}
	// The broker does not invent synthetic claims.
	if len(id.Claims) != len(in) {
		t.Errorf("claims map has %d entries, want %d (no synthetic claims)", len(id.Claims), len(in))
	}
}

func TestResolveIdentity_User(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		claims            map[string]any
		wantPrincipal     string
		wantErrorContains string
	}{
		{
			name: "explicit email claim",
			claims: map[string]any{
				"sub":   "internal-id-12345",
				"email": "user@example.com",
			},
			wantPrincipal: "user@example.com",
		},
		{
			name: "fallback to sub when no email",
			claims: map[string]any{
				"sub": "user@example.com",
			},
			wantPrincipal: "user@example.com",
		},
		{
			name:              "rejects token with neither sub nor email",
			claims:            map[string]any{"foo": "bar"},
			wantErrorContains: "neither email nor sub",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			id, err := auth.ResolveIdentity(auth.IdentityTypeUser, tc.claims)
			if tc.wantErrorContains != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.wantErrorContains)
				}
				if !strings.Contains(err.Error(), tc.wantErrorContains) {
					t.Fatalf("expected error containing %q, got %q", tc.wantErrorContains, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if id.Principal != tc.wantPrincipal {
				t.Errorf("principal: got %q, want %q", id.Principal, tc.wantPrincipal)
			}
		})
	}
}

func TestResolveIdentity_DefensiveCopy(t *testing.T) {
	t.Parallel()
	// Mutating the returned Identity's Claims must not affect
	// the caller's input map.
	in := map[string]any{"sub": "x"}
	id, err := auth.ResolveIdentity(auth.IdentityTypeCI, in)
	if err != nil {
		t.Fatalf("ResolveIdentity: %v", err)
	}
	id.Claims["new"] = "value"
	if _, ok := in["new"]; ok {
		t.Error("mutation of returned claims leaked into caller's map")
	}
}

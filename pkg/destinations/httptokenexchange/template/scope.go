package template

import (
	"context"
	"fmt"
	"time"

	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/auth"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/secrets"
)

// Scope is the per-evaluation context passed to every chunk during
// Template.Eval. It carries the resolved Identity, the secret
// loader, the clock, and the registries of built-in functions.
//
// A Scope is constructed once per /token request: the Identity is
// the snapshot stored against the nonce, Secrets is the loader
// configured at start-up, and Now is overridden in tests.
type Scope struct {
	// Identity is the resolved caller. Variable references of the
	// form ${identity.PATH} read from this value's exported
	// fields and Claims map.
	Identity *auth.Identity

	// Secrets resolves named secret references emitted by the
	// ${secret:NAME} function.
	Secrets secrets.Loader

	// NamedSecrets binds operator-chosen secret names (the keys
	// of the configuration's secrets section) to SecretRefs. The
	// ${secret:NAME} function looks names up here.
	NamedSecrets map[string]secrets.SecretRef

	// Now returns the current time. Tests may substitute this to
	// produce stable output.
	Now func() time.Time

	// Funcs is the registry of built-in functions. Use
	// DefaultFuncs to obtain the standard set; tests may add or
	// override entries to inject mock behaviour.
	Funcs map[string]Func

	// LazyFuncs is the registry of built-in functions that need
	// access to their unevaluated argument templates — typically
	// because they implement error-tolerant evaluation rules
	// (${default:EXPR:fallback}). The dispatcher checks
	// LazyFuncs before Funcs so a name registered in both maps
	// resolves to the lazy form; in practice the two registries
	// have disjoint keys.
	LazyFuncs map[string]LazyFunc
}

// Func is the signature implemented by every built-in function that
// evaluates its arguments eagerly. Implementations should fail
// loudly on argument-shape errors and return early for transient
// runtime errors so the surrounding /token handler can surface a
// meaningful HTTP status.
type Func func(ctx context.Context, scope *Scope, args []string) (string, error)

// LazyFunc is the signature implemented by built-in functions that
// take responsibility for evaluating their own arguments. The
// dispatcher passes the parsed argument templates directly; the
// function decides when (or whether) to call Template.Eval on each.
// This is the mechanism that lets ${default:EXPR:fallback} swallow
// a failure from EXPR and substitute the fallback expression.
type LazyFunc func(ctx context.Context, scope *Scope, args []*Template) (string, error)

// DefaultScope constructs a Scope wired with the default function
// registries. Callers typically do not need to override the function
// maps; tests do so to inject deterministic behaviour for ${file:},
// ${secret:} and ${signjwt:}.
func DefaultScope(identity *auth.Identity, ldr secrets.Loader, named map[string]secrets.SecretRef) *Scope {
	return &Scope{
		Identity:     identity,
		Secrets:      ldr,
		NamedSecrets: named,
		Now:          time.Now,
		Funcs:        DefaultFuncs(),
		LazyFuncs:    DefaultLazyFuncs(),
	}
}

// lookupRoot resolves the head of a variable reference path to the
// underlying value. The supported roots are "identity" (which
// returns a map view of the caller Identity, including a "claims"
// sub-map) and any other identifier the caller has injected by
// pre-populating Funcs with a constant-returning function.
//
// Unknown roots are reported as an error.
func (s *Scope) lookupRoot(name string) (any, error) {
	switch name {
	case "identity":
		if s.Identity == nil {
			return nil, fmt.Errorf("template: ${identity.*} requires a resolved identity")
		}
		return map[string]any{
			"type":      string(s.Identity.Type),
			"principal": s.Identity.Principal,
			"claims":    map[string]any(s.Identity.Claims),
		}, nil
	default:
		return nil, fmt.Errorf("template: unknown variable root %q", name)
	}
}

// Package destinations defines the interface implemented by every
// configured credential-mint destination, the registry that holds
// the running set of destination instances, and the dispatch logic
// that maps the operator-supplied configuration to the underlying
// destination type implementations.
//
// The broker ships two destination types: httpTokenExchange, which
// expresses every mint flow as a templated HTTP request, and
// staticSecret, which dispenses a credential read from a file on
// disk for systems whose API does not expose an OIDC exchange. New
// types are added by appending a new case to BuildRegistry and a
// new sub-package under destinations/.
package destinations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/auth"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/destinations/httptokenexchange"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/destinations/staticsecret"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/metrics"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/secrets"
)

// Destination is the interface implemented by every concrete
// destination type. A single Destination instance corresponds to one
// named entry in the operator's configuration.
//
// Implementations must be safe for concurrent use; the /token
// handler dispatches to the same instance for every request to a
// given destination name.
type Destination interface {
	// Mint produces a fresh token for the supplied identity. The
	// returned Token's Value is the raw token string suitable for
	// inclusion in an Authorization header or equivalent;
	// ExpiresAt records when the token ceases to be valid.
	Mint(ctx context.Context, identity *auth.Identity) (*Token, error)
}

// Renderable is the optional contract a Destination implements
// when the broker can dry-run its outbound HTTP request without
// dispatching it. The `bb-credential-broker render` subcommand
// type-asserts every looked-up destination against this
// interface; destinations that mint locally (staticSecret)
// return ErrNotRenderable.
type Renderable interface {
	Destination

	// RenderRequest builds the *http.Request the destination
	// would send to its upstream when Mint is invoked with the
	// supplied identity, without actually dispatching it.
	// Implementations evaluate templates, build the body and
	// headers, and return the populated request so an operator
	// can inspect it offline. Errors propagate any template or
	// build failure the operator should see.
	RenderRequest(ctx context.Context, identity *auth.Identity) (*http.Request, error)
}

// ErrNotRenderable is the sentinel destination implementations
// return from RenderRequest when their mint flow does not
// correspond to a single outbound HTTP request (the staticSecret
// type, which simply reads bytes from disk). The render
// subcommand maps the sentinel to a friendly operator-facing
// message rather than printing it as a generic error.
var ErrNotRenderable = errors.New("destination is not renderable as an HTTP request")

// Token is the credential returned by Destination.Mint. It is also
// the payload of /token's HTTP response.
type Token struct {
	// Value is the raw token string.
	Value string

	// ExpiresAt is the absolute time after which the token is
	// expected to be rejected by the destination service. The
	// broker propagates this to the worker so the worker can
	// avoid refresh storms.
	ExpiresAt time.Time

	// Scheme indicates how the token is conventionally presented
	// to the destination service (e.g. "bearer"). The broker
	// passes this through verbatim; downstream tools may use it
	// to construct the appropriate Authorization header.
	Scheme string

	// Username is the basic-auth username paired with Value when
	// Scheme is "basic". It is empty for bearer-token destinations
	// and is set by destination types whose target service expects
	// a username (typically the static-secret type when dispensing
	// a personal access token to git or an OCI registry, where
	// the convention is to use a placeholder such as
	// "x-access-token").
	Username string
}

// Registry holds the constructed Destinations keyed by the operator-
// chosen name.
type Registry map[string]Destination

// Lookup returns the Destination registered under name, or nil if no
// such destination exists.
func (r Registry) Lookup(name string) Destination {
	return r[name]
}

// Dependencies bundles the shared services that destination types
// may need at construction or mint time. Adding a new type-wide
// service to the broker means adding a field here and threading it
// through BuildRegistry.
type Dependencies struct {
	// Secrets resolves runtime secret references emitted by
	// templated requests via the ${secret:NAME} function.
	Secrets secrets.Loader

	// NamedSecrets binds operator-chosen secret names to their
	// SecretRefs. The httpTokenExchange templating engine reads
	// from this map at evaluation time.
	NamedSecrets map[string]secrets.SecretRef

	// Metrics, when non-nil, is used to record per-destination
	// mint counters and latency histograms. Tests typically pass
	// nil here.
	Metrics *metrics.Metrics
}

// BuildRegistry constructs a Registry from the configuration's
// destinations map and the supplied Dependencies. Each entry is
// dispatched to the appropriate type constructor and wrapped in
// the standard metrics middleware.
//
// BuildRegistry surfaces every per-destination construction error
// with the destination name as a prefix so that misconfigured
// entries can be located without further log diving.
func BuildRegistry(raw map[string]json.RawMessage, deps Dependencies) (Registry, error) {
	out := make(Registry, len(raw))
	for name, msg := range raw {
		d, err := buildOne(name, msg, deps)
		if err != nil {
			return nil, fmt.Errorf("destinations[%q]: %w", name, err)
		}
		out[name] = &instrumentedDestination{
			name:    name,
			inner:   d,
			metrics: deps.Metrics,
		}
	}
	return out, nil
}

// destinationConfig is the discriminated-union envelope carried in
// each destinations entry of the operator's configuration. Adding a
// new destination type means adding a new field here and a new case
// in buildOne.
type destinationConfig struct {
	HTTPTokenExchange *httptokenexchange.Config `json:"httpTokenExchange,omitempty"`
	StaticSecret      *staticsecret.Config      `json:"staticSecret,omitempty"`
}

// buildOne dispatches a single destinations entry to the appropriate
// type constructor and wraps the returned implementation in the
// adapter required to satisfy Destination.
func buildOne(name string, msg json.RawMessage, deps Dependencies) (Destination, error) {
	dec := json.NewDecoder(bytesReader(msg))
	dec.DisallowUnknownFields()
	var cfg destinationConfig
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	switch {
	case cfg.HTTPTokenExchange != nil && cfg.StaticSecret != nil:
		return nil, fmt.Errorf("multiple destination type discriminators set; expected exactly one")
	case cfg.HTTPTokenExchange != nil:
		impl, err := httptokenexchange.New(name, cfg.HTTPTokenExchange, httptokenexchange.Dependencies{
			Secrets:      deps.Secrets,
			NamedSecrets: deps.NamedSecrets,
		})
		if err != nil {
			return nil, err
		}
		return &httpTokenExchangeAdapter{impl: impl}, nil
	case cfg.StaticSecret != nil:
		impl, err := staticsecret.New(name, cfg.StaticSecret)
		if err != nil {
			return nil, err
		}
		return &staticSecretAdapter{impl: impl}, nil
	default:
		return nil, fmt.Errorf("no destination type discriminator set; expected one of: httpTokenExchange, staticSecret")
	}
}

// httpTokenExchangeAdapter converts the package-internal Token shape
// returned by httptokenexchange.Impl.Mint into the public Token type
// declared by Destination. The adapter keeps httptokenexchange free
// of any dependency on its parent package, which would otherwise
// form an import cycle.
type httpTokenExchangeAdapter struct {
	impl *httptokenexchange.Impl
}

func (a *httpTokenExchangeAdapter) Mint(ctx context.Context, identity *auth.Identity) (*Token, error) {
	t, err := a.impl.Mint(ctx, identity)
	if err != nil {
		return nil, err
	}
	scheme := t.Scheme
	if scheme == "" {
		scheme = "bearer"
	}
	return &Token{
		Value:     t.Value,
		ExpiresAt: t.ExpiresAt,
		Scheme:    scheme,
	}, nil
}

// RenderRequest implements Renderable for httpTokenExchange.
// Returns the *http.Request the destination would dispatch to
// its upstream when invoked with identity, without dispatching it.
func (a *httpTokenExchangeAdapter) RenderRequest(ctx context.Context, identity *auth.Identity) (*http.Request, error) {
	return a.impl.RenderRequest(ctx, identity)
}

// staticSecretAdapter converts the package-internal Token shape
// returned by staticsecret.Impl.Mint into the public Token type.
// Mirrors httpTokenExchangeAdapter; the indirection exists for the
// same import-cycle reason.
type staticSecretAdapter struct {
	impl *staticsecret.Impl
}

func (a *staticSecretAdapter) Mint(ctx context.Context, identity *auth.Identity) (*Token, error) {
	t, err := a.impl.Mint(ctx, identity)
	if err != nil {
		return nil, err
	}
	return &Token{
		Value:     t.Value,
		ExpiresAt: t.ExpiresAt,
		Scheme:    t.Scheme,
		Username:  t.Username,
	}, nil
}

// RenderRequest implements Renderable for staticSecret. The
// destination performs no upstream HTTP request — it just reads a
// file — so the sentinel is the operator-facing signal that
// `bb-credential-broker render` cannot show an HTTP request for
// this destination type.
func (a *staticSecretAdapter) RenderRequest(_ context.Context, _ *auth.Identity) (*http.Request, error) {
	return nil, ErrNotRenderable
}

// instrumentedDestination wraps an inner Destination with
// per-destination Prometheus counters and a duration histogram. The
// middleware is applied to every Destination produced by
// BuildRegistry so that operators see consistent metrics regardless
// of which destination type is in use.
type instrumentedDestination struct {
	name    string
	inner   Destination
	metrics *metrics.Metrics
}

func (d *instrumentedDestination) Mint(ctx context.Context, identity *auth.Identity) (*Token, error) {
	start := time.Now()
	tok, err := d.inner.Mint(ctx, identity)
	d.metrics.RecordMint(d.name, err, time.Since(start))
	return tok, err
}

// RenderRequest forwards to the inner destination's Renderable
// implementation. The metrics middleware does not record render
// calls because they are an operator-side dry-run path, not
// production mint traffic.
func (d *instrumentedDestination) RenderRequest(ctx context.Context, identity *auth.Identity) (*http.Request, error) {
	r, ok := d.inner.(Renderable)
	if !ok {
		return nil, ErrNotRenderable
	}
	return r.RenderRequest(ctx, identity)
}

// Package destinations defines the interface implemented by every
// configured credential-mint destination, the registry that holds
// the running set of destination instances, and the dispatch logic
// that maps the operator-supplied configuration to the underlying
// destination type implementations.
//
// The broker ships a single destination type, httpTokenExchange,
// that expresses every mint flow as a templated HTTP request. New
// types are added by appending a new case to BuildRegistry and a
// new sub-package under destinations/.
package destinations

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/auth"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/destinations/httptokenexchange"
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
	case cfg.HTTPTokenExchange != nil:
		impl, err := httptokenexchange.New(name, cfg.HTTPTokenExchange, httptokenexchange.Dependencies{
			Secrets:      deps.Secrets,
			NamedSecrets: deps.NamedSecrets,
		})
		if err != nil {
			return nil, err
		}
		return &httpTokenExchangeAdapter{impl: impl}, nil
	default:
		return nil, fmt.Errorf("no destination type discriminator set; expected one of: httpTokenExchange")
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

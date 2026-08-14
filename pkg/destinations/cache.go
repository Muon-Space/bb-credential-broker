package destinations

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/Muon-Space/bb-credential-broker/pkg/auth"
)

// cacheRefreshSkew is how long before a cached token's reported
// expiry the cache treats it as stale and re-mints. It absorbs
// clock skew between the broker and the destination service and
// the latency of the request that will carry the credential. The
// value is sized well below the refresh skew used by client-side
// caches because the tokens cached here can be as short-lived as
// 60 seconds in total; a larger skew would consume most of the
// usable window.
const cacheRefreshSkew = 5 * time.Second

// cachedDestination wraps a Destination whose mint flow is
// identity-invariant, memoising the most recently minted Token
// until shortly before its reported expiry.
//
// The wrapper is only sound for destinations whose Mint result
// does not depend on the calling Identity: every caller receives
// the same cached Token, and on a cache miss the mint is performed
// under whichever caller's identity and context arrived first.
// BuildRegistry applies it to the destination types that satisfy
// this property (registryTokenExchange, whose exchange
// authenticates with a fixed operator-supplied credential); it is
// never applied to identity-templated destinations.
//
// Concurrent misses are de-duplicated with the same
// mutex-plus-WaitGroup pattern the egress sidecar's client-side
// token cache uses: the first caller to observe a stale cache
// performs the mint while later callers wait on it and then
// re-read the cache, so a burst of /token requests for one
// destination produces a single upstream call. A Token whose
// ExpiresAt is zero is dispensed but never stored, because a
// credential with no reported lifetime cannot be cached safely.
//
// Cached Token values are shared across callers and must not be
// mutated after Mint returns.
type cachedDestination struct {
	inner Destination
	now   func() time.Time

	mu        sync.Mutex
	cached    *Token
	refreshAt time.Time
	inflight  *sync.WaitGroup
}

// newCachedDestination wraps inner in a cachedDestination. The
// caller is responsible for ensuring inner's mint flow is
// identity-invariant; see the type comment.
func newCachedDestination(inner Destination) *cachedDestination {
	return &cachedDestination{
		inner: inner,
		now:   time.Now,
	}
}

// Mint implements Destination. A fresh cached Token is returned
// without touching the inner destination; otherwise the inner mint
// runs (de-duplicated across concurrent callers) and its result is
// cached until cacheRefreshSkew before the reported expiry.
//
// On a cache hit no upstream call occurs, so any MintAudit
// installed in ctx is left unpopulated and the audit-log entry
// omits the upstream_* fields, the same way destinations that
// never perform an upstream call do.
func (c *cachedDestination) Mint(ctx context.Context, identity *auth.Identity) (*Token, error) {
	c.mu.Lock()
	if tok, ok := c.freshLocked(); ok {
		c.mu.Unlock()
		return tok, nil
	}
	if wg := c.inflight; wg != nil {
		c.mu.Unlock()
		wg.Wait()
		c.mu.Lock()
		if tok, ok := c.freshLocked(); ok {
			c.mu.Unlock()
			return tok, nil
		}
		// The in-flight mint failed or produced a still-stale
		// entry; fall through and mint ourselves.
	}
	wg := &sync.WaitGroup{}
	wg.Add(1)
	c.inflight = wg
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		c.inflight = nil
		c.mu.Unlock()
		wg.Done()
	}()

	tok, err := c.inner.Mint(ctx, identity)
	if err != nil {
		return nil, err
	}
	if tok.ExpiresAt.IsZero() {
		return tok, nil
	}

	c.mu.Lock()
	c.cached = tok
	c.refreshAt = tok.ExpiresAt.Add(-cacheRefreshSkew)
	c.mu.Unlock()
	return tok, nil
}

// freshLocked returns the cached Token and true when one exists
// and has not yet reached its refresh instant. Callers must hold
// c.mu.
func (c *cachedDestination) freshLocked() (*Token, bool) {
	if c.cached != nil && c.now().Before(c.refreshAt) {
		return c.cached, true
	}
	return nil, false
}

// RenderRequest forwards to the inner destination's Renderable
// implementation. Rendering is an operator-side dry-run path and
// never consults or populates the cache.
func (c *cachedDestination) RenderRequest(ctx context.Context, identity *auth.Identity) (*http.Request, error) {
	r, ok := c.inner.(Renderable)
	if !ok {
		return nil, ErrNotRenderable
	}
	return r.RenderRequest(ctx, identity)
}

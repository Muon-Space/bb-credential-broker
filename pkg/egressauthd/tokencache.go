package egressauthd

import (
	"context"
	"sync"
	"time"
)

// refreshSkew is how long before a cached credential's reported expiry
// the cache treats it as stale and re-mints. It absorbs clock skew
// between the sidecar and the destination service and the latency of
// the in-flight request that will carry the credential.
const refreshSkew = 30 * time.Second

// defaultTokenTTL is the lifetime the cache assumes when the broker
// reports no expiry. It is deliberately short so a credential whose
// real lifetime is unknown is re-minted often rather than used past a
// silent expiry.
const defaultTokenTTL = 5 * time.Minute

// cacheKey identifies a cached credential. A credential is scoped to
// both the action (so two builds never share a token) and the BROKER
// destination (so a build's token for one destination is distinct from
// its token for another). Keying on the broker destination — not the
// per-tool loopback prefix — means several tool routes that share one
// broker destination (registry pypi/cargo/docker -> "registry") reuse a
// single minted token rather than minting one per tool.
type cacheKey struct {
	actionID    string
	destination string // broker destination
}

// cachedToken is a stored credential plus the absolute time at which
// the cache should re-mint it.
type cachedToken struct {
	token     *MintedToken
	refreshAt time.Time
}

// tokenCache memoises broker mints per (action, destination),
// re-minting a credential shortly before its reported expiry. It is
// safe for concurrent use; concurrent misses for the same key are
// de-duplicated so a burst of action requests to a cold host produces a
// single broker mint.
type tokenCache struct {
	broker  BrokerClient
	metrics *Metrics
	now     func() time.Time

	mu      sync.Mutex
	entries map[cacheKey]*cachedToken
	// inflight de-duplicates concurrent misses for the same key.
	inflight map[cacheKey]*sync.WaitGroup
}

// newTokenCache constructs a tokenCache backed by broker.
func newTokenCache(broker BrokerClient, metrics *Metrics) *tokenCache {
	return &tokenCache{
		broker:   broker,
		metrics:  metrics,
		now:      time.Now,
		entries:  map[cacheKey]*cachedToken{},
		inflight: map[cacheKey]*sync.WaitGroup{},
	}
}

// Get returns a non-expired credential for the action's BROKER
// destination, minting one via the broker if the cache is cold or the
// cached credential is within refreshSkew of expiry. Concurrent callers
// for the same key share a single mint. destination is the broker
// destination name (the value redeemed at /token), so routes sharing a
// broker destination share a cache entry.
func (c *tokenCache) Get(ctx context.Context, action *Action, destination string) (*MintedToken, error) {
	key := cacheKey{actionID: action.ID, destination: destination}

	c.mu.Lock()
	if entry, ok := c.entries[key]; ok && c.now().Before(entry.refreshAt) {
		tok := entry.token
		c.mu.Unlock()
		c.metrics.RecordCacheLookup("hit")
		return tok, nil
	}
	// Cold or stale. If another goroutine is already minting this
	// key, wait for it and then re-read the cache rather than issuing
	// a duplicate broker call.
	if wg, ok := c.inflight[key]; ok {
		c.mu.Unlock()
		wg.Wait()
		c.mu.Lock()
		if entry, ok := c.entries[key]; ok && c.now().Before(entry.refreshAt) {
			tok := entry.token
			c.mu.Unlock()
			c.metrics.RecordCacheLookup("hit")
			return tok, nil
		}
		// The in-flight mint failed or produced a still-stale entry;
		// fall through and mint ourselves.
	}
	wg := &sync.WaitGroup{}
	wg.Add(1)
	c.inflight[key] = wg
	c.mu.Unlock()
	c.metrics.RecordCacheLookup("miss")

	defer func() {
		c.mu.Lock()
		delete(c.inflight, key)
		c.mu.Unlock()
		wg.Done()
	}()

	tok, err := c.broker.Mint(ctx, MintRequest{
		Grant:       action.Grant,
		Destination: destination,
	})
	if err != nil {
		c.metrics.RecordBrokerMint(destination, "error")
		return nil, err
	}
	c.metrics.RecordBrokerMint(destination, "success")

	c.mu.Lock()
	c.entries[key] = &cachedToken{token: tok, refreshAt: c.refreshAt(tok)}
	c.mu.Unlock()
	return tok, nil
}

// refreshAt computes the time at which tok should be re-minted: a skew
// before its reported expiry, or a short default from now when the
// broker reported no expiry.
func (c *tokenCache) refreshAt(tok *MintedToken) time.Time {
	if tok.ExpiresAt.IsZero() {
		return c.now().Add(defaultTokenTTL)
	}
	return tok.ExpiresAt.Add(-refreshSkew)
}

// evictAction drops every cached credential belonging to actionID. The
// proxy calls it when an action is torn down so a re-used action_id can
// never return a stale credential.
func (c *tokenCache) evictAction(actionID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key := range c.entries {
		if key.actionID == actionID {
			delete(c.entries, key)
		}
	}
}

package egressauthd

import (
	"sync"
	"time"
)

// Action is the in-memory record the sidecar holds for one registered
// action. It binds an action_id to the broker
// delegation grant the worker obtained at /delegate, the loopback proxy
// port allocated for it, and its expiry. The sidecar relays Grant to the
// broker's /token endpoint on each mint; it carries no identity of its
// own, because authorization is the broker's (the grant was scoped to a
// destination set at /delegate).
type Action struct {
	// ID is the opaque action_id the control server returned to the
	// worker. The proxy keys per-request lookups on it.
	ID string

	// Grant is the broker delegation grant (the nonce /delegate
	// returned). The sidecar sends it verbatim as the "nonce" field of
	// each /token request for this action; the broker's
	// granted_destinations check on the grant is the authorization
	// decision.
	Grant string

	// ProxyPort is the loopback TCP port the per-action forward proxy
	// listens on.
	ProxyPort int

	// ExpiresAt is the absolute time after which the action is
	// evicted and its proxy torn down. The control server sets it
	// from the worker's expires_at.
	ExpiresAt time.Time
}

// actionRegistry is the concurrency-safe store of live actions. It
// owns TTL eviction: a background sweeper removes actions past their
// ExpiresAt and invokes the registered teardown hook so the proxy
// listener is released.
type actionRegistry struct {
	mu      sync.RWMutex
	actions map[string]*Action

	// onEvict is invoked (outside the lock) for every action removed
	// by Delete or the TTL sweeper, so the owner can tear down the
	// per-action proxy. It is set once at construction.
	onEvict func(*Action)

	now func() time.Time
}

// newActionRegistry constructs an empty registry. onEvict is called
// for every action removed via Delete or TTL expiry; it may be nil in
// tests that do not wire a proxy.
func newActionRegistry(onEvict func(*Action)) *actionRegistry {
	return &actionRegistry{
		actions: map[string]*Action{},
		onEvict: onEvict,
		now:     time.Now,
	}
}

// Add inserts a, replacing any existing action with the same ID
// (evicting the replaced one through onEvict so its proxy is released).
func (r *actionRegistry) Add(a *Action) {
	r.mu.Lock()
	prev := r.actions[a.ID]
	r.actions[a.ID] = a
	r.mu.Unlock()
	if prev != nil && r.onEvict != nil {
		r.onEvict(prev)
	}
}

// Get returns the live action with the given ID, or (nil, false) if it
// is absent or already past its expiry. A lookup of an expired action
// returns false even before the sweeper has removed it, so the proxy
// fails closed at the TTL boundary without depending on sweep timing.
func (r *actionRegistry) Get(id string) (*Action, bool) {
	r.mu.RLock()
	a, ok := r.actions[id]
	r.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if !a.ExpiresAt.IsZero() && r.now().After(a.ExpiresAt) {
		return nil, false
	}
	return a, true
}

// Delete removes the action with the given ID and invokes onEvict for
// it. It reports whether an action was present.
func (r *actionRegistry) Delete(id string) bool {
	r.mu.Lock()
	a, ok := r.actions[id]
	if ok {
		delete(r.actions, id)
	}
	r.mu.Unlock()
	if ok && r.onEvict != nil {
		r.onEvict(a)
	}
	return ok
}

// sweepExpired removes every action past its expiry and invokes
// onEvict for each. It returns the number swept so the caller (and
// tests) can observe progress.
func (r *actionRegistry) sweepExpired() int {
	now := r.now()
	var expired []*Action
	r.mu.Lock()
	for id, a := range r.actions {
		if !a.ExpiresAt.IsZero() && now.After(a.ExpiresAt) {
			expired = append(expired, a)
			delete(r.actions, id)
		}
	}
	r.mu.Unlock()
	for _, a := range expired {
		if r.onEvict != nil {
			r.onEvict(a)
		}
	}
	return len(expired)
}

// runSweeper runs sweepExpired every interval until done is closed. It
// is started as a background goroutine by the server.
func (r *actionRegistry) runSweeper(done <-chan struct{}, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
			r.sweepExpired()
		}
	}
}

// snapshot returns a shallow copy of the live actions, used by the
// server on shutdown to tear down every remaining proxy.
func (r *actionRegistry) snapshot() []*Action {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Action, 0, len(r.actions))
	for _, a := range r.actions {
		out = append(out, a)
	}
	return out
}

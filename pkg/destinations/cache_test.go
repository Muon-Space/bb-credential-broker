package destinations

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Muon-Space/bb-credential-broker/pkg/auth"
)

// stubDestination is a controllable Destination for exercising the
// cache wrapper in isolation. mint is consulted on every inner Mint
// call with the 1-based call number.
type stubDestination struct {
	mint  func(call int) (*Token, error)
	calls int32
}

func (s *stubDestination) Mint(_ context.Context, _ *auth.Identity) (*Token, error) {
	return s.mint(int(atomic.AddInt32(&s.calls, 1)))
}

func (s *stubDestination) callCount() int {
	return int(atomic.LoadInt32(&s.calls))
}

// renderableStub extends stubDestination with a canned Renderable
// implementation so pass-through can be asserted.
type renderableStub struct {
	stubDestination
	rendered *http.Request
}

func (s *renderableStub) RenderRequest(_ context.Context, _ *auth.Identity) (*http.Request, error) {
	return s.rendered, nil
}

func cacheTestIdentity() *auth.Identity {
	return &auth.Identity{Type: auth.IdentityTypeCI, Principal: "p"}
}

func TestCachedDestination_ReusesFreshToken(t *testing.T) {
	t.Parallel()
	frozen := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	stub := &stubDestination{mint: func(_ int) (*Token, error) {
		return &Token{Value: "tok", ExpiresAt: frozen.Add(5 * time.Minute)}, nil
	}}
	c := newCachedDestination(stub)
	c.now = func() time.Time { return frozen }

	first, err := c.Mint(context.Background(), cacheTestIdentity())
	if err != nil {
		t.Fatalf("Mint #1: %v", err)
	}
	second, err := c.Mint(context.Background(), cacheTestIdentity())
	if err != nil {
		t.Fatalf("Mint #2: %v", err)
	}
	if first != second {
		t.Error("expected the cached Token to be shared across calls")
	}
	if got := stub.callCount(); got != 1 {
		t.Errorf("inner mint count: got %d, want 1", got)
	}
}

func TestCachedDestination_RefreshesBeforeReportedExpiry(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	stub := &stubDestination{mint: func(_ int) (*Token, error) {
		return &Token{Value: "tok", ExpiresAt: now.Add(60 * time.Second)}, nil
	}}
	c := newCachedDestination(stub)
	c.now = func() time.Time { return now }

	if _, err := c.Mint(context.Background(), cacheTestIdentity()); err != nil {
		t.Fatalf("Mint #1: %v", err)
	}

	// One second past the refresh instant (expiry minus skew) but
	// still before the reported expiry itself: the cache must
	// already re-mint rather than dispense a nearly-dead token.
	now = now.Add(60*time.Second - cacheRefreshSkew + time.Second)

	if _, err := c.Mint(context.Background(), cacheTestIdentity()); err != nil {
		t.Fatalf("Mint #2: %v", err)
	}
	if got := stub.callCount(); got != 2 {
		t.Errorf("inner mint count: got %d, want 2 (stale entry must re-mint)", got)
	}
}

func TestCachedDestination_ZeroExpiryIsNotCached(t *testing.T) {
	t.Parallel()
	stub := &stubDestination{mint: func(_ int) (*Token, error) {
		return &Token{Value: "tok"}, nil
	}}
	c := newCachedDestination(stub)

	for i := 0; i < 2; i++ {
		if _, err := c.Mint(context.Background(), cacheTestIdentity()); err != nil {
			t.Fatalf("Mint #%d: %v", i+1, err)
		}
	}
	if got := stub.callCount(); got != 2 {
		t.Errorf("inner mint count: got %d, want 2 (a token without expiry must not be cached)", got)
	}
}

func TestCachedDestination_ErrorIsNotCached(t *testing.T) {
	t.Parallel()
	stub := &stubDestination{mint: func(call int) (*Token, error) {
		if call == 1 {
			return nil, errors.New("upstream unavailable")
		}
		return &Token{Value: "recovered", ExpiresAt: time.Now().Add(time.Minute)}, nil
	}}
	c := newCachedDestination(stub)

	if _, err := c.Mint(context.Background(), cacheTestIdentity()); err == nil {
		t.Fatal("Mint #1: expected error, got nil")
	}
	tok, err := c.Mint(context.Background(), cacheTestIdentity())
	if err != nil {
		t.Fatalf("Mint #2: %v", err)
	}
	if tok.Value != "recovered" {
		t.Errorf("Value: got %q, want %q", tok.Value, "recovered")
	}
}

func TestCachedDestination_ConcurrentMissesShareOneMint(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	stub := &stubDestination{mint: func(_ int) (*Token, error) {
		<-release
		return &Token{Value: "tok", ExpiresAt: time.Now().Add(time.Minute)}, nil
	}}
	c := newCachedDestination(stub)

	const n = 10
	var wg sync.WaitGroup
	results := make([]*Token, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = c.Mint(context.Background(), cacheTestIdentity())
		}(i)
	}
	// Let every goroutine reach the miss path before the single
	// inner mint completes, so this exercises the concurrent-miss
	// dedup rather than racing goroutine scheduling.
	deadline := time.Now().Add(2 * time.Second)
	for stub.callCount() < 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	close(release)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("Mint #%d: %v", i, err)
		}
	}
	for i, r := range results {
		if r != results[0] {
			t.Errorf("result #%d: expected all concurrent callers to share one minted Token", i)
		}
	}
	if got := stub.callCount(); got != 1 {
		t.Errorf("inner mint count: got %d, want 1", got)
	}
}

func TestCachedDestination_RenderRequestPassesThrough(t *testing.T) {
	t.Parallel()
	want, err := http.NewRequest(http.MethodGet, "https://registry.example.com/v2/token", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	stub := &renderableStub{rendered: want}
	stub.mint = func(_ int) (*Token, error) { return &Token{Value: "tok"}, nil }
	c := newCachedDestination(stub)

	got, err := c.RenderRequest(context.Background(), cacheTestIdentity())
	if err != nil {
		t.Fatalf("RenderRequest: %v", err)
	}
	if got != want {
		t.Error("expected the inner destination's rendered request to pass through unchanged")
	}
}

func TestCachedDestination_NonRenderableInnerYieldsSentinel(t *testing.T) {
	t.Parallel()
	stub := &stubDestination{mint: func(_ int) (*Token, error) { return &Token{Value: "tok"}, nil }}
	c := newCachedDestination(stub)

	if _, err := c.RenderRequest(context.Background(), cacheTestIdentity()); !errors.Is(err, ErrNotRenderable) {
		t.Errorf("RenderRequest error: got %v, want ErrNotRenderable", err)
	}
}

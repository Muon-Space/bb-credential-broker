package store_test

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/auth"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/store"
)

func newRecord(t *testing.T) *store.Record {
	t.Helper()
	return &store.Record{
		Identity: &auth.Identity{
			Type:      auth.IdentityTypeCI,
			Principal: "repo:owner/repo:ref:refs/heads/main",
		},
		AllowedDestinations: []string{"alpha", "beta"},
	}
}

func TestInMemoryStore_MintClaim(t *testing.T) {
	t.Parallel()

	s := store.NewInMemoryStore(5*time.Minute, 0)
	rec := newRecord(t)

	nonce, err := s.Mint(rec)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if nonce == "" {
		t.Fatal("Mint returned empty nonce")
	}

	got, err := s.Claim(nonce)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if got.Identity.Principal != rec.Identity.Principal {
		t.Errorf("Claim returned wrong record: got principal %q, want %q",
			got.Identity.Principal, rec.Identity.Principal)
	}
}

func TestInMemoryStore_SingleUse(t *testing.T) {
	t.Parallel()

	s := store.NewInMemoryStore(5*time.Minute, 0)
	nonce, err := s.Mint(newRecord(t))
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if _, err := s.Claim(nonce); err != nil {
		t.Fatalf("first Claim: %v", err)
	}
	_, err = s.Claim(nonce)
	if !errors.Is(err, store.ErrAlreadyClaimed) {
		t.Fatalf("second Claim: got err %v, want ErrAlreadyClaimed", err)
	}
}

func TestInMemoryStore_TTLExpiry(t *testing.T) {
	t.Parallel()

	s := store.NewInMemoryStore(50*time.Millisecond, 0)
	nonce, err := s.Mint(newRecord(t))
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	time.Sleep(75 * time.Millisecond)
	_, err = s.Claim(nonce)
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Claim after TTL: got err %v, want ErrNotFound", err)
	}
}

func TestInMemoryStore_UnknownNonceIsNotFound(t *testing.T) {
	t.Parallel()

	s := store.NewInMemoryStore(5*time.Minute, 0)
	_, err := s.Claim("never-minted")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Claim of unknown nonce: got err %v, want ErrNotFound", err)
	}
}

// TestInMemoryStore_ClaimRace asserts that concurrent claims of the
// same nonce result in exactly one success and N-1 ErrAlreadyClaimed
// returns. This is the defining safety property of the store.
func TestInMemoryStore_ClaimRace(t *testing.T) {
	t.Parallel()

	const goroutines = 100
	s := store.NewInMemoryStore(5*time.Minute, 0)
	nonce, err := s.Mint(newRecord(t))
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	var (
		wg        sync.WaitGroup
		successes atomic.Int32
		failures  atomic.Int32
		other     atomic.Int32
	)
	wg.Add(goroutines)
	start := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			<-start
			_, err := s.Claim(nonce)
			switch {
			case err == nil:
				successes.Add(1)
			case errors.Is(err, store.ErrAlreadyClaimed):
				failures.Add(1)
			default:
				other.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if successes.Load() != 1 {
		t.Errorf("expected exactly 1 successful claim, got %d", successes.Load())
	}
	if failures.Load() != goroutines-1 {
		t.Errorf("expected %d ErrAlreadyClaimed, got %d", goroutines-1, failures.Load())
	}
	if other.Load() != 0 {
		t.Errorf("unexpected error count: %d", other.Load())
	}
}

func TestInMemoryStore_MintRejectsNil(t *testing.T) {
	t.Parallel()
	s := store.NewInMemoryStore(time.Minute, 0)
	if _, err := s.Mint(nil); err == nil {
		t.Fatal("Mint(nil): expected error, got nil")
	}
}

func TestRecord_AllowsDestination(t *testing.T) {
	t.Parallel()
	r := &store.Record{AllowedDestinations: []string{"alpha", "beta"}}
	if !r.AllowsDestination("alpha") {
		t.Error("alpha should be allowed")
	}
	if r.AllowsDestination("gamma") {
		t.Error("gamma should not be allowed")
	}
	empty := &store.Record{}
	if empty.AllowsDestination("alpha") {
		t.Error("empty AllowedDestinations should reject everything")
	}
}

func TestNew_RejectsMissingBackend(t *testing.T) {
	t.Parallel()
	if _, err := store.New(store.Config{}); err == nil {
		t.Fatal("New with empty Config: expected error, got nil")
	}
}

func TestNew_RejectsZeroTTL(t *testing.T) {
	t.Parallel()
	cfg := store.Config{InMemory: &store.InMemoryConfig{}}
	if _, err := store.New(cfg); err == nil {
		t.Fatal("New with zero TTL: expected error, got nil")
	}
}

func TestDuration_UnmarshalJSON(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		input   string
		want    time.Duration
		wantErr bool
	}{
		{name: "minutes", input: `"15m"`, want: 15 * time.Minute},
		{name: "seconds", input: `"30s"`, want: 30 * time.Second},
		{name: "compound", input: `"1h30m"`, want: 90 * time.Minute},
		{name: "non-string is rejected", input: `15`, wantErr: true},
		{name: "garbage string is rejected", input: `"not-a-duration"`, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var d store.Duration
			err := d.UnmarshalJSON([]byte(tc.input))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if time.Duration(d) != tc.want {
				t.Errorf("got %v, want %v", time.Duration(d), tc.want)
			}
		})
	}
}

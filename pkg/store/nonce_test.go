package store_test

import (
	"testing"
	"time"

	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/auth"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/store"
)

// newRecord returns a Record populated with values typical of a
// /delegate response. It is reused across the store tests in this
// package.
func newRecord(t *testing.T) *store.Record {
	t.Helper()
	return &store.Record{
		Identity: &auth.Identity{
			Type:      auth.IdentityTypeCI,
			Principal: "repo:owner/repo:ref:refs/heads/main",
			Claims: map[string]any{
				"repository": "owner/repo",
				"ref":        "refs/heads/main",
			},
		},
		AllowedDestinations: []string{"alpha", "beta"},
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

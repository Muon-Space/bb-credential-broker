package destinations_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/auth"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/destinations"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/metrics"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/secrets"
)

func TestBuildRegistry_HappyPath(t *testing.T) {
	t.Parallel()

	raw := map[string]json.RawMessage{
		"example": json.RawMessage(`{
			"httpTokenExchange": {
				"request": {
					"method": "POST",
					"url": "https://example.com/token",
					"headers": {"Content-Type": "application/json"},
					"body": {"json": {}}
				},
				"response": {
					"tokenJsonPath": "access_token",
					"expiresInJsonPath": "expires_in"
				}
			}
		}`),
	}
	reg, err := destinations.BuildRegistry(raw, destinations.Dependencies{
		Secrets:      secrets.NewMapLoader(),
		NamedSecrets: map[string]secrets.SecretRef{},
	})
	if err != nil {
		t.Fatalf("BuildRegistry: %v", err)
	}
	if reg.Lookup("example") == nil {
		t.Fatal("example destination not registered")
	}
}

func TestBuildRegistry_UnknownTypeIsRejected(t *testing.T) {
	t.Parallel()

	raw := map[string]json.RawMessage{
		"bogus": json.RawMessage(`{"unknownType": {}}`),
	}
	_, err := destinations.BuildRegistry(raw, destinations.Dependencies{})
	if err == nil {
		t.Fatal("expected error for unknown type, got nil")
	}
	if !strings.Contains(err.Error(), "bogus") {
		t.Errorf("error %q should mention destination name", err.Error())
	}
}

func TestBuildRegistry_MissingDiscriminatorIsRejected(t *testing.T) {
	t.Parallel()

	raw := map[string]json.RawMessage{
		"empty": json.RawMessage(`{}`),
	}
	_, err := destinations.BuildRegistry(raw, destinations.Dependencies{})
	if err == nil {
		t.Fatal("expected error for missing discriminator, got nil")
	}
	if !strings.Contains(err.Error(), "no destination type discriminator") {
		t.Errorf("error %q lacks expected wording", err.Error())
	}
}

func TestBuildRegistry_MalformedTemplateIsRejected(t *testing.T) {
	t.Parallel()

	// The url template contains an unterminated ${ — the
	// constructor must reject it at start-up, not at request time.
	raw := map[string]json.RawMessage{
		"bad": json.RawMessage(`{
			"httpTokenExchange": {
				"request": {
					"method": "POST",
					"url":    "https://example.com/${unterminated"
				},
				"response": { "tokenJsonPath": "access_token" }
			}
		}`),
	}
	_, err := destinations.BuildRegistry(raw, destinations.Dependencies{})
	if err == nil {
		t.Fatal("expected template parse error at registry build, got nil")
	}
}

func TestRegistry_LookupReturnsNilForUnknown(t *testing.T) {
	t.Parallel()
	r := destinations.Registry{}
	if r.Lookup("absent") != nil {
		t.Fatal("Lookup of absent destination should return nil")
	}
}

// TestBuildRegistry_InstrumentsMintCalls verifies that destinations
// returned by BuildRegistry are wrapped with the metrics middleware
// and that mint calls increment the per-destination counter.
func TestBuildRegistry_InstrumentsMintCalls(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"access_token":"abc"}`))
	}))
	defer srv.Close()

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)

	raw := map[string]json.RawMessage{
		"alpha": json.RawMessage(`{
			"httpTokenExchange": {
				"request": {"method": "POST", "url": "` + srv.URL + `/"},
				"response": {"tokenJsonPath": "access_token"}
			}
		}`),
	}
	r, err := destinations.BuildRegistry(raw, destinations.Dependencies{
		Secrets:      secrets.NewMapLoader(),
		NamedSecrets: map[string]secrets.SecretRef{},
		Metrics:      m,
	})
	if err != nil {
		t.Fatalf("BuildRegistry: %v", err)
	}

	if _, err := r.Lookup("alpha").Mint(context.Background(),
		&auth.Identity{Type: auth.IdentityTypeCI, Principal: "p"}); err != nil {
		t.Fatalf("Mint: %v", err)
	}
	count, err := testutil.GatherAndCount(reg, metrics.Namespace+"_mint_requests_total")
	if err != nil {
		t.Fatalf("GatherAndCount: %v", err)
	}
	if count != 1 {
		t.Errorf("mint_requests_total series count: got %d, want 1", count)
	}
}

// TestInstrumentedDestination_NilMetricsIsNoOp confirms that a
// destination wrapped with a nil metrics handle still functions
// correctly. This protects callers (notably tests) from having to
// construct a registry just to exercise BuildRegistry.
func TestInstrumentedDestination_NilMetricsIsNoOp(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"token":"x"}`))
	}))
	defer srv.Close()

	raw := map[string]json.RawMessage{
		"alpha": json.RawMessage(`{
			"httpTokenExchange": {
				"request": {"method": "POST", "url": "` + srv.URL + `/"},
				"response": {"tokenJsonPath": "token"}
			}
		}`),
	}
	r, err := destinations.BuildRegistry(raw, destinations.Dependencies{
		Secrets:      secrets.NewMapLoader(),
		NamedSecrets: map[string]secrets.SecretRef{},
		// Metrics intentionally omitted.
	})
	if err != nil {
		t.Fatalf("BuildRegistry: %v", err)
	}
	if _, err := r.Lookup("alpha").Mint(context.Background(),
		&auth.Identity{Type: auth.IdentityTypeCI, Principal: "p"}); err != nil {
		t.Fatalf("Mint: %v", err)
	}
}

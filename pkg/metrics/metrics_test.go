package metrics_test

import (
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/metrics"
)

func TestNew_RegistersAllCollectors(t *testing.T) {
	t.Parallel()
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	if m == nil {
		t.Fatal("New returned nil")
	}

	// Vec collectors emit metric families only after at least
	// one observation has been recorded against them. Trigger
	// each Record method once so Gather can see every family
	// the constructor was supposed to register.
	m.RecordDelegate(200, "ci", time.Millisecond)
	m.RecordToken(200, "ci", "x", time.Millisecond)
	m.RecordMint("x", nil, time.Millisecond)

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	wantNames := map[string]bool{
		metrics.Namespace + "_delegate_requests_total":   false,
		metrics.Namespace + "_delegate_duration_seconds": false,
		metrics.Namespace + "_token_requests_total":      false,
		metrics.Namespace + "_token_duration_seconds":    false,
		metrics.Namespace + "_mint_requests_total":       false,
		metrics.Namespace + "_mint_duration_seconds":     false,
	}
	for _, mf := range families {
		if _, ok := wantNames[mf.GetName()]; ok {
			wantNames[mf.GetName()] = true
		}
	}
	for name, present := range wantNames {
		if !present {
			t.Errorf("collector %q not registered", name)
		}
	}
}

func TestRecordDelegate_IncrementsAndObserves(t *testing.T) {
	t.Parallel()
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)

	m.RecordDelegate(200, "ci", 50*time.Millisecond)
	m.RecordDelegate(401, "", 5*time.Millisecond)
	m.RecordDelegate(200, "ci", 75*time.Millisecond)

	// Two unique (status, identity_type) tuples → two series;
	// the second 200/ci call increments the existing counter
	// rather than creating a third series.
	if got := mustGatherAndCount(t, reg, metrics.Namespace+"_delegate_requests_total"); got != 2 {
		t.Errorf("delegate_requests_total series count: got %d, want 2", got)
	}
}

func TestRecordToken_IncludesDestinationLabel(t *testing.T) {
	t.Parallel()
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)

	m.RecordToken(200, "ci", "alpha", 30*time.Millisecond)
	m.RecordToken(404, "ci", "missing", 1*time.Millisecond)
	m.RecordToken(200, "ci", "alpha", 35*time.Millisecond)

	if got := mustGatherAndCount(t, reg, metrics.Namespace+"_token_requests_total"); got != 2 {
		t.Errorf("token_requests_total series count: got %d, want 2", got)
	}
}

func TestRecordMint_OutcomeLabel(t *testing.T) {
	t.Parallel()
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)

	m.RecordMint("alpha", nil, 80*time.Millisecond)
	m.RecordMint("alpha", errors.New("upstream broke"), 5*time.Millisecond)
	m.RecordMint("beta", nil, 60*time.Millisecond)

	if got := mustGatherAndCount(t, reg, metrics.Namespace+"_mint_requests_total"); got != 3 {
		t.Errorf("mint_requests_total series count: got %d, want 3", got)
	}
}

// mustGatherAndCount wraps testutil.GatherAndCount with a fail-fast
// helper so tests can assert series counts without boilerplate.
func mustGatherAndCount(t *testing.T, g prometheus.Gatherer, name string) int {
	t.Helper()
	n, err := testutil.GatherAndCount(g, name)
	if err != nil {
		t.Fatalf("GatherAndCount(%s): %v", name, err)
	}
	return n
}

func TestRecordMethods_NilReceiverIsNoOp(t *testing.T) {
	t.Parallel()
	// The broker passes a real *Metrics through the dependency
	// chain in production, but tests outside the metrics package
	// rely on the methods being safe to call on a nil receiver.
	var m *metrics.Metrics
	m.RecordDelegate(200, "ci", time.Millisecond)
	m.RecordToken(200, "ci", "x", time.Millisecond)
	m.RecordMint("x", nil, time.Millisecond)
}

func TestNew_PanicsOnDuplicateRegistration(t *testing.T) {
	t.Parallel()
	reg := prometheus.NewRegistry()
	metrics.New(reg)
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on duplicate registration, got none")
		}
	}()
	metrics.New(reg)
}

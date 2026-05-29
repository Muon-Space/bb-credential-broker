package egressauthd

import (
	"github.com/prometheus/client_golang/prometheus"
)

// metricsNamespace is the Prometheus metric-name prefix for the
// sidecar, matching the broker's "buildbarn_*" convention.
const metricsNamespace = "buildbarn_egress_authd"

// Metrics owns the sidecar's Prometheus collectors. All Record*
// methods are nil-safe so tests can omit instrumentation.
type Metrics struct {
	egressRequests *prometheus.CounterVec
	activeActions  prometheus.Gauge
	brokerMints    *prometheus.CounterVec
	tokenCacheHits *prometheus.CounterVec
}

// NewMetrics constructs a *Metrics registered against reg.
func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		egressRequests: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: metricsNamespace,
				Subsystem: "egress",
				Name:      "requests_total",
				Help:      "Number of proxied egress requests, labelled by destination and decision.",
			},
			[]string{"destination", "decision"},
		),
		activeActions: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: metricsNamespace,
				Subsystem: "actions",
				Name:      "active",
				Help:      "Number of currently registered (live) actions.",
			},
		),
		brokerMints: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: metricsNamespace,
				Subsystem: "broker",
				Name:      "mints_total",
				Help:      "Number of /token mint calls to the broker, labelled by destination and outcome.",
			},
			[]string{"destination", "outcome"},
		),
		tokenCacheHits: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: metricsNamespace,
				Subsystem: "token_cache",
				Name:      "lookups_total",
				Help:      "Number of credential cache lookups, labelled by result (hit or miss).",
			},
			[]string{"result"},
		),
	}
	reg.MustRegister(m.egressRequests, m.activeActions, m.brokerMints, m.tokenCacheHits)
	return m
}

// RecordEgress increments the egress-request counter.
func (m *Metrics) RecordEgress(destination, decision string) {
	if m == nil {
		return
	}
	m.egressRequests.WithLabelValues(destination, decision).Inc()
}

// SetActiveActions records the current count of live actions.
func (m *Metrics) SetActiveActions(n int) {
	if m == nil {
		return
	}
	m.activeActions.Set(float64(n))
}

// RecordBrokerMint increments the broker-mint counter.
func (m *Metrics) RecordBrokerMint(destination, outcome string) {
	if m == nil {
		return
	}
	m.brokerMints.WithLabelValues(destination, outcome).Inc()
}

// RecordCacheLookup increments the cache-lookup counter with result
// "hit" or "miss".
func (m *Metrics) RecordCacheLookup(result string) {
	if m == nil {
		return
	}
	m.tokenCacheHits.WithLabelValues(result).Inc()
}

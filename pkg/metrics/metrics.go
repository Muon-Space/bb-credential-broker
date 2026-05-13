// Package metrics defines the broker's Prometheus collectors and
// the small set of helpers used by the HTTP handlers and the
// destination registry to record observations.
//
// Collectors are owned by a *Metrics value rather than registered
// against the default Prometheus registry; this keeps tests
// isolated and lets the diagnostics HTTP server expose the
// broker's own registry rather than every package's transitive
// promauto registrations.
//
// All Record* methods are nil-safe so that tests that do not care
// about metrics can pass a nil *Metrics through the dependency
// chain without additional plumbing.
package metrics

import (
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Namespace is the Prometheus metric-name prefix shared by every
// collector this package exposes. The value matches the convention
// used by sibling Buildbarn services (which use "buildbarn" as
// their root namespace).
const Namespace = "buildbarn_credential_broker"

// Metrics owns the collectors used to instrument the broker.
//
// Construct an instance with New, passing the Registerer the
// /metrics handler will scrape from. Tests typically construct a
// dedicated registry via prometheus.NewRegistry() so they are not
// polluted by metric values produced by other tests.
type Metrics struct {
	delegateRequests *prometheus.CounterVec
	delegateDuration *prometheus.HistogramVec

	tokenRequests *prometheus.CounterVec
	tokenDuration *prometheus.HistogramVec

	mintRequests *prometheus.CounterVec
	mintDuration *prometheus.HistogramVec
}

// New constructs a *Metrics with all collectors registered against
// reg. New panics if any collector fails to register, which can
// only happen when an incompatible collector is already registered
// against reg.
func New(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		delegateRequests: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: Namespace,
				Subsystem: "delegate",
				Name:      "requests_total",
				Help:      "Number of /delegate requests, labelled by HTTP status code and the resolved identity type.",
			},
			[]string{"status", "identity_type"},
		),
		delegateDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: Namespace,
				Subsystem: "delegate",
				Name:      "duration_seconds",
				Help:      "Duration of /delegate requests in seconds, labelled by HTTP status code.",
				Buckets:   prometheus.DefBuckets,
			},
			[]string{"status"},
		),
		tokenRequests: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: Namespace,
				Subsystem: "token",
				Name:      "requests_total",
				Help:      "Number of /token requests, labelled by HTTP status code, the resolved identity type, and the requested destination.",
			},
			[]string{"status", "identity_type", "destination"},
		),
		tokenDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: Namespace,
				Subsystem: "token",
				Name:      "duration_seconds",
				Help:      "Duration of /token requests in seconds, labelled by HTTP status code and the requested destination.",
				Buckets:   prometheus.DefBuckets,
			},
			[]string{"status", "destination"},
		),
		mintRequests: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: Namespace,
				Subsystem: "mint",
				Name:      "requests_total",
				Help:      "Number of outbound mint calls to upstream destinations, labelled by destination and outcome (success or error).",
			},
			[]string{"destination", "outcome"},
		),
		mintDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: Namespace,
				Subsystem: "mint",
				Name:      "duration_seconds",
				Help:      "Duration of outbound mint calls in seconds, labelled by destination and outcome.",
				Buckets:   prometheus.DefBuckets,
			},
			[]string{"destination", "outcome"},
		),
	}
	reg.MustRegister(
		m.delegateRequests,
		m.delegateDuration,
		m.tokenRequests,
		m.tokenDuration,
		m.mintRequests,
		m.mintDuration,
	)
	return m
}

// RecordDelegate increments the /delegate counter and records the
// request duration. identityType may be empty when the request was
// rejected before identity resolution (typically a JWT validation
// failure).
func (m *Metrics) RecordDelegate(status int, identityType string, duration time.Duration) {
	if m == nil {
		return
	}
	statusLabel := strconv.Itoa(status)
	m.delegateRequests.WithLabelValues(statusLabel, identityType).Inc()
	m.delegateDuration.WithLabelValues(statusLabel).Observe(duration.Seconds())
}

// RecordToken increments the /token counter and records the
// request duration. destination may be empty when the request was
// rejected before destination dispatch (e.g. source-IP gate
// failures, malformed bodies).
func (m *Metrics) RecordToken(status int, identityType, destination string, duration time.Duration) {
	if m == nil {
		return
	}
	statusLabel := strconv.Itoa(status)
	m.tokenRequests.WithLabelValues(statusLabel, identityType, destination).Inc()
	m.tokenDuration.WithLabelValues(statusLabel, destination).Observe(duration.Seconds())
}

// RecordMint increments the mint counter and records the duration
// of a single outbound credential-mint call. outcomeFromError
// translates the supplied error into the canonical outcome label.
func (m *Metrics) RecordMint(destination string, err error, duration time.Duration) {
	if m == nil {
		return
	}
	outcome := outcomeFromError(err)
	m.mintRequests.WithLabelValues(destination, outcome).Inc()
	m.mintDuration.WithLabelValues(destination, outcome).Observe(duration.Seconds())
}

// outcomeFromError returns "success" when err is nil and "error"
// otherwise. The label set is intentionally narrow: more granular
// classification belongs in the audit log, where the full error
// string is recorded.
func outcomeFromError(err error) string {
	if err == nil {
		return "success"
	}
	return "error"
}

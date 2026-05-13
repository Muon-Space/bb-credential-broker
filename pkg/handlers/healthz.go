package handlers

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// HealthzHandler is the implementation of GET /-/healthy. It always
// returns 200 OK with a fixed body. The handler is intentionally
// simple: a more elaborate readiness check would risk failing the
// pod for reasons unrelated to the broker's ability to serve
// requests.
type HealthzHandler struct{}

// NewHealthzHandler constructs a HealthzHandler.
func NewHealthzHandler() HealthzHandler { return HealthzHandler{} }

// ServeHTTP implements http.Handler.
func (HealthzHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

// MetricsHandler returns the Prometheus exposition handler scoped
// to the supplied gatherer. Passing the broker's own registry
// rather than the default one keeps the /metrics output focused on
// collectors the broker explicitly registered.
func MetricsHandler(g prometheus.Gatherer) http.Handler {
	return promhttp.HandlerFor(g, promhttp.HandlerOpts{})
}

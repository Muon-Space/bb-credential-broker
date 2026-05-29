package egressauthd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sync/errgroup"
)

// sweepInterval is how often the action registry is swept for expired
// actions. The per-lookup expiry check already fails closed at the TTL
// boundary; the sweeper exists to release proxy listeners and cached
// credentials promptly rather than to enforce correctness.
const sweepInterval = 30 * time.Second

// Server is the running egress-authd sidecar. Construction is split
// from Run so integration tests can wire a fake broker without going
// through the file-backed config and real network listeners.
type Server struct {
	cfg          *Config
	control      *controlServer
	promRegistry *prometheus.Registry
	metrics      *Metrics

	socketListener net.Listener
	controlServer  *http.Server
	diagServer     *http.Server
}

// New constructs a Server from cfg, building the broker client, token
// cache, control server and (optionally) diagnostics server. The broker
// client is constructed here so an unreadable CA bundle surfaces at
// start-up.
func New(cfg *Config) (*Server, error) {
	broker, err := NewBrokerClient(cfg.BrokerTokenURL, cfg.CABundleFile)
	if err != nil {
		return nil, err
	}
	return newServerWithBroker(cfg, broker)
}

// newServerWithBroker is the dependency-injecting constructor shared by
// New and the integration tests. It wires everything except the broker
// transport, which the caller supplies.
func newServerWithBroker(cfg *Config, broker BrokerClient) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	var caBundle []byte
	if cfg.CABundleFile != "" {
		// #nosec G304 -- operator-supplied configuration.
		b, err := os.ReadFile(cfg.CABundleFile)
		if err != nil {
			return nil, fmt.Errorf("egressauthd: read upstream CA bundle %s: %w", cfg.CABundleFile, err)
		}
		caBundle = b
	}
	upstream := upstreamTLSConfig(caBundle)

	promRegistry := prometheus.NewRegistry()
	metrics := NewMetrics(promRegistry)
	cache := newTokenCache(broker, metrics)
	audit := NewStdoutAuditLogger()
	control := newControlServer(cfg, cache, audit, metrics, upstream)

	return &Server{
		cfg:          cfg,
		control:      control,
		promRegistry: promRegistry,
		metrics:      metrics,
	}, nil
}

// Run constructs a Server from cfg and serves until the process
// receives SIGINT or SIGTERM.
func Run(ctx context.Context, cfg *Config) error {
	s, err := New(cfg)
	if err != nil {
		return err
	}
	return s.Serve(ctx)
}

// Serve binds the control socket and diagnostics listener, starts the
// TTL sweeper, and blocks until ctx is cancelled or a listener fails.
// On shutdown every live per-action proxy is torn down.
func (s *Server) Serve(ctx context.Context) error {
	ctx, cancel := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	ln, err := s.listenSocket()
	if err != nil {
		return err
	}
	s.socketListener = ln
	s.controlServer = &http.Server{Handler: s.control.Handler(), ReadHeaderTimeout: 30 * time.Second}

	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		slog.Info("control socket listening", "socket", s.cfg.ListenSocket)
		if err := s.controlServer.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("control server: %w", err)
		}
		return nil
	})

	if s.cfg.MetricsListenAddress != "" {
		s.diagServer = s.buildDiagnosticsServer()
		g.Go(func() error {
			slog.Info("diagnostics listening", "addr", s.cfg.MetricsListenAddress)
			if err := s.diagServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				return fmt.Errorf("diagnostics server: %w", err)
			}
			return nil
		})
	}

	g.Go(func() error {
		done := make(chan struct{})
		go func() { <-gctx.Done(); close(done) }()
		s.control.registry.runSweeper(done, sweepInterval)
		return nil
	})

	// Shut down listeners and tear down proxies when the context is
	// cancelled.
	g.Go(func() error {
		<-gctx.Done()
		shutdownCtx, c := context.WithTimeout(context.Background(), 10*time.Second)
		defer c()
		_ = s.controlServer.Shutdown(shutdownCtx)
		if s.diagServer != nil {
			_ = s.diagServer.Shutdown(shutdownCtx)
		}
		s.control.closeAll()
		return nil
	})

	if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

// listenSocket binds the Unix-domain control socket, removing any stale
// socket file left by a previous crash and tightening its permissions
// so only the pod's own processes can dial it.
func (s *Server) listenSocket() (net.Listener, error) {
	path := s.cfg.ListenSocket
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("egressauthd: create socket dir: %w", err)
	}
	// Remove a stale socket from a previous run; ENOENT is fine.
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("egressauthd: remove stale socket: %w", err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("egressauthd: listen on %s: %w", path, err)
	}
	// #nosec G302 -- 0660 is intentional: the worker container shares
	// the pod's fsGroup and must be able to dial the control socket;
	// 0600 would lock out a sidecar that runs as a different UID but
	// the same supplementary group.
	if err := os.Chmod(path, 0o660); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("egressauthd: chmod socket: %w", err)
	}
	return ln, nil
}

// buildDiagnosticsServer constructs the HTTP server exposing /-/healthy
// and /metrics on the configured diagnostics address.
func (s *Server) buildDiagnosticsServer() *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/-/healthy", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.Handle("/metrics", promhttp.HandlerFor(s.promRegistry, promhttp.HandlerOpts{}))
	return &http.Server{
		Addr:              s.cfg.MetricsListenAddress,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
}

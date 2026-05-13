// Package app constructs the broker's dependency graph from a
// loaded configuration and starts the HTTP servers and background
// loops that make up the running process.
//
// The entry point cmd/bb-credential-broker/main delegates to Run
// after loading the configuration; tests construct a *App directly
// to exercise integrated behaviour without going through the
// process entry point.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sync/errgroup"

	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/audit"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/auth"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/config"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/destinations"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/handlers"
	brokermetrics "muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/metrics"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/policy"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/secrets"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/store"
)

// App is the running broker. Construction is split from Run so that
// integration tests can wire bespoke dependencies without going
// through the AWS-SDK code path.
type App struct {
	cfg           *config.Config
	parser        *auth.Parser
	policy        policy.Engine
	store         store.NonceStore
	registry      destinations.Registry
	auditLogger   *audit.Logger
	metrics       *brokermetrics.Metrics
	promRegistry  *prometheus.Registry
	jwksRefresh   time.Duration
	apiServer     *http.Server
	diagServer    *http.Server
	delegateRoute string
	tokenRoute    string
	healthzRoute  string
	metricsRoute  string
}

// New constructs an App from a loaded configuration. AWS SDK
// configuration is loaded via the default chain; the caller must
// arrange for AWS credentials (typically IRSA) to be available in
// the broker's environment before calling Run.
func New(ctx context.Context, cfg *config.Config) (*App, error) {
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws config: %w", err)
	}
	smClient := secretsmanager.NewFromConfig(awsCfg)
	awsLoader := secrets.NewAWSSecretsManagerLoader(smClient, time.Hour)
	loader := secrets.NewLoader(awsLoader)

	promRegistry := prometheus.NewRegistry()
	m := brokermetrics.New(promRegistry)

	parser, err := auth.NewParser(cfg.JWTAuth)
	if err != nil {
		return nil, fmt.Errorf("jwt parser: %w", err)
	}
	nonceStore, err := store.New(cfg.NonceStore)
	if err != nil {
		return nil, fmt.Errorf("nonce store: %w", err)
	}
	policyEngine, err := policy.New(cfg.Policy)
	if err != nil {
		return nil, fmt.Errorf("policy engine: %w", err)
	}
	registry, err := destinations.BuildRegistry(cfg.Destinations, destinations.Dependencies{
		Secrets:      loader,
		NamedSecrets: cfg.Secrets,
		Metrics:      m,
	})
	if err != nil {
		return nil, fmt.Errorf("destinations: %w", err)
	}

	auditLogger := audit.NewStdoutLogger()

	a := &App{
		cfg:           cfg,
		parser:        parser,
		policy:        policyEngine,
		store:         nonceStore,
		registry:      registry,
		auditLogger:   auditLogger,
		metrics:       m,
		promRegistry:  promRegistry,
		jwksRefresh:   5 * time.Minute,
		delegateRoute: "/delegate",
		tokenRoute:    "/token",
		healthzRoute:  "/-/healthy",
		metricsRoute:  "/metrics",
	}
	a.apiServer = a.buildAPIServer()
	a.diagServer = a.buildDiagnosticsServer()
	return a, nil
}

// Run starts the HTTP servers and background loops, then blocks
// until either a fatal error occurs or the process receives SIGINT
// or SIGTERM.
func Run(ctx context.Context, cfg *config.Config) error {
	a, err := New(ctx, cfg)
	if err != nil {
		return err
	}
	return a.Serve(ctx)
}

// Serve runs all background routines until ctx is cancelled or one
// of them fails. Cancellation propagates to every routine so that
// in-flight work can drain.
func (a *App) Serve(ctx context.Context) error {
	ctx, cancel := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error { return runHTTPServer(gctx, a.apiServer, "api") })
	g.Go(func() error { return runHTTPServer(gctx, a.diagServer, "diagnostics") })
	for _, c := range a.parser.Caches() {
		c := c
		g.Go(func() error {
			done := make(chan struct{})
			go func() {
				<-gctx.Done()
				close(done)
			}()
			c.RunRefreshLoop(done, a.jwksRefresh, func(err error) {
				slog.Warn("jwks refresh failed", "error", err)
			})
			return nil
		})
	}

	if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

// buildAPIServer constructs the HTTP server that serves /delegate
// and /token on the API listener.
func (a *App) buildAPIServer() *http.Server {
	mux := http.NewServeMux()
	mux.Handle(a.delegateRoute, handlers.NewDelegateHandler(a.parser, a.policy, a.store, a.auditLogger, a.metrics))
	mux.Handle(a.tokenRoute, handlers.NewTokenHandler(a.cfg.AllowedNets(), a.store, a.registry, a.auditLogger, a.metrics))
	read, write := a.cfg.APIServer.HTTPServerTimeouts()
	return &http.Server{
		Addr:         a.cfg.APIServer.ListenAddress,
		Handler:      mux,
		ReadTimeout:  read,
		WriteTimeout: write,
	}
}

// buildDiagnosticsServer constructs the HTTP server that exposes
// /-/healthy and /metrics. Diagnostics are intentionally on a
// separate listener so that the API listener can be exposed via
// ingress without inadvertently surfacing health and metrics
// endpoints to external callers.
func (a *App) buildDiagnosticsServer() *http.Server {
	mux := http.NewServeMux()
	mux.Handle(a.healthzRoute, handlers.NewHealthzHandler())
	mux.Handle(a.metricsRoute, handlers.MetricsHandler(a.promRegistry))
	read, write := a.cfg.DiagnosticsServer.HTTPServerTimeouts()
	return &http.Server{
		Addr:         a.cfg.DiagnosticsServer.ListenAddress,
		Handler:      mux,
		ReadTimeout:  read,
		WriteTimeout: write,
	}
}

// runHTTPServer runs srv until ctx is cancelled, then drains
// in-flight requests for up to 30 seconds before returning.
func runHTTPServer(ctx context.Context, srv *http.Server, name string) error {
	errCh := make(chan error, 1)
	go func() {
		slog.Info("server listening", "name", name, "addr", srv.Addr)
		errCh <- srv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("%s shutdown: %w", name, err)
		}
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("%s: %w", name, err)
	}
}

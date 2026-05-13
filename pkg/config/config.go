// Package config defines the broker's top-level configuration schema
// and provides a loader that materialises it from a Jsonnet file.
//
// The schema is split across several packages so that each subsystem
// owns the shape of its own slice of the configuration. This package
// merely aggregates those shapes into a single Config struct that the
// app wiring can consume.
package config

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/google/go-jsonnet"

	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/auth"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/policy"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/secrets"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/store"
)

// Config is the broker's top-level configuration. Each field maps to
// a section of the operator-supplied Jsonnet file.
type Config struct {
	// APIServer configures the HTTP listener that exposes
	// /delegate and /token. This listener is intended to be
	// reachable from external networks (typically via an
	// in-cluster ingress). /token is further restricted to a
	// configured set of source CIDRs.
	APIServer ServerConfig `json:"apiServer"`

	// DiagnosticsServer configures the HTTP listener that exposes
	// /-/healthy, /metrics and /debug/pprof. This listener is
	// intended to be reachable only from the cluster's monitoring
	// stack.
	DiagnosticsServer ServerConfig `json:"diagnosticsServer"`

	// TokenAllowedCIDRs enumerates the source CIDRs from which
	// /token requests are accepted. Requests from sources outside
	// this set receive a 401 response regardless of nonce
	// validity. The list must be non-empty.
	TokenAllowedCIDRs []string `json:"tokenAllowedCIDRs"`

	// JWTAuth configures the issuers accepted at /delegate.
	JWTAuth auth.JWTAuthConfig `json:"jwtAuth"`

	// NonceStore selects and configures the backend that stores
	// in-flight nonces.
	NonceStore store.Config `json:"nonceStore"`

	// Secrets is a map of operator-chosen names to SecretRefs.
	// Templated destination requests refer to entries by name
	// using ${secret:NAME} expressions; the deployment's IAM
	// policy enumerates the underlying refs.
	Secrets map[string]secrets.SecretRef `json:"secrets,omitempty"`

	// Destinations is a map of operator-chosen destination names
	// to typed destination configurations. The map is held as
	// json.RawMessage values so that this package does not need
	// to import the destinations package; final parsing happens
	// inside the destinations registry constructor.
	Destinations map[string]json.RawMessage `json:"destinations,omitempty"`

	// Policy specifies which destinations each Identity may mint
	// tokens for.
	Policy policy.Config `json:"policy,omitempty"`
}

// ServerConfig configures a single HTTP listener.
type ServerConfig struct {
	// ListenAddress is a Go-style listen address such as ":8080".
	ListenAddress string `json:"listenAddress"`

	// ReadTimeout caps the time spent reading the request body.
	ReadTimeout store.Duration `json:"readTimeout,omitempty"`

	// WriteTimeout caps the time spent writing the response body.
	WriteTimeout store.Duration `json:"writeTimeout,omitempty"`
}

// Load reads, evaluates and unmarshals the Jsonnet configuration at
// path, then performs the validations that can be done without
// constructing dependent subsystems. Construction of the secret
// loader, JWT parser, nonce store, policy engine and destinations
// registry happens in the app wiring.
func Load(path string) (*Config, error) {
	vm := jsonnet.MakeVM()
	rendered, err := vm.EvaluateFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: evaluate %s: %w", path, err)
	}

	var c Config
	dec := json.NewDecoder(strings.NewReader(rendered))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: decode %s: %w", path, err)
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	return &c, nil
}

// Validate performs the structural checks that do not require
// constructing dependent subsystems. Errors mention the offending
// configuration field by name.
func (c *Config) Validate() error {
	if c.APIServer.ListenAddress == "" {
		return fmt.Errorf("apiServer.listenAddress is required")
	}
	if c.DiagnosticsServer.ListenAddress == "" {
		return fmt.Errorf("diagnosticsServer.listenAddress is required")
	}
	if len(c.TokenAllowedCIDRs) == 0 {
		return fmt.Errorf("tokenAllowedCIDRs must list at least one CIDR")
	}
	for i, c := range c.TokenAllowedCIDRs {
		if _, _, err := net.ParseCIDR(c); err != nil {
			return fmt.Errorf("tokenAllowedCIDRs[%d]: %w", i, err)
		}
	}
	if len(c.JWTAuth.Issuers) == 0 {
		return fmt.Errorf("jwtAuth.issuers must list at least one issuer")
	}
	for i, iss := range c.JWTAuth.Issuers {
		if _, err := url.Parse(iss.URL); err != nil {
			return fmt.Errorf("jwtAuth.issuers[%d].url: %w", i, err)
		}
		if iss.JWKSFile == "" {
			return fmt.Errorf("jwtAuth.issuers[%d].jwksFile is required", i)
		}
		switch iss.IdentityType {
		case auth.IdentityTypeCI, auth.IdentityTypeUser:
		default:
			return fmt.Errorf("jwtAuth.issuers[%d].identityType: must be %q or %q",
				i, auth.IdentityTypeCI, auth.IdentityTypeUser)
		}
	}
	if c.NonceStore.InMemory == nil {
		return fmt.Errorf("nonceStore: no backend configured; expected one of: inMemory")
	}
	for name, ref := range c.Secrets {
		if err := ref.Validate(); err != nil {
			return fmt.Errorf("secrets[%q]: %w", name, err)
		}
	}
	for name := range c.Destinations {
		if name == "" {
			return fmt.Errorf("destinations: empty destination name is not allowed")
		}
	}
	return nil
}

// AllowedNets returns the parsed CIDRs the /token handler accepts.
// The function panics if Validate would have returned an error;
// callers are expected to invoke Validate (transitively, via Load)
// before calling AllowedNets.
func (c *Config) AllowedNets() []*net.IPNet {
	out := make([]*net.IPNet, 0, len(c.TokenAllowedCIDRs))
	for _, s := range c.TokenAllowedCIDRs {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			panic(fmt.Sprintf("config: AllowedNets called on un-validated config: %v", err))
		}
		out = append(out, n)
	}
	return out
}

// HTTPServerTimeouts returns the read and write timeouts for s,
// substituting reasonable defaults when the operator has not set
// them.
func (s ServerConfig) HTTPServerTimeouts() (read, write time.Duration) {
	read = time.Duration(s.ReadTimeout)
	if read == 0 {
		read = 10 * time.Second
	}
	write = time.Duration(s.WriteTimeout)
	if write == 0 {
		write = 10 * time.Second
	}
	return read, write
}

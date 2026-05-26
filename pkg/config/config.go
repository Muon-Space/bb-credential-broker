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

	// BrokerSigner is the optional configuration for the broker's
	// own RSA signing key and the JSON Web Key Set the broker
	// publishes at /.well-known/jwks.json. The block is intended
	// for deployments whose destinations rely on broker-minted
	// JWTs as their subject_token — typically OAuth 2.0
	// token-exchange endpoints whose downstream evaluates
	// identity-mapping claims only against the JWT carried in
	// subject_token and silently drops any request-body
	// extension fields. When BrokerSigner is omitted the JWKS
	// endpoint is not registered and the broker behaves exactly
	// as it did before this feature shipped.
	BrokerSigner *BrokerSignerConfig `json:"brokerSigner,omitempty"`
}

// BrokerSignerConfig configures the broker's optional RSA
// signing keys and the JWKS endpoint that publishes their public
// halves.
type BrokerSignerConfig struct {
	// PrivateKeySecret is the name of an entry in the top-level
	// Secrets map whose resolved value is the PEM-encoded RSA
	// private key the broker uses to sign its own JWTs. The
	// public half is derived at startup and published via the
	// JWKS endpoint. Use PrivateKeySecrets instead when rotation
	// overlap is needed; PrivateKeySecret is preserved as a
	// single-key shortcut.
	//
	// Exactly one of PrivateKeySecret and PrivateKeySecrets
	// must be set.
	PrivateKeySecret string `json:"privateKeySecret,omitempty"`

	// PrivateKeySecrets is the ordered list of named-secret
	// entries holding the broker's signing keys. The first
	// entry is the active signer (the key signjwt uses when
	// minting new JWTs); every entry contributes one JWK to the
	// published JWKS so downstream verifiers can validate JWTs
	// signed with any of them. This shape exists to support
	// zero-downtime key rotation:
	//
	//  1. Stage a new key under a new named secret.
	//  2. Append the new secret to privateKeySecrets and
	//     restart pods. JWKS now publishes both keys; broker
	//     still signs with the first.
	//  3. Wait the JWKS Cache-Control window (default 300s)
	//     for downstream caches to re-fetch.
	//  4. Reorder privateKeySecrets so the new key is first
	//     and restart pods. Broker now signs with the new key;
	//     the old key remains in the JWKS so any straggler JWT
	//     signed during the change-over window still verifies.
	//  5. Wait the cache window again, then drop the old
	//     secret from privateKeySecrets and restart pods.
	//
	// Exactly one of PrivateKeySecret and PrivateKeySecrets
	// must be set.
	PrivateKeySecrets []string `json:"privateKeySecrets,omitempty"`

	// Issuer, when non-empty, is the public URL the broker
	// stamps into the iss claim of every JWT it signs and
	// advertises in the OAuth 2.0 / OIDC discovery document
	// served at /.well-known/openid-configuration. Spec-
	// compliant downstreams (any GenericOidc consumer) can then
	// auto-discover the broker's JWKS without operator-side
	// per-field configuration. When Issuer is empty the
	// discovery handler is not registered; the JWKS endpoint
	// stays available unchanged.
	Issuer string `json:"issuer,omitempty"`
}

// EffectiveSigningSecrets returns the ordered list of named-
// secret references the broker should load and sign with. The
// helper resolves the PrivateKeySecret / PrivateKeySecrets
// either-or so callers do not have to branch on the single-vs-
// list shape themselves.
func (b *BrokerSignerConfig) EffectiveSigningSecrets() []string {
	if b == nil {
		return nil
	}
	if len(b.PrivateKeySecrets) > 0 {
		return b.PrivateKeySecrets
	}
	if b.PrivateKeySecret != "" {
		return []string{b.PrivateKeySecret}
	}
	return nil
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
	if c.NonceStore.Signed == nil {
		return fmt.Errorf("nonceStore: no backend configured; expected one of: signed")
	}
	if c.NonceStore.Signed.SigningKeyFile == "" {
		return fmt.Errorf("nonceStore.signed.signingKeyFile is required")
	}
	if c.NonceStore.Signed.TTL <= 0 {
		return fmt.Errorf("nonceStore.signed.ttl must be a positive duration")
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
	if c.BrokerSigner != nil {
		single := c.BrokerSigner.PrivateKeySecret
		list := c.BrokerSigner.PrivateKeySecrets
		switch {
		case single == "" && len(list) == 0:
			return fmt.Errorf("brokerSigner: one of privateKeySecret or privateKeySecrets is required")
		case single != "" && len(list) > 0:
			return fmt.Errorf("brokerSigner: privateKeySecret and privateKeySecrets are mutually exclusive")
		}
		for i, name := range c.BrokerSigner.EffectiveSigningSecrets() {
			if name == "" {
				return fmt.Errorf("brokerSigner.privateKeySecrets[%d] is empty", i)
			}
			if _, ok := c.Secrets[name]; !ok {
				return fmt.Errorf("brokerSigner: signing key %q does not name an entry in secrets", name)
			}
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

package app

import (
	"errors"
	"fmt"

	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/auth"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/config"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/destinations"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/policy"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/secrets"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/store"
)

// Validate loads the Jsonnet configuration at path, evaluates it,
// and runs every configuration-load-time check the broker performs
// at start-up, aggregating errors so an operator sees each problem
// in a single invocation rather than discovering them one at a time
// across successive broker restarts.
//
// Validate is the entry point for the `bb-credential-broker validate`
// subcommand. It is intentionally side-effect free: it does not bind
// network listeners, open outbound HTTP connections, read from AWS
// Secrets Manager, or start background goroutines. Operators can run
// it in CI or as a terragrunt-plan precondition.
func Validate(path string) error {
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	return ValidateConfig(cfg)
}

// ValidateConfig runs every configuration-load-time check the broker
// performs at start-up against an already-loaded Config and returns
// the aggregate of all errors discovered.
//
// app.New calls ValidateConfig before constructing the AWS-backed
// secret loader so that misconfiguration surfaces with the same
// error messages whether the operator runs `bb-credential-broker
// validate` ahead of time or discovers the problem at broker boot.
//
// ValidateConfig substitutes a no-op secret loader for the
// destinations registry: templated ${secret:NAME} references are
// resolved against the broker's configured secrets map (a name-only
// check), not against the underlying backend, so validation does
// not require AWS credentials or network reachability.
//
// Asymmetry worth flagging: the brokerSigner key's PEM is also
// only name-checked here against the secrets map. The PEM bytes
// themselves cannot be parsed without reaching the secret backend,
// so a malformed or wrong-type signing key surfaces only at the
// app.New code path. config.Validate covers the name reference;
// that is the most validate can do without AWS credentials.
func ValidateConfig(cfg *config.Config) error {
	if cfg == nil {
		return fmt.Errorf("config is nil")
	}

	var errs []error

	if _, err := auth.NewParser(cfg.JWTAuth); err != nil {
		errs = append(errs, fmt.Errorf("jwtAuth: %w", err))
	}
	if _, err := store.New(cfg.NonceStore); err != nil {
		errs = append(errs, fmt.Errorf("nonceStore: %w", err))
	}
	if _, err := policy.New(cfg.Policy); err != nil {
		errs = append(errs, fmt.Errorf("policy: %w", err))
	}
	if _, err := destinations.BuildRegistry(cfg.Destinations, destinations.Dependencies{
		Secrets:      secrets.NewMapLoader(),
		NamedSecrets: cfg.Secrets,
	}); err != nil {
		errs = append(errs, fmt.Errorf("destinations: %w", err))
	}

	return errors.Join(errs...)
}

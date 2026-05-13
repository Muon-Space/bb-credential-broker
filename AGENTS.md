# Contributor guide

## Architecture overview

`bb-credential-broker` is a small HTTP service. The package layout is:

```
cmd/bb-credential-broker/      Binary entry point.
pkg/app/                       Top-level dependency wiring.
pkg/config/                    Configuration schema and loader (Jsonnet).
pkg/auth/                      JWT validation and the Identity type.
pkg/store/                     Nonce store (interface + in-memory implementation).
pkg/secrets/                   Secret loader (interface + AWS Secrets Manager implementation).
pkg/policy/                    Per-identity policy resolver.
pkg/destinations/              Destination interface and registry.
  httptokenexchange/           Generic templated HTTP destination type.
    template/                  Templating language used by the type above.
pkg/handlers/                  HTTP handlers for /delegate, /token, /-/healthy, /metrics.
pkg/audit/                     Structured stdout audit logger.
examples/                      Operator-facing example configurations.
```

The dependency direction is strictly upward: `pkg/app` imports everything,
the handler package imports the data and policy packages, the
`httptokenexchange` package imports the templating package, and the
templating package depends only on the `secrets` and `auth` packages.

## Build and test

```sh
make build    # ./bin/bb-credential-broker
make test     # all unit tests
make lint     # golangci-lint
```

The container image is built with:

```sh
make docker-build
make docker-run    # mounts examples/config.jsonnet into the container
```

## Adding a new template function

The most common reason to extend the binary is to teach the templating
engine a new function. Each function lives in
`pkg/destinations/httptokenexchange/template/funcs.go`. To add a new one:

1. Implement the function and add it to the registry in `funcs.go`.
2. Add unit tests covering the happy path and each error mode in
   `funcs_test.go`.
3. Document the function in the templating reference table in `README.md`.

## Adding a new destination protocol

In most cases this does not require any binary change. New destination
protocols are expressed by writing a `httpTokenExchange` configuration in
the operator's Jsonnet file. The binary should only need to be modified
when an existing template function is insufficient to express the
destination's authentication flow.

## Coding conventions

- Doc comments on exported identifiers begin with the identifier name and
  end in a full stop.
- Inline comments explain why, not what.
- Errors returned to callers are wrapped with enough context to identify
  the operation that failed; in particular, errors that originate from
  configuration are wrapped with the name of the offending destination,
  secret or policy entry.
- Tests live next to the package they exercise. Table-driven tests are
  preferred for any code that has more than two distinct inputs.

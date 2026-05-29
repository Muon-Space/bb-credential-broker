# Contributor guide

## Architecture overview

`bb-credential-broker` is a small HTTP service. The package layout is:

```
cmd/bb-credential-broker/      Broker binary entry point.
cmd/egress-authd/              Egress sidecar binary entry point.
pkg/app/                       Top-level broker dependency wiring.
pkg/config/                    Broker configuration schema and loader (Jsonnet).
pkg/auth/                      JWT validation and the Identity type.
pkg/store/                     Nonce store (interface + signed-JWT implementation).
pkg/secrets/                   Secret loader (interface + AWS Secrets Manager implementation).
pkg/policy/                    Per-identity policy resolver.
pkg/destinations/              Destination interface and registry.
  httptokenexchange/           Generic templated HTTP destination type.
    template/                  Templating language used by the type above.
pkg/handlers/                  HTTP handlers for /delegate, /token, /-/healthy, /metrics.
pkg/audit/                     Structured stdout audit logger.
pkg/egressauthd/               Egress sidecar: control UDS server, per-action
                               forward proxy, broker /token client, token cache.
examples/                      Operator-facing example configurations.
```

The broker exposes exactly two credential endpoints: `POST /delegate`
(validate a CI/user JWT, mint a delegation grant scoped to a set of
destinations) and `POST /token` (exchange a grant for a destination
credential). There is no separate on-behalf-of mint path.

## egress-authd

`egress-authd` (`pkg/egressauthd/`, `cmd/egress-authd/`) is a sidecar that
runs next to a `bb-worker` and injects broker-minted credentials into an
action's outbound HTTP(S) traffic. It is a pure consumer of the broker's
existing `/token` endpoint — it adds **no** broker-side auth surface.

The worker obtains a delegation grant at `/delegate` (scoped to a set of
destinations), then registers an action over a Unix-domain control socket
passing that **grant**. The sidecar binds the grant to a per-action
loopback forward proxy (default: a plain-HTTP reverse-proxy that points
each tool at a per-tool index/registry override; `mitm` is the legacy
HTTPS_PROXY/CA path behind a flag) and returns the proxy port plus the
env (and, in loopback mode, config files) the worker injects into the
action. For each mapped destination host the proxy exchanges the grant
for a credential via `POST /token {"nonce": <grant>, "destination": …}`,
caches it per `(action, destination)`, and injects it as an
`Authorization` header before forwarding over TLS.

Authorization is the broker's: `/token` mints only for a destination the
grant was scoped to at `/delegate` (its `granted_destinations` set). The
sidecar therefore makes no authorization decision of its own; it fails
closed on a broker `403`, any error, an unknown action, or a request to a
host with no destination mapping. Every proxied request emits one
structured audit line (`{action_id, host, destination, decision}`).

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

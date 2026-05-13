# bb-credential-broker

`bb-credential-broker` mints short-lived, per-build-identity credentials for
actions running on Buildbarn Remote Execution workers. It allows workers to
hold zero long-lived secret material: each action carries a single-use nonce
that the worker exchanges for destination-scoped tokens at runtime.

The broker is intended to be deployed alongside `bb-storage`, `bb-scheduler`
and `bb-worker` inside the same Kubernetes namespace.

## How it works

Two endpoints, both speaking JSON over HTTP:

- `POST /delegate` — exposed externally; authenticated by bearer JWT.
  Validates the caller's JWT against the configured set of issuers, resolves
  the JWT claims to an `Identity`, and consults the per-identity policy to
  determine the set of destinations the caller is allowed to mint tokens
  for. Returns a single-use nonce with a short TTL.

- `POST /token` — exposed only inside the cluster; further restricted to a
  set of source CIDRs as defense-in-depth. Accepts a nonce together with the
  name of a destination, claims the nonce atomically, dispatches to the
  named destination's mint flow, and returns the freshly minted token.

The broker has no compiled-in knowledge of any particular destination
service. It contains a single generic destination type, `httpTokenExchange`,
that is parameterised entirely from the operator's configuration. Adding
support for a new destination protocol is a configuration change rather
than a code change.

## Configuration

Configuration is supplied as a single Jsonnet file, evaluated at start-up
and unmarshaled into the broker's configuration schema. See
[`examples/config.jsonnet`](./examples/config.jsonnet) for a worked example.

The top-level structure is:

```jsonnet
{
  apiServer:         { listenAddress: ':8080' },
  diagnosticsServer: { listenAddress: ':9980' },
  tokenAllowedCIDRs: ['10.0.0.0/8'],
  jwtAuth:    { issuers: [...] },
  nonceStore: { inMemory: { ttl: '15m', maxSize: 100000 } },
  secrets:    { 'name-of-secret': { awsSecretsManager: { arn, field } }, ... },
  destinations: {
    'destination-name': {
      httpTokenExchange: {
        request:  { method, url, headers, body },
        response: { tokenJsonPath, expiresInJsonPath OR expiresAtJsonPath },
      },
    },
    ...
  },
  policy: {
    ci:    [ { match: {...}, allowedDestinations: [...] }, ... ],
    users: [ { match: {...}, allowedDestinations: [...] }, ... ],
  },
}
```

### Templating

Any string field inside a destination's `request` block may contain
`${func[:arg[:arg...]]}` expressions. Arguments may themselves be `${...}`
expressions; the innermost expression is evaluated first.

| Function | Purpose | Example |
| --- | --- | --- |
| `${file:PATH}` | Read a file at request time. | `${file:/var/run/secrets/.../token}` |
| `${secret:NAME}` | Load a named secret via the configured loader. | `${secret:github-app-key}` |
| `${identity.PATH}` | Substitute a field from the resolved `Identity`. | `${identity.principal}`, `${identity.claims.email}` |
| `${json:VALUE}` | Serialise a value to a JSON string. | `${json:{originating_subject: "${identity.principal}"}}` |
| `${signjwt:ALG:KEYREF:CLAIMS}` | Sign a JWT and return the compact serialisation. | `${signjwt:RS256:${secret:gh-app-key}:${json:{iss:"123",iat:${now},exp:${now+540s}}}}` |
| `${now}` | Unix epoch seconds at evaluation time. | `${now}` |
| `${now+DUR}` | Unix epoch seconds plus a Go-style duration. | `${now+540s}`, `${now+10m}` |
| `${b64:STR}` | Base64 encode the argument. | `${b64:user:pass}` |
| `${env:VAR}` | Read an environment variable. Substituted at start-up rather than per request. | `${env:AWS_REGION}` |

## Building

```sh
make build         # ./bin/bb-credential-broker
make test          # unit tests
make lint          # golangci-lint
make docker-build  # multi-stage build, distroless/static runtime
make docker-run    # run the development image with examples/config.jsonnet
```

## Releases

Each push to `main` produces a fresh release. The release tag follows
the `${BUILD_SCM_TIMESTAMP}-${BUILD_SCM_REVISION}` convention used by
the rest of the Buildbarn project (e.g. `20260513T120000Z-abc1234`).

**Prebuilt binaries** are attached to each
[GitHub release](https://github.com/Muon-Space/bb-credential-broker/releases),
together with a `sha256` file covering every artifact. The set of
platforms built per release is:

| OS / arch          | Notes                                                  |
| ------------------ | ------------------------------------------------------ |
| `linux_amd64`      |                                                        |
| `linux_amd64_v3`   | Built with `GOAMD64=v3` (Haswell or newer).            |
| `linux_386`        |                                                        |
| `linux_arm`        | `GOARM=7`.                                             |
| `linux_arm64`      |                                                        |
| `darwin_amd64`     |                                                        |
| `darwin_arm64`     |                                                        |
| `freebsd_amd64`    |                                                        |
| `windows_amd64`    | Suffixed `.exe`.                                       |

**Container images** are published to the GitHub Container Registry:

```sh
docker pull ghcr.io/muon-space/bb-credential-broker:latest
```

Each release publishes the same multi-arch manifest under three tags:

- `ghcr.io/muon-space/bb-credential-broker:<release-tag>` — pinned
- `ghcr.io/muon-space/bb-credential-broker:<sha7>` — pinned (short git SHA)
- `ghcr.io/muon-space/bb-credential-broker:latest` — tracks the tip of `main`

`linux/amd64` and `linux/arm64` are both available behind the same
tag.

## Observability

`GET /metrics` on the diagnostics listener exposes the Prometheus
exposition format. Broker-specific collectors are namespaced under
`buildbarn_credential_broker_`:

| Metric | Type | Labels |
| --- | --- | --- |
| `buildbarn_credential_broker_delegate_requests_total` | Counter | `status`, `identity_type` |
| `buildbarn_credential_broker_delegate_duration_seconds` | Histogram | `status` |
| `buildbarn_credential_broker_token_requests_total` | Counter | `status`, `identity_type`, `destination` |
| `buildbarn_credential_broker_token_duration_seconds` | Histogram | `status`, `destination` |
| `buildbarn_credential_broker_mint_requests_total` | Counter | `destination`, `outcome` |
| `buildbarn_credential_broker_mint_duration_seconds` | Histogram | `destination`, `outcome` |

`status` is the HTTP status code emitted to the caller, as a string.
`identity_type` is `"ci"`, `"user"`, or empty when the request was
rejected before identity resolution (typically a JWT failure).
`destination` is the operator-chosen destination name and is empty when
the request did not reach destination dispatch. `outcome` is `"success"`
or `"error"`; finer-grained classification belongs in the audit log,
where the full error string is recorded.

Standard Go runtime metrics (`go_gc_duration_seconds`, `go_goroutines`,
etc.) are exposed alongside the broker collectors via the same
endpoint.

## License

Apache 2.0. See [`LICENSE`](./LICENSE).

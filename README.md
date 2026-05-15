# bb-credential-broker

`bb-credential-broker` mints short-lived, per-build-identity credentials for
actions running on Buildbarn Remote Execution workers. It allows workers to
hold zero long-lived secret material: each action carries a short-lived
delegation token that the worker exchanges for destination-scoped credentials
at runtime.

The broker is intended to be deployed alongside `bb-storage`, `bb-scheduler`
and `bb-worker` inside the same Kubernetes namespace.

## How it works

Two endpoints, both speaking JSON over HTTP:

- `POST /delegate` — exposed externally; authenticated by bearer JWT.
  Validates the caller's JWT against the configured set of issuers, resolves
  the JWT claims to an `Identity`, and consults the per-identity policy to
  determine the set of destinations the caller is allowed to mint tokens
  for. Returns a short-lived delegation token (a broker-signed JWT) and the
  granted destinations.

- `POST /token` — exposed only inside the cluster; further restricted to a
  set of source CIDRs as defense-in-depth. Accepts a delegation token
  together with the name of a destination, validates the token against the
  broker's signing key, dispatches to the named destination's mint flow,
  and returns the freshly minted credential.

The broker has no compiled-in knowledge of any particular destination
service. It ships two generic destination types parameterised entirely
from the operator's configuration: `httpTokenExchange`, which expresses
every mint flow as a templated HTTP request, and `staticSecret`, which
dispenses a credential read verbatim from a file on disk. Adding support
for a new destination protocol is a configuration change rather than a
code change.

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
  nonceStore: { signed: { signingKeyFile: '/etc/broker/signing-key', ttl: '5m' } },
  secrets:    { 'name-of-secret': { awsSecretsManager: { arn, field } }, ... },
  destinations: {
    'token-exchange-destination': {
      httpTokenExchange: {
        request:  { method, url, headers, body },
        response: { tokenJsonPath, expiresInJsonPath OR expiresAtJsonPath },
      },
    },
    'static-secret-destination': {
      staticSecret: {
        file:     '/etc/broker/destinations/<name>',  // K8s Secret mount
        scheme:   'bearer' | 'basic',                 // optional, default 'bearer'
        username: '<basic-auth username>',            // optional, used when scheme='basic'
        cacheTtl: '<go duration>',                    // optional, default '1h'
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

### Static-secret destinations

`httpTokenExchange` covers any destination whose API exposes a token-mint
endpoint. For systems that genuinely require a long-lived credential —
typically a personal access token for a service whose API does not
implement OIDC token-exchange — use a `staticSecret` destination instead.

The broker reads the credential from a file on disk on every `Mint`
call. The intended source is a Kubernetes Secret mounted into the
broker's pod; operators are free to populate the underlying Secret from
any backend already in use (External Secrets Operator syncing from AWS
Secrets Manager, CSI Secrets Store, Sealed Secrets, plain `kubectl`).
The broker itself only needs read access to the file at startup —
adding a new static-secret destination is an operator-side change to
the pod's volume mounts plus a new entry in the broker's `destinations`
map; no broker code change.

Per-identity policy gating still applies — a `staticSecret` destination
is only dispensed to callers whose `Identity` matches the policy below
— and every dispense is recorded in the audit log along with the
calling principal. Compared to "project the secret into every worker
pod" (Phase 0 in the design), the broker's role is to enforce
authorization on the dispense and to keep the credential out of every
non-broker pod's environment until it is actually requested.

The `/token` response carries the credential in the standard `token`
field. When `scheme: 'basic'` is configured, an additional `username`
field is populated and the worker-side credential helper should
construct an `Authorization: Basic base64(username:token)` header (this
is the convention git, npm, and OCI registries use when authenticating
with a personal access token). When `scheme: 'bearer'` (the default)
the `username` field is omitted and the helper should send
`Authorization: Bearer <token>`.

**Trade-off worth flagging.** A static credential is structurally
weaker than a per-build minted token: it is long-lived, leaks have
broader blast radius, and per-action revocation is impossible. Use this
destination type only when the upstream service forces it. Scope the
underlying credential as tightly as the upstream API allows (read-only,
single-resource scope where possible) and rotate the underlying Secret
out of band on whatever cadence your threat model demands. The broker
re-reads the file on every `Mint`, so the next dispense after rotation
returns the new value with no broker restart.

### Nonce store

`/delegate` returns a delegation token whose validity is determined entirely
by its signature. Any broker replica that holds the same signing key can
validate any other replica's tokens, which means the broker can be deployed
with `replica_count > 1` without a shared backend. The trade-off is that the
strict single-use property of an in-memory nonce is downgraded to "limited
use within the TTL window": a token may be claimed any number of times until
its expiry.

The signing key is HMAC-SHA-256 (HS256). Operators generate a key, mount it
into the broker's pod from a Kubernetes Secret, and reference its file path
from the broker's configuration:

```sh
# Generate a 32-byte random key on a workstation.
openssl rand 32 > broker-signing-key

# Stage it as a Kubernetes Secret.
kubectl create secret generic bb-credential-broker-signing-key \
  --from-file=key=broker-signing-key

# Mount it into the broker's pod (excerpt):
#   volumes:
#     - name: signing-key
#       secret: { secretName: bb-credential-broker-signing-key }
#   volumeMounts:
#     - name: signing-key
#       mountPath: /etc/broker
#       readOnly: true
#
# And reference the file from the broker's config:
#   nonceStore: { signed: { signingKeyFile: '/etc/broker/key', ttl: '5m' } }
```

The broker requires at least 32 bytes (256 bits) of key material, which is
the minimum recommended for HS256 by RFC 7518 §3.2. Key rotation is a pod
restart with the new key in place; this release does not implement kid-based
key sets.

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

### Audit log

Every `/delegate` and `/token` request emits a single JSON line on
stdout, suitable for ingestion by the cluster's log-collection stack.
Each record carries the operation (`delegate` or `token`), the
resolved identity type and principal, the destination (for `/token`),
the granted destinations (for `/delegate`), the success flag, and on
failure the underlying reason. Token values, secret material and
request bodies never appear.

The error string for `/token` rejections preserves the underlying
reason from the signed-token validator (`token is expired`,
`signing method HS512 is invalid`, `token has invalid issuer`, etc.)
even though the HTTP response to the caller is uniformly `410 Gone`
with body `nonce is not valid`. Operators can therefore distinguish
routine token expiry from active forgery attempts in the audit log
without leaking the distinction to clients.

## License

Apache 2.0. See [`LICENSE`](./LICENSE).

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
| `${default:EXPR:FALLBACK}` | Evaluate `EXPR`; return `FALLBACK` if `EXPR` fails for any reason (missing variable, missing secret, file read error, etc.). Both arguments are templates and may contain nested `${...}` expressions. | `${default:${identity.claims.classification}:unclassified}` |
| `${json:KEY:VALUE:KEY:VALUE:...}` | Construct a JSON object. Each VALUE is a template; the result is auto-typed (numbers/booleans/null/pre-quoted strings/objects/arrays pass through verbatim, bare strings are JSON-escaped and quoted). Key order follows the operator-supplied argument order, not lexicographic sort. Used internally by the canonical broker-signed-JWT pattern to avoid hand-written braces, commas and quotes. | `${json:iat:${now}:sub:${identity.principal}}` |

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

### Broker-signed JWTs

Some destination services — JFrog's OAuth 2.0 token-exchange
endpoint (`/access/api/v1/oidc/token`) is the motivating example —
evaluate identity-mapping conditions only against the claims
inside the JWT carried as `subject_token`. Any request-body
extension that names additional claims for the mapping engine to
consider is silently dropped, so an operator who needs the
broker's `Identity` to drive scoping on the downstream side has
to forward those claims **inside the signed token**, not alongside
it.

The broker supports this by minting an RS256-signed JWT inline in
the destination's template, and by publishing the corresponding
public key at `/.well-known/jwks.json` on the API listener so the
downstream service can verify the signature.

#### Configuring the broker

Operators stage an RSA private key as a named secret and reference
it from a new top-level `brokerSigner` block:

```sh
# Generate a 2048-bit RSA key.
openssl genrsa -out broker-signing-key.pem 2048

# Stage in AWS Secrets Manager (the broker's default loader
# backend); operators using other backends register the key via
# their existing mechanism.
aws secretsmanager create-secret \
  --name bb-credential-broker/signing-key \
  --secret-string "$(jq -Rs '{private_key: .}' < broker-signing-key.pem)"
```

```jsonnet
{
  secrets: {
    'broker-signing-key': {
      awsSecretsManager: {
        arn:   'arn:aws:secretsmanager:...:bb-credential-broker/signing-key',
        field: 'private_key',
      },
    },
  },
  brokerSigner: {
    privateKeySecret: 'broker-signing-key',
    // Optional. When set, the broker also registers
    // /.well-known/openid-configuration so spec-compliant
    // downstreams (any GenericOidc consumer) auto-discover the
    // JWKS endpoint instead of being configured per-field.
    issuer: 'https://broker.example.com',
  },
}
```

When `brokerSigner` is present the broker registers a
`GET /.well-known/jwks.json` handler on the API listener (the
same listener `/delegate` and `/token` sit behind) returning a
single-key JWKS. If `brokerSigner.issuer` is also set the broker
registers `GET /.well-known/openid-configuration` returning a
minimal OAuth 2.0 / OIDC discovery document so downstreams can
auto-discover the JWKS URI. The JWKS body shape:

```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": "<RFC 7638 JWK thumbprint of the public key>",
      "n":   "<base64url modulus>",
      "e":   "AQAB"
    }
  ]
}
```

The endpoint is unauthenticated (a JSON Web Key Set is intended
to be public) and is served with `Cache-Control: max-age=300` so
downstream verifiers do not pound the API listener.

#### Using the key from a destination template

`${signjwt:RS256:${secret:NAME}:CLAIMS-JSON}` produces a compact
JWT signed with the named key. The function always stamps the
RFC 7638 JWK thumbprint of the public key into the `kid` header —
deterministic from the key alone, matching what the JWKS endpoint
publishes. Downstream verifiers resolve the right key without
operator coordination:

```jsonnet
'token-exchange-via-broker-jwt': {
  httpTokenExchange: {
    request: {
      method: 'POST',
      url:    'https://destination.example.com/access/api/v1/oidc/token',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: { form: {
        grant_type:         'urn:ietf:params:oauth:grant-type:token-exchange',
        subject_token_type: 'urn:ietf:params:oauth:token-type:id_token',
        subject_token:
          '${signjwt:RS256:${secret:broker-signing-key}:${json:' +
          'iss:"https://broker.example.com":' +
          'sub:${identity.principal}:' +
          'iat:${now}:' +
          'exp:${now+300s}:' +
          'aud:"destination-token-exchange":' +
          'team:${default:${identity.claims.team}:unknown}' +
          '}}',
        provider_name: 'bb-credential-broker',
      } },
    },
    response: { tokenJsonPath: 'access_token', expiresInJsonPath: 'expires_in' },
  },
}
```

`${json:...}` is the recommended way to construct the signjwt
claims body: it auto-types each value (numbers stay unquoted,
runtime strings get JSON-escaped and quoted, pre-quoted literals
pass through verbatim) and key order follows the operator-supplied
argument order. Operators who prefer to write the JSON literally
can still pass a JSON object as `signjwt`'s third argument
directly and wrap runtime strings in `${jsonString:...}`.

#### Tuning the JWT for a specific downstream

`subject_token_type`, `sub`, and `aud` are deliberately
operator-tunable in the template above because the right value
for each depends on what the downstream OIDC provider validates:

- **`subject_token_type`.** RFC 8693 §3 defines both
  `urn:ietf:params:oauth:token-type:jwt` (generic JWT) and
  `urn:ietf:params:oauth:token-type:id_token` (OIDC ID Token).
  A broker-signed JWT is technically the former, but some
  downstreams (JFrog among them) historically accept only
  `:id_token`. The example defaults to `:id_token` because it is
  the broadly-accepted shape; operators whose downstream documents
  `:jwt` set that value instead.
- **`sub`.** Downstream identity-mapping engines typically gate
  on `sub`. Operators whose existing mappings expect a fixed
  service-account subject (`system:serviceaccount:NAMESPACE:NAME`,
  for example) hard-code that string. Operators who want each
  mapping to pivot on the originating CI principal forward
  `${jsonString:${identity.principal}}` as the example does.
- **`aud`.** Set this to whatever the downstream OIDC provider
  registers as its expected audience, or omit it entirely if the
  provider does not validate audience.

`examples/config.jsonnet` carries a worked end-to-end example
under the `artifactory-prod` destination.

#### Higher-level destination type for the common case

For destinations that follow the canonical pattern — an RFC 8693
token-exchange endpoint, broker-signed JWT as `subject_token`,
form-encoded body — the `oidcTokenExchange` destination type
packages the boilerplate into a type-safe block. Operators write
only the fields downstream identity mappings actually look at:

```jsonnet
'token-exchange': {
  oidcTokenExchange: {
    url:          'https://destination.example.com/access/api/v1/oidc/token',
    providerName: 'bb-credential-broker',
    subjectToken: {
      signedJWT: {
        signingKey: 'broker-signing-key',
        issuer:     'https://broker.example.com',
        subject:    '${identity.principal}',
        audience:   'destination-token-exchange',
        ttl:        '5m',
        claims: {
          team: '${default:${identity.claims.team}:unknown}',
        },
      },
    },
    response: { tokenJsonPath: 'access_token', expiresInJsonPath: 'expires_in' },
  },
}
```

The broker compiles this down to an equivalent `httpTokenExchange`
config at start-up: the form body is assembled correctly, the
`subject_token` is constructed via `signjwt` + `json` with the
right `iat` / `exp` / `kid`, and the response shape passes
through verbatim. Bug fixes and feature additions to
`httpTokenExchange` benefit both types because there is only one
HTTP code path.

Drop down to `httpTokenExchange` directly for destinations whose
request shape needs custom headers, non-form bodies, or anything
else the higher-level type does not cover.

#### Registering the broker as an OIDC provider downstream

For a JFrog deployment the recipe is:

1. **Manage Integrations → OIDC Integrations → New Integration**.
   - Provider Type: `GenericOidc`.
   - Issuer URL: the value the broker stamps into `iss` (must
     match exactly).
   - JWKS URL: `<broker-url>/.well-known/jwks.json`.
   - Audience (if your JFrog version requires one): match the
     `aud` your destination template embeds.
2. Configure one or more **Identity Mappings** on the new
   provider whose `Claims JSON` matches the claims your
   destination template forwards.

Other generic-OIDC consumers follow the same shape: point them at
the broker's issuer URL and JWKS endpoint, configure mappings
against the claims you forward.

#### Key rotation

The `privateKeySecret` shape (single key) supports rotation by
pod restart with the new key in place — same model the HMAC
nonce-store signing key uses. The kid changes deterministically
when the key changes, so downstream verifiers (which cache by
kid) automatically re-fetch the JWKS the next time they see a
JWT with an unknown kid. The trade-off is a window of up to the
JWKS `Cache-Control: max-age` (default 300 seconds) during which
downstream caches reject newly-signed JWTs.

For zero-downtime rotation, use the `privateKeySecrets` list
shape instead. The broker publishes every key in the JWKS while
signing only with the first; operators rotate by reordering the
list across two pod restarts:

```jsonnet
// Step 1: stage the new key as a second list entry, restart pods.
// JWKS now publishes both keys; broker still signs with key-v1.
brokerSigner: {
  privateKeySecrets: ['broker-key-v1', 'broker-key-v2'],
}

// Step 2: wait the JWKS Cache-Control window (default 300s) for
// downstream verifiers to re-fetch and learn the new key.

// Step 3: reorder the list so the new key is first, restart pods.
// Broker now signs with key-v2; key-v1 stays in the JWKS so any
// straggler JWT signed during the change-over window still
// verifies.
brokerSigner: {
  privateKeySecrets: ['broker-key-v2', 'broker-key-v1'],
}

// Step 4: wait the cache window again.

// Step 5: drop the old key, restart pods. Single-key state.
brokerSigner: {
  privateKeySecrets: ['broker-key-v2'],
}
```

`privateKeySecret` and `privateKeySecrets` are mutually exclusive
— the broker rejects configurations that set both at load time.

### Body encoding gotcha

`body.json` rejects a specific footgun pattern at configuration
load: a leaf string that contains BOTH a template expression
(`${...}`) AND a literal `"` character. The configuration loader
points operators at the offending leaf path and recommends
`body.form` or `body.raw` instead.

The reason is subtle: the broker stores `body.json` as
JSON-serialised bytes and runs the template parser across them,
but the parser tracks string-literal nesting inside function
arguments via an unescaped `"` toggle. A template argument that
includes literal `"` characters becomes `\"` after JSON encoding;
the first `\"` flips the parser into "inside string", every
subsequent `\"` keeps it there, and the parser eventually
surfaces an `unterminated argument` error far from the offending
byte.

The check is deliberately narrow:

- `"${secret:my-bearer-token}"` — passes (template but no literal quote).
- `"${identity.principal}"` — passes (template but no literal quote).
- `"static \"quoted\" value"` — passes (literal quotes but no template).
- `"${signjwt:RS256:k:{\"iss\":\"x\"}}"` — rejected (template argument
  carries inline JSON whose quotes will JSON-escape into the
  footgun pattern).

The shapes that work for templated bodies:

- **`body.form`** — each key/value pair is templated in isolation
  and URL-encoded at request time. The canonical shape for
  RFC 8693 token-exchange endpoints.
- **`body.raw`** — one opaque templated payload. Combine with an
  explicit `Content-Type` header. The recommended shape when the
  body needs to be JSON-shaped: use `${json:...}` (see the
  Templating table) to construct the JSON object, set
  `Content-Type: application/json` in `request.headers`.

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

## Operating

The broker has a single executable with three subcommand forms:

```sh
bb-credential-broker <config.jsonnet>                        # run the broker
bb-credential-broker validate <config.jsonnet>               # check configuration
bb-credential-broker render --identity FILE \                # dry-run a destination
  [--secret name=value ...] [--output request|jwt|url] \
  <config.jsonnet> <destination>
```

The `validate` subcommand loads the configuration and runs every
check the broker performs at start-up — Jsonnet evaluation, JWKS
file parsing, signing-key length, CIDR syntax, secret-ref name
resolution, policy entry compilation, destination template parsing
— and exits 0 when the configuration is valid or non-zero with an
aggregated error list when it is not. The subcommand does not bind
network listeners, open outbound HTTP connections, read AWS Secrets
Manager, or start background goroutines.

Run it in CI as a gate on changes to the deployment's configuration
inputs, or as a `terragrunt plan` precondition so misconfiguration
is caught at PR review time rather than when the broker pod fails
to start in cluster.

The `render` subcommand prints the exact HTTP request the broker
would dispatch for a given destination + identity pair, without
actually dispatching it. Use it to iterate on destination templates
locally instead of redeploying the broker and tailing audit logs.
The real secret loader is replaced with an in-memory map seeded
from `--secret name=value` flags, so AWS credentials are not
required. The `--identity` flag points at a JSON file shaped like
the broker's internal `Identity`:

```json
{
  "type":      "ci",
  "principal": "repo:owner/repo:ref:refs/heads/main",
  "claims":    {"actor": "alice", "repository": "owner/repo"}
}
```

`--output` defaults to `request` (curl-friendly representation of
the full HTTP request); `--output jwt` decodes any `subject_token`
form field as a JWT and prints its header and claims; `--output url`
prints just the resolved URL. Destinations that mint locally (the
`staticSecret` type) have no HTTP request to render and surface a
friendly message instead.

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
stdout. The line is written synchronously and is flushed before the
HTTP response is sent so an audit entry is never lost to a caller
disconnect mid-request.

Token values, secret material and request bodies never appear in
audit output. The HTTP responses returned to callers stay opaque —
the audit log retains the operator-readable detail under
`denial_reason`.

#### Schema

The published shape is a stable interface; downstream Loki / Grafana
dashboards consume it. Any change to a field that is not strictly
additive constitutes a schema break and requires a coordinated
rollout.

`/delegate` (one line per request):

```json
{
  "ts": "2026-05-21T10:23:45.123Z",
  "event": "delegate",
  "identity": {
    "type": "ci",
    "principal": "repo:owner/repo:ref:refs/heads/main",
    "claims": { /* every claim from the validated JWT, verbatim */ }
  },
  "result": "granted",
  "granted_destinations": ["artifactory", "github-app"],
  "delegation_token_jti": "<jti claim from issued JWT>",
  "delegation_token_exp": "2026-05-21T10:28:45Z"
}
```

On denial: `"result": "denied"`, `identity` may be `null` for
pre-resolution rejections, and `denial_reason` carries one of the
canonical reasons documented below. `identity.claims` is always an
object (never `null`); the empty object indicates a JWT carrying no
claims beyond `iss`/`sub`/`aud`/`exp`/`iat`.

`/token` (one line per request):

```json
{
  "ts": "2026-05-21T10:24:01.456Z",
  "event": "token",
  "identity": { /* same shape as above */ },
  "destination": "artifactory",
  "result": "success",
  "upstream_url": "https://artifactory.example.com/access/api/v1/oidc/token",
  "upstream_status": 200,
  "upstream_duration_ms": 123,
  "token_expires_at": "2026-05-21T10:39:01Z"
}
```

On failure: `"result": "failure"`, `denial_reason` carries the
canonical reason, and `upstream_response_excerpt` carries the
first 256 bytes of the upstream response body (only for upstream
non-success status codes).

Destinations that perform no upstream call — the `staticSecret`
type — omit the `upstream_url`, `upstream_status`,
`upstream_duration_ms` and `upstream_response_excerpt` fields
entirely.

#### Canonical denial reasons

`/delegate`:
- `missing or malformed Authorization header`
- `jwt validation failed: <underlying error>`
- `malformed request body`
- `requested_destinations must not be empty`
- `policy resolution error: <underlying error>`
- `no policy entry matched identity`
- `requested destination not in granted set: <destination>`
- `nonce mint failed: <underlying error>`

`/token`:
- `source address is not permitted`
- `malformed request body`
- `nonce and destination are required`
- `nonce is not valid: <underlying error>`
- `destination is not granted by this nonce`
- `destination is not configured`
- `destination mint failed: <underlying error>`

The `<underlying error>` suffixes preserve the verifier's reason
(`token is expired`, `signing method HS512 is invalid`, etc.) so
operators can distinguish routine expiry from active forgery
attempts without leaking the distinction to clients.

## License

Apache 2.0. See [`LICENSE`](./LICENSE).

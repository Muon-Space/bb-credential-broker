// Example bb-credential-broker configuration. The shape mirrors the
// schema documented in pkg/config/config.go. Three destinations are
// configured below to illustrate the standard patterns:
//
//   - artifactory-prod: an RFC 8693 OAuth 2.0 token-exchange flow,
//     using the broker's projected ServiceAccount JWT as the
//     subject token.
//   - github-app:       a GitHub App installation token mint, where
//     the broker signs an RS256 App JWT and exchanges it for a
//     short-lived installation token.
//   - vault-jwt:        a Vault auth/jwt/login flow that returns a
//     client token in exchange for a JWT proof of identity.
//
// Adding a fourth destination is purely a configuration change: the
// broker contains no protocol-specific code beyond the generic
// httpTokenExchange type used here.

{
  apiServer: {
    listenAddress: ':8080',
    readTimeout:   '10s',
    writeTimeout:  '10s',
  },
  diagnosticsServer: {
    listenAddress: ':9980',
  },

  // Defense in depth: /token requests must originate from one of
  // the listed CIDRs (typically the bazel-cache namespace's pod
  // CIDR). The NetworkPolicy that fronts the broker is the primary
  // gate; this list is the secondary check inside the binary.
  tokenAllowedCIDRs: ['10.0.0.0/8'],

  jwtAuth: {
    issuers: [
      {
        url:          'https://token.actions.githubusercontent.com',
        jwksFile:     '/etc/jwks/github-jwks.json',
        audience:     'bb-credential-broker',
        identityType: 'ci',
      },
      {
        url:          'https://idp.example.com/oauth2/default',
        jwksFile:     '/etc/jwks/okta-jwks.json',
        identityType: 'user',
      },
    ],
  },

  // The signed nonce store is stateless: tokens issued by one broker
  // replica are valid for any other replica that holds the same
  // signing key. This allows the broker to scale horizontally without
  // a shared backend. The trade-off is that the strict single-use
  // guarantee of an in-memory store is relaxed to "limited-use within
  // the TTL window".
  //
  // The signing key is read from disk at startup. Operators typically
  // mount the file from a Kubernetes Secret. Generate the key with
  // a tool such as `openssl rand 32 > key`; the broker requires at
  // least 32 bytes of key material.
  nonceStore: {
    signed: {
      signingKeyFile: '/etc/broker/signing-key',
      ttl:            '5m',
    },
  },

  // Named secrets are fetched lazily at the first ${secret:NAME}
  // reference and cached for the loader's TTL. The broker's IRSA
  // policy enumerates the ARNs listed below.
  secrets: {
    'github-app-key': {
      awsSecretsManager: {
        arn:   'arn:aws:secretsmanager:us-east-1:000000000000:secret:bb-credential-broker/github-app',
        field: 'private_key',
      },
    },
    // PEM-encoded RSA private key the broker uses to sign its
    // own subject_token JWTs (see the artifactory-prod
    // destination below). The public half is derived at startup
    // and published at /.well-known/jwks.json on the API
    // listener.
    'broker-signing-key': {
      awsSecretsManager: {
        arn:   'arn:aws:secretsmanager:us-east-1:000000000000:secret:bb-credential-broker/signing-key',
        field: 'private_key',
      },
    },
  },

  // Enable the broker's own JWT signing path. When this block is
  // present the broker exposes /.well-known/jwks.json on the API
  // listener carrying the public half of the named key.
  // Destinations whose downstream evaluates identity-mapping
  // claims only inside the JWT carried as subject_token (notably
  // any OAuth 2.0 token-exchange endpoint that silently drops
  // request-body extensions) reference the same named secret in
  // a ${signjwt:RS256:${secret:broker-signing-key}:...}
  // expression. The kid the broker stamps into each JWT header
  // matches the kid published in the JWKS, so downstream
  // verifiers resolve the right key without operator
  // coordination.
  brokerSigner: {
    privateKeySecret: 'broker-signing-key',
    // Issuer is the public URL the broker stamps into the iss
    // claim of every JWT it signs and advertises via
    // /.well-known/openid-configuration. Set this so spec-
    // compliant downstreams can auto-discover the JWKS endpoint
    // rather than be configured per-field.
    issuer: 'https://bb-credential-broker.example.com',
  },

  destinations: {
    // Canonical OAuth 2.0 / RFC 8693 token-exchange destination
    // (Artifactory's /access/api/v1/oidc/token is the worked
    // example, but the same shape applies to any RFC 8693
    // endpoint that evaluates identity-mapping claims only
    // against the JWT carried in subject_token). The
    // oidcTokenExchange destination type packages the
    // boilerplate — form encoding, signjwt construction,
    // iat/exp wiring, kid alignment with /.well-known/jwks.json
    // — into a type-safe config block; operators write only the
    // fields downstream identity mappings actually look at.
    //
    // For destinations whose request shape needs custom headers
    // or a non-form body, drop down to the lower-level
    // httpTokenExchange type (see the github-app example below
    // for that shape).
    'artifactory-prod': {
      oidcTokenExchange: {
        url:          'https://artifactory.example.com/access/api/v1/oidc/token',
        providerName: 'bb-credential-broker',
        subjectToken: {
          signedJWT: {
            signingKey: 'broker-signing-key',
            issuer:     'https://bb-credential-broker.example.com',
            // 'subject' is the JWT's sub claim. Operators tune
            // this to whatever the downstream identity-mapping
            // engine pivots on. Forwarding the originating CI
            // principal lets mappings gate per-build; hard-
            // coding a service-account string is the right
            // choice when existing mappings already expect one.
            subject:    '${identity.principal}',
            audience:   'artifactory-token-exchange',
            ttl:        '5m',
            claims: {
              // Each value is a template; the broker auto-types
              // it (numbers stay unquoted, runtime strings get
              // JSON-escaped and quoted).
              team: '${default:${identity.claims.team}:unknown}',
            },
          },
        },
        response: {
          tokenJsonPath:     'access_token',
          expiresInJsonPath: 'expires_in',
        },
      },
    },

    'github-app': {
      httpTokenExchange: {
        request: {
          method: 'POST',
          url:    'https://api.github.com/app/installations/12345678/access_tokens',
          headers: {
            'Accept':        'application/vnd.github+json',
            'Content-Type':  'application/json',
            'Authorization': 'Bearer ${signjwt:RS256:${secret:github-app-key}:${json:iss:"123456":iat:${now}:exp:${now+540s}}}',
          },
          // body.raw with an explicit application/json Content-Type
          // is the recommended shape for templated JSON bodies;
          // body.json is rejected at configuration load for
          // templated values (see README "Body encoding gotcha").
          //
          // GitHub's installation-token API expects a list of
          // "owner/repo" strings under repositories. The ${json:...}
          // helper builds the array as a one-element JSON array via
          // a string-typed value, then this raw template wraps the
          // outer object.
          body: { raw:
            '{"repositories":[${jsonString:${identity.claims.repository}}],' +
            '"permissions":{"contents":"read"}}',
          },
        },
        response: {
          expectStatus:      201,
          tokenJsonPath:     'token',
          expiresAtJsonPath: 'expires_at',
        },
      },
    },

    'vault-jwt': {
      httpTokenExchange: {
        request: {
          method: 'POST',
          url:    'https://vault.example.com/v1/auth/jwt/login',
          headers: {
            'Content-Type': 'application/json',
          },
          // body.raw + explicit Content-Type for templated JSON
          // (body.json is rejected at configuration load for
          // templated values; see README "Body encoding gotcha").
          body: { raw:
            '${json:jwt:${file:/var/run/secrets/eks.amazonaws.com/serviceaccount/token}:role:"bb-credential-broker"}',
          },
        },
        response: {
          expectStatus:      200,
          tokenJsonPath:     'auth.client_token',
          expiresInJsonPath: 'auth.lease_duration',
        },
      },
    },

    // staticSecret dispenses a credential read verbatim from a file
    // on disk. The intended source is a Kubernetes Secret mounted
    // into the broker's pod; operators are free to populate the
    // underlying Secret from any backend (External Secrets Operator
    // syncing from AWS Secrets Manager, CSI Secrets Store, Sealed
    // Secrets, manual kubectl). The broker itself only needs read
    // access to the file at startup.
    //
    // The destination is appropriate for credentials that genuinely
    // cannot be minted on demand — typically long-lived personal
    // access tokens for systems whose API does not expose an OIDC
    // token-exchange flow (GitHub Enterprise package reads, for
    // example, accept only PATs or GitHub Actions tokens; the broker
    // cannot mint the latter). Per-identity policy gating still
    // applies — only callers whose Identity matches the policy below
    // can request the credential — and every dispense is recorded in
    // the audit log.
    'ghe-packages-pat': {
      staticSecret: {
        // Mount your K8s Secret at this path. Example pod spec:
        //   volumes:
        //     - name: ghe-pat
        //       secret: { secretName: ghe-packages-pat }
        //   volumeMounts:
        //     - name: ghe-pat
        //       mountPath: /etc/broker/destinations/ghe-packages-pat
        //       subPath:   token
        //       readOnly:  true
        file:     '/etc/broker/destinations/ghe-packages-pat',
        scheme:   'basic',
        username: 'x-access-token',
        cacheTtl: '1h',
      },
    },
  },

  // Per-identity policy. Each match key is a dotted path into the
  // resolved Identity (one of "principal", "type" or
  // "claims.<your-claim-name>"); each value selects an operator
  // (equals, glob, in) and the operand to compare against. Multiple
  // keys are AND-combined.
  //
  // The broker has no compiled-in knowledge of any specific claim
  // name. Operators whose identity provider emits custom claims
  // (such as a tier indicator, an export-control flag, a project
  // tag, etc.) match against those claims by name here.
  policy: {
    ci: [
      {
        match:               { 'claims.repository': { equals: 'example-org/example-repo' } },
        allowedDestinations: ['artifactory-prod', 'github-app', 'ghe-packages-pat'],
      },
      {
        match:               { 'claims.repository': { glob: 'example-org/*' } },
        allowedDestinations: ['artifactory-prod'],
      },
    ],
    users: [
      {
        // Demonstrates matching against an arbitrary IDP-emitted
        // claim. Replace 'tier' with whatever attribute your
        // identity provider attaches to user tokens.
        match:               { 'claims.tier': { equals: 'internal' } },
        allowedDestinations: ['artifactory-prod', 'vault-jwt'],
      },
      {
        // Demonstrates matching against an array-valued claim.
        // OIDC providers such as Okta emit group membership as a
        // JSON array under the 'groups' claim natively; the
        // contains operator inspects the array and matches when
        // the named value is present.
        match:               { 'claims.groups': { contains: 'bazel-broker-itar' } },
        allowedDestinations: ['artifactory-prod'],
      },
    ],
  },
}

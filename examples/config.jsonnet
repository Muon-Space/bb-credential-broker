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
  },

  destinations: {
    'artifactory-prod': {
      httpTokenExchange: {
        request: {
          method: 'POST',
          url:    'https://artifactory.example.com/access/api/v1/oidc/token',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: { form: {
            grant_type:         'urn:ietf:params:oauth:grant-type:token-exchange',
            subject_token_type: 'urn:ietf:params:oauth:token-type:id_token',
            subject_token:      '${file:/var/run/secrets/eks.amazonaws.com/serviceaccount/token}',
            provider_name:      'eks-bazel-cache',
            additional_claims:  '{"originating_subject":${jsonString:${identity.principal}}}',
          } },
        },
        response: {
          expectStatus:      200,
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
            'Authorization': 'Bearer ${signjwt:RS256:${secret:github-app-key}:{"iss":"123456","iat":${now},"exp":${now+540s}}}',
          },
          body: { json: {
            // GitHub's installation-token API expects a list of
            // "owner/repo" strings. Many CI OIDC tokens emit this
            // as the standard "repository" claim; templates may
            // reference any other claim if your IDP names it
            // differently.
            repositories: ['${identity.claims.repository}'],
            permissions:  { contents: 'read' },
          } },
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
          body: { json: {
            jwt:  '${file:/var/run/secrets/eks.amazonaws.com/serviceaccount/token}',
            role: 'bb-credential-broker',
          } },
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

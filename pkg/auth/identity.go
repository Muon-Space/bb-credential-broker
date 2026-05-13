// Package auth contains the types and helpers used to validate the
// bearer JWTs presented to the broker's /delegate endpoint and to
// translate the validated claims into a credential-mint Identity.
package auth

import (
	"fmt"
	"maps"
)

// IdentityType distinguishes between the two principal kinds of caller
// the broker recognises: machine identities derived from CI workflow
// OIDC tokens, and human identities derived from interactive identity
// provider tokens.
type IdentityType string

const (
	// IdentityTypeCI is the IdentityType used for callers that
	// authenticated using an OIDC token issued by a continuous
	// integration provider, e.g. GitHub Actions.
	IdentityTypeCI IdentityType = "ci"

	// IdentityTypeUser is the IdentityType used for callers that
	// authenticated using a token issued by an interactive identity
	// provider, e.g. an OIDC provider used by a developer's local
	// credential helper.
	IdentityTypeUser IdentityType = "user"
)

// Identity is the resolved view of the caller of /delegate. It is the
// result of validating the caller's JWT, deciding which IdentityType
// applies, and copying the relevant claims out of the token into a
// stable shape that the rest of the broker can consume.
//
// Identity is the unit on which the policy engine operates and the
// value passed to template functions as ${identity.PATH}.
type Identity struct {
	// Type indicates whether this Identity describes a CI workflow
	// or an interactive user.
	Type IdentityType

	// Principal is a stable, human-readable string that uniquely
	// identifies the caller. For CI identities this is the JWT's
	// sub claim (e.g. "repo:owner/repo:ref:refs/heads/main"). For
	// user identities this is typically the email address.
	Principal string

	// Claims is the map of token claims, extended with any
	// synthetic fields materialised by the resolver. Template
	// expressions of the form ${identity.claims.KEY} read from
	// this map.
	Claims map[string]any
}

// ResolveIdentity constructs an Identity from a set of validated JWT
// claims and the IdentityType associated with the issuing source.
//
// The returned Identity carries every original claim verbatim. The
// broker does not derive any synthetic claims; operators that want
// fields such as a normalised repository name should match against
// whatever claim their identity provider emits natively.
//
// Principal is selected by IdentityType:
//
//   - IdentityTypeCI uses the standard JWT "sub" claim, which the
//     broker treats as the canonical, opaque identifier of the
//     calling CI workflow.
//
//   - IdentityTypeUser prefers the "email" claim when present and
//     falls back to "sub" otherwise. Both are RFC 7519 standard
//     claims emitted by mainstream OIDC providers.
//
// ResolveIdentity returns an error if the claims do not contain the
// fields required to populate Principal for the given IdentityType.
func ResolveIdentity(t IdentityType, claims map[string]any) (*Identity, error) {
	if claims == nil {
		return nil, fmt.Errorf("identity: claims map is nil")
	}

	// Defensive copy so callers cannot mutate the broker's view
	// of the claims after the fact.
	enriched := make(map[string]any, len(claims))
	maps.Copy(enriched, claims)

	id := &Identity{Type: t, Claims: enriched}

	switch t {
	case IdentityTypeCI:
		sub, ok := claims["sub"].(string)
		if !ok || sub == "" {
			return nil, fmt.Errorf("identity: ci token has no string sub claim")
		}
		id.Principal = sub
	case IdentityTypeUser:
		if email, ok := claims["email"].(string); ok && email != "" {
			id.Principal = email
		} else if sub, ok := claims["sub"].(string); ok && sub != "" {
			id.Principal = sub
		} else {
			return nil, fmt.Errorf("identity: user token has neither email nor sub claim")
		}
	default:
		return nil, fmt.Errorf("identity: unknown identity type %q", t)
	}

	return id, nil
}

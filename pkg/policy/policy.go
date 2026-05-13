// Package policy resolves the set of destination names that a given
// Identity is permitted to mint tokens for.
//
// The policy schema is defined in this package so that the
// configuration loader can validate it without taking a dependency
// on the broker's destination types. Policy evaluation is independent
// of which destinations are actually configured; the handler layer
// is responsible for intersecting the policy result with the set of
// destinations the operator wired up.
//
// The matcher schema is intentionally claim-driven. The operator
// nominates which fields of the Identity to match against by
// supplying dotted paths (for example "claims.repository" or
// "principal"); the broker has no compiled-in knowledge of any
// specific claim name. Operators whose identity provider emits
// custom claims can match against those claims without changes to
// the broker.
package policy

import (
	"fmt"
	"path"
	"slices"
	"strings"

	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/auth"
)

// Config is the policy section of the broker's top-level
// configuration.
type Config struct {
	// CI lists the policy entries evaluated for IdentityTypeCI
	// callers, in order. The first entry whose Match expression
	// evaluates to true wins.
	CI []Entry `json:"ci,omitempty"`

	// Users lists the policy entries evaluated for
	// IdentityTypeUser callers, in order. The first entry whose
	// Match expression evaluates to true wins.
	Users []Entry `json:"users,omitempty"`
}

// Entry is a single rule in the policy table. The Match map
// describes which Identities the entry applies to; the
// AllowedDestinations slice enumerates the destination names that
// matching Identities may request.
//
// An entry whose Match map is empty (or omitted) matches every
// Identity of the relevant type; it serves as a catch-all and must
// therefore appear last in the list to be useful.
type Entry struct {
	// Match is the predicate evaluated against the candidate
	// Identity. Each map key is a dotted path into the Identity
	// (see ResolvePath); each value selects the operator and
	// operand to apply at that path. Multiple keys are
	// AND-combined: every check must pass for the entry to
	// match.
	Match map[string]Match `json:"match,omitempty"`

	// AllowedDestinations is the set of destination names the
	// matching Identity is permitted to mint tokens for.
	AllowedDestinations []string `json:"allowedDestinations"`
}

// Match describes a single comparison applied to one Identity field.
//
// Exactly one of the operator fields must be set per Match value.
// Pointer types are used for the scalar operators so that empty
// strings remain valid operands (a deployment may legitimately want
// to match an empty claim).
//
// Operators:
//
//	equals   exact string match
//	glob     path.Match-style glob match (segments separated by '/'')
//	in       membership in a set of strings
//
// Adding a new operator is done by appending a field here and a
// corresponding case to the compileMatch dispatcher.
type Match struct {
	Equals *string  `json:"equals,omitempty"`
	Glob   *string  `json:"glob,omitempty"`
	In     []string `json:"in,omitempty"`
}

// Engine resolves an Identity to a slice of allowed destination
// names. Implementations must be safe for concurrent use.
type Engine interface {
	// Resolve returns the destinations id is permitted to mint
	// tokens for. The returned slice may be empty, in which case
	// /delegate responds with 403 Forbidden.
	Resolve(id *auth.Identity) ([]string, error)
}

// New constructs an Engine from cfg. Every check in every entry is
// compiled and validated up front so that configuration errors
// (unknown identity-field paths, malformed glob patterns, missing
// or ambiguous operators) surface at start-up rather than at the
// first request.
func New(cfg Config) (Engine, error) {
	eng := &matchingEngine{}
	for i, e := range cfg.CI {
		if err := validateEntry(e); err != nil {
			return nil, fmt.Errorf("policy.ci[%d]: %w", i, err)
		}
		ce, err := compileEntry(e)
		if err != nil {
			return nil, fmt.Errorf("policy.ci[%d]: %w", i, err)
		}
		eng.ci = append(eng.ci, ce)
	}
	for i, e := range cfg.Users {
		if err := validateEntry(e); err != nil {
			return nil, fmt.Errorf("policy.users[%d]: %w", i, err)
		}
		ce, err := compileEntry(e)
		if err != nil {
			return nil, fmt.Errorf("policy.users[%d]: %w", i, err)
		}
		eng.users = append(eng.users, ce)
	}
	return eng, nil
}

// validateEntry rejects entries with neither match nor
// allowedDestinations. An entry with neither cannot have any
// observable effect; rejecting it at start-up catches likely
// configuration errors.
func validateEntry(e Entry) error {
	if len(e.AllowedDestinations) == 0 && len(e.Match) == 0 {
		return fmt.Errorf("entry has neither match nor allowedDestinations")
	}
	return nil
}

// check is the compiled form of a single key/value pair from an
// Entry's Match map.
type check func(*auth.Identity) bool

// compiledEntry pairs the AND-combined checks with the destinations
// to grant when all checks pass.
type compiledEntry struct {
	checks  []check
	allowed []string
}

// matchingEngine is the production Engine implementation. It holds
// the pre-compiled entries grouped by the IdentityType against
// which they are evaluated.
type matchingEngine struct {
	ci    []compiledEntry
	users []compiledEntry
}

// Resolve walks the entries for the identity's type in declaration
// order and returns the AllowedDestinations of the first entry
// whose checks all pass. When no entry matches, the returned slice
// is nil and the wire effect is /delegate returning 403.
func (e *matchingEngine) Resolve(id *auth.Identity) ([]string, error) {
	if id == nil {
		return nil, fmt.Errorf("policy: identity is nil")
	}
	var entries []compiledEntry
	switch id.Type {
	case auth.IdentityTypeCI:
		entries = e.ci
	case auth.IdentityTypeUser:
		entries = e.users
	default:
		return nil, fmt.Errorf("policy: unknown identity type %q", id.Type)
	}
	for _, ce := range entries {
		if allPass(ce.checks, id) {
			return ce.allowed, nil
		}
	}
	return nil, nil
}

// allPass reports whether every check in cs returns true for id. An
// empty check list trivially returns true; this is the mechanism by
// which a catch-all entry (Match: {}) matches every Identity.
func allPass(cs []check, id *auth.Identity) bool {
	for _, c := range cs {
		if !c(id) {
			return false
		}
	}
	return true
}

// compileEntry builds the compiledEntry that backs a single Entry
// at evaluation time.
func compileEntry(e Entry) (compiledEntry, error) {
	out := compiledEntry{allowed: e.AllowedDestinations}
	for fieldPath, m := range e.Match {
		c, err := compileMatch(fieldPath, m)
		if err != nil {
			return compiledEntry{}, fmt.Errorf("match[%q]: %w", fieldPath, err)
		}
		out.checks = append(out.checks, c)
	}
	return out, nil
}

// compileMatch builds the single check that evaluates m against the
// value resolved from fieldPath on the candidate Identity.
func compileMatch(fieldPath string, m Match) (check, error) {
	if err := validateFieldPath(fieldPath); err != nil {
		return nil, err
	}
	op, err := selectOperator(m)
	if err != nil {
		return nil, err
	}
	return func(id *auth.Identity) bool {
		v, ok := ResolvePath(id, fieldPath)
		if !ok {
			return false
		}
		return op(v)
	}, nil
}

// validateFieldPath surfaces typos in match keys at start-up.
//
// The first path segment must be one of "principal", "type" or
// "claims". For "claims", at least one further segment is required;
// for "principal" and "type" no further segments are permitted.
//
// Deeper segments under "claims" are not validated because the set
// of claim names is determined at runtime by the configured identity
// providers.
func validateFieldPath(p string) error {
	parts := strings.Split(p, ".")
	if parts[0] == "" {
		return fmt.Errorf("field path is empty")
	}
	switch parts[0] {
	case "principal", "type":
		if len(parts) != 1 {
			return fmt.Errorf("field path %q: %s does not have sub-fields", p, parts[0])
		}
	case "claims":
		if len(parts) < 2 {
			return fmt.Errorf("field path %q: claims requires a sub-field name", p)
		}
		if slices.Contains(parts[1:], "") {
			return fmt.Errorf("field path %q: empty path component", p)
		}
	default:
		return fmt.Errorf("field path %q: first segment must be one of principal, type, claims", p)
	}
	return nil
}

// stringPredicate is a function that compares its argument against
// the operand baked into the Match value at compile time.
type stringPredicate func(value string) bool

// selectOperator validates that exactly one operator field is set on
// m and returns the corresponding stringPredicate.
func selectOperator(m Match) (stringPredicate, error) {
	set := 0
	if m.Equals != nil {
		set++
	}
	if m.Glob != nil {
		set++
	}
	if m.In != nil {
		set++
	}
	switch set {
	case 0:
		return nil, fmt.Errorf("no operator set; expected one of: equals, glob, in")
	case 1:
	default:
		return nil, fmt.Errorf("multiple operators set; expected exactly one of: equals, glob, in")
	}
	switch {
	case m.Equals != nil:
		want := *m.Equals
		return func(v string) bool { return v == want }, nil
	case m.Glob != nil:
		pattern := *m.Glob
		// Calling path.Match once at compile time surfaces
		// pattern-syntax errors at broker start-up rather
		// than at the first /delegate that exercises the
		// entry.
		if _, err := path.Match(pattern, "probe"); err != nil {
			return nil, fmt.Errorf("invalid glob pattern: %w", err)
		}
		return func(v string) bool {
			matched, err := path.Match(pattern, v)
			return err == nil && matched
		}, nil
	default:
		want := slices.Clone(m.In)
		return func(v string) bool { return slices.Contains(want, v) }, nil
	}
}

// ResolvePath returns the string value at the given dotted path on
// id, or ("", false) if the path does not select a string-valued
// field. Supported roots are "principal", "type" and "claims.X.Y".
//
// ResolvePath is exported so that future matchers (and any future
// audit-log enrichment) can reuse the same resolution rules.
func ResolvePath(id *auth.Identity, p string) (string, bool) {
	if id == nil {
		return "", false
	}
	parts := strings.Split(p, ".")
	switch parts[0] {
	case "principal":
		if len(parts) != 1 {
			return "", false
		}
		return id.Principal, true
	case "type":
		if len(parts) != 1 {
			return "", false
		}
		return string(id.Type), true
	case "claims":
		if len(parts) < 2 {
			return "", false
		}
		var cur any = map[string]any(id.Claims)
		for _, key := range parts[1:] {
			m, ok := cur.(map[string]any)
			if !ok {
				return "", false
			}
			cur, ok = m[key]
			if !ok {
				return "", false
			}
		}
		s, ok := cur.(string)
		return s, ok
	default:
		return "", false
	}
}

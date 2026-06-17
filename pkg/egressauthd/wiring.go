package egressauthd

import (
	"fmt"
	"path/filepath"
	"strings"
)

// This file implements the generic, config-driven action-wiring primitive:
// a route declares env vars and files to materialise into the action, with
// content built from a fixed, audited token vocabulary. It replaces the
// previous per-tool Go generators — docker/cargo/git/pypi (and any future
// tool) are now pure config (action_env + action_files), and the only Go is
// this tiny token substituter plus a path guard. The broker stays agnostic:
// it still dispenses only {token, scheme, username}; egress-authd renders.

// credentialTokenPrefix is the token namespace whose PRESENCE in a rendered
// template both (a) triggers a broker mint for the route's destination and
// (b) marks the produced file as credential-bearing (written at rest, the
// gated MODE-C exception). Mirrors the broker's ${secret:NAME}-presence
// trigger. `grep -r '${credential' <config>` is therefore the complete,
// statically-auditable list of routes that write a secret into the action.
const credentialTokenPrefix = "${credential."

// validationVars returns every token name the renderer recognises, each
// mapped to a placeholder. Config.Validate renders each route template against
// it so an action_env/action_file referencing an unknown ${token} (a typo, or
// a token outside the allowed vocabulary) fails config load rather than at
// action time.
func validationVars() map[string]string {
	return map[string]string{
		"loopbackRoute": "", "loopbackBase": "", "loopbackHostPort": "",
		"host": "", "destination": "", "basePath": "",
		"actionDir": "", "actionID": "", "controlSocket": "",
		"credential.token": "", "credential.username": "",
		"credential.scheme": "", "credential.basicAuth": "",
	}
}

// renderTemplate substitutes ${name} tokens in tmpl from vars. A ${name}
// whose name is absent from vars is an ERROR — a typo'd or unauthorised token
// fails closed rather than silently mis-wiring or emitting nothing. "$$" is a
// literal "$"; a lone "$" not introducing "${" or "$$" is literal.
//
// This is deliberately a tiny, FUNCTION-FREE substituter. Action-wiring
// templates may reference only the fixed routing/credential token set the
// caller puts in vars — there are no file/env/secret/exec functions — so an
// operator-authored template can never read arbitrary disk, exfiltrate process
// state, or compute beyond routing. That constraint is the core guardrail and
// the reason this is not the broker's richer ${func:arg} engine.
func renderTemplate(tmpl string, vars map[string]string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(tmpl); {
		if tmpl[i] != '$' {
			b.WriteByte(tmpl[i])
			i++
			continue
		}
		// tmpl[i] == '$'
		switch {
		case i+1 < len(tmpl) && tmpl[i+1] == '$':
			b.WriteByte('$')
			i += 2
		case i+1 < len(tmpl) && tmpl[i+1] == '{':
			rel := strings.IndexByte(tmpl[i+2:], '}')
			if rel < 0 {
				return "", fmt.Errorf("unterminated ${...} at offset %d", i)
			}
			name := tmpl[i+2 : i+2+rel]
			val, ok := vars[name]
			if !ok {
				return "", fmt.Errorf("unknown template token ${%s}", name)
			}
			b.WriteString(val)
			i += 2 + rel + 1
		default:
			b.WriteByte('$')
			i++
		}
	}
	return b.String(), nil
}

// referencesCredential reports whether any template references a
// ${credential.*} token — the mint trigger and the at-rest-credential marker.
func referencesCredential(tmpls ...string) bool {
	for _, t := range tmpls {
		if strings.Contains(t, credentialTokenPrefix) {
			return true
		}
	}
	return false
}

// cleanActionPath resolves a route-supplied relative file path against the
// per-action dir, refusing anything that could escape it: an empty path, an
// absolute path, a ".." segment, or a cleaned result outside actionDir. It
// returns the absolute path to write. This is the path-sandbox guardrail for
// config-driven file materialisation.
func cleanActionPath(actionDir, rel string) (string, error) {
	if rel == "" {
		return "", fmt.Errorf("action file path is empty")
	}
	if filepath.IsAbs(rel) {
		return "", fmt.Errorf("action file path %q must be relative", rel)
	}
	clean := filepath.Clean(rel)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("action file path %q escapes the action dir", rel)
	}
	full := filepath.Join(actionDir, clean)
	if full != actionDir && !strings.HasPrefix(full, actionDir+string(filepath.Separator)) {
		return "", fmt.Errorf("action file path %q escapes the action dir", rel)
	}
	return full, nil
}

// stripURLScheme removes a leading http:// or https:// from a URL, leaving the
// host:port/path form the ${loopbackHostPort} token exposes (a containers
// registries.conf "location" wants this scheme-stripped form).
func stripURLScheme(u string) string {
	for _, p := range []string{"http://", "https://"} {
		if strings.HasPrefix(u, p) {
			return u[len(p):]
		}
	}
	return u
}

// parseFileMode parses an octal file-mode string against a small allowlist.
// An empty value defaults to 0600. Only 0600 and 0644 are permitted so a
// config cannot make a credential-bearing file world-writable or executable.
func parseFileMode(s string) (uint32, error) {
	switch s {
	case "", "0600":
		return 0o600, nil
	case "0644":
		return 0o644, nil
	default:
		return 0, fmt.Errorf("file mode %q not allowed (permitted: 0600, 0644)", s)
	}
}

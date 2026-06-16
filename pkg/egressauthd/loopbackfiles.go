package egressauthd

import (
	"encoding/json"
	"fmt"
)

// This file builds the config-file payloads the worker materialises in
// loopback mode for tools that cannot be redirected to the per-action
// loopback proxy by environment variables alone.
// Each generator emits the smallest config that points the tool at the
// loopback route (http://127.0.0.1:<port>/<destination>) so the
// reverse-proxy front-end injects the broker-minted credential and
// forwards to the real upstream over TLS.
//
// The worker owns final placement: the returned path is a hint relative
// to the action's home directory. The contents are deterministic given
// the loopback route (and, where the tool needs it, the upstream host).

// cargoConfigTOML returns a .cargo/config.toml that replaces the
// crates.io source with the loopback route. cargo's registry client
// defaults to rustls + webpki-roots and ignores env-supplied CAs and
// proxy source selection, so source replacement is the only reliable
// redirect. The loopback route serves plain HTTP, which cargo accepts
// for a registry source on loopback. The sparse protocol is used so
// cargo issues per-crate HTTP GETs the reverse-proxy can authenticate.
func cargoConfigTOML(route string) string {
	return fmt.Sprintf(`# Written by egress-authd (loopback mode). Redirects the crates.io
# registry through the per-action loopback proxy, which injects the
# broker-minted credential and forwards to the real upstream over TLS.
[source.crates-io]
replace-with = "egress-authd"

[source.egress-authd]
registry = "sparse+%s/"

[registries.egress-authd]
protocol = "sparse"
`, route)
}

// dockerRegistriesConf returns a containers-style registries.conf
// (honoured by buildah/podman/skopeo) that mirrors the upstream registry
// host to the loopback route. A docker/OCI client cannot be pointed at a
// loopback mirror by env; the mirror is daemon/containers configuration.
// insecure = true is required because the loopback endpoint is plain
// HTTP; the real upstream leg remains TLS-verified by the proxy.
func dockerRegistriesConf(host, route string) string {
	location := loopbackLocation(route)
	return fmt.Sprintf(`# Written by egress-authd (loopback mode). Mirrors the upstream
# registry through the per-action loopback proxy, which injects the
# broker-minted credential and forwards to the real upstream over TLS.
[[registry]]
prefix = "%s"
location = "%s"

[[registry.mirror]]
location = "%s"
insecure = true
`, host, host, location)
}

// dockerAuthFallbackUsername is used in a docker config.json "auth" blob
// when a basic-scheme destination configures no username. Docker's config
// loader rejects an empty username ("invalid auth configuration file"),
// but token-as-password OCI registries (GHE/GitHub container registry)
// ignore the username and validate only the token, so any non-empty
// sentinel works. "x-access-token" is GitHub's documented convention for
// token-as-password auth.
const dockerAuthFallbackUsername = "x-access-token"

// dockerConfigAuthEntry is one registry's credential in a docker CLI
// config.json "auths" map: the base64(username:password) blob the docker
// CLI forwards to the daemon as the X-Registry-Auth header on a pull.
type dockerConfigAuthEntry struct {
	Auth string `json:"auth"`
}

// dockerConfigJSON returns a docker CLI config.json ($DOCKER_CONFIG/
// config.json) whose "auths" map carries one credential per registry
// host. The values in auths are already the base64("username:token")
// blobs basicAuth produces.
//
// This is the docker tool's DELIBERATE DIVERGENCE from the loopback
// proxy-injection model every other tool uses. A docker image pull is
// performed by the long-lived dockerd daemon, which is started before
// the action and never traverses the per-action loopback proxy, so it
// cannot be credential-injected there (it does not read
// CONTAINERS_REGISTRIES_CONF either — that file is for
// buildah/podman/skopeo, which DO honour the proxy). The docker CLI /
// docker compose, by contrast, reads $DOCKER_CONFIG/config.json at
// invocation time and forwards the matching auth to the daemon as the
// per-pull X-Registry-Auth header. So for the docker tool egress-authd
// mints the broker credential at action-env-build time and materialises
// it here, where the daemon's pull leg will actually receive it.
func dockerConfigJSON(auths map[string]string) (string, error) {
	entries := make(map[string]dockerConfigAuthEntry, len(auths))
	for host, auth := range auths {
		entries[host] = dockerConfigAuthEntry{Auth: auth}
	}
	b, err := json.MarshalIndent(struct {
		Auths map[string]dockerConfigAuthEntry `json:"auths"`
	}{Auths: entries}, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal docker config.json: %w", err)
	}
	return string(b) + "\n", nil
}

// gitInsteadOf returns a .gitconfig that rewrites https://<host>/ to the
// loopback route via url.insteadOf, so git-over-https for the upstream
// flows through the per-action loopback proxy. git has no index/registry
// env, so the rewrite lives in config. The route keeps its scheme
// (plain http to loopback); git follows the rewrite transparently.
func gitInsteadOf(host, route string) string {
	return fmt.Sprintf(`# Written by egress-authd (loopback mode). Redirects git-over-https
# for the upstream through the per-action loopback proxy, which injects
# the broker-minted credential and forwards to the real upstream over
# TLS.
[url "%s/"]
	insteadOf = "https://%s/"
`, route, host)
}

// loopbackLocation strips the scheme from a loopback route, yielding the
// host:port/path form a containers registry "location" expects.
func loopbackLocation(route string) string {
	for _, prefix := range []string{"http://", "https://"} {
		if len(route) >= len(prefix) && route[:len(prefix)] == prefix {
			return route[len(prefix):]
		}
	}
	return route
}

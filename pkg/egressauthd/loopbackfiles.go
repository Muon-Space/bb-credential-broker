package egressauthd

import "fmt"

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

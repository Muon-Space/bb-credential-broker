package egressauthd

import (
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// serveLoopbackReverse handles an origin-form request to the loopback
// endpoint. The leading path segment names the broker destination; it
// selects the upstream host, the request is rewritten to target that
// host over TLS, and the shared credential core authorises and injects.
//
// Addressing scheme: the per-action listener serves a single plain-HTTP
// port and selects the upstream by the FIRST path segment of an
// origin-form request, which names the broker destination. The rest of
// the path (and the query) is forwarded to the upstream, with the host's
// configured base path (if any) prepended:
//
//	GET http://127.0.0.1:<port>/<destination>/<req-path>?<q>
//	      -> https://<host(destination)><base-path>/<req-path>?<q>
//
// The destination is the same identifier host_destination_map maps a
// host to, so the per-tool index/registry env overrides embed it
// directly. The single-port-with-path-prefix scheme is used rather than
// one-port-per-upstream so the existing single proxy_port control
// contract is unchanged: one port per action carries every mapped
// upstream.
func (p *actionProxy) serveLoopbackReverse(w http.ResponseWriter, r *http.Request) {
	dest, rest := splitDestinationPath(r.URL.Path)
	if dest == "" {
		// No destination prefix: nothing routable. Fail closed.
		p.logEgress("", "", DecisionDeniedHost, http.StatusNotFound, "missing destination path prefix")
		p.metrics.RecordEgress("", DecisionDeniedHost)
		http.Error(w, "missing destination path prefix", http.StatusNotFound)
		return
	}

	upstream, ok := p.cfg.upstreamForDestination(dest)
	if !ok {
		// The path prefix does not name a mapped destination. Fail
		// closed with 403 so an action cannot reach an arbitrary
		// upstream by guessing a destination name.
		p.logEgress("", dest, DecisionDeniedHost, http.StatusForbidden, "destination not mapped")
		p.metrics.RecordEgress(dest, DecisionDeniedHost)
		http.Error(w, "destination not mapped", http.StatusForbidden)
		return
	}
	host := upstream.Host

	// Rewrite the request to target the real upstream over TLS. The
	// upstream sees the configured base path (if any) followed by the
	// request path with the destination prefix stripped, and the mapped
	// host. Injection uses the matched route's BROKER destination (not a
	// host re-derivation), so a multi-tool host with per-route broker
	// destinations mints the credential for exactly the tool route the
	// loopback prefix selected.
	r.URL.Scheme = "https"
	r.URL.Host = host
	r.URL.Path = upstream.BasePath + rest
	r.Host = host

	decision, status, mappedDest, reason, body := p.injectForDestination(r, upstream.BrokerDestination)
	if body == nil {
		p.logEgress(host, mappedDest, decision, status, reason)
		p.metrics.RecordEgress(mappedDest, decision)
		http.Error(w, reason, status)
		return
	}
	defer func() { _ = body.Close() }()

	resp, err := p.roundTrip(r)
	if err != nil {
		p.logEgress(host, mappedDest, DecisionError, http.StatusBadGateway, err.Error())
		p.metrics.RecordEgress(mappedDest, DecisionError)
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	// Audit before streaming the body so the record is durable even if
	// the client disconnects mid-copy (mirrors the broker invariant).
	p.logEgress(host, mappedDest, decision, resp.StatusCode, "")
	p.metrics.RecordEgress(mappedDest, decision)
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// serveLoopbackConnect handles a CONNECT in loopback mode. There is no
// MITM CA, so the proxy cannot inject a credential into the encrypted
// stream; instead it enforces the host mapping and, for a mapped host,
// blind-tunnels the TCP stream to the upstream. This is a fallback for
// tooling that honours HTTPS_PROXY but is not pointed at a per-tool
// override URL; authenticated traffic flows through the reverse-proxy
// path. A host with no destination mapping is rejected with 403.
func (p *actionProxy) serveLoopbackConnect(w http.ResponseWriter, r *http.Request) {
	host := hostnameOnly(r.Host)
	if !p.cfg.allowedHost(host) {
		p.logEgress(host, "", DecisionDeniedHost, http.StatusForbidden, "host not permitted")
		p.metrics.RecordEgress("", DecisionDeniedHost)
		http.Error(w, "host not permitted", http.StatusForbidden)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "proxy does not support hijacking", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer func() { _ = clientConn.Close() }()

	// #nosec G704 -- r.Host is gated by the allowedHost check above:
	// only a host on the sidecar's host allow-list reaches this dial.
	// The allow-list is the SSRF control, not the absence of
	// request-derived input.
	upstreamConn, err := net.DialTimeout("tcp", ensurePort(r.Host), 15*time.Second)
	if err != nil {
		_, _ = clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		p.logEgress(host, "", DecisionError, http.StatusBadGateway, "dial upstream: "+err.Error())
		p.metrics.RecordEgress("", DecisionError)
		return
	}
	defer func() { _ = upstreamConn.Close() }()

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	// The destination is unknown to the proxy at the byte level (TLS is
	// opaque here), so this is recorded as a forwarded-no-inject tunnel.
	p.logEgress(host, "", DecisionForwardedNoInject, http.StatusOK, "blind tunnel (loopback connect)")
	p.metrics.RecordEgress("", DecisionForwardedNoInject)

	// Pump bytes both ways until either side closes.
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstreamConn, clientConn); done <- struct{}{} }()
	go func() { _, _ = io.Copy(clientConn, upstreamConn); done <- struct{}{} }()
	<-done
}

// splitDestinationPath splits an origin-form request path into its
// leading destination segment and the remainder (with a leading slash).
// "/registry-pypi/simple/foo/" -> ("registry-pypi",
// "/simple/foo/"). A path with no segment returns ("", path).
func splitDestinationPath(path string) (destination, rest string) {
	trimmed := strings.TrimPrefix(path, "/")
	if trimmed == "" {
		return "", path
	}
	if i := strings.IndexByte(trimmed, '/'); i >= 0 {
		return trimmed[:i], trimmed[i:]
	}
	// Just the destination, no trailing path: forward root.
	return trimmed, "/"
}

// ensurePort returns hostport unchanged when it already carries a port,
// or appends :443 (the only sensible default for a CONNECT) otherwise.
func ensurePort(hostport string) string {
	if _, _, err := net.SplitHostPort(hostport); err == nil {
		return hostport
	}
	return net.JoinHostPort(hostport, "443")
}

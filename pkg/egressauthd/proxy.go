package egressauthd

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// actionProxy is the per-action proxy. It listens on a
// loopback port bound to one action's grant, enforces the host
// allow-list, injects a broker-minted Authorization header for mapped
// hosts, and forwards over TLS to the real upstream.
//
// Two interception modes share the same credential core
// (authorizeAndInject + roundTrip):
//
//   - Loopback (default, EgressModeLoopback): the listener serves PLAIN
//     HTTP and reverse-proxies each origin-form request to the upstream
//     selected by the request's leading path segment (the broker
//     destination name). Tools are pointed at the loopback endpoint by
//     per-tool index/registry env overrides. No MITM CA is involved, so
//     clients whose TLS stack ignores env-supplied CAs work unmodified.
//     A plain-HTTP catch-all (absolute-form HTTP_PROXY request) and a
//     blind CONNECT tunnel for allow-listed hosts are also served for
//     tooling that bypasses the per-tool override.
//
//   - MITM (EgressModeMITM): the listener is an HTTPS_PROXY that
//     terminates the action's CONNECT tunnels with a per-action
//     ephemeral CA, then injects on the decrypted requests. Tool-
//     agnostic for any client that honours HTTPS_PROXY and trusts the
//     env-supplied CA.
//
// The injection and forwarding core lives in authorizeAndInject /
// roundTrip, which take an already-constructed *http.Request and are
// independent of how that request was obtained; both front-ends call
// them unchanged.
type actionProxy struct {
	action  *Action
	cfg     *Config
	cache   *tokenCache
	ca      *ephemeralCA // nil in loopback mode
	audit   AuditLogger
	metrics *Metrics

	// transport dials the real upstreams for this action. It is scoped
	// to one action (and torn down with it); Go's transport pools idle
	// connections per destination host, so a connection authenticated
	// for one host is never reused for another even while the transport
	// keeps connections warm across the action's many requests.
	transport *http.Transport

	listener net.Listener
	server   *http.Server

	closeOnce sync.Once
}

// newActionProxy builds (but does not start) a proxy for action. The
// listener is bound by Start so port-allocation races surface there. An
// ephemeral CA is generated only for MITM mode; the loopback front-end
// needs no CA because it never terminates client TLS.
func newActionProxy(action *Action, cfg *Config, cache *tokenCache, audit AuditLogger, metrics *Metrics, upstream *tls.Config) (*actionProxy, error) {
	p := &actionProxy{
		action:  action,
		cfg:     cfg,
		cache:   cache,
		audit:   audit,
		metrics: metrics,
		transport: &http.Transport{
			TLSClientConfig:     upstream,
			ForceAttemptHTTP2:   true,
			MaxIdleConns:        8,
			IdleConnTimeout:     30 * time.Second,
			TLSHandshakeTimeout: 15 * time.Second,
		},
	}
	if cfg.Mode() == EgressModeMITM {
		ttl := time.Until(action.ExpiresAt)
		ca, err := newEphemeralCA(ttl)
		if err != nil {
			return nil, err
		}
		p.ca = ca
	}
	return p, nil
}

// caCertPEM returns the PEM the worker hands to the action so it trusts
// the proxy's MITM leaves, or nil in loopback mode where no CA exists.
func (p *actionProxy) caCertPEM() []byte {
	if p.ca == nil {
		return nil
	}
	return p.ca.certPEM
}

// Start binds the proxy's listener on 127.0.0.1:port and serves until
// Close is called. It returns once the listener is bound so the control
// handler can report the port to the worker only after it is reachable.
func (p *actionProxy) Start(port int) error {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return fmt.Errorf("egressauthd: bind proxy for action %s on port %d: %w", p.action.ID, port, err)
	}
	p.listener = ln
	p.server = &http.Server{
		Handler:           http.HandlerFunc(p.serveHTTP),
		ReadHeaderTimeout: 30 * time.Second,
	}
	go func() { _ = p.server.Serve(ln) }()
	return nil
}

// Close tears down the proxy listener. It is idempotent so the TTL
// sweeper and an explicit DELETE racing on the same action are safe.
func (p *actionProxy) Close() {
	p.closeOnce.Do(func() {
		if p.server != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = p.server.Shutdown(ctx)
		}
		if p.listener != nil {
			_ = p.listener.Close()
		}
		if p.transport != nil {
			p.transport.CloseIdleConnections()
		}
	})
}

// serveHTTP is the proxy's HTTP entry point. Dispatch depends on the
// configured mode and the request form.
//
// Loopback mode:
//   - CONNECT          → blind TCP tunnel for an allow-listed host (no
//     injection; the per-tool override URL carries authenticated
//     traffic, this is a fallback for tools that bypass it).
//   - absolute-form    → plain-HTTP catch-all proxy request: allow-list
//     and inject by the absolute URL's host.
//   - origin-form      → reverse-proxy: the leading path segment names
//     the broker destination, which selects the upstream host.
//
// MITM mode:
//   - CONNECT          → terminate the tunnel with the ephemeral CA and
//     inject on the decrypted requests.
//   - otherwise        → plain-HTTP proxy request.
func (p *actionProxy) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if p.cfg.Mode() == EgressModeLoopback {
		switch {
		case r.Method == http.MethodConnect:
			p.serveLoopbackConnect(w, r)
		case r.URL.IsAbs():
			// Catch-all HTTP_PROXY request: target is in the request URL.
			p.servePlainHTTP(w, r)
		default:
			// Origin-form request to the loopback endpoint: reverse-proxy
			// by the destination path prefix.
			p.serveLoopbackReverse(w, r)
		}
		return
	}

	if r.Method == http.MethodConnect {
		p.serveConnect(w, r)
		return
	}
	p.servePlainHTTP(w, r)
}

// serveConnect handles an HTTPS_PROXY CONNECT: it hijacks the client
// connection, performs a TLS handshake presenting a leaf minted for the
// requested host, then reads and forwards the decrypted request(s).
func (p *actionProxy) serveConnect(w http.ResponseWriter, r *http.Request) {
	host := hostnameOnly(r.Host)

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

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	leaf, err := p.ca.leafFor(host)
	if err != nil {
		p.logEgress(host, "", DecisionError, 0, "leaf mint failed: "+err.Error())
		return
	}
	tlsConn := tls.Server(clientConn, &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		MinVersion:   tls.VersionTLS12,
	})
	if err := tlsConn.Handshake(); err != nil {
		// A handshake failure here is normally the action declining to
		// trust the ephemeral CA; record it so the operator sees the
		// trust-bootstrap gap rather than a silent hang.
		p.logEgress(host, "", DecisionError, 0, "tls handshake failed: "+err.Error())
		return
	}
	defer func() { _ = tlsConn.Close() }()

	// Serve decrypted requests on the tunnel. HTTP/1.1 keep-alive may
	// carry several; loop until the client closes or a forward fails.
	reader := bufio.NewReader(tlsConn)
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}
		req.URL.Scheme = "https"
		req.URL.Host = r.Host
		keepAlive := p.forward(tlsConn, req, host)
		if !keepAlive {
			return
		}
	}
}

// servePlainHTTP handles a plain-HTTP (non-CONNECT) proxy request. The
// absolute-form request URL carries the target; the host's allow-list
// and injection are applied identically to the MITM path.
func (p *actionProxy) servePlainHTTP(w http.ResponseWriter, r *http.Request) {
	host := hostnameOnly(r.Host)
	if r.URL.Host != "" {
		host = hostnameOnly(r.URL.Host)
	}
	// Normalise to an absolute https-less target the forward path can
	// dial. Plain-HTTP egress is unusual in-cluster but supported.
	if r.URL.Scheme == "" {
		r.URL.Scheme = "http"
	}
	if r.URL.Host == "" {
		r.URL.Host = r.Host
	}

	decision, status, dest, reason, body := p.authorizeAndInject(r, host)
	if body == nil {
		p.logEgress(host, dest, decision, status, reason)
		p.metrics.RecordEgress(dest, decision)
		http.Error(w, reason, status)
		return
	}
	defer func() { _ = body.Close() }()

	resp, err := p.roundTrip(r)
	if err != nil {
		p.logEgress(host, dest, DecisionError, http.StatusBadGateway, err.Error())
		p.metrics.RecordEgress(dest, DecisionError)
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	// Emit the audit line and metric before streaming the body back, so
	// the record is durable even if the client disconnects mid-copy
	// (mirrors the broker handlers' audit-before-response invariant).
	p.logEgress(host, dest, decision, resp.StatusCode, "")
	p.metrics.RecordEgress(dest, decision)
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// forward applies the allow-list and credential injection to a
// decrypted request and writes the upstream response back over conn. It
// returns whether the connection should be kept alive for another
// request.
func (p *actionProxy) forward(conn io.Writer, req *http.Request, host string) bool {
	decision, status, dest, reason, body := p.authorizeAndInject(req, host)
	if body == nil {
		writeRawResponse(conn, status, reason)
		p.logEgress(host, dest, decision, status, reason)
		p.metrics.RecordEgress(dest, decision)
		return false
	}
	defer func() { _ = body.Close() }()

	resp, err := p.roundTrip(req)
	if err != nil {
		writeRawResponse(conn, http.StatusBadGateway, "upstream error")
		p.logEgress(host, dest, DecisionError, http.StatusBadGateway, err.Error())
		p.metrics.RecordEgress(dest, DecisionError)
		return false
	}
	defer func() { _ = resp.Body.Close() }()

	// Emit the audit line and metric before writing the response back,
	// so the record is durable even if the write to the client fails.
	statusCode := resp.StatusCode
	keepAlive := !resp.Close && req.Header.Get("Connection") != "close"
	p.logEgress(host, dest, decision, statusCode, "")
	p.metrics.RecordEgress(dest, decision)

	if err := resp.Write(conn); err != nil {
		return false
	}
	return keepAlive
}

// authorizeAndInject enforces the host allow-list and injects a
// broker-minted Authorization header when a destination is mapped. It
// returns the decision, the HTTP status to use on rejection, the BROKER
// destination name (for audit/metrics and as the cache key), a rejection
// reason, and the request body to forward. A nil body signals "do not
// forward": the caller writes status+reason and stops (fail-closed). The
// destination resolved here is the broker destination (what is minted at
// /token), not the per-tool loopback prefix.
func (p *actionProxy) authorizeAndInject(req *http.Request, host string) (decision string, status int, dest, reason string, body io.ReadCloser) {
	dest, hasDest := p.cfg.destinationForHost(host)
	if !hasDest {
		// Host has no destination mapping: fail closed (do not forward).
		// Gating is "host is mapped to a destination"; the broker's
		// /token enforces the grant's destination scope on top.
		return DecisionDeniedHost, http.StatusForbidden, "", "host not permitted", nil
	}
	return p.injectForDestination(req, dest)
}

// injectForDestination mints (or reuses) the credential for an
// already-resolved BROKER destination and sets the Authorization header.
// It is the shared mint core: the catch-all / MITM paths reach it via
// authorizeAndInject (which resolves the destination from the host),
// while the loopback reverse-proxy path calls it directly with the broker
// destination of the route it matched by loopback path prefix — so a
// multi-tool host whose routes carry distinct broker destinations still
// mints the right one rather than the host's first route's default. dest
// is the broker destination and is returned for audit/metrics; it is the
// cache key, so routes sharing a broker destination share one mint.
func (p *actionProxy) injectForDestination(req *http.Request, dest string) (decision string, status int, outDest, reason string, body io.ReadCloser) {
	tok, err := p.cache.Get(req.Context(), p.action, dest)
	if err != nil {
		if errors.Is(err, ErrBrokerDenied) {
			return DecisionFailClosedBroker, http.StatusForbidden, dest, "broker denied destination", nil
		}
		// Broker unreachable or any other mint failure: fail closed.
		return DecisionFailClosedBroker, http.StatusBadGateway, dest, "broker mint failed: " + err.Error(), nil
	}

	req.Header.Set("Authorization", authorizationHeader(tok))
	return DecisionForwardedInjected, http.StatusOK, dest, "", req.Body
}

// roundTrip dispatches req to the real upstream over the per-action
// transport (see actionProxy.transport for why connection reuse is safe
// here despite the per-request header rewrite).
func (p *actionProxy) roundTrip(req *http.Request) (*http.Response, error) {
	outReq := req.Clone(req.Context())
	// RequestURI must be empty on a client request.
	outReq.RequestURI = ""
	removeHopByHopHeaders(outReq.Header)
	return p.transport.RoundTrip(outReq)
}

// logEgress emits the single audit line for one proxied request.
func (p *actionProxy) logEgress(host, dest, decision string, status int, reason string) {
	if p.audit == nil {
		return
	}
	p.audit.LogEgress(EgressEntry{
		ActionID:    p.action.ID,
		Host:        host,
		Destination: dest,
		Decision:    decision,
		StatusCode:  status,
		Reason:      reason,
	})
}

// authorizationHeader builds the Authorization header value from a
// minted token, title-casing the scheme (HTTP schemes are
// case-insensitive but conventionally title-cased).
func authorizationHeader(tok *MintedToken) string {
	scheme := tok.Scheme
	switch strings.ToLower(scheme) {
	case "bearer", "":
		return "Bearer " + tok.Token
	case "basic":
		return "Basic " + basicAuth(tok.Username, tok.Token)
	default:
		// Pass an operator-chosen scheme through with its first letter
		// upper-cased.
		return strings.ToUpper(scheme[:1]) + scheme[1:] + " " + tok.Token
	}
}

// hostnameOnly strips an optional :port from a host[:port] value.
func hostnameOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

// upstreamTLSConfig builds the TLS config the proxy uses to dial real
// upstreams, optionally trusting an additional PEM bundle on top of the
// system roots.
func upstreamTLSConfig(caBundlePEM []byte) *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if len(caBundlePEM) > 0 {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if pool.AppendCertsFromPEM(caBundlePEM) {
			cfg.RootCAs = pool
		}
	}
	return cfg
}

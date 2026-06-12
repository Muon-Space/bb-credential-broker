// Package egressauthd implements the egress-authd sidecar: a
// per-action forward proxy that injects broker-minted credentials into
// a Buildbarn action's outbound HTTP(S) traffic.
//
// The sidecar runs next to a bb-worker (or bb-runner) container. The
// worker registers an action over a Unix-domain control socket
// (pkg/egressauthd Control), passing the per-action
// delegation grant the broker issued at /delegate; the sidecar
// allocates a per-action loopback proxy bound to that grant and returns
// the proxy port plus the environment variables (and, in loopback mode,
// any config files) the worker injects into the action at exec time.
// For each mapped destination host the proxy exchanges the grant for a
// credential at the broker's existing /token endpoint,
// caches it, and injects it as an Authorization header before
// forwarding over TLS.
//
// Authorization is the broker's: /token only mints for a destination
// the grant was scoped to at /delegate (its granted_destinations set).
// The sidecar therefore does not make any authorization decision of its
// own; it binds a grant to a proxy and relays the grant to /token,
// failing closed on a 403, any error, an unknown action, or a request to
// a host it has no destination mapping for.
//
// Two interception modes are supported (egress_mode): the default
// "loopback" serves plain HTTP and reverse-proxies to the upstream over
// real TLS, pointing each tool at a per-tool index/registry override
// (so tools whose TLS stack ignores env-supplied CAs, like uv and
// cargo, work unmodified); "mitm" is the legacy HTTPS_PROXY CONNECT
// path with a per-action ephemeral CA.
//
// The package layout mirrors the broker's pkg/app wiring:
//
//	config.go        Configuration schema and Jsonnet loader.
//	broker.go        Broker /token client.
//	tokencache.go    Per-(action,destination) credential cache.
//	actions.go       In-memory action registry with TTL eviction.
//	ca.go            Per-action ephemeral CA for the MITM proxy.
//	proxy.go         Per-action proxy: mode dispatch + injection core.
//	loopback.go      Loopback-mode reverse-proxy and blind-tunnel front-ends.
//	loopbackfiles.go Loopback-mode per-tool config-file payloads (cargo/docker/git).
//	control.go       Control UDS server.
//	audit.go         Structured stdout audit logger.
//	metrics.go       Prometheus collectors.
//	server.go        Top-level dependency wiring.
package egressauthd

import (
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/google/go-jsonnet"
)

// EgressMode selects how the per-action proxy intercepts an action's
// outbound traffic.
type EgressMode string

// Tool tags name a build tool whose private registry a host serves, so
// loopback mode can emit that tool's native index/registry override.
const (
	ToolPyPI   = "pypi"   // uv / pip simple index
	ToolCargo  = "cargo"  // cargo registry (source replacement)
	ToolDocker = "docker" // docker / OCI registry mirror
	ToolGit    = "git"    // git remote over https
)

// knownTool reports whether tag is a recognised route tool tag. An
// empty tag is permitted (a host reachable via the catch-all proxy with
// no tool-native override); only a non-empty, unrecognised tag is
// rejected.
func knownTool(tag string) bool {
	switch tag {
	case "", ToolPyPI, ToolCargo, ToolDocker, ToolGit:
		return true
	default:
		return false
	}
}

const (
	// EgressModeLoopback (the default) serves PLAIN HTTP on the
	// per-action loopback port and reverse-proxies each request to the
	// mapped upstream over real TLS. Tools are pointed at the loopback
	// endpoint by per-tool index/registry env overrides (and a
	// catch-all HTTP_PROXY/HTTPS_PROXY); no MITM CA is involved, so
	// tools whose TLS stack ignores env-supplied CAs (uv, cargo's
	// registry path on rustls+webpki-roots) work unmodified.
	EgressModeLoopback EgressMode = "loopback"

	// EgressModeMITM is the original behaviour: the loopback port is an
	// HTTPS_PROXY that terminates the action's CONNECT tunnels with a
	// per-action ephemeral CA and forwards over TLS. Tool-agnostic for
	// any client that honours HTTPS_PROXY AND trusts an env-supplied
	// CA, but rejected by tools that hard-code their own trust store.
	EgressModeMITM EgressMode = "mitm"
)

// Config is the egress-authd sidecar's top-level configuration.
// The shape is flat and generic: a host allow-list and a
// host->destination route table, with no authorization policy of its
// own, because authorization is the broker's (a grant scoped at
// /delegate). The shape is loaded from a Jsonnet file, mirroring the
// broker's configuration style so operators carry one mental model
// across both binaries.
type Config struct {
	// BrokerTokenURL is the base URL of the bb-credential-broker.
	// The sidecar appends /token. Must be an
	// absolute https URL in production.
	BrokerTokenURL string `json:"broker_token_url"`

	// EgressMode selects the per-action interception strategy:
	// "loopback" (default) or "mitm". See EgressMode. An empty value
	// is treated as "loopback".
	EgressMode EgressMode `json:"egress_mode,omitempty"`

	// ListenSocket is the filesystem path of the control Unix-domain
	// socket. The worker dials this to register and
	// deregister actions.
	ListenSocket string `json:"listen_socket"`

	// ProxyPortRange is the inclusive [lo, hi] loopback TCP port
	// range from which per-action forward proxies are allocated. A
	// fresh port is taken per action and released on teardown.
	ProxyPortRange [2]int `json:"proxy_port_range"`

	// HostDestinationMap maps an upstream host (no scheme, no port) to
	// the broker destination name whose credential the proxy injects on
	// requests to that host. It is the simple, one-tool-per-host form; a
	// host that serves several tools (different destinations sharing one
	// host) is expressed in Routes instead. A request to a host present
	// in neither this map nor Routes is failed closed (not forwarded):
	// this map (unioned with Routes) is the host allow-list.
	HostDestinationMap map[string]string `json:"host_destination_map,omitempty"`

	// HostToolMap optionally tags a host in HostDestinationMap with the
	// build tool whose private registry it serves (pypi, cargo, docker,
	// git). In loopback mode the tag selects the per-tool index/registry
	// env overrides (and, for tools that cannot be pointed at a loopback
	// URL by env alone, the config-file payload). A host with no tag
	// still gets the generic catch-all proxy and a loopback route; the
	// tag only adds the tool-native override. Ignored in MITM mode.
	HostToolMap map[string]string `json:"host_tool_map,omitempty"`

	// HostBasePathMap optionally records, per host in HostDestinationMap,
	// the base path under which the host's registry lives (for example
	// "/api/pypi/index/simple"). In loopback mode the
	// reverse-proxy PREPENDS this base path to the
	// (destination-prefix-stripped) request path before forwarding to the
	// upstream, so the per-tool env override can stay the bare loopback
	// route. Ignored in MITM mode. Leading slash optional; a trailing
	// slash is trimmed.
	HostBasePathMap map[string]string `json:"host_base_path_map,omitempty"`

	// Routes is the multi-tool form: an explicit list of upstream
	// routes, used when a single host serves more than one tool's
	// registry (for example a registry serving pypi, cargo
	// and docker repositories). Each route binds (host, tool) to a
	// UNIQUE loopback path prefix (Destination) and a broker destination
	// (BrokerDestination, which MAY be shared), plus an optional base
	// path, so the tools coexist on the same host with separate loopback
	// prefixes while reusing one minted credential. Routes and the
	// Host*Map fields may both be set; they are merged into one internal
	// route list (a Host*Map entry contributes one route for its host).
	// Two routes must not name the same Destination (loopback prefix);
	// BrokerDestination may repeat.
	Routes []Route `json:"routes,omitempty"`

	// MetricsListenAddress, when non-empty, is the address the
	// sidecar's Prometheus /metrics and /-/healthy endpoints listen
	// on (for example ":9982"). When empty the diagnostics listener
	// is not started.
	MetricsListenAddress string `json:"metrics_listen_address,omitempty"`

	// NoProxy is the comma-separated value injected as NO_PROXY (and
	// no_proxy) into the action environment so in-cluster traffic
	// (the broker, bb-storage, the apiserver) bypasses the proxy.
	// When empty a conservative default covering loopback and the
	// cluster service CIDRs is injected; operators override per
	// cluster.
	NoProxy string `json:"no_proxy,omitempty"`

	// CABundleFile, when non-empty, is a PEM CA bundle the proxy
	// trusts when dialling upstream destinations over TLS, in
	// addition to the system roots. Operators set it when a
	// destination presents a certificate chained to a private CA.
	CABundleFile string `json:"ca_bundle_file,omitempty"`

	// ActionFilesDir is the directory in which the sidecar materialises
	// per-action helper dotfiles for tools whose proxy redirection cannot
	// be expressed in environment variables alone (cargo source
	// replacement, container-tooling registries.conf, git insteadOf).
	// The path is shared between this sidecar and the action's runtime
	// container (typically a Kubernetes emptyDir mounted into both): the
	// sidecar writes <action_files_dir>/<action_id>/<file> and emits
	// per-tool env variables (CARGO_HOME, CONTAINERS_REGISTRIES_CONF,
	// GIT_CONFIG_GLOBAL) pointing at those paths. The per-action
	// subdirectory is created with mode 0700 so concurrent actions on
	// the same pod cannot enumerate each other's files; cleanup is bound
	// to the action lifecycle (DELETE /actions/{id} and the TTL sweep).
	// Required in loopback mode whenever any route carries a tool that
	// needs a config file (cargo, docker, git).
	ActionFilesDir string `json:"action_files_dir"`

	// routesOnce guards the one-time computation of routesCache. The
	// configuration is immutable after loading, so the merged route list
	// is built once and reused by every subsequent lookup.
	routesOnce  sync.Once
	routesCache []destinationUpstream
}

// Route binds one upstream (host, tool) to the broker destination whose
// credential authenticates it and the base path its registry lives
// under. It is the multi-tool unit: several routes may share a host so a
// host serving pypi + cargo + docker exposes one route per tool, each
// with its own loopback path prefix (Destination) but, typically, one
// shared broker destination (BrokerDestination).
type Route struct {
	// Host is the upstream hostname (no scheme, no port).
	Host string `json:"host"`

	// Destination is the UNIQUE loopback path prefix this route is
	// addressed by in loopback mode (for example "registry-pypi").
	// It must be unique across all routes because it disambiguates the
	// reverse-proxy path-prefix lookup; it is NOT (necessarily) a broker
	// destination name. The broker destination credential injection
	// redeems is BrokerDestination.
	Destination string `json:"destination"`

	// BrokerDestination is the broker destination name whose credential
	// the proxy mints at /token and injects on requests routed to this
	// (host, tool). Unlike Destination it MAY repeat across routes, so a
	// host serving pypi + cargo + docker can expose three routes with
	// distinct loopback prefixes (Destination) that all redeem one shared
	// broker destination (for example "registry"), reusing one minted
	// credential. When empty it defaults to Destination (the single-tool
	// case where the loopback prefix and broker destination coincide).
	BrokerDestination string `json:"broker_destination,omitempty"`

	// Tool optionally tags the route with the build tool whose registry
	// the host serves (pypi, cargo, docker, git). Selects the per-tool
	// env override / config-file payload in loopback mode. Empty for a
	// host reached via the catch-all proxy only.
	Tool string `json:"tool,omitempty"`

	// BasePath optionally records the base path the host's registry
	// lives under; the loopback reverse-proxy prepends it to the
	// prefix-stripped request path. Leading slash optional; trailing
	// slash trimmed.
	BasePath string `json:"base_path,omitempty"`
}

// Load reads, evaluates and unmarshals the Jsonnet configuration at
// path, then validates it. The loader mirrors the broker's
// config.Load so operators iterate with the same tooling.
func Load(path string) (*Config, error) {
	vm := jsonnet.MakeVM()
	rendered, err := vm.EvaluateFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: evaluate %s: %w", path, err)
	}
	var c Config
	dec := json.NewDecoder(strings.NewReader(rendered))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: decode %s: %w", path, err)
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	return &c, nil
}

// Validate performs structural checks on the loaded configuration.
// Errors mention the offending field by name so a misconfiguration is
// located without log diving.
func (c *Config) Validate() error {
	switch c.EgressMode {
	case "", EgressModeLoopback, EgressModeMITM:
		// "" defaults to loopback; resolved by Mode().
	default:
		return fmt.Errorf("egress_mode must be %q or %q, got %q", EgressModeLoopback, EgressModeMITM, c.EgressMode)
	}
	if c.BrokerTokenURL == "" {
		return fmt.Errorf("broker_token_url is required")
	}
	u, err := url.Parse(c.BrokerTokenURL)
	if err != nil {
		return fmt.Errorf("broker_token_url: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("broker_token_url must be an absolute URL, got %q", c.BrokerTokenURL)
	}
	if c.ListenSocket == "" {
		return fmt.Errorf("listen_socket is required")
	}
	lo, hi := c.ProxyPortRange[0], c.ProxyPortRange[1]
	if lo <= 0 || hi <= 0 || lo > hi || hi > 65535 {
		return fmt.Errorf("proxy_port_range must be a valid inclusive [lo,hi] within 1..65535, got [%d,%d]", lo, hi)
	}

	// The host->destination map and the routes list together form the
	// host allow-list; at least one must map something.
	for host, dest := range c.HostDestinationMap {
		if host == "" {
			return fmt.Errorf("host_destination_map: empty host is not allowed")
		}
		if dest == "" {
			return fmt.Errorf("host_destination_map[%q]: empty destination is not allowed", host)
		}
	}
	for host, tool := range c.HostToolMap {
		if host == "" {
			return fmt.Errorf("host_tool_map: empty host is not allowed")
		}
		if !knownTool(tool) {
			return fmt.Errorf("host_tool_map[%q]: unknown tool %q (recognised: %s, %s, %s, %s)",
				host, tool, ToolPyPI, ToolCargo, ToolDocker, ToolGit)
		}
		if _, ok := c.HostDestinationMap[host]; !ok {
			return fmt.Errorf("host_tool_map[%q]: host has no host_destination_map entry, so no credential would be injected", host)
		}
	}
	for host := range c.HostBasePathMap {
		if host == "" {
			return fmt.Errorf("host_base_path_map: empty host is not allowed")
		}
		if _, ok := c.HostDestinationMap[host]; !ok {
			return fmt.Errorf("host_base_path_map[%q]: host has no host_destination_map entry", host)
		}
	}
	for i, rt := range c.Routes {
		if rt.Host == "" {
			return fmt.Errorf("routes[%d]: host is required", i)
		}
		if rt.Destination == "" {
			return fmt.Errorf("routes[%d]: destination is required", i)
		}
		if !knownTool(rt.Tool) {
			return fmt.Errorf("routes[%d]: unknown tool %q (recognised: %s, %s, %s, %s)",
				i, rt.Tool, ToolPyPI, ToolCargo, ToolDocker, ToolGit)
		}
	}

	// The merged route list must name each Destination (loopback path
	// prefix) once: a duplicate would make the reverse-proxy path-prefix
	// lookup ambiguous. BrokerDestination is deliberately NOT required to
	// be unique — several tool routes legitimately share one broker
	// destination (registry pypi/cargo/docker -> "registry"). Each
	// merged route must, however, carry a non-empty broker destination
	// after defaulting, or a mapped request would have nothing to mint.
	seen := map[string]string{} // destination -> host
	for _, rt := range c.routes() {
		if rt.Destination == "" {
			continue
		}
		if rt.BrokerDestination == "" {
			return fmt.Errorf("route for destination %q (host %q) has an empty broker destination",
				rt.Destination, rt.Host)
		}
		if prevHost, dup := seen[rt.Destination]; dup {
			return fmt.Errorf("destination %q is mapped by more than one route (hosts %q and %q); each destination must be unique",
				rt.Destination, prevHost, rt.Host)
		}
		seen[rt.Destination] = rt.Host
	}
	if len(c.routes()) == 0 {
		return fmt.Errorf("at least one of host_destination_map or routes must map a host to a destination")
	}

	// action_files_dir is required whenever any route carries a tool
	// whose redirection is expressed as a config file (cargo, docker,
	// git): those payloads are materialised under that directory and
	// referenced from injected env vars (CARGO_HOME, etc.). A pypi-only
	// or untagged-host-only deployment does not need it; a deployment
	// that mixes file-needing tools without it would silently fail to
	// redirect the action's traffic for those tools, so we fail fast.
	if c.Mode() == EgressModeLoopback {
		needsFiles := false
		for _, du := range c.routes() {
			switch du.Tool {
			case ToolCargo, ToolDocker, ToolGit:
				needsFiles = true
			}
		}
		if needsFiles {
			if c.ActionFilesDir == "" {
				return fmt.Errorf("action_files_dir is required when any route carries a tool that needs a config file (cargo, docker, git)")
			}
			if !filepath.IsAbs(c.ActionFilesDir) {
				return fmt.Errorf("action_files_dir must be an absolute path, got %q", c.ActionFilesDir)
			}
		}
	}
	return nil
}

// routes returns the merged internal route list, computed once and
// memoised: the configuration is immutable after loading, so the
// per-request lookups reuse a single built slice rather than rebuilding
// it on every call.
func (c *Config) routes() []destinationUpstream {
	c.routesOnce.Do(func() {
		c.routesCache = c.computeRoutes()
	})
	return c.routesCache
}

// computeRoutes builds the merged internal route list: every Routes entry
// followed by one route per HostDestinationMap entry (folding in that
// host's tool tag and base path). It is the single representation the
// proxy and control server consume, so the simple HostXMap form and the
// explicit Routes form behave identically downstream. The order is
// deterministic: explicit routes first (in declared order), then
// HostDestinationMap entries in sorted-host order.
func (c *Config) computeRoutes() []destinationUpstream {
	out := make([]destinationUpstream, 0, len(c.Routes)+len(c.HostDestinationMap))
	for _, rt := range c.Routes {
		brokerDest := rt.BrokerDestination
		if brokerDest == "" {
			// Single-tool route: the loopback prefix and the broker
			// destination coincide.
			brokerDest = rt.Destination
		}
		out = append(out, destinationUpstream{
			Destination:       rt.Destination,
			BrokerDestination: brokerDest,
			Host:              rt.Host,
			Tool:              rt.Tool,
			BasePath:          normalizeBasePath(rt.BasePath),
		})
	}
	for _, host := range sortedKeys(c.HostDestinationMap) {
		// A flat host->destination entry is single-tool: the map value is
		// both the loopback prefix and the broker destination.
		dest := c.HostDestinationMap[host]
		out = append(out, destinationUpstream{
			Destination:       dest,
			BrokerDestination: dest,
			Host:              host,
			Tool:              c.HostToolMap[host],
			BasePath:          normalizeBasePath(c.HostBasePathMap[host]),
		})
	}
	return out
}

// allowedHost reports whether host is reachable: it appears in the
// merged route list (host_destination_map or routes). The proxy fails
// closed for any host that is not mapped — gating is "host has a
// destination", and the broker's /token enforces the grant scope.
func (c *Config) allowedHost(host string) bool {
	for _, du := range c.routes() {
		if du.Host == host {
			return true
		}
	}
	return false
}

// destinationForHost returns the BROKER destination to mint for a
// request addressed to host by the catch-all / plain-HTTP path, where
// the loopback prefix is not carried in the URL. When several routes
// share the host (a multi-tool host) they typically share one broker
// destination, so the first route's broker destination is the host-level
// default; per-tool traffic uses the loopback reverse-proxy path, which
// resolves the route by its loopback path prefix and then mints that
// route's broker destination. A host with no route returns ("", false):
// the proxy fails closed.
func (c *Config) destinationForHost(host string) (string, bool) {
	for _, du := range c.routes() {
		if du.Host == host && du.BrokerDestination != "" {
			return du.BrokerDestination, true
		}
	}
	return "", false
}

// Mode returns the resolved egress mode, mapping the empty value to the
// loopback default.
func (c *Config) Mode() EgressMode {
	if c.EgressMode == "" {
		return EgressModeLoopback
	}
	return c.EgressMode
}

// mappedUpstreams returns the merged route list with each destination
// represented once, in a stable order. It underpins loopback-mode
// addressing (the destination name is the loopback path prefix) and the
// per-tool URL overrides returned in the action env. A duplicate
// destination is rejected at validation, so no de-duplication on
// destination is needed here; the slice is returned as-is.
func (c *Config) mappedUpstreams() []destinationUpstream {
	return c.routes()
}

// normalizeBasePath canonicalises an upstream base path to either ""
// (host root) or a value with a leading slash and no trailing slash, so
// it can be string-joined with a leading-slash request path without
// producing a double or missing slash.
func normalizeBasePath(p string) string {
	p = strings.Trim(p, "/")
	if p == "" {
		return ""
	}
	return "/" + p
}

// upstreamForDestination returns the merged route whose destination
// matches, for loopback reverse-proxy routing. It is the lookup the
// loopback listener performs on the path-prefix destination segment of
// an inbound request.
func (c *Config) upstreamForDestination(destination string) (destinationUpstream, bool) {
	for _, du := range c.routes() {
		if du.Destination == destination {
			return du, true
		}
	}
	return destinationUpstream{}, false
}

// destinationUpstream pairs a route's unique loopback path prefix
// (Destination) and the broker destination its credential is minted
// against (BrokerDestination) with the upstream host, plus the optional
// build-tool tag and upstream base path for that host. It is used to
// build loopback addressing and env overrides. Destination is the
// addressing/uniqueness key; BrokerDestination is what is minted and
// cached (it may be shared across routes).
type destinationUpstream struct {
	Destination       string
	BrokerDestination string
	Host              string
	Tool              string // "" when the route carries no tool tag
	BasePath          string // "" (host root) or a leading-slash, no-trailing-slash path
}

// sortedKeys returns the keys of m in ascending order for deterministic
// iteration.
func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

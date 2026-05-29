// Example egress-authd sidecar configuration. The shape mirrors the
// schema documented in pkg/egressauthd/config.go.
//
// egress-authd runs next to a bb-worker container. The worker obtains a
// broker delegation grant at /delegate (scoped to a set of
// destinations), registers each action over the control socket passing
// that grant, and the sidecar allocates a per-action loopback proxy
// bound to the grant. It returns the proxy port plus the environment
// variables (and, in loopback mode, any config files) the worker injects
// into the action at exec time. For each mapped destination host the
// proxy exchanges the grant for a credential at the broker's existing
// /token endpoint and injects it as an Authorization header before
// forwarding over TLS.
//
// Authorization is the broker's: /token mints only for a destination the
// grant was scoped to at /delegate. The sidecar makes no authorization
// decision of its own; it binds a grant to a proxy, relays the grant to
// /token, and fails closed on a 403, any error, an unknown action, or a
// request to a host with no destination mapping. The host->destination
// map below mirrors the broker's destinations.jsonnet for the same
// cluster.

{
  // The broker's API base URL. The sidecar appends /token.
  broker_token_url: 'https://broker.example.com',

  // How the per-action proxy intercepts egress: 'loopback' (default) or
  // 'mitm'. loopback serves plain HTTP on the loopback port and
  // reverse-proxies to the upstream over real TLS, pointing each tool at
  // a per-tool index/registry override; it works with uv and cargo,
  // whose TLS stacks ignore env-supplied CAs and so reject the MITM
  // path. mitm is the legacy HTTPS_PROXY CONNECT path with a per-action
  // ephemeral CA (EGRESS_AUTHD_CA_PEM).
  egress_mode: 'loopback',

  // Control Unix-domain socket the worker dials to register and
  // deregister actions. Typically an emptyDir shared
  // between the worker and sidecar containers.
  listen_socket: '/var/run/egress-authd/control.sock',

  // Inclusive [lo, hi] loopback port range from which per-action
  // forward proxies are allocated.
  proxy_port_range: [15000, 15999],

  // Optional diagnostics listener exposing /-/healthy and /metrics.
  metrics_listen_address: ':9982',

  // In-cluster destinations that must bypass the proxy. The broker,
  // bb-storage and the API server are reached directly, not through the
  // per-action proxy.
  no_proxy: 'localhost,127.0.0.1,::1,.svc,.svc.cluster.local,.cluster.local,169.254.169.254',

  // Simple, one-tool-per-host form. A request to a host present here
  // (or in `routes` below) is forwarded with the named destination's
  // credential injected; a request to any other host fails closed. The
  // union of these hosts and the `routes` hosts is the allow-list.
  host_destination_map: {
    // Git host raw content, fetched via the catch-all proxy (no tool tag).
    'raw.git.example.com': 'git-host',
  },

  // Optional per-host tool tag (pypi | cargo | docker | git). In
  // loopback mode the tag selects that tool's native index/registry
  // override (env for pypi, a written config file for cargo/docker/git).
  host_tool_map: {},

  // Optional per-host upstream base path the loopback reverse-proxy
  // prepends to the prefix-stripped request path, so a tool's env
  // override can stay the bare loopback route.
  host_base_path_map: {},

  // Multi-tool form: when one host serves several tools' registries
  // (a registry serving pypi + cargo + docker), give one route per tool.
  // Each route binds (host, tool) to a DISTINCT broker destination and
  // base path, so the tools coexist on the same host with separate
  // credentials and separate loopback path prefixes. Each destination
  // must be unique across all routes.
  routes: [
    {
      host: 'registry.example.com',
      destination: 'registry-pypi',
      tool: 'pypi',
      base_path: '/api/pypi/index/simple',
    },
    {
      host: 'registry.example.com',
      destination: 'registry-cargo',
      tool: 'cargo',
      base_path: '/api/cargo/index',
    },
    {
      host: 'registry.example.com',
      destination: 'registry-docker',
      tool: 'docker',
    },
  ],
}

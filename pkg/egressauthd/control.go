package egressauthd

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// controlServer implements the worker→sidecar control API over a
// Unix-domain socket. It owns the action registry, the
// per-action proxy lifecycle, and loopback port allocation.
type controlServer struct {
	cfg      *Config
	registry *actionRegistry
	cache    *tokenCache
	audit    AuditLogger
	metrics  *Metrics
	upstream *tls.Config

	mu      sync.Mutex
	proxies map[string]*actionProxy // action_id -> proxy
	// usedPorts tracks loopback ports currently allocated to proxies
	// so the allocator does not hand the same port to two actions.
	usedPorts map[int]struct{}
	nextPort  int

	now func() time.Time
}

// newControlServer constructs the control server and wires the action
// registry's eviction hook to proxy teardown so a TTL-expired or
// explicitly-deleted action releases its proxy and cached credentials.
func newControlServer(cfg *Config, cache *tokenCache, audit AuditLogger, metrics *Metrics, upstream *tls.Config) *controlServer {
	cs := &controlServer{
		cfg:       cfg,
		cache:     cache,
		audit:     audit,
		metrics:   metrics,
		upstream:  upstream,
		proxies:   map[string]*actionProxy{},
		usedPorts: map[int]struct{}{},
		nextPort:  cfg.ProxyPortRange[0],
		now:       time.Now,
	}
	cs.registry = newActionRegistry(cs.teardownAction)
	return cs
}

// Handler returns the http.Handler that serves the control API. The
// server binds it to the Unix-domain socket listener.
func (cs *controlServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/actions", cs.handleActions)
	mux.HandleFunc("/actions/", cs.handleActionByID)
	return mux
}

// createActionRequest is the JSON body POSTed to /actions. It binds the
// broker delegation grant to a per-action proxy; it carries nothing but
// the grant and its expiry, because authorization is the broker's (the
// grant was scoped to a destination set at /delegate).
type createActionRequest struct {
	Grant     string `json:"grant"`
	ExpiresAt string `json:"expires_at"`
}

// createActionResponse is the JSON body /actions returns on success:
// the action_id, the loopback proxy port, and the environment variables
// the worker injects into the action at exec time. Per-tool config files
// (cargo, docker, git) are materialised under
// <Config.ActionFilesDir>/<action_id>/ by the sidecar itself and
// referenced from env vars in Env; the worker does not write files.
type createActionResponse struct {
	ActionID  string            `json:"action_id"`
	ProxyPort int               `json:"proxy_port"`
	Env       map[string]string `json:"env"`
}

// handleActions serves POST /actions: it validates the grant,
// allocates a proxy on a fresh loopback port, registers the action, and
// returns the port plus the action environment.
func (cs *controlServer) handleActions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req createActionRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "malformed request body", http.StatusBadRequest)
		return
	}
	if req.Grant == "" {
		http.Error(w, "grant is required", http.StatusBadRequest)
		return
	}
	expiresAt, err := parseExpiry(req.ExpiresAt, cs.now())
	if err != nil {
		http.Error(w, "invalid expires_at: "+err.Error(), http.StatusBadRequest)
		return
	}

	actionID, err := newActionID()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	action := &Action{
		ID:        actionID,
		Grant:     req.Grant,
		ExpiresAt: expiresAt,
	}

	port, proxy, err := cs.startProxy(action)
	if err != nil {
		http.Error(w, "could not allocate proxy: "+err.Error(), http.StatusInternalServerError)
		return
	}
	action.ProxyPort = port

	// Build the env (and materialise the per-action helper-file directory
	// in loopback mode) BEFORE registering the action, so a write failure
	// tears down the proxy and surfaces the error to the caller (the
	// worker) rather than leaving a half-registered action whose env
	// points at a non-existent dir.
	env, err := cs.actionEnv(action, proxy)
	if err != nil {
		proxy.Close()
		cs.mu.Lock()
		delete(cs.usedPorts, port)
		cs.mu.Unlock()
		http.Error(w, "could not prepare action env: "+err.Error(), http.StatusInternalServerError)
		return
	}

	cs.mu.Lock()
	cs.proxies[actionID] = proxy
	cs.mu.Unlock()
	cs.registry.Add(action)
	cs.metrics.SetActiveActions(len(cs.registry.snapshot()))

	writeJSON(w, http.StatusOK, createActionResponse{
		ActionID:  actionID,
		ProxyPort: port,
		Env:       env,
	})
}

// handleActionByID serves DELETE /actions/{action_id}.
func (cs *controlServer) handleActionByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/actions/")
	if id == "" || strings.Contains(id, "/") {
		http.Error(w, "action_id is required", http.StatusBadRequest)
		return
	}
	cs.registry.Delete(id) // teardown happens via the eviction hook
	cs.metrics.SetActiveActions(len(cs.registry.snapshot()))
	w.WriteHeader(http.StatusOK)
}

// actionEnv builds the environment variables the worker injects into
// the action at exec time, and (in loopback mode) materialises the
// per-action helper config files under
// <Config.ActionFilesDir>/<action.ID>/ that those env vars reference.
// The env shape depends on the configured egress mode and the
// sidecar's route table; the per-action directory and file contents
// are otherwise identical across actions of one sidecar.
func (cs *controlServer) actionEnv(action *Action, proxy *actionProxy) (map[string]string, error) {
	if cs.cfg.Mode() == EgressModeLoopback {
		return cs.loopbackActionEnv(action)
	}
	return cs.mitmActionEnv(action.ProxyPort, proxy), nil
}

// mitmActionEnv is the original MITM env: HTTP_PROXY/HTTPS_PROXY point
// at the per-action proxy; NO_PROXY keeps in-cluster traffic direct; the
// per-action CA PEM is surfaced under EGRESS_AUTHD_CA_PEM so HTTPS
// clients can be told to trust the proxy's MITM leaves.
func (cs *controlServer) mitmActionEnv(port int, proxy *actionProxy) map[string]string {
	proxyURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	env := map[string]string{
		"HTTP_PROXY":  proxyURL,
		"HTTPS_PROXY": proxyURL,
		"http_proxy":  proxyURL,
		"https_proxy": proxyURL,
		"NO_PROXY":    cs.noProxy(),
		"no_proxy":    cs.noProxy(),
		// Trust-bootstrap for the MITM CA. The worker is expected to
		// materialise EGRESS_AUTHD_CA_PEM to a file and point the
		// remaining vars at it; they are provided as the conventional
		// names common tooling honours.
		"EGRESS_AUTHD_CA_PEM": string(proxy.caCertPEM()),
	}
	return env
}

// loopbackActionEnv builds the loopback-mode env and, for routes whose
// tool needs a config file (cargo, docker, git), materialises that file
// under <Config.ActionFilesDir>/<action.ID>/ and emits an env var
// pointing at it. The base env is a plain-HTTP HTTP_PROXY/HTTPS_PROXY
// catch-all at the loopback port plus NO_PROXY; EGRESS_AUTHD_CA_PEM is
// intentionally absent because no MITM CA exists. On top of the
// catch-all, every mapped upstream gets a loopback route under its
// destination path prefix, and a tagged host (HostToolMap) additionally
// gets that tool's native index/registry override — as env when env
// suffices (pypi), or as the env+file pair when it does not.
//
// The per-action directory is created with mode 0700 so concurrent
// actions on the same pod cannot enumerate each other's helper files
// (the action_id itself is 128 bits of base64-URL entropy, so guessing
// is infeasible; 0700 is defence-in-depth). Cleanup is bound to the
// action lifecycle in teardownAction.
func (cs *controlServer) loopbackActionEnv(action *Action) (map[string]string, error) {
	base := fmt.Sprintf("http://127.0.0.1:%d", action.ProxyPort)
	env := map[string]string{
		// Catch-all so any tool that honours the proxy env reaches a
		// mapped host even without a per-tool override. Plain HTTP to the
		// loopback listener; the listener reverse-proxies over real TLS
		// upstream.
		"HTTP_PROXY":  base,
		"HTTPS_PROXY": base,
		"http_proxy":  base,
		"https_proxy": base,
		"NO_PROXY":    cs.noProxy(),
		"no_proxy":    cs.noProxy(),
	}

	// Lazy: only allocate the per-action dir the first time a route
	// produces a file. A pypi-only or untagged-host-only deployment
	// touches the filesystem zero times.
	var actionDir string
	ensureDir := func() error {
		if actionDir != "" {
			return nil
		}
		if cs.cfg.ActionFilesDir == "" {
			// Config.Validate prevents this at startup whenever a
			// file-needing route is present; defensive guard.
			return fmt.Errorf("action_files_dir is not configured but a route requires per-action helper files")
		}
		dir := filepath.Join(cs.cfg.ActionFilesDir, action.ID)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create per-action helper dir: %w", err)
		}
		actionDir = dir
		return nil
	}
	writeFile := func(name, contents string) error {
		if err := ensureDir(); err != nil {
			return err
		}
		path := filepath.Join(actionDir, name)
		if d := filepath.Dir(path); d != actionDir {
			if err := os.MkdirAll(d, 0o700); err != nil {
				return fmt.Errorf("create per-action helper subdir: %w", err)
			}
		}
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
		return nil
	}

	for _, du := range cs.cfg.mappedUpstreams() {
		// The per-destination loopback URL mirrors the upstream path:
		// http://127.0.0.1:<port>/<dest><base-path>. Embedding the base
		// path in the URL the tool is pointed at (rather than prepending
		// it in the reverse-proxy) keeps the loopback path depth equal to
		// the upstream path depth, so RELATIVE links emitted by the
		// upstream (computed against its real path) resolve to URLs that
		// stay inside the destination namespace. The reverse-proxy
		// enforces the base path as a containment subtree (403 outside).
		route := base + "/" + du.Destination + du.BasePath
		switch du.Tool {
		case ToolPyPI:
			// uv and pip both accept an index URL via env. For PyPI-style
			// registries the route's base path must be the PACKAGE-REPO
			// ROOT (e.g. /api/pypi/<repo>), NOT the .../simple index: the
			// PEP 503 simple index lives at <root>/simple, but the file
			// links it serves resolve to sibling paths OUTSIDE /simple
			// (JFrog: <root>/packages/...), which must stay inside the
			// containment subtree. We expose both the uv and pip names so
			// either tool is covered.
			index := route + "/simple"
			env["UV_DEFAULT_INDEX"] = index
			env["UV_INDEX"] = index
			env["PIP_INDEX_URL"] = index
			env["PIP_EXTRA_INDEX_URL"] = index
		case ToolCargo:
			// cargo's registry path defaults to rustls+webpki-roots and
			// ignores env-supplied CAs and (for the registry) HTTP_PROXY
			// source selection; source replacement must be expressed in
			// config. Write a config.toml under a per-action CARGO_HOME
			// that replaces the crates.io source with the loopback route.
			// CARGO_HOME must be writable: cargo populates
			// $CARGO_HOME/{registry,git,...} during builds.
			if err := writeFile("cargo/config.toml", cargoConfigTOML(route)); err != nil {
				return nil, err
			}
			env["CARGO_HOME"] = filepath.Join(actionDir, "cargo")
		case ToolDocker:
			// A docker/OCI client cannot be pointed at a loopback mirror
			// by env; the registry mirror is daemon/containers
			// configuration. Write a containers registries.conf mirroring
			// the upstream host to the loopback route, and point
			// buildah/podman/skopeo at it via CONTAINERS_REGISTRIES_CONF.
			if err := writeFile("registries.conf", dockerRegistriesConf(du.Host, route)); err != nil {
				return nil, err
			}
			env["CONTAINERS_REGISTRIES_CONF"] = filepath.Join(actionDir, "registries.conf")
		case ToolGit:
			// git has no index env; an insteadOf rewrite in gitconfig
			// redirects https://<host>/ to the loopback route. Since git
			// 2.32, GIT_CONFIG_GLOBAL overrides the search for
			// $HOME/.gitconfig, so the action's HOME is untouched.
			if err := writeFile("gitconfig", gitInsteadOf(du.Host, route)); err != nil {
				return nil, err
			}
			env["GIT_CONFIG_GLOBAL"] = filepath.Join(actionDir, "gitconfig")
		}
	}
	return env, nil
}

// noProxy returns the configured NO_PROXY value or a conservative
// default covering loopback and the cluster service CIDRs.
func (cs *controlServer) noProxy() string {
	if cs.cfg.NoProxy != "" {
		return cs.cfg.NoProxy
	}
	return "localhost,127.0.0.1,::1,.svc,.svc.cluster.local,.cluster.local,169.254.169.254"
}

// startProxy allocates a loopback port and starts a per-action proxy on
// it, retrying across the configured range until a bind succeeds.
func (cs *controlServer) startProxy(action *Action) (int, *actionProxy, error) {
	proxy, err := newActionProxy(action, cs.cfg, cs.cache, cs.audit, cs.metrics, cs.upstream)
	if err != nil {
		return 0, nil, err
	}
	lo, hi := cs.cfg.ProxyPortRange[0], cs.cfg.ProxyPortRange[1]
	total := hi - lo + 1

	cs.mu.Lock()
	defer cs.mu.Unlock()
	for tried := 0; tried < total; tried++ {
		port := cs.nextPort
		cs.nextPort++
		if cs.nextPort > hi {
			cs.nextPort = lo
		}
		if _, busy := cs.usedPorts[port]; busy {
			continue
		}
		if err := proxy.Start(port); err != nil {
			// Port taken by something outside our bookkeeping; skip it.
			continue
		}
		cs.usedPorts[port] = struct{}{}
		return port, proxy, nil
	}
	return 0, nil, fmt.Errorf("no free port in range [%d,%d]", lo, hi)
}

// teardownAction is the registry eviction hook: it closes the action's
// proxy, frees its port, drops its cached credentials, and removes the
// per-action helper-files directory. It runs for both explicit DELETEs
// and TTL expiry.
func (cs *controlServer) teardownAction(a *Action) {
	cs.mu.Lock()
	proxy := cs.proxies[a.ID]
	delete(cs.proxies, a.ID)
	delete(cs.usedPorts, a.ProxyPort)
	cs.mu.Unlock()

	if proxy != nil {
		proxy.Close()
	}
	if cs.cache != nil {
		cs.cache.evictAction(a.ID)
	}
	if cs.cfg.ActionFilesDir != "" {
		// Best-effort: a leftover dir is bounded by the next pod restart
		// (emptyDir is pod-scoped) and is not security-critical (the
		// contents are routing config, not credentials).
		_ = os.RemoveAll(filepath.Join(cs.cfg.ActionFilesDir, a.ID))
	}
}

// closeAll tears down every live proxy. The server calls it on shutdown.
func (cs *controlServer) closeAll() {
	for _, a := range cs.registry.snapshot() {
		cs.registry.Delete(a.ID)
	}
}

// parseExpiry parses an RFC3339 expires_at, defaulting to one hour from
// now when empty. An expiry in the past is rejected.
func parseExpiry(s string, now time.Time) (time.Time, error) {
	if s == "" {
		return now.Add(time.Hour), nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, err
	}
	if !t.After(now) {
		return time.Time{}, fmt.Errorf("expires_at is in the past")
	}
	return t, nil
}

// newActionID returns a fresh URL-safe 128-bit random action_id.
func newActionID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// writeJSON serialises v to w with the supplied status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

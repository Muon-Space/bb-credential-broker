// Command egress-authd-cred is a tool-agnostic credential adapter that fetches
// a broker-minted credential from the egress-authd sidecar's per-action control
// socket at use time, instead of materialising the credential into the action's
// filesystem.
//
// It serves three credential-helper protocols, selected by the basename of
// argv[0] (the image ships the binary under three hard-linked names):
//
//   - docker-credential-egress-authd → Docker's credential-helper protocol
//     (get/store/erase/list; get reads the registry server URL from stdin and
//     replies with {ServerURL, Username, Secret} JSON).
//   - git-credential-egress-authd → Git's credential-helper protocol
//     (get/store/erase; get reads key=value lines from stdin and echoes them
//     back with username= and password= appended).
//   - egress-authd-cred (the bare, unprefixed name) → Bazel/EngFlow's
//     credential-helper protocol (get reads {"uri":"…"} JSON from stdin and
//     replies with {"headers":{"Authorization":["<scheme> <token>"]}} JSON).
//     Bazel is the only consumer whose canonical invocation is the unprefixed
//     binary path plus `get`, so the no-prefix case maps to it unambiguously.
//
// Every adapter reads the action id and control-socket path from the
// environment the worker injected into the action (EGRESS_AUTHD_ACTION_ID,
// EGRESS_AUTHD_CONTROL_SOCKET), calls
// GET http://unix/actions/{id}/credential?host=<host> over the Unix socket, and
// shapes the broker's {scheme, username, token} reply into the protocol's wire
// format. All adapters fail closed: any error exits non-zero so the fetch is
// rejected rather than proceeding unauthenticated. store/erase are no-ops (the
// adapter persists nothing).
//
// This is the "at-use, not at-rest" counterpart to the loopback proxy's header
// injection: the credential lives only in this short-lived process during a
// fetch, never in a file the action can read later.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// fallbackUsername is sent to docker/git when the broker credential carries no
// username. Docker rejects an empty username, but token-as-password OCI
// registries (GHE/GitHub container registry) ignore it and validate only the
// secret, so any non-empty sentinel works.
const fallbackUsername = "x-access-token"

// adapter renders one credential-helper protocol. Adapters take an explicit
// stdin/stdout (rather than touching os.Stdin/os.Stdout) so they are unit
// testable without spawning a subprocess.
type adapter func(args []string, stdin io.Reader, stdout io.Writer) error

func main() {
	a := dispatch(filepath.Base(os.Args[0]))
	if err := a(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, filepath.Base(os.Args[0])+":", err)
		os.Exit(1)
	}
}

// dispatch selects the adapter for the binary's argv[0] basename. docker and
// git are always reached via their prefixed names; the bare name (and anything
// unrecognised) maps to the Bazel/EngFlow adapter.
func dispatch(base string) adapter {
	switch base {
	case "docker-credential-egress-authd":
		return dockerAdapter
	case "git-credential-egress-authd":
		return gitAdapter
	default:
		return bazelAdapter
	}
}

// brokerCredential is the egress-authd control endpoint's response. The broker
// only populates {scheme, username, token} today; Expires is accepted for
// forward-compatibility and omitted from output when empty.
type brokerCredential struct {
	Scheme   string `json:"scheme"`
	Username string `json:"username"`
	Token    string `json:"token"`
	Expires  string `json:"expires,omitempty"`
}

// fetchCredential calls the sidecar control socket and returns the broker
// credential for host, or an error (fail-closed) if the socket is unreachable,
// returns non-200, or returns an empty token.
func fetchCredential(socket, actionID, host string) (*brokerCredential, error) {
	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socket)
			},
		},
	}
	u := fmt.Sprintf("http://unix/actions/%s/credential?host=%s",
		url.PathEscape(actionID), url.QueryEscape(host))
	// #nosec G704 -- http transport DialContext is pinned to the per-action
	// unix socket; the URL host is never resolved or dialed.
	resp, err := client.Get(u)
	if err != nil {
		return nil, fmt.Errorf("contact egress-authd control socket %s: %w", socket, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return nil, fmt.Errorf("egress-authd returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var cred brokerCredential
	if err := json.NewDecoder(resp.Body).Decode(&cred); err != nil {
		return nil, fmt.Errorf("decode credential: %w", err)
	}
	if cred.Token == "" {
		return nil, fmt.Errorf("egress-authd returned an empty token")
	}
	return &cred, nil
}

// actionEnv reads the required per-action environment the worker injected. Both
// variables must be set; a missing one is a fail-closed error.
func actionEnv() (actionID, socket string, err error) {
	actionID = os.Getenv("EGRESS_AUTHD_ACTION_ID")
	socket = os.Getenv("EGRESS_AUTHD_CONTROL_SOCKET")
	if actionID == "" || socket == "" {
		return "", "", fmt.Errorf("EGRESS_AUTHD_ACTION_ID and EGRESS_AUTHD_CONTROL_SOCKET must be set")
	}
	return actionID, socket, nil
}

// normalizeHost reduces a docker-supplied server URL to the bare hostname the
// sidecar's host->destination map and docker's credHelpers keys use: it strips
// a scheme, any path, and an optional port.
func normalizeHost(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		return h
	}
	return s
}

// dockerCredential is docker's credential-helper `get` reply.
type dockerCredential struct {
	ServerURL string
	Username  string
	Secret    string
}

// dockerAdapter implements docker's credential-helper protocol. Behaviour is
// byte-identical to the former docker-credential-egress-authd command.
func dockerAdapter(args []string, stdin io.Reader, stdout io.Writer) error {
	op := ""
	if len(args) > 0 {
		op = args[0]
	}
	switch op {
	case "get":
		return dockerGet(stdin, stdout)
	case "store", "erase":
		// This adapter persists nothing. Consume stdin so docker does not
		// observe a broken pipe, then succeed.
		_, _ = io.Copy(io.Discard, stdin)
		return nil
	case "list":
		// We do not enumerate stored credentials.
		_, _ = fmt.Fprintln(stdout, "{}")
		return nil
	default:
		return fmt.Errorf("usage: docker-credential-egress-authd <get|store|erase|list>")
	}
}

func dockerGet(stdin io.Reader, stdout io.Writer) error {
	data, err := io.ReadAll(io.LimitReader(stdin, 4096))
	if err != nil {
		return fmt.Errorf("read server URL from stdin: %w", err)
	}
	host := normalizeHost(string(data))
	if host == "" {
		return fmt.Errorf("empty registry host on stdin")
	}
	actionID, socket, err := actionEnv()
	if err != nil {
		return err
	}
	cred, err := fetchCredential(socket, actionID, host)
	if err != nil {
		return err
	}
	username := cred.Username
	if username == "" {
		username = fallbackUsername
	}
	out := dockerCredential{ServerURL: host, Username: username, Secret: cred.Token}
	// #nosec G117 -- docker credential-helper get-reply requires the field
	// name "Secret"; not an accidentally serialized secret.
	return json.NewEncoder(stdout).Encode(out)
}

// gitAdapter implements git's credential-helper protocol. get reads the
// key=value attribute lines git sends on stdin, fetches the credential for the
// requested host, and echoes the attributes back with username= and password=
// appended (basic-scheme only; the credential is sent as the password).
func gitAdapter(args []string, stdin io.Reader, stdout io.Writer) error {
	op := ""
	if len(args) > 0 {
		op = args[0]
	}
	switch op {
	case "get":
		return gitGet(stdin, stdout)
	case "store", "erase":
		// This adapter persists nothing. Drain stdin and succeed.
		_, _ = io.Copy(io.Discard, stdin)
		return nil
	default:
		return fmt.Errorf("usage: git-credential-egress-authd <get|store|erase>")
	}
}

func gitGet(stdin io.Reader, stdout io.Writer) error {
	attrs, order, err := readGitAttrs(stdin)
	if err != nil {
		return err
	}
	host := gitHost(attrs)
	if host == "" {
		return fmt.Errorf("git credential request carried no host")
	}
	actionID, socket, err := actionEnv()
	if err != nil {
		return err
	}
	cred, err := fetchCredential(socket, actionID, host)
	if err != nil {
		return err
	}
	username := cred.Username
	if username == "" {
		username = fallbackUsername
	}
	// Echo the request attributes back (git matches them), then supply the
	// resolved username/password, terminated by a blank line.
	var b strings.Builder
	for _, k := range order {
		if k == "username" || k == "password" {
			continue
		}
		fmt.Fprintf(&b, "%s=%s\n", k, attrs[k])
	}
	fmt.Fprintf(&b, "username=%s\n", username)
	fmt.Fprintf(&b, "password=%s\n", cred.Token)
	b.WriteString("\n")
	_, err = io.WriteString(stdout, b.String())
	return err
}

// readGitAttrs parses git's key=value credential lines from stdin. Parsing
// stops at the first blank line or EOF. It returns the attribute map plus the
// keys in first-seen order so the reply preserves the request's ordering.
func readGitAttrs(stdin io.Reader) (map[string]string, []string, error) {
	data, err := io.ReadAll(io.LimitReader(stdin, 8192))
	if err != nil {
		return nil, nil, fmt.Errorf("read git credential attributes from stdin: %w", err)
	}
	attrs := make(map[string]string)
	var order []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			break
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if _, seen := attrs[k]; !seen {
			order = append(order, k)
		}
		attrs[k] = v
	}
	return attrs, order, nil
}

// gitHost resolves the registry host from git's credential attributes: a full
// url= attribute wins (its .Host is used), otherwise the host= attribute.
func gitHost(attrs map[string]string) string {
	if raw := attrs["url"]; raw != "" {
		if u, err := url.Parse(raw); err == nil && u.Host != "" {
			return normalizeHost(u.Host)
		}
	}
	return normalizeHost(attrs["host"])
}

// bazelHeaders is the Bazel/EngFlow credential-helper `get` reply.
type bazelHeaders struct {
	Headers map[string][]string `json:"headers"`
	Expires string              `json:"expires,omitempty"`
}

// bazelRequest is the Bazel/EngFlow credential-helper `get` request.
type bazelRequest struct {
	URI string `json:"uri"`
}

// bazelAdapter implements Bazel's (EngFlow-compatible) credential-helper
// protocol: get reads {"uri":"…"} from stdin and replies with an Authorization
// header carrying the broker credential. This is the only adapter that uses the
// broker-supplied scheme (defaulting to Bearer).
func bazelAdapter(args []string, stdin io.Reader, stdout io.Writer) error {
	op := ""
	if len(args) > 0 {
		op = args[0]
	}
	if op != "get" {
		return fmt.Errorf("usage: egress-authd-cred get")
	}
	var req bazelRequest
	if err := json.NewDecoder(io.LimitReader(stdin, 8192)).Decode(&req); err != nil {
		return fmt.Errorf("decode bazel credential request: %w", err)
	}
	if req.URI == "" {
		return fmt.Errorf("bazel credential request carried no uri")
	}
	u, err := url.Parse(req.URI)
	if err != nil {
		return fmt.Errorf("parse bazel credential uri %q: %w", req.URI, err)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("bazel credential uri %q has no host", req.URI)
	}
	actionID, socket, err := actionEnv()
	if err != nil {
		return err
	}
	cred, err := fetchCredential(socket, actionID, host)
	if err != nil {
		return err
	}
	scheme := cred.Scheme
	if scheme == "" {
		scheme = "Bearer"
	}
	out := bazelHeaders{
		Headers: map[string][]string{
			"Authorization": {scheme + " " + cred.Token},
		},
		Expires: cred.Expires,
	}
	return json.NewEncoder(stdout).Encode(out)
}

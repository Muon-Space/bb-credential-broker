// Command docker-credential-egress-authd is a Docker credential helper that
// fetches a broker-minted registry credential from the egress-authd sidecar's
// per-action control socket at pull time, instead of materialising the
// credential into the action's filesystem.
//
// Docker invokes it (per its credential-helper protocol) as
// `docker-credential-egress-authd <op>`; for `get` the registry server URL is
// read from stdin. The helper reads the action id and control-socket path from
// the environment the worker injected into the action (EGRESS_AUTHD_ACTION_ID,
// EGRESS_AUTHD_CONTROL_SOCKET), calls
// GET http://unix/actions/{id}/credential?host=<host> over the Unix socket,
// and replies with Docker's get-protocol JSON {ServerURL, Username, Secret}.
//
// It fails closed: any error exits non-zero so the docker pull is rejected
// rather than proceeding unauthenticated. store/erase are no-ops (the helper
// persists nothing); list returns an empty set.
//
// This is the "at-use, not at-rest" counterpart to the loopback proxy's
// header injection: the credential lives only in this short-lived process
// during a pull, never in a file the action can read later.
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
	"strings"
	"time"
)

// fallbackUsername is sent to docker when the broker credential carries no
// username. Docker rejects an empty username, but token-as-password OCI
// registries (GHE/GitHub container registry) ignore it and validate only the
// secret, so any non-empty sentinel works.
const fallbackUsername = "x-access-token"

func main() {
	op := ""
	if len(os.Args) > 1 {
		op = os.Args[1]
	}
	switch op {
	case "get":
		if err := get(os.Stdin, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "docker-credential-egress-authd:", err)
			os.Exit(1)
		}
	case "store", "erase":
		// This helper persists nothing. Consume stdin so docker does not
		// observe a broken pipe, then succeed.
		_, _ = io.Copy(io.Discard, os.Stdin)
	case "list":
		// We do not enumerate stored credentials.
		fmt.Println("{}")
	default:
		fmt.Fprintln(os.Stderr, "usage: docker-credential-egress-authd <get|store|erase|list>")
		os.Exit(1)
	}
}

// dockerCredential is docker's credential-helper `get` reply.
type dockerCredential struct {
	ServerURL string
	Username  string
	Secret    string
}

// brokerCredential is the egress-authd control endpoint's response.
type brokerCredential struct {
	Scheme   string `json:"scheme"`
	Username string `json:"username"`
	Token    string `json:"token"`
}

func get(stdin io.Reader, stdout io.Writer) error {
	data, err := io.ReadAll(io.LimitReader(stdin, 4096))
	if err != nil {
		return fmt.Errorf("read server URL from stdin: %w", err)
	}
	host := normalizeHost(string(data))
	if host == "" {
		return fmt.Errorf("empty registry host on stdin")
	}

	actionID := os.Getenv("EGRESS_AUTHD_ACTION_ID")
	socket := os.Getenv("EGRESS_AUTHD_CONTROL_SOCKET")
	if actionID == "" || socket == "" {
		return fmt.Errorf("EGRESS_AUTHD_ACTION_ID and EGRESS_AUTHD_CONTROL_SOCKET must be set")
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
	return json.NewEncoder(stdout).Encode(out)
}

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

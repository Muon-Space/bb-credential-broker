package main

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// shortSocketPath returns a Unix-socket path short enough to fit the platform's
// sockaddr_un.sun_path limit (~104 bytes on darwin, ~108 on linux). t.TempDir()
// builds a long path keyed off the (possibly deeply-nested) test name, which can
// overflow that limit and fail bind() with EINVAL, so we mint a short temp dir
// under the system temp root and register its cleanup.
func shortSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ea")
	if err != nil {
		t.Fatalf("mkdir temp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "c.sock")
}

// startFakeBroker spins up an HTTP server on a Unix socket that mimics the
// egress-authd control endpoint GET /actions/{id}/credential?host=. It returns
// 200 {scheme,username,token} for the known (id="act1", host="ghcr.io"), 404
// for an unknown action id, and 403 for a host that is not mapped. The
// returned values are configurable so individual cases can exercise the
// empty-username and scheme paths. The socket path is returned and the server
// is torn down via t.Cleanup.
func startFakeBroker(t *testing.T, scheme, username, token string) string {
	t.Helper()
	sock := shortSocketPath(t)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix %s: %v", sock, err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/actions/", func(w http.ResponseWriter, r *http.Request) {
		// Path is /actions/{id}/credential.
		rest := strings.TrimPrefix(r.URL.Path, "/actions/")
		id, tail, _ := strings.Cut(rest, "/")
		if tail != "credential" || r.Method != http.MethodGet {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if id != "act1" {
			http.Error(w, "unknown action", http.StatusNotFound)
			return
		}
		host := r.URL.Query().Get("host")
		if host != "ghcr.io" {
			http.Error(w, "host not mapped", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"scheme":   scheme,
			"username": username,
			"token":    token,
		})
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return sock
}

// setActionEnv points the adapters at the fake broker for action "act1".
func setActionEnv(t *testing.T, socket string) {
	t.Helper()
	t.Setenv("EGRESS_AUTHD_ACTION_ID", "act1")
	t.Setenv("EGRESS_AUTHD_CONTROL_SOCKET", socket)
}

func TestDockerGet(t *testing.T) {
	sock := startFakeBroker(t, "Bearer", "ci-bot", "tok-abc")
	setActionEnv(t, sock)

	var out strings.Builder
	if err := dockerAdapter([]string{"get"}, strings.NewReader("ghcr.io\n"), &out); err != nil {
		t.Fatalf("dockerAdapter get: %v", err)
	}
	var got dockerCredential
	if err := json.Unmarshal([]byte(out.String()), &got); err != nil {
		t.Fatalf("decode docker reply %q: %v", out.String(), err)
	}
	if got.ServerURL != "ghcr.io" || got.Username != "ci-bot" || got.Secret != "tok-abc" {
		t.Fatalf("docker reply = %+v, want {ghcr.io ci-bot tok-abc}", got)
	}
}

func TestDockerGetEmptyUsername(t *testing.T) {
	sock := startFakeBroker(t, "Bearer", "", "tok-abc")
	setActionEnv(t, sock)

	var out strings.Builder
	if err := dockerAdapter([]string{"get"}, strings.NewReader("https://ghcr.io/v2/\n"), &out); err != nil {
		t.Fatalf("dockerAdapter get: %v", err)
	}
	var got dockerCredential
	if err := json.Unmarshal([]byte(out.String()), &got); err != nil {
		t.Fatalf("decode docker reply %q: %v", out.String(), err)
	}
	if got.Username != fallbackUsername {
		t.Fatalf("docker username = %q, want %q (fallback)", got.Username, fallbackUsername)
	}
	if got.Secret != "tok-abc" {
		t.Fatalf("docker secret = %q, want tok-abc", got.Secret)
	}
}

func TestDockerGetUnknownHostFailsClosed(t *testing.T) {
	sock := startFakeBroker(t, "Bearer", "ci-bot", "tok-abc")
	setActionEnv(t, sock)

	var out strings.Builder
	err := dockerAdapter([]string{"get"}, strings.NewReader("docker.io\n"), &out)
	if err == nil {
		t.Fatalf("dockerAdapter get for unmapped host should fail closed, got nil err and output %q", out.String())
	}
}

func TestGitGet(t *testing.T) {
	sock := startFakeBroker(t, "Bearer", "ci-bot", "tok-xyz")
	setActionEnv(t, sock)

	var out strings.Builder
	in := "protocol=https\nhost=ghcr.io\n\n"
	if err := gitAdapter([]string{"get"}, strings.NewReader(in), &out); err != nil {
		t.Fatalf("gitAdapter get: %v", err)
	}
	s := out.String()
	if !strings.Contains(s, "username=ci-bot\n") {
		t.Fatalf("git reply missing username line: %q", s)
	}
	if !strings.Contains(s, "password=tok-xyz\n") {
		t.Fatalf("git reply missing password line: %q", s)
	}
	if !strings.Contains(s, "host=ghcr.io\n") {
		t.Fatalf("git reply should echo host= attribute: %q", s)
	}
	if !strings.HasSuffix(s, "\n\n") {
		t.Fatalf("git reply should end with a blank line: %q", s)
	}
}

func TestGitGetViaURLAttr(t *testing.T) {
	sock := startFakeBroker(t, "Bearer", "ci-bot", "tok-xyz")
	setActionEnv(t, sock)

	var out strings.Builder
	in := "url=https://ghcr.io/Muon-Space/foo\n\n"
	if err := gitAdapter([]string{"get"}, strings.NewReader(in), &out); err != nil {
		t.Fatalf("gitAdapter get via url attr: %v", err)
	}
	s := out.String()
	if !strings.Contains(s, "password=tok-xyz\n") {
		t.Fatalf("git reply (url attr) missing password line: %q", s)
	}
}

func TestBazelGet(t *testing.T) {
	sock := startFakeBroker(t, "", "ci-bot", "tok-bz")
	setActionEnv(t, sock)

	var out strings.Builder
	if err := bazelAdapter([]string{"get"}, strings.NewReader(`{"uri":"https://ghcr.io/v2/"}`), &out); err != nil {
		t.Fatalf("bazelAdapter get: %v", err)
	}
	var got bazelHeaders
	if err := json.Unmarshal([]byte(out.String()), &got); err != nil {
		t.Fatalf("decode bazel reply %q: %v", out.String(), err)
	}
	auth := got.Headers["Authorization"]
	if len(auth) != 1 || auth[0] != "Bearer tok-bz" {
		t.Fatalf("bazel Authorization = %v, want [Bearer tok-bz]", auth)
	}
}

func TestBazelGetWithScheme(t *testing.T) {
	sock := startFakeBroker(t, "Token", "ci-bot", "tok-bz")
	setActionEnv(t, sock)

	var out strings.Builder
	if err := bazelAdapter([]string{"get"}, strings.NewReader(`{"uri":"https://ghcr.io/v2/"}`), &out); err != nil {
		t.Fatalf("bazelAdapter get: %v", err)
	}
	var got bazelHeaders
	if err := json.Unmarshal([]byte(out.String()), &got); err != nil {
		t.Fatalf("decode bazel reply %q: %v", out.String(), err)
	}
	auth := got.Headers["Authorization"]
	if len(auth) != 1 || auth[0] != "Token tok-bz" {
		t.Fatalf("bazel Authorization = %v, want [Token tok-bz]", auth)
	}
}

func TestArgv0Dispatch(t *testing.T) {
	// adapterName maps an adapter func to a stable id by invoking dispatch
	// against a sentinel; we compare function behaviour indirectly by name.
	cases := []struct {
		argv0 string
		want  string
	}{
		{"docker-credential-egress-authd", "docker"},
		{"git-credential-egress-authd", "git"},
		{"egress-authd-cred", "bazel"},
		{"/abs/path/git-credential-egress-authd", "git"},
		{"/usr/local/bin/egress-authd-cred", "bazel"},
		{"something-unexpected", "bazel"},
	}
	for _, tc := range cases {
		got := adapterID(dispatch(filepath.Base(tc.argv0)))
		if got != tc.want {
			t.Errorf("dispatch(base(%q)) = %s adapter, want %s", tc.argv0, got, tc.want)
		}
	}
}

// adapterID identifies which adapter dispatch returned by exercising it against
// a request that all three reject before any network I/O, then keying off the
// usage string. This avoids comparing function pointers (which Go forbids).
func adapterID(a adapter) string {
	var out strings.Builder
	err := a([]string{"__bogus_op__"}, strings.NewReader(""), &out)
	if err == nil {
		return "unknown"
	}
	switch {
	case strings.Contains(err.Error(), "docker-credential-egress-authd"):
		return "docker"
	case strings.Contains(err.Error(), "git-credential-egress-authd"):
		return "git"
	case strings.Contains(err.Error(), "egress-authd-cred"):
		return "bazel"
	default:
		return "unknown"
	}
}

func TestStoreEraseNoOp(t *testing.T) {
	// store/erase must drain stdin, write nothing, and return nil — for both
	// the docker and git adapters. They must not require the broker env.
	for _, tc := range []struct {
		name string
		a    adapter
	}{
		{"docker", dockerAdapter},
		{"git", gitAdapter},
	} {
		for _, op := range []string{"store", "erase"} {
			var out strings.Builder
			in := strings.NewReader("protocol=https\nhost=ghcr.io\nusername=x\npassword=y\n\n")
			if err := tc.a([]string{op}, in, &out); err != nil {
				t.Errorf("%s %s: unexpected error %v", tc.name, op, err)
			}
			if out.String() != "" {
				t.Errorf("%s %s: wrote output %q, want none", tc.name, op, out.String())
			}
			// stdin must be fully drained.
			if n, _ := io.Copy(io.Discard, in); n != 0 {
				t.Errorf("%s %s: stdin not fully drained (%d bytes left)", tc.name, op, n)
			}
		}
	}
}

func TestMissingEnvFailsClosed(t *testing.T) {
	// No EGRESS_AUTHD_* env set: get must fail closed for every adapter.
	t.Setenv("EGRESS_AUTHD_ACTION_ID", "")
	t.Setenv("EGRESS_AUTHD_CONTROL_SOCKET", "")

	var out strings.Builder
	if err := dockerAdapter([]string{"get"}, strings.NewReader("ghcr.io\n"), &out); err == nil {
		t.Errorf("docker get with no env should fail closed")
	}
	out.Reset()
	if err := gitAdapter([]string{"get"}, strings.NewReader("host=ghcr.io\n\n"), &out); err == nil {
		t.Errorf("git get with no env should fail closed")
	}
	out.Reset()
	if err := bazelAdapter([]string{"get"}, strings.NewReader(`{"uri":"https://ghcr.io/"}`), &out); err == nil {
		t.Errorf("bazel get with no env should fail closed")
	}
}

func TestEmptyTokenFailsClosed(t *testing.T) {
	sock := startFakeBroker(t, "Bearer", "ci-bot", "")
	setActionEnv(t, sock)

	var out strings.Builder
	if err := dockerAdapter([]string{"get"}, strings.NewReader("ghcr.io\n"), &out); err == nil {
		t.Fatalf("docker get with empty broker token should fail closed, got output %q", out.String())
	}
}

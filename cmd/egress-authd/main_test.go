package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// validConfig is the smallest egress-authd configuration that passes
// every start-up validation check: an absolute broker URL, a control
// socket, a valid port range, and one mapped host.
const validConfig = `{
  broker_token_url: 'https://broker.example.com',
  listen_socket: '/run/egress-authd/control.sock',
  proxy_port_range: [15000, 15999],
  host_destination_map: { 'registry.example.com': 'registry' },
}`

// writeConfig writes body to a temporary Jsonnet file and returns its
// path.
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.jsonnet")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestRun(t *testing.T) {
	t.Parallel()
	valid := writeConfig(t, validConfig)
	invalid := writeConfig(t, `{ broker_token_url: '' }`)

	tests := []struct {
		name string
		args []string
		want int
	}{
		{name: "no arguments", args: []string{"egress-authd"}, want: 2},
		{name: "too many arguments", args: []string{"egress-authd", "a", "b"}, want: 2},
		{name: "validate without path", args: []string{"egress-authd", "validate"}, want: 2},
		{name: "validate valid config", args: []string{"egress-authd", "validate", valid}, want: 0},
		{name: "validate invalid config", args: []string{"egress-authd", "validate", invalid}, want: 1},
		{name: "validate missing file", args: []string{"egress-authd", "validate", "/no/such/config.jsonnet"}, want: 1},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var stderr bytes.Buffer
			if got := run(tc.args, &stderr); got != tc.want {
				t.Errorf("run(%q): got exit %d, want %d (stderr=%q)", tc.args, got, tc.want, stderr.String())
			}
		})
	}
}

// Command egress-authd is the per-action egress proxy sidecar that
// injects broker-minted credentials into a Buildbarn action's outbound
// HTTP(S) traffic.
//
// Usage:
//
//	egress-authd <config.jsonnet>
//	egress-authd validate <config.jsonnet>
//
// The single-positional-argument form runs the sidecar against the
// supplied configuration. The `validate` subcommand loads the same
// configuration and runs every start-up validation path without binding
// the control socket or diagnostics listener; it exits 0 when the
// configuration is valid and non-zero when it is not.
//
// The sidecar is configured by a Jsonnet file matching
// pkg/egressauthd.Config. It exposes a worker→sidecar
// control API over a Unix-domain socket; per registered
// action it allocates a loopback forward proxy that exchanges the
// action's broker delegation grant for a credential at the broker's
// /token endpoint.
package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"

	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/egressauthd"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))
	os.Exit(run(os.Args, os.Stderr))
}

// run dispatches the CLI. It is factored out of main so unit tests can
// drive the entry point without invoking os.Exit. The returned integer
// is the process exit code: 0 on success, 1 on runtime failure, and 2
// on usage errors.
func run(args []string, stderr io.Writer) int {
	if len(args) < 2 {
		usage(stderr, args[0])
		return 2
	}
	switch args[1] {
	case "validate":
		if len(args) != 3 {
			usage(stderr, args[0])
			return 2
		}
		if _, err := egressauthd.Load(args[2]); err != nil {
			_, _ = fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	default:
		if len(args) != 2 {
			usage(stderr, args[0])
			return 2
		}
		cfg, err := egressauthd.Load(args[1])
		if err != nil {
			slog.Error("load configuration", "error", err)
			return 1
		}
		if err := egressauthd.Run(context.Background(), cfg); err != nil {
			slog.Error("sidecar exited with error", "error", err)
			return 1
		}
		return 0
	}
}

// usage prints the sidecar's CLI synopsis to w.
func usage(w io.Writer, prog string) {
	_, _ = fmt.Fprintf(w,
		"usage:\n  %s <config.jsonnet>\n  %s validate <config.jsonnet>\n",
		prog, prog)
}

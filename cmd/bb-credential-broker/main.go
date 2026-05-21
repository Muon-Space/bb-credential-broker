// Command bb-credential-broker is the broker's executable entry
// point.
//
// Usage:
//
//	bb-credential-broker <config.jsonnet>
//	bb-credential-broker validate <config.jsonnet>
//
// The single-positional-argument form runs the broker against the
// supplied configuration. The `validate` subcommand loads the same
// configuration and runs every start-up validation path without
// binding listeners, opening outbound connections, or starting
// background goroutines; it exits 0 when the configuration is valid
// and non-zero when it is not. Operators are expected to run the
// validate subcommand in CI or as a terragrunt-plan precondition.
package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"

	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/app"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/config"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))
	os.Exit(run(os.Args, os.Stderr))
}

// run dispatches the CLI. It is factored out of main so unit tests
// can drive the entry point without invoking os.Exit, and accepts
// stderr as an io.Writer so tests can capture output without
// mutating the process-global os.Stderr (which would race when
// multiple test functions run in parallel).
//
// The returned integer is the process exit code: 0 on success, 1
// on runtime failure, and 2 on usage errors.
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
		if err := app.Validate(args[2]); err != nil {
			_, _ = fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	default:
		// Backwards-compatible single-argument form: the lone
		// positional argument is the configuration path.
		if len(args) != 2 {
			usage(stderr, args[0])
			return 2
		}
		cfg, err := config.Load(args[1])
		if err != nil {
			slog.Error("load configuration", "error", err)
			return 1
		}
		if err := app.Run(context.Background(), cfg); err != nil {
			slog.Error("server exited with error", "error", err)
			return 1
		}
		return 0
	}
}

// usage prints the broker's CLI synopsis to w. Both the run and
// validate subcommands surface here so operators discover the
// validate path the first time they invoke the binary with no
// arguments.
func usage(w io.Writer, prog string) {
	_, _ = fmt.Fprintf(w, "usage:\n  %s <config.jsonnet>\n  %s validate <config.jsonnet>\n", prog, prog)
}

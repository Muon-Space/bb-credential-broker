// Command bb-credential-broker is the broker's executable entry
// point. It accepts a single positional argument: the path to the
// Jsonnet configuration file. All other tunables live in that file.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/app"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/config"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <config.jsonnet>\n", os.Args[0])
		os.Exit(2)
	}

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	cfg, err := config.Load(os.Args[1])
	if err != nil {
		slog.Error("load configuration", "error", err)
		os.Exit(1)
	}

	if err := app.Run(context.Background(), cfg); err != nil {
		slog.Error("server exited with error", "error", err)
		os.Exit(1)
	}
}

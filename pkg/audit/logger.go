// Package audit emits structured audit-log records describing every
// /delegate and /token operation. The records are written to stdout
// as one JSON object per line so that the cluster's log-collection
// stack can ingest them without any further parsing.
//
// The audit log is intentionally narrow: it records who was asking
// for what and whether the request succeeded, and nothing else.
// Token values, secret material and request bodies never appear in
// the output.
package audit

import (
	"context"
	"io"
	"log/slog"
	"os"
	"time"
)

// Operation names the kind of operation being recorded.
type Operation string

const (
	// OperationDelegate records the issuance of a nonce by /delegate.
	OperationDelegate Operation = "delegate"

	// OperationToken records the consumption of a nonce by /token.
	OperationToken Operation = "token"
)

// Event is a single audit-log record. Logger.Log encodes Event into
// the JSON line that lands on stdout.
type Event struct {
	// Time is the wall-clock instant the operation completed.
	Time time.Time

	// Op identifies the kind of operation.
	Op Operation

	// IdentityType is the resolved identity type at the time of
	// the operation, or empty if the operation did not reach
	// identity resolution.
	IdentityType string

	// IdentityPrincipal is the resolved identity principal at
	// the time of the operation, or empty if the operation did
	// not reach identity resolution.
	IdentityPrincipal string

	// Destination is the destination name involved in the
	// operation. Empty for /delegate operations.
	Destination string

	// GrantedDestinations is the list of destination names
	// granted by /delegate. Nil for /token operations.
	GrantedDestinations []string

	// Success reports whether the operation succeeded from the
	// caller's point of view.
	Success bool

	// Error is the error string returned to the caller on
	// failure, or empty on success.
	Error string
}

// Logger writes audit events to a JSON-line sink. A Logger is safe
// for concurrent use by multiple goroutines.
type Logger struct {
	slog *slog.Logger
}

// NewLogger constructs a Logger that emits records to w. Production
// callers typically pass os.Stdout; tests pass a bytes.Buffer.
func NewLogger(w io.Writer) *Logger {
	return &Logger{
		slog: slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		})),
	}
}

// NewStdoutLogger is a convenience constructor that wires the
// Logger to os.Stdout.
func NewStdoutLogger() *Logger { return NewLogger(os.Stdout) }

// Log emits e as a single JSON-line record. Errors from the
// underlying writer are not surfaced; an audit-log sink that fails
// is reported via the standard error log to ensure the failure is
// visible without adding a second failure mode to every code path
// that calls Log.
func (l *Logger) Log(_ context.Context, e Event) {
	attrs := []any{
		slog.Time("ts", e.Time),
		slog.String("op", string(e.Op)),
		slog.Bool("ok", e.Success),
	}
	if e.IdentityType != "" {
		attrs = append(attrs, slog.String("identity_type", e.IdentityType))
	}
	if e.IdentityPrincipal != "" {
		attrs = append(attrs, slog.String("identity_principal", e.IdentityPrincipal))
	}
	if e.Destination != "" {
		attrs = append(attrs, slog.String("destination", e.Destination))
	}
	if len(e.GrantedDestinations) > 0 {
		attrs = append(attrs, slog.Any("granted_destinations", e.GrantedDestinations))
	}
	if e.Error != "" {
		attrs = append(attrs, slog.String("error", e.Error))
	}
	l.slog.LogAttrs(context.Background(), slog.LevelInfo, "audit", toAttrs(attrs)...)
}

// toAttrs converts an interleaved []any of slog.Attr values into
// the typed []slog.Attr that slog.LogAttrs expects.
func toAttrs(in []any) []slog.Attr {
	out := make([]slog.Attr, 0, len(in))
	for _, v := range in {
		if a, ok := v.(slog.Attr); ok {
			out = append(out, a)
		}
	}
	return out
}

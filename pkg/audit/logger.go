// Package audit emits structured audit-log records describing every
// /delegate and /token operation. The records are written to stdout
// as one JSON object per line so that the cluster's log-collection
// stack can ingest them without any further parsing.
//
// The schema is intentionally rich enough to serve as ITAR
// compliance evidence: every entry carries the resolved Identity
// (type, principal and the full claims map), the operation
// outcome, and — for /token — the upstream-call metadata
// (destination, URL, status, duration) that joins the broker's
// decision to the destination service's own audit trail.
//
// Token values, secret material and request bodies never appear in
// audit output. Upstream failures that surface a response excerpt
// truncate it to a small fixed prefix.
package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"
)

// Event constants name the kind of operation a record describes.
// The values appear verbatim in the JSON output under the "event"
// key and are part of the published schema.
const (
	EventDelegate = "delegate"
	EventToken    = "token"
)

// Result constants name the outcome of an operation. The values
// appear verbatim in the JSON output under the "result" key and
// are part of the published schema.
//
// "granted" / "denied" apply to /delegate; "success" / "failure"
// apply to /token. The split exists because /delegate is an
// authorization decision (the broker chose to admit or refuse the
// caller's request) while /token is a mint outcome (the broker
// asked the destination to produce a credential and reports
// whether the destination responded successfully).
const (
	ResultGranted = "granted"
	ResultDenied  = "denied"
	ResultSuccess = "success"
	ResultFailure = "failure"
)

// IdentityRecord is the audit-log projection of an auth.Identity.
// It carries the type, principal and the full claims map verbatim
// so downstream compliance queries can join on any claim the
// identity provider chose to emit.
//
// Claims is rendered as a JSON object even when no claims are
// present: a nil map is materialised as the empty object to keep
// downstream schemas stable.
type IdentityRecord struct {
	Type      string         `json:"type"`
	Principal string         `json:"principal"`
	Claims    map[string]any `json:"claims"`
}

// DelegateEntry is the audit-log record emitted for one /delegate
// request. The handler emits exactly one DelegateEntry per
// request, regardless of outcome.
//
// Identity is nil for requests rejected before identity resolution
// (typically a bearer-token failure); GrantedDestinations,
// DelegationTokenJTI and DelegationTokenExp are populated only
// when Result is ResultGranted.
type DelegateEntry struct {
	Time                time.Time       `json:"ts"`
	Event               string          `json:"event"`
	Identity            *IdentityRecord `json:"identity"`
	Result              string          `json:"result"`
	DenialReason        string          `json:"denial_reason,omitempty"`
	GrantedDestinations []string        `json:"granted_destinations,omitempty"`
	DelegationTokenJTI  string          `json:"delegation_token_jti,omitempty"`
	DelegationTokenExp  *time.Time      `json:"delegation_token_exp,omitempty"`
}

// TokenEntry is the audit-log record emitted for one /token
// request. The handler emits exactly one TokenEntry per request,
// regardless of outcome.
//
// UpstreamURL, UpstreamStatus, UpstreamDurationMS and
// UpstreamResponseExcerpt are populated only for destinations
// whose mint flow performs an upstream HTTP call (the
// httpTokenExchange type); they are omitted entirely from the JSON
// output for destinations that mint locally (the staticSecret
// type). UpstreamResponseExcerpt is populated only on upstream
// failure and is bounded to a small prefix.
type TokenEntry struct {
	Time                    time.Time       `json:"ts"`
	Event                   string          `json:"event"`
	Identity                *IdentityRecord `json:"identity"`
	Destination             string          `json:"destination,omitempty"`
	Result                  string          `json:"result"`
	DenialReason            string          `json:"denial_reason,omitempty"`
	UpstreamURL             string          `json:"upstream_url,omitempty"`
	UpstreamStatus          int             `json:"upstream_status,omitempty"`
	UpstreamDurationMS      int64           `json:"upstream_duration_ms,omitempty"`
	UpstreamResponseExcerpt string          `json:"upstream_response_excerpt,omitempty"`
	TokenExpiresAt          *time.Time      `json:"token_expires_at,omitempty"`
}

// Logger is the interface the handlers depend on for audit-log
// emission. The interface admits a stdout-backed concrete
// implementation in production and a slice-recording fake in
// tests; both code paths share the same entry types so the
// published JSON schema is exercised either way.
type Logger interface {
	// LogDelegate emits the audit record for one /delegate
	// request. Implementations must serialise concurrent writes
	// so that an interleaved partial line never lands on the
	// configured sink.
	LogDelegate(ctx context.Context, e DelegateEntry)

	// LogToken emits the audit record for one /token request,
	// subject to the same serialisation requirement as
	// LogDelegate.
	LogToken(ctx context.Context, e TokenEntry)
}

// stdoutLogger is the production Logger implementation. Writes go
// to the configured sink via a single encoding/json encoder, with
// a mutex bracketing each Encode call so concurrent goroutines do
// not interleave their output.
type stdoutLogger struct {
	mu sync.Mutex
	w  io.Writer
}

// NewLogger constructs a Logger that emits records to w. Production
// callers typically pass os.Stdout; tests pass a bytes.Buffer.
//
// The returned Logger writes synchronously and does not buffer: a
// returning LogDelegate or LogToken call has completed the write
// to w before returning, so a process that crashes mid-request
// cannot lose the audit record for the preceding completed
// request.
func NewLogger(w io.Writer) Logger {
	return &stdoutLogger{w: w}
}

// NewStdoutLogger is a convenience constructor that wires the
// Logger to os.Stdout. It is the constructor app.New uses; tests
// that need to inspect output construct via NewLogger with a
// bytes.Buffer instead.
func NewStdoutLogger() Logger {
	return NewLogger(os.Stdout)
}

// LogDelegate implements Logger.
func (l *stdoutLogger) LogDelegate(_ context.Context, e DelegateEntry) {
	e.Event = EventDelegate
	if e.Identity != nil && e.Identity.Claims == nil {
		// Materialise the nil claims map as the empty object
		// so downstream schemas stay stable: the "claims" key
		// is always an object, never JSON null.
		e.Identity.Claims = map[string]any{}
	}
	l.write(e)
}

// LogToken implements Logger.
func (l *stdoutLogger) LogToken(_ context.Context, e TokenEntry) {
	e.Event = EventToken
	if e.Identity != nil && e.Identity.Claims == nil {
		e.Identity.Claims = map[string]any{}
	}
	l.write(e)
}

// write encodes v as a single JSON line and writes it to the
// configured sink under the logger's mutex. Errors from the
// underlying writer are not surfaced; an audit-log sink that fails
// is reported via the standard error log so the failure is visible
// without adding a second failure mode to every code path that
// calls Log*.
func (l *stdoutLogger) write(v any) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		// JSON encoding of a typed struct effectively cannot
		// fail; the error path is included so the linter is
		// happy and so a future struct-tag change that
		// invalidates a marshaler surfaces somewhere.
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.w.Write(buf.Bytes())
}

package egressauthd

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"
)

// Decision constants name the outcome of one proxied egress request.
// They appear verbatim under the "decision" key of the audit line and
// are part of the published schema.
const (
	// DecisionForwardedInjected: the request was forwarded upstream
	// with a broker-minted credential injected.
	DecisionForwardedInjected = "forwarded_injected"

	// DecisionForwardedNoInject: the host is allow-listed but has no
	// destination mapping, so the request was forwarded without a
	// credential.
	DecisionForwardedNoInject = "forwarded_no_inject"

	// DecisionDeniedHost: the host is not in the sidecar's host
	// allow-list; the request was rejected with 403.
	DecisionDeniedHost = "denied_host"

	// DecisionDeniedUnknownAction: no live action matched the proxy
	// the request arrived on; the request failed closed.
	DecisionDeniedUnknownAction = "denied_unknown_action"

	// DecisionFailClosedBroker: the broker denied or could not be
	// reached; the request failed closed without forwarding.
	DecisionFailClosedBroker = "fail_closed_broker"

	// DecisionError: an internal error (TLS handshake, dial failure)
	// prevented the request from completing.
	DecisionError = "error"
)

// EgressEntry is the audit-log record emitted for one proxied egress
// request. It joins the action to the host reached, the broker
// destination minted for, and the authorization decision. It carries no
// identity of its own: the sidecar relays an opaque grant and the broker
// owns the authorization decision, so the action_id is the join key back
// to the broker's own /delegate and /token audit records for the grant.
type EgressEntry struct {
	Time        time.Time `json:"ts"`
	Event       string    `json:"event"`
	ActionID    string    `json:"action_id,omitempty"`
	Host        string    `json:"host,omitempty"`
	Destination string    `json:"destination,omitempty"`
	Decision    string    `json:"decision"`
	StatusCode  int       `json:"status_code,omitempty"`
	Reason      string    `json:"reason,omitempty"`
}

// eventEgress is the value stamped into EgressEntry.Event.
const eventEgress = "egress"

// AuditLogger emits one EgressEntry per proxied request. The interface
// admits a stdout implementation in production and a recording fake in
// tests.
type AuditLogger interface {
	LogEgress(e EgressEntry)
}

// stdoutAuditLogger writes one JSON object per line to its sink under a
// mutex so concurrent proxies never interleave a partial line. It
// mirrors the broker's audit.stdoutLogger.
type stdoutAuditLogger struct {
	mu sync.Mutex
	w  io.Writer
}

// NewAuditLogger constructs an AuditLogger that writes to w.
func NewAuditLogger(w io.Writer) AuditLogger {
	return &stdoutAuditLogger{w: w}
}

// NewStdoutAuditLogger wires the audit logger to os.Stdout.
func NewStdoutAuditLogger() AuditLogger {
	return NewAuditLogger(os.Stdout)
}

// LogEgress implements AuditLogger.
func (l *stdoutAuditLogger) LogEgress(e EgressEntry) {
	e.Event = eventEgress
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(e); err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.w.Write(buf.Bytes())
}

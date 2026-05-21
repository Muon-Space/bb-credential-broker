package audit

import (
	"context"
	"time"
)

// MintAudit captures the upstream-call metadata that the /token
// handler folds into the TokenEntry it emits. Destination
// implementations populate these fields incrementally during their
// Mint call; the /token handler reads them after Mint returns so
// the audit record covers both success and failure paths uniformly.
//
// Destinations that perform no upstream HTTP call (the
// staticSecret type) leave the struct zero. The fields are tagged
// omitempty on the corresponding TokenEntry shape so absence is
// reflected in the JSON output without per-destination-type
// branching at the audit-log site.
type MintAudit struct {
	// UpstreamURL is the absolute URL the destination resolved
	// after template expansion and dispatched its request to.
	UpstreamURL string

	// UpstreamStatusCode is the HTTP status the upstream
	// service returned. It is zero when the request did not
	// reach the upstream (transport error, context cancellation,
	// etc.) and for destinations that perform no upstream call.
	UpstreamStatusCode int

	// UpstreamDuration is the wall-clock time taken by the
	// upstream round trip. It is zero when no upstream call was
	// attempted.
	UpstreamDuration time.Duration

	// UpstreamResponseExcerpt is a short prefix of the upstream
	// response body, populated only when the upstream rejected
	// the mint with a non-success status. The destination
	// implementation chooses the truncation length so the
	// excerpt fits comfortably on a single audit-log line.
	UpstreamResponseExcerpt string
}

// mintAuditKey is the unexported type used to key the MintAudit
// value inside a context. Using an unexported type prevents
// accidental collisions with values installed by unrelated code.
type mintAuditKey struct{}

// ContextWithMintAudit installs a MintAudit value into ctx so the
// destination implementation invoked further down the call chain
// can populate its fields. The /token handler is the sole producer
// of this context value; destination implementations are the sole
// consumers.
func ContextWithMintAudit(ctx context.Context, a *MintAudit) context.Context {
	return context.WithValue(ctx, mintAuditKey{}, a)
}

// MintAuditFromContext returns the MintAudit value previously
// installed on ctx, or nil when no MintAudit is in scope. Callers
// guard against a nil result so they continue to work in code
// paths (typically unit tests) that do not wrap their context.
func MintAuditFromContext(ctx context.Context) *MintAudit {
	if ctx == nil {
		return nil
	}
	a, _ := ctx.Value(mintAuditKey{}).(*MintAudit)
	return a
}

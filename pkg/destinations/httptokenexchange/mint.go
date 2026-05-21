package httptokenexchange

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/audit"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/auth"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/destinations/httptokenexchange/template"
)

// upstreamExcerptBytes bounds the response-body prefix the audit
// log records on upstream failure. 256 bytes is enough for every
// upstream auth-error message we have observed and small enough to
// keep an audit-log line workable.
const upstreamExcerptBytes = 256

// Mint executes the destination's templated HTTP exchange against
// the upstream service and returns the resulting Token.
//
// The flow is:
//
//  1. Build a per-request template Scope with the resolved Identity
//     and the destination's secret-loader bindings, then register
//     the now+DUR helpers used by any of the destination's
//     templates.
//  2. Evaluate the URL, header and body templates and assemble an
//     http.Request.
//  3. Send the request via the cached client.
//  4. Validate the response status against ExpectStatus and read
//     the body up to maxResponseBytes.
//  5. JSON-decode the body and apply the configured JMESPath
//     expressions to extract the token value and its expiry.
//
// Errors at any stage are wrapped with the destination's name and
// the offending step so they read sensibly in the audit log.
func (i *Impl) Mint(ctx context.Context, identity *auth.Identity) (*Token, error) {
	scope := template.DefaultScope(identity, i.deps.Secrets, i.deps.NamedSecrets)
	if err := i.registerNowOffsets(scope); err != nil {
		return nil, fmt.Errorf("%s: register now offsets: %w", i.name, err)
	}

	mintAudit := audit.MintAuditFromContext(ctx)

	req, err := i.buildRequest(ctx, scope)
	if err != nil {
		return nil, fmt.Errorf("%s: build request: %w", i.name, err)
	}
	// Record the resolved upstream URL before dispatching the
	// request so the audit log captures it even when the
	// transport call fails (the upstream service was never
	// reached but the broker did attempt to mint against it).
	if mintAudit != nil {
		mintAudit.UpstreamURL = req.URL.String()
	}

	start := time.Now()
	resp, err := i.client.Do(req)
	elapsed := time.Since(start)
	if mintAudit != nil {
		mintAudit.UpstreamDuration = elapsed
		if resp != nil {
			mintAudit.UpstreamStatusCode = resp.StatusCode
		}
	}
	if err != nil {
		return nil, fmt.Errorf("%s: outbound request: %w", i.name, err)
	}
	defer func() { _ = resp.Body.Close() }()

	expectStatus := i.cfg.Response.ExpectStatus
	if expectStatus == 0 {
		expectStatus = http.StatusOK
	}
	if resp.StatusCode != expectStatus {
		// Include a truncated response body in the error so that
		// audit-log readers can diagnose upstream rejection without
		// re-running the request locally with verbose logging. The
		// body is bounded to 1 KiB; that is enough for every
		// upstream auth error message we have seen and small enough
		// to keep the audit-log line workable. Any token material
		// the broker sent in the request is in the request, not in
		// the response, so this does not widen the credential leak
		// surface.
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		trimmed := strings.TrimSpace(string(snippet))
		if mintAudit != nil {
			mintAudit.UpstreamResponseExcerpt = truncate(trimmed, upstreamExcerptBytes)
		}
		return nil, fmt.Errorf("%s: response status %d, want %d; body: %s",
			i.name, resp.StatusCode, expectStatus, trimmed)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("%s: read response body: %w", i.name, err)
	}

	var decoded any
	if err := json.Unmarshal(body, &decoded); err != nil {
		return nil, fmt.Errorf("%s: parse response body as JSON: %w", i.name, err)
	}

	tok, err := i.extractToken(decoded)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i.name, err)
	}
	return tok, nil
}

// truncate returns s if its length is within n; otherwise it
// returns the first n bytes of s. The truncation is byte-wise
// rather than rune-wise because the audit-log consumer treats
// excerpts as opaque diagnostic strings and the bound exists to
// keep the line workable, not to preserve human-readable
// substrings.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// buildRequest evaluates the URL, header and body templates and
// assembles a single *http.Request bound to ctx.
func (i *Impl) buildRequest(ctx context.Context, scope *template.Scope) (*http.Request, error) {
	rawURL, err := i.parsedURL.Eval(ctx, scope)
	if err != nil {
		return nil, fmt.Errorf("evaluate url: %w", err)
	}
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse url %q: %w", rawURL, err)
	}
	if !parsedURL.IsAbs() || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		return nil, fmt.Errorf("url %q must be an absolute http or https URL", rawURL)
	}

	body, contentType, err := i.buildBody(ctx, scope)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, i.cfg.Request.Method, parsedURL.String(), body)
	if err != nil {
		return nil, fmt.Errorf("construct http request: %w", err)
	}

	for _, h := range i.parsedHeaders {
		k, err := h.key.Eval(ctx, scope)
		if err != nil {
			return nil, fmt.Errorf("evaluate header key: %w", err)
		}
		v, err := h.value.Eval(ctx, scope)
		if err != nil {
			return nil, fmt.Errorf("evaluate header value for %q: %w", k, err)
		}
		req.Header.Set(k, v)
	}

	// Default the Content-Type for known body shapes only when
	// the operator did not supply one explicitly via Headers.
	if contentType != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", contentType)
	}

	return req, nil
}

// buildBody evaluates the active body template (form, json, or raw)
// and returns an io.Reader plus the implied Content-Type.
//
// A nil reader and empty content type are returned when the
// destination has no body configured.
func (i *Impl) buildBody(ctx context.Context, scope *template.Scope) (io.Reader, string, error) {
	switch {
	case i.parsedForm != nil:
		values := url.Values{}
		for _, kv := range i.parsedForm {
			k, err := kv.key.Eval(ctx, scope)
			if err != nil {
				return nil, "", fmt.Errorf("evaluate form key: %w", err)
			}
			v, err := kv.value.Eval(ctx, scope)
			if err != nil {
				return nil, "", fmt.Errorf("evaluate form value for %q: %w", k, err)
			}
			values.Set(k, v)
		}
		return strings.NewReader(values.Encode()), "application/x-www-form-urlencoded", nil
	case i.parsedJSON != nil:
		s, err := i.parsedJSON.Eval(ctx, scope)
		if err != nil {
			return nil, "", fmt.Errorf("evaluate json body: %w", err)
		}
		// The fully-templated body must still parse as JSON;
		// surface the error here rather than letting the
		// destination service reject a malformed payload.
		var probe any
		if err := json.Unmarshal([]byte(s), &probe); err != nil {
			return nil, "", fmt.Errorf("templated json body is not valid JSON: %w", err)
		}
		return strings.NewReader(s), "application/json", nil
	case i.parsedRaw != nil:
		s, err := i.parsedRaw.Eval(ctx, scope)
		if err != nil {
			return nil, "", fmt.Errorf("evaluate raw body: %w", err)
		}
		return strings.NewReader(s), "", nil
	default:
		return nil, "", nil
	}
}

// extractToken applies the configured JMESPath expressions to
// decoded and returns the populated Token.
func (i *Impl) extractToken(decoded any) (*Token, error) {
	tokenAny, err := i.tokenPath.Search(decoded)
	if err != nil {
		return nil, fmt.Errorf("apply tokenJsonPath: %w", err)
	}
	if tokenAny == nil {
		return nil, fmt.Errorf("tokenJsonPath %q yielded no value", i.cfg.Response.TokenJSONPath)
	}
	tokenStr, ok := tokenAny.(string)
	if !ok {
		return nil, fmt.Errorf("tokenJsonPath %q resolved to non-string %T", i.cfg.Response.TokenJSONPath, tokenAny)
	}

	expiresAt, err := i.extractExpiry(decoded)
	if err != nil {
		return nil, err
	}

	return &Token{
		Value:     tokenStr,
		Scheme:    i.cfg.Response.Scheme,
		ExpiresAt: expiresAt,
	}, nil
}

// extractExpiry applies whichever expiry JMESPath is configured and
// converts the resolved value into an absolute time. When no expiry
// path is set, the zero time is returned and propagated to the
// worker as "unknown".
func (i *Impl) extractExpiry(decoded any) (time.Time, error) {
	switch {
	case i.expiresInPath != nil:
		v, err := i.expiresInPath.Search(decoded)
		if err != nil {
			return time.Time{}, fmt.Errorf("apply expiresInJsonPath: %w", err)
		}
		secs, err := asFloat(v)
		if err != nil {
			return time.Time{}, fmt.Errorf("expiresInJsonPath: %w", err)
		}
		return time.Now().Add(time.Duration(secs * float64(time.Second))), nil
	case i.expiresAtPath != nil:
		v, err := i.expiresAtPath.Search(decoded)
		if err != nil {
			return time.Time{}, fmt.Errorf("apply expiresAtJsonPath: %w", err)
		}
		s, ok := v.(string)
		if !ok {
			return time.Time{}, fmt.Errorf("expiresAtJsonPath resolved to non-string %T", v)
		}
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return time.Time{}, fmt.Errorf("expiresAtJsonPath: parse RFC3339: %w", err)
		}
		return t, nil
	default:
		return time.Time{}, nil
	}
}

// asFloat converts a value pulled from a JSON-decoded body into a
// float64. The decoder yields float64 for plain numbers; the
// json.Number path is included for callers that may have configured
// a decoder with UseNumber.
func asFloat(v any) (float64, error) {
	switch n := v.(type) {
	case float64:
		return n, nil
	case json.Number:
		f, err := n.Float64()
		if err != nil {
			return 0, fmt.Errorf("not a number: %w", err)
		}
		return f, nil
	default:
		return 0, fmt.Errorf("not a number, got %T", v)
	}
}

// registerNowOffsets walks each pre-parsed template and registers
// the matching now+DUR helper functions on scope. This must run
// per-request because the template package's RegisterNowOffset
// mutates the scope's function map in place.
func (i *Impl) registerNowOffsets(scope *template.Scope) error {
	for _, t := range i.allTemplates() {
		if t == nil {
			continue
		}
		if err := template.RegisterNowOffset(scope, t); err != nil {
			return err
		}
	}
	return nil
}

// allTemplates returns every template held by the Impl. The slice
// is allocated per call but the elements are shared with the Impl;
// callers must not mutate the returned templates.
func (i *Impl) allTemplates() []*template.Template {
	out := make([]*template.Template, 0, 1+2*len(i.parsedHeaders)+2*len(i.parsedForm)+2)
	out = append(out, i.parsedURL)
	for _, h := range i.parsedHeaders {
		out = append(out, h.key, h.value)
	}
	for _, h := range i.parsedForm {
		out = append(out, h.key, h.value)
	}
	if i.parsedJSON != nil {
		out = append(out, i.parsedJSON)
	}
	if i.parsedRaw != nil {
		out = append(out, i.parsedRaw)
	}
	return out
}

package httptokenexchange_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/audit"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/auth"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/destinations/httptokenexchange"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/secrets"
)

// fakeDestination wraps an httptest.Server with a recording handler
// so that tests can both stand up a fake upstream and inspect the
// request the broker sent.
type fakeDestination struct {
	server *httptest.Server

	requestMethod string
	requestPath   string
	requestQuery  url.Values
	requestHeader http.Header
	requestBody   []byte
}

// newFakeDestination starts an httptest.Server that returns
// statusCode and responseBody for every request, capturing the
// inbound request details into the returned fakeDestination.
func newFakeDestination(statusCode int, responseBody string) *fakeDestination {
	f := &fakeDestination{}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requestMethod = r.Method
		f.requestPath = r.URL.Path
		f.requestQuery = r.URL.Query()
		f.requestHeader = r.Header.Clone()
		body, _ := io.ReadAll(r.Body)
		f.requestBody = body
		w.WriteHeader(statusCode)
		_, _ = io.WriteString(w, responseBody)
	}))
	return f
}

func (f *fakeDestination) Close()      { f.server.Close() }
func (f *fakeDestination) URL() string { return f.server.URL }

func newTestIdentity() *auth.Identity {
	return &auth.Identity{
		Type:      auth.IdentityTypeCI,
		Principal: "repo:owner/repo:ref:refs/heads/main",
		Claims: map[string]any{
			"repository": "owner/repo",
			"actor":      "alice",
		},
	}
}

func newTestDeps() httptokenexchange.Dependencies {
	return httptokenexchange.Dependencies{
		Secrets:      secrets.NewMapLoader(),
		NamedSecrets: map[string]secrets.SecretRef{},
	}
}

func TestMint_HappyPath_JSONBodyAndExpiresIn(t *testing.T) {
	t.Parallel()
	fake := newFakeDestination(http.StatusOK, `{"access_token":"abc123","expires_in":3600,"token_type":"Bearer"}`)
	defer fake.Close()

	cfg := &httptokenexchange.Config{
		Request: httptokenexchange.RequestConfig{
			Method: "POST",
			URL:    fake.URL() + "/token",
			Headers: map[string]string{
				"X-Originator": "${identity.principal}",
			},
			Body: &httptokenexchange.BodyConfig{
				JSON: json.RawMessage(`{"actor":"${identity.claims.actor}"}`),
			},
		},
		Response: httptokenexchange.ResponseConfig{
			TokenJSONPath:     "access_token",
			ExpiresInJSONPath: "expires_in",
		},
	}

	impl, err := httptokenexchange.New("test", cfg, newTestDeps())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	before := time.Now()
	tok, err := impl.Mint(context.Background(), newTestIdentity())
	after := time.Now()
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	if tok.Value != "abc123" {
		t.Errorf("Token.Value: got %q, want %q", tok.Value, "abc123")
	}
	expectedExpiry := before.Add(3600 * time.Second)
	if tok.ExpiresAt.Before(expectedExpiry) || tok.ExpiresAt.After(after.Add(3600*time.Second)) {
		t.Errorf("Token.ExpiresAt: %v not within expected window [%v, %v]",
			tok.ExpiresAt, expectedExpiry, after.Add(3600*time.Second))
	}

	// Confirm the upstream saw the templated header and body.
	if got := fake.requestHeader.Get("X-Originator"); got != "repo:owner/repo:ref:refs/heads/main" {
		t.Errorf("X-Originator header: got %q", got)
	}
	if got := string(fake.requestBody); got != `{"actor":"alice"}` {
		t.Errorf("request body: got %q", got)
	}
	if got := fake.requestHeader.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type: got %q, want application/json", got)
	}
}

func TestMint_HappyPath_ExpiresAtRFC3339(t *testing.T) {
	t.Parallel()
	expiresAt := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	body := `{"token":"xyz","expires_at":"` + expiresAt.Format(time.RFC3339) + `"}`
	fake := newFakeDestination(http.StatusCreated, body)
	defer fake.Close()

	cfg := &httptokenexchange.Config{
		Request: httptokenexchange.RequestConfig{
			Method: "POST",
			URL:    fake.URL() + "/token",
		},
		Response: httptokenexchange.ResponseConfig{
			ExpectStatus:      http.StatusCreated,
			TokenJSONPath:     "token",
			ExpiresAtJSONPath: "expires_at",
		},
	}

	impl, err := httptokenexchange.New("test", cfg, newTestDeps())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	tok, err := impl.Mint(context.Background(), newTestIdentity())
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if tok.Value != "xyz" {
		t.Errorf("Token.Value: got %q, want xyz", tok.Value)
	}
	if !tok.ExpiresAt.Equal(expiresAt) {
		t.Errorf("Token.ExpiresAt: got %v, want %v", tok.ExpiresAt, expiresAt)
	}
}

func TestMint_HappyPath_FormBody(t *testing.T) {
	t.Parallel()
	fake := newFakeDestination(http.StatusOK, `{"access_token":"form-token"}`)
	defer fake.Close()

	cfg := &httptokenexchange.Config{
		Request: httptokenexchange.RequestConfig{
			Method: "POST",
			URL:    fake.URL() + "/token",
			Body: &httptokenexchange.BodyConfig{
				Form: map[string]string{
					"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
					"subject":    "${identity.principal}",
				},
			},
		},
		Response: httptokenexchange.ResponseConfig{
			TokenJSONPath: "access_token",
		},
	}

	impl, err := httptokenexchange.New("test", cfg, newTestDeps())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := impl.Mint(context.Background(), newTestIdentity()); err != nil {
		t.Fatalf("Mint: %v", err)
	}

	if got := fake.requestHeader.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type: got %q", got)
	}
	parsed, err := url.ParseQuery(string(fake.requestBody))
	if err != nil {
		t.Fatalf("parse body: %v", err)
	}
	if got := parsed.Get("grant_type"); got != "urn:ietf:params:oauth:grant-type:token-exchange" {
		t.Errorf("grant_type: got %q", got)
	}
	if got := parsed.Get("subject"); got != "repo:owner/repo:ref:refs/heads/main" {
		t.Errorf("subject: got %q", got)
	}
}

func TestMint_HappyPath_RawBody(t *testing.T) {
	t.Parallel()
	fake := newFakeDestination(http.StatusOK, `{"token":"raw-token"}`)
	defer fake.Close()

	cfg := &httptokenexchange.Config{
		Request: httptokenexchange.RequestConfig{
			Method: "POST",
			URL:    fake.URL() + "/raw",
			Headers: map[string]string{
				"Content-Type": "text/plain",
			},
			Body: &httptokenexchange.BodyConfig{
				Raw: "raw payload for ${identity.principal}",
			},
		},
		Response: httptokenexchange.ResponseConfig{
			TokenJSONPath: "token",
		},
	}

	impl, err := httptokenexchange.New("test", cfg, newTestDeps())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := impl.Mint(context.Background(), newTestIdentity()); err != nil {
		t.Fatalf("Mint: %v", err)
	}

	if got := string(fake.requestBody); got != "raw payload for repo:owner/repo:ref:refs/heads/main" {
		t.Errorf("body: got %q", got)
	}
	if got := fake.requestHeader.Get("Content-Type"); got != "text/plain" {
		t.Errorf("explicit Content-Type was overridden: got %q", got)
	}
}

func TestMint_NowOffsetInHeader(t *testing.T) {
	t.Parallel()
	fake := newFakeDestination(http.StatusOK, `{"token":"x"}`)
	defer fake.Close()

	cfg := &httptokenexchange.Config{
		Request: httptokenexchange.RequestConfig{
			Method: "POST",
			URL:    fake.URL() + "/",
			Headers: map[string]string{
				"X-Issued-At": "${now}",
				"X-Expires":   "${now+540s}",
			},
		},
		Response: httptokenexchange.ResponseConfig{TokenJSONPath: "token"},
	}

	impl, err := httptokenexchange.New("test", cfg, newTestDeps())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	before := time.Now().Unix()
	if _, err := impl.Mint(context.Background(), newTestIdentity()); err != nil {
		t.Fatalf("Mint: %v", err)
	}

	gotIssued := fake.requestHeader.Get("X-Issued-At")
	if gotIssued == "" {
		t.Fatalf("X-Issued-At header not set")
	}
	gotExpires := fake.requestHeader.Get("X-Expires")
	if gotExpires == "" {
		t.Fatalf("X-Expires header not set")
	}
	// Sanity-check: expires - issued = 540 (seconds offset).
	var iss, exp int64
	if _, err := jsonNumberToInt64(gotIssued, &iss); err != nil {
		t.Fatalf("parse X-Issued-At: %v", err)
	}
	if _, err := jsonNumberToInt64(gotExpires, &exp); err != nil {
		t.Fatalf("parse X-Expires: %v", err)
	}
	if exp-iss != 540 {
		t.Errorf("expires - issued: got %d, want 540", exp-iss)
	}
	if iss < before {
		t.Errorf("X-Issued-At %d earlier than test start %d", iss, before)
	}
}

// jsonNumberToInt64 parses a JSON-style integer string into i.
func jsonNumberToInt64(s string, i *int64) (int64, error) {
	n := json.Number(s)
	v, err := n.Int64()
	if err != nil {
		return 0, err
	}
	*i = v
	return v, nil
}

func TestMint_WrongStatusReturnsError(t *testing.T) {
	t.Parallel()
	fake := newFakeDestination(http.StatusInternalServerError, `oops`)
	defer fake.Close()

	cfg := &httptokenexchange.Config{
		Request:  httptokenexchange.RequestConfig{Method: "POST", URL: fake.URL() + "/"},
		Response: httptokenexchange.ResponseConfig{TokenJSONPath: "token"},
	}
	impl, err := httptokenexchange.New("test", cfg, newTestDeps())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = impl.Mint(context.Background(), newTestIdentity())
	if err == nil {
		t.Fatal("expected error for 500 response, got nil")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error %q should mention the status", err.Error())
	}
	// The error must include the upstream response body so that
	// audit-log readers can diagnose unexpected upstream rejections
	// without re-running the request locally.
	if !strings.Contains(err.Error(), "oops") {
		t.Errorf("error %q should include the upstream response body", err.Error())
	}
}

// TestMint_WrongStatusTruncatesLargeBody pins the 1 KiB cap on the
// body snippet included in the error so that a misbehaving upstream
// returning megabytes of HTML cannot make the audit-log line
// unworkable.
func TestMint_WrongStatusTruncatesLargeBody(t *testing.T) {
	t.Parallel()
	body := strings.Repeat("x", 64*1024)
	fake := newFakeDestination(http.StatusForbidden, body)
	defer fake.Close()

	cfg := &httptokenexchange.Config{
		Request:  httptokenexchange.RequestConfig{Method: "POST", URL: fake.URL() + "/"},
		Response: httptokenexchange.ResponseConfig{TokenJSONPath: "token"},
	}
	impl, err := httptokenexchange.New("test", cfg, newTestDeps())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = impl.Mint(context.Background(), newTestIdentity())
	if err == nil {
		t.Fatal("expected error for 403 response, got nil")
	}
	// Allow some slack for the surrounding error-message bytes;
	// the cap on the body snippet itself is 1024.
	if got := len(err.Error()); got > 2048 {
		t.Errorf("error length %d exceeds expected cap; body should have been truncated", got)
	}
}

func TestMint_TokenFieldMissing(t *testing.T) {
	t.Parallel()
	fake := newFakeDestination(http.StatusOK, `{"other_field":"value"}`)
	defer fake.Close()

	cfg := &httptokenexchange.Config{
		Request:  httptokenexchange.RequestConfig{Method: "POST", URL: fake.URL() + "/"},
		Response: httptokenexchange.ResponseConfig{TokenJSONPath: "access_token"},
	}
	impl, err := httptokenexchange.New("test", cfg, newTestDeps())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = impl.Mint(context.Background(), newTestIdentity())
	if err == nil {
		t.Fatal("expected error for missing token field, got nil")
	}
	if !strings.Contains(err.Error(), "tokenJsonPath") {
		t.Errorf("error %q should mention tokenJsonPath", err.Error())
	}
}

func TestMint_TokenFieldNonString(t *testing.T) {
	t.Parallel()
	fake := newFakeDestination(http.StatusOK, `{"access_token":42}`)
	defer fake.Close()

	cfg := &httptokenexchange.Config{
		Request:  httptokenexchange.RequestConfig{Method: "POST", URL: fake.URL() + "/"},
		Response: httptokenexchange.ResponseConfig{TokenJSONPath: "access_token"},
	}
	impl, err := httptokenexchange.New("test", cfg, newTestDeps())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = impl.Mint(context.Background(), newTestIdentity())
	if err == nil {
		t.Fatal("expected error for non-string token, got nil")
	}
	if !strings.Contains(err.Error(), "non-string") {
		t.Errorf("error %q should mention non-string", err.Error())
	}
}

func TestMint_BadJSONResponse(t *testing.T) {
	t.Parallel()
	fake := newFakeDestination(http.StatusOK, `not json at all`)
	defer fake.Close()

	cfg := &httptokenexchange.Config{
		Request:  httptokenexchange.RequestConfig{Method: "POST", URL: fake.URL() + "/"},
		Response: httptokenexchange.ResponseConfig{TokenJSONPath: "access_token"},
	}
	impl, err := httptokenexchange.New("test", cfg, newTestDeps())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = impl.Mint(context.Background(), newTestIdentity())
	if err == nil {
		t.Fatal("expected JSON parse error, got nil")
	}
}

func TestMint_NetworkError(t *testing.T) {
	t.Parallel()
	cfg := &httptokenexchange.Config{
		Request: httptokenexchange.RequestConfig{
			Method: "POST",
			// Port 1 is reserved and reliably unbindable.
			URL: "http://127.0.0.1:1/",
		},
		Response: httptokenexchange.ResponseConfig{TokenJSONPath: "token"},
	}
	impl, err := httptokenexchange.New("test", cfg, newTestDeps())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = impl.Mint(context.Background(), newTestIdentity())
	if err == nil {
		t.Fatal("expected network error, got nil")
	}
}

func TestMint_RejectsNonHTTPScheme(t *testing.T) {
	t.Parallel()
	cfg := &httptokenexchange.Config{
		Request:  httptokenexchange.RequestConfig{Method: "POST", URL: "ftp://example.com/"},
		Response: httptokenexchange.ResponseConfig{TokenJSONPath: "token"},
	}
	impl, err := httptokenexchange.New("test", cfg, newTestDeps())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = impl.Mint(context.Background(), newTestIdentity())
	if err == nil {
		t.Fatal("expected error for non-http URL, got nil")
	}
	if !strings.Contains(err.Error(), "http or https") {
		t.Errorf("error %q should mention scheme constraint", err.Error())
	}
}

func TestMint_TemplatedJSONBodyMustParseAsJSON(t *testing.T) {
	t.Parallel()
	fake := newFakeDestination(http.StatusOK, `{"token":"x"}`)
	defer fake.Close()

	cfg := &httptokenexchange.Config{
		Request: httptokenexchange.RequestConfig{
			Method: "POST",
			URL:    fake.URL() + "/",
			Body: &httptokenexchange.BodyConfig{
				// After substitution this resolves to a string
				// that is not valid JSON ("alice" without quotes
				// inside the JSON literal).
				JSON: json.RawMessage(`{actor: ${identity.claims.actor}}`),
			},
		},
		Response: httptokenexchange.ResponseConfig{TokenJSONPath: "token"},
	}
	impl, err := httptokenexchange.New("test", cfg, newTestDeps())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = impl.Mint(context.Background(), newTestIdentity())
	if err == nil {
		t.Fatal("expected error for malformed templated JSON body, got nil")
	}
}

func TestMint_ContextCancellationStopsRequest(t *testing.T) {
	t.Parallel()
	// Server hangs longer than the test cancellation window.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"token":"late"}`))
	}))
	defer srv.Close()

	cfg := &httptokenexchange.Config{
		Request:  httptokenexchange.RequestConfig{Method: "POST", URL: srv.URL + "/"},
		Response: httptokenexchange.ResponseConfig{TokenJSONPath: "token"},
	}
	impl, err := httptokenexchange.New("test", cfg, newTestDeps())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err = impl.Mint(ctx, newTestIdentity())
	if err == nil {
		t.Fatal("expected context-cancellation error, got nil")
	}
}

func TestNew_RejectsMalformedTokenJSONPath(t *testing.T) {
	t.Parallel()
	cfg := &httptokenexchange.Config{
		Request:  httptokenexchange.RequestConfig{Method: "POST", URL: "https://example.com/"},
		Response: httptokenexchange.ResponseConfig{TokenJSONPath: "[invalid"},
	}
	if _, err := httptokenexchange.New("x", cfg, newTestDeps()); err == nil {
		t.Fatal("expected JMESPath compile error, got nil")
	}
}

func TestNew_RejectsMalformedExpiresInJSONPath(t *testing.T) {
	t.Parallel()
	cfg := &httptokenexchange.Config{
		Request: httptokenexchange.RequestConfig{Method: "POST", URL: "https://example.com/"},
		Response: httptokenexchange.ResponseConfig{
			TokenJSONPath:     "token",
			ExpiresInJSONPath: "[invalid",
		},
	}
	if _, err := httptokenexchange.New("x", cfg, newTestDeps()); err == nil {
		t.Fatal("expected JMESPath compile error, got nil")
	}
}

func TestMint_CapsResponseBodyAtMaxBytes(t *testing.T) {
	t.Parallel()
	// A response body larger than maxResponseBytes is read up to
	// the cap; the truncation happens inside io.LimitReader so
	// the JSON parse will fail. We assert on the parse error
	// rather than depending on a specific cap value.
	huge := strings.Repeat("x", 2<<20)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, huge)
	}))
	defer srv.Close()

	cfg := &httptokenexchange.Config{
		Request:  httptokenexchange.RequestConfig{Method: "POST", URL: srv.URL + "/"},
		Response: httptokenexchange.ResponseConfig{TokenJSONPath: "token"},
	}
	impl, err := httptokenexchange.New("test", cfg, newTestDeps())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = impl.Mint(context.Background(), newTestIdentity())
	if err == nil {
		t.Fatal("expected error from oversized response, got nil")
	}
}

func TestMint_GETRequestSendsNoBody(t *testing.T) {
	t.Parallel()
	fake := newFakeDestination(http.StatusOK, `{"token":"x"}`)
	defer fake.Close()

	cfg := &httptokenexchange.Config{
		Request:  httptokenexchange.RequestConfig{Method: "GET", URL: fake.URL() + "/"},
		Response: httptokenexchange.ResponseConfig{TokenJSONPath: "token"},
	}
	impl, err := httptokenexchange.New("test", cfg, newTestDeps())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := impl.Mint(context.Background(), newTestIdentity()); err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if fake.requestMethod != "GET" {
		t.Errorf("method: got %q, want GET", fake.requestMethod)
	}
	if len(fake.requestBody) != 0 {
		t.Errorf("body: got %q, want empty", fake.requestBody)
	}
}

// TestMint_PopulatesMintAuditOnSuccess verifies that the audit
// hook receives the resolved upstream URL, the upstream status
// code, and a non-zero duration. The /token handler reads these
// out of the context-installed MintAudit after Mint returns and
// folds them into the TokenEntry it emits.
func TestMint_PopulatesMintAuditOnSuccess(t *testing.T) {
	t.Parallel()
	fake := newFakeDestination(http.StatusOK, `{"token":"abc"}`)
	defer fake.Close()

	cfg := &httptokenexchange.Config{
		Request:  httptokenexchange.RequestConfig{Method: "POST", URL: fake.URL() + "/token"},
		Response: httptokenexchange.ResponseConfig{TokenJSONPath: "token"},
	}
	impl, err := httptokenexchange.New("test", cfg, newTestDeps())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	mintAudit := &audit.MintAudit{}
	ctx := audit.ContextWithMintAudit(context.Background(), mintAudit)
	if _, err := impl.Mint(ctx, newTestIdentity()); err != nil {
		t.Fatalf("Mint: %v", err)
	}

	if mintAudit.UpstreamURL != fake.URL()+"/token" {
		t.Errorf("UpstreamURL: got %q, want %q", mintAudit.UpstreamURL, fake.URL()+"/token")
	}
	if mintAudit.UpstreamStatusCode != http.StatusOK {
		t.Errorf("UpstreamStatusCode: got %d, want %d", mintAudit.UpstreamStatusCode, http.StatusOK)
	}
	if mintAudit.UpstreamDuration <= 0 {
		t.Errorf("UpstreamDuration: got %v, want > 0", mintAudit.UpstreamDuration)
	}
	if mintAudit.UpstreamResponseExcerpt != "" {
		t.Errorf("UpstreamResponseExcerpt: got %q on success, want empty", mintAudit.UpstreamResponseExcerpt)
	}
}

// TestMint_PopulatesMintAuditOnUpstreamRejection covers the
// failure path: the audit hook captures the upstream status, a
// non-zero duration, and an excerpt of the upstream response body
// truncated to the documented prefix length.
func TestMint_PopulatesMintAuditOnUpstreamRejection(t *testing.T) {
	t.Parallel()
	fake := newFakeDestination(http.StatusUnauthorized, `{"error":"the-upstream-said-no"}`)
	defer fake.Close()

	cfg := &httptokenexchange.Config{
		Request:  httptokenexchange.RequestConfig{Method: "POST", URL: fake.URL() + "/token"},
		Response: httptokenexchange.ResponseConfig{TokenJSONPath: "token"},
	}
	impl, err := httptokenexchange.New("test", cfg, newTestDeps())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	mintAudit := &audit.MintAudit{}
	ctx := audit.ContextWithMintAudit(context.Background(), mintAudit)
	if _, err := impl.Mint(ctx, newTestIdentity()); err == nil {
		t.Fatal("expected Mint error from non-200 status, got nil")
	}

	if mintAudit.UpstreamStatusCode != http.StatusUnauthorized {
		t.Errorf("UpstreamStatusCode: got %d, want %d", mintAudit.UpstreamStatusCode, http.StatusUnauthorized)
	}
	if !strings.Contains(mintAudit.UpstreamResponseExcerpt, "the-upstream-said-no") {
		t.Errorf("UpstreamResponseExcerpt: got %q", mintAudit.UpstreamResponseExcerpt)
	}
}

// TestMint_TruncatesExcerpt verifies the 256-byte cap on the
// upstream-response excerpt: a longer body is sliced rather than
// inflating the audit-log line.
func TestMint_TruncatesExcerpt(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("x", 1024)
	fake := newFakeDestination(http.StatusBadRequest, long)
	defer fake.Close()

	cfg := &httptokenexchange.Config{
		Request:  httptokenexchange.RequestConfig{Method: "POST", URL: fake.URL() + "/token"},
		Response: httptokenexchange.ResponseConfig{TokenJSONPath: "token"},
	}
	impl, err := httptokenexchange.New("test", cfg, newTestDeps())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	mintAudit := &audit.MintAudit{}
	ctx := audit.ContextWithMintAudit(context.Background(), mintAudit)
	_, _ = impl.Mint(ctx, newTestIdentity())

	if got := len(mintAudit.UpstreamResponseExcerpt); got > 256 {
		t.Errorf("UpstreamResponseExcerpt length: got %d, want <= 256", got)
	}
}

// TestMint_PopulatesMintAuditOnTransportError exercises the
// transport-failure path: the URL was resolved and captured, but
// the request never received a response (http.Client returned an
// error). The status stays zero and the duration is still
// recorded.
func TestMint_PopulatesMintAuditOnTransportError(t *testing.T) {
	t.Parallel()
	// Construct a URL that points at an unreachable port so the
	// http.Client surfaces a transport error rather than receiving
	// a response.
	cfg := &httptokenexchange.Config{
		Request:  httptokenexchange.RequestConfig{Method: "POST", URL: "http://127.0.0.1:1/token"},
		Response: httptokenexchange.ResponseConfig{TokenJSONPath: "token"},
	}
	impl, err := httptokenexchange.New("test", cfg, newTestDeps())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	mintAudit := &audit.MintAudit{}
	ctx := audit.ContextWithMintAudit(context.Background(), mintAudit)
	if _, err := impl.Mint(ctx, newTestIdentity()); err == nil {
		t.Fatal("expected transport error, got nil")
	}

	if mintAudit.UpstreamURL == "" {
		t.Errorf("UpstreamURL: got empty, want populated even on transport error")
	}
	if mintAudit.UpstreamStatusCode != 0 {
		t.Errorf("UpstreamStatusCode: got %d, want 0 (no response received)", mintAudit.UpstreamStatusCode)
	}
}

// TestMint_NoMintAuditInContextIsHarmless makes sure callers that
// do not install a MintAudit are not penalised: the destination
// implementation must skip the population calls rather than panic
// on a nil pointer.
func TestMint_NoMintAuditInContextIsHarmless(t *testing.T) {
	t.Parallel()
	fake := newFakeDestination(http.StatusOK, `{"token":"abc"}`)
	defer fake.Close()

	cfg := &httptokenexchange.Config{
		Request:  httptokenexchange.RequestConfig{Method: "POST", URL: fake.URL() + "/"},
		Response: httptokenexchange.ResponseConfig{TokenJSONPath: "token"},
	}
	impl, err := httptokenexchange.New("test", cfg, newTestDeps())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// No ContextWithMintAudit wrapper here.
	if _, err := impl.Mint(context.Background(), newTestIdentity()); err != nil {
		t.Fatalf("Mint without MintAudit context: %v", err)
	}
}

package httptokenexchange_test

import (
	"encoding/json"
	"strings"
	"testing"

	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/destinations/httptokenexchange"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/secrets"
)

func newDeps() httptokenexchange.Dependencies {
	return httptokenexchange.Dependencies{
		Secrets:      secrets.NewMapLoader(),
		NamedSecrets: map[string]secrets.SecretRef{},
	}
}

func TestNew_AcceptsMinimalConfig(t *testing.T) {
	t.Parallel()
	cfg := &httptokenexchange.Config{
		Request: httptokenexchange.RequestConfig{
			Method: "POST",
			URL:    "https://example.com/token",
		},
		Response: httptokenexchange.ResponseConfig{
			TokenJSONPath: "token",
		},
	}
	if _, err := httptokenexchange.New("example", cfg, newDeps()); err != nil {
		t.Fatalf("New: %v", err)
	}
}

func TestNew_RejectsUnsupportedMethod(t *testing.T) {
	t.Parallel()
	cfg := &httptokenexchange.Config{
		Request:  httptokenexchange.RequestConfig{Method: "DELETE", URL: "https://x/"},
		Response: httptokenexchange.ResponseConfig{TokenJSONPath: "token"},
	}
	_, err := httptokenexchange.New("x", cfg, newDeps())
	if err == nil || !strings.Contains(err.Error(), "DELETE") {
		t.Fatalf("expected unsupported method error, got %v", err)
	}
}

func TestNew_RejectsBothExpiryFieldsSet(t *testing.T) {
	t.Parallel()
	cfg := &httptokenexchange.Config{
		Request: httptokenexchange.RequestConfig{Method: "POST", URL: "https://x/"},
		Response: httptokenexchange.ResponseConfig{
			TokenJSONPath:     "token",
			ExpiresInJSONPath: "expires_in",
			ExpiresAtJSONPath: "expires_at",
		},
	}
	_, err := httptokenexchange.New("x", cfg, newDeps())
	if err == nil || !strings.Contains(err.Error(), "expiresIn") {
		t.Fatalf("expected expiry-conflict error, got %v", err)
	}
}

func TestNew_RejectsTwoBodyKindsSet(t *testing.T) {
	t.Parallel()
	cfg := &httptokenexchange.Config{
		Request: httptokenexchange.RequestConfig{
			Method: "POST",
			URL:    "https://x/",
			Body: &httptokenexchange.BodyConfig{
				Form: map[string]string{"k": "v"},
				Raw:  "raw",
			},
		},
		Response: httptokenexchange.ResponseConfig{TokenJSONPath: "token"},
	}
	_, err := httptokenexchange.New("x", cfg, newDeps())
	if err == nil || !strings.Contains(err.Error(), "body") {
		t.Fatalf("expected body conflict error, got %v", err)
	}
}

func TestNew_ParsesTemplatesAtConstruction(t *testing.T) {
	t.Parallel()
	cfg := &httptokenexchange.Config{
		Request: httptokenexchange.RequestConfig{
			Method:  "POST",
			URL:     "https://x/${unterminated",
			Headers: map[string]string{"X-Hdr": "ok"},
		},
		Response: httptokenexchange.ResponseConfig{TokenJSONPath: "token"},
	}
	_, err := httptokenexchange.New("x", cfg, newDeps())
	if err == nil {
		t.Fatal("expected template parse error, got nil")
	}
}

func TestNew_ValidatesEveryBodyKind(t *testing.T) {
	t.Parallel()
	for _, body := range []*httptokenexchange.BodyConfig{
		{Form: map[string]string{"a": "${env:NONEXISTENT_OK}"}},
		{JSON: json.RawMessage(`{"a":"${env:NONEXISTENT_OK}"}`)},
		{Raw: "${env:NONEXISTENT_OK}"},
	} {
		cfg := &httptokenexchange.Config{
			Request: httptokenexchange.RequestConfig{
				Method: "POST", URL: "https://x/", Body: body,
			},
			Response: httptokenexchange.ResponseConfig{TokenJSONPath: "token"},
		}
		if _, err := httptokenexchange.New("x", cfg, newDeps()); err != nil {
			t.Errorf("body kind: %v", err)
		}
	}
}

func TestImpl_NameRoundTrips(t *testing.T) {
	t.Parallel()
	cfg := &httptokenexchange.Config{
		Request:  httptokenexchange.RequestConfig{Method: "POST", URL: "https://x/"},
		Response: httptokenexchange.ResponseConfig{TokenJSONPath: "token"},
	}
	impl, err := httptokenexchange.New("named", cfg, newDeps())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if impl.Name() != "named" {
		t.Errorf("Name: got %q, want %q", impl.Name(), "named")
	}
}

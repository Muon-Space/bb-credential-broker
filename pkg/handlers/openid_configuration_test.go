package handlers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/handlers"
)

func TestOpenIDConfiguration_GET(t *testing.T) {
	t.Parallel()
	h, err := handlers.NewOpenIDConfigurationHandler(handlers.OpenIDConfigurationParams{
		Issuer: "https://broker.example.com",
	})
	if err != nil {
		t.Fatalf("NewOpenIDConfigurationHandler: %v", err)
	}
	r := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want %d", w.Code, http.StatusOK)
	}
	if got := w.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type: got %q, want application/json", got)
	}
	if cc := w.Header().Get("Cache-Control"); !strings.HasPrefix(cc, "max-age=") {
		t.Errorf("Cache-Control: got %q, want max-age=N", cc)
	}

	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["issuer"] != "https://broker.example.com" {
		t.Errorf("issuer: got %v", got["issuer"])
	}
	if got["jwks_uri"] != "https://broker.example.com/.well-known/jwks.json" {
		t.Errorf("jwks_uri default: got %v", got["jwks_uri"])
	}
	// Required fields per the spec.
	for _, k := range []string{"id_token_signing_alg_values_supported", "response_types_supported", "subject_types_supported"} {
		if _, ok := got[k]; !ok {
			t.Errorf("missing required field %q", k)
		}
	}
}

func TestOpenIDConfiguration_ExplicitJWKSURI(t *testing.T) {
	t.Parallel()
	h, err := handlers.NewOpenIDConfigurationHandler(handlers.OpenIDConfigurationParams{
		Issuer:  "https://broker.example.com",
		JWKSURI: "https://broker.example.com/keys",
	})
	if err != nil {
		t.Fatalf("NewOpenIDConfigurationHandler: %v", err)
	}
	r := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var got map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got["jwks_uri"] != "https://broker.example.com/keys" {
		t.Errorf("jwks_uri override: got %v", got["jwks_uri"])
	}
}

// TestOpenIDConfiguration_HEAD pins the documented behaviour that
// HEAD requests return headers identical to GET but no body, the
// same shape the JWKS handler implements.
func TestOpenIDConfiguration_HEAD(t *testing.T) {
	t.Parallel()
	h, _ := handlers.NewOpenIDConfigurationHandler(handlers.OpenIDConfigurationParams{Issuer: "x"})
	r := httptest.NewRequest(http.MethodHead, "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("status: got %d, want 200", w.Code)
	}
	if w.Body.Len() != 0 {
		t.Errorf("HEAD body: got %d bytes, want 0", w.Body.Len())
	}
}

func TestOpenIDConfiguration_RejectsOtherMethods(t *testing.T) {
	t.Parallel()
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			h, _ := handlers.NewOpenIDConfigurationHandler(handlers.OpenIDConfigurationParams{Issuer: "x"})
			r := httptest.NewRequest(method, "/.well-known/openid-configuration", nil)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusMethodNotAllowed {
				t.Errorf("status: got %d, want %d", w.Code, http.StatusMethodNotAllowed)
			}
		})
	}
}

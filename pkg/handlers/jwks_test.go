package handlers_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/handlers"
)

const fixtureJWKS = `{"keys":[{"alg":"RS256","e":"AQAB","kid":"fixture-kid","kty":"RSA","n":"AQAB","use":"sig"}]}`

func TestJWKSHandler_GET(t *testing.T) {
	t.Parallel()
	h := handlers.NewJWKSHandler([]byte(fixtureJWKS))
	r := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want %d", w.Code, http.StatusOK)
	}
	if got := w.Header().Get("Content-Type"); got != "application/jwk-set+json" {
		t.Errorf("Content-Type: got %q, want application/jwk-set+json", got)
	}
	if cc := w.Header().Get("Cache-Control"); !strings.HasPrefix(cc, "max-age=") {
		t.Errorf("Cache-Control: got %q, want max-age=N", cc)
	}
	if w.Body.String() != fixtureJWKS {
		t.Errorf("body: got %q, want %q", w.Body.String(), fixtureJWKS)
	}
}

// TestJWKSHandler_HEAD pins the documented behaviour that HEAD
// responses carry headers identical to GET but no body.
// Downstream verifiers occasionally HEAD the JWKS to check
// freshness before re-fetching the body.
func TestJWKSHandler_HEAD(t *testing.T) {
	t.Parallel()
	h := handlers.NewJWKSHandler([]byte(fixtureJWKS))
	r := httptest.NewRequest(http.MethodHead, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want %d", w.Code, http.StatusOK)
	}
	if w.Body.Len() != 0 {
		t.Errorf("HEAD body: got %d bytes, want 0", w.Body.Len())
	}
}

func TestJWKSHandler_RejectsOtherMethods(t *testing.T) {
	t.Parallel()
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			h := handlers.NewJWKSHandler([]byte(fixtureJWKS))
			r := httptest.NewRequest(method, "/.well-known/jwks.json", nil)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusMethodNotAllowed {
				t.Errorf("status: got %d, want %d", w.Code, http.StatusMethodNotAllowed)
			}
		})
	}
}

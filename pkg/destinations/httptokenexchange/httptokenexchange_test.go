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
	// body.json with templated leaf strings is rejected at
	// configuration load (see TestNew_RejectsTemplatedValuesInBodyJSON);
	// the body.json case here uses a non-templated payload to
	// exercise the basic parse path without tripping that check.
	for _, body := range []*httptokenexchange.BodyConfig{
		{Form: map[string]string{"a": "${env:NONEXISTENT_OK}"}},
		{JSON: json.RawMessage(`{"a":"static-value"}`)},
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

// TestNew_RejectsDefaultWithWrongArity captures the spec
// requirement that ${default:...} arg-count errors surface at
// configuration load (broker startup), not at the first /token
// request that exercises the template. The walk inside New visits
// every template chunk and runs the registered validators.
func TestNew_RejectsDefaultWithWrongArity(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		body *httptokenexchange.BodyConfig
		url  string
	}{
		{name: "zero args in url", url: "https://example.com/${default}"},
		{name: "one arg in url", url: "https://example.com/${default:value}"},
		{name: "three args in url", url: "https://example.com/${default:a:b:c}"},
		{
			name: "zero args in raw body",
			url:  "https://example.com/",
			body: &httptokenexchange.BodyConfig{Raw: "${default}"},
		},
		{
			name: "three args in form value",
			url:  "https://example.com/",
			body: &httptokenexchange.BodyConfig{Form: map[string]string{"k": "${default:a:b:c}"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := &httptokenexchange.Config{
				Request:  httptokenexchange.RequestConfig{Method: "POST", URL: tc.url, Body: tc.body},
				Response: httptokenexchange.ResponseConfig{TokenJSONPath: "token"},
			}
			_, err := httptokenexchange.New("x", cfg, newDeps())
			if err == nil {
				t.Fatalf("expected default arity error, got nil")
			}
			if !strings.Contains(err.Error(), "default") {
				t.Errorf("error %q should mention the default function", err.Error())
			}
			if !strings.Contains(err.Error(), "argument") {
				t.Errorf("error %q should mention argument count", err.Error())
			}
		})
	}
}

// TestNew_AcceptsDefaultWithTwoArgs confirms the validator does
// not reject the supported shape — including nested arguments,
// which exercise the recursive walk.
func TestNew_AcceptsDefaultWithTwoArgs(t *testing.T) {
	t.Parallel()
	cfg := &httptokenexchange.Config{
		Request: httptokenexchange.RequestConfig{
			Method:  "POST",
			URL:     "https://example.com/token",
			Headers: map[string]string{"X-Default": "${default:${identity.claims.absent}:${identity.principal}}"},
		},
		Response: httptokenexchange.ResponseConfig{TokenJSONPath: "token"},
	}
	if _, err := httptokenexchange.New("x", cfg, newDeps()); err != nil {
		t.Errorf("expected default with two args to pass, got %v", err)
	}
}

// TestNew_RejectsUnknownTemplateFunction surfaces the operator
// typo class where a destination template references a built-in
// function the broker does not implement. Without the
// configuration-load-time check the error would surface only at
// the first /token request, after deploy.
func TestNew_RejectsUnknownTemplateFunction(t *testing.T) {
	t.Parallel()
	cfg := &httptokenexchange.Config{
		Request: httptokenexchange.RequestConfig{
			Method:  "POST",
			URL:     "https://example.com/${jsonn:value}",
			Headers: map[string]string{},
		},
		Response: httptokenexchange.ResponseConfig{TokenJSONPath: "token"},
	}
	_, err := httptokenexchange.New("x", cfg, newDeps())
	if err == nil {
		t.Fatal("expected error for unknown function ${jsonn:...}, got nil")
	}
	if !strings.Contains(err.Error(), "jsonn") {
		t.Errorf("error %q should name the unknown function", err.Error())
	}
	if !strings.Contains(err.Error(), "unknown template function") {
		t.Errorf("error %q should say unknown template function", err.Error())
	}
}

// TestNew_AcceptsAllBuiltinFunctions confirms the validator does
// not false-positive on any of the documented function names,
// including the dynamically-registered ${now+DUR} shorthand and
// the lazy-evaluated ${default:...}.
func TestNew_AcceptsAllBuiltinFunctions(t *testing.T) {
	t.Parallel()
	cfg := &httptokenexchange.Config{
		Request: httptokenexchange.RequestConfig{
			Method: "POST",
			URL:    "https://example.com/${env:UNSET_OK}",
			Headers: map[string]string{
				"X-Now":     "${now}",
				"X-NowOff":  "${now+30s}",
				"X-B64":     "${b64:hello}",
				"X-JSONStr": "${jsonString:hello}",
				"X-Default": "${default:${identity.claims.absent}:fallback}",
			},
		},
		Response: httptokenexchange.ResponseConfig{TokenJSONPath: "token"},
	}
	if _, err := httptokenexchange.New("x", cfg, newDeps()); err != nil {
		t.Errorf("expected all built-ins to validate, got %v", err)
	}
}

// TestNew_RejectsTemplatedValuesInBodyJSON pins the documented
// invariant from the README "Body encoding gotcha" section: a
// body.json whose leaf strings include ${...} expressions is
// rejected at startup with an actionable error pointing the
// operator at body.form or body.raw. Without the check the
// template parser surfaces a misleading "unterminated argument"
// at /token time when the JSON encoder's \" sequences confuse
// the parser's string-literal tracking.
func TestNew_RejectsTemplatedValuesInBodyJSON(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		json string
		want string // expected substring in the error message
	}{
		{
			name: "templated leaf in top-level object",
			json: `{"sub":"${identity.principal}"}`,
			want: "sub",
		},
		{
			name: "templated leaf in nested object",
			json: `{"outer":{"inner":"${now}"}}`,
			want: "outer.inner",
		},
		{
			name: "templated leaf inside an array element",
			json: `{"items":["plain","${env:HOME}"]}`,
			want: "items[1]",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := &httptokenexchange.Config{
				Request: httptokenexchange.RequestConfig{
					Method: "POST", URL: "https://example.com/",
					Body: &httptokenexchange.BodyConfig{JSON: json.RawMessage(tc.json)},
				},
				Response: httptokenexchange.ResponseConfig{TokenJSONPath: "token"},
			}
			_, err := httptokenexchange.New("x", cfg, newDeps())
			if err == nil {
				t.Fatal("expected body.json template-value rejection, got nil")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q should mention the offending leaf path %q", err.Error(), tc.want)
			}
			if !strings.Contains(err.Error(), "body.form") {
				t.Errorf("error %q should point operators at body.form / body.raw", err.Error())
			}
		})
	}
}

// TestNew_AcceptsBodyJSONWithoutTemplates confirms the validator
// does not false-positive on body.json that is genuinely
// template-free.
func TestNew_AcceptsBodyJSONWithoutTemplates(t *testing.T) {
	t.Parallel()
	cfg := &httptokenexchange.Config{
		Request: httptokenexchange.RequestConfig{
			Method: "POST", URL: "https://example.com/",
			Body: &httptokenexchange.BodyConfig{JSON: json.RawMessage(`{"hardcoded":"value","n":42}`)},
		},
		Response: httptokenexchange.ResponseConfig{TokenJSONPath: "token"},
	}
	if _, err := httptokenexchange.New("x", cfg, newDeps()); err != nil {
		t.Errorf("expected template-free body.json to pass, got %v", err)
	}
}

// TestNew_RejectsUndefinedSecretReference verifies the secret-name
// resolution check that ships alongside this destination's
// configuration-load walk. A ${secret:NAME} whose NAME is a static
// literal must resolve to a key in the operator-supplied secrets
// map. Templated secret names are intentionally left for evaluation
// time.
func TestNew_RejectsUndefinedSecretReference(t *testing.T) {
	t.Parallel()
	cfg := &httptokenexchange.Config{
		Request: httptokenexchange.RequestConfig{
			Method:  "POST",
			URL:     "https://example.com/token",
			Headers: map[string]string{"Authorization": "Bearer ${secret:not-registered}"},
		},
		Response: httptokenexchange.ResponseConfig{TokenJSONPath: "token"},
	}
	_, err := httptokenexchange.New("x", cfg, newDeps())
	if err == nil {
		t.Fatal("expected undefined-secret error, got nil")
	}
	if !strings.Contains(err.Error(), "not-registered") {
		t.Errorf("error %q should mention the missing secret name", err.Error())
	}
}

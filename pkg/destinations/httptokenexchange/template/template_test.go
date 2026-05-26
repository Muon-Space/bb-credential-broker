package template_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/auth"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/destinations/httptokenexchange/template"
)

// fixedTime returns a constant time so that ${now} expansions are
// reproducible.
func fixedTime() time.Time { return time.Unix(1700000000, 0) }

func newScope(t *testing.T, identity *auth.Identity) *template.Scope {
	t.Helper()
	s := template.DefaultScope(identity, nil, nil)
	s.Now = fixedTime
	return s
}

func TestParse_LiteralOnly(t *testing.T) {
	t.Parallel()
	tmpl, err := template.Parse("hello world")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	got, err := tmpl.Eval(context.Background(), newScope(t, nil))
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if got != "hello world" {
		t.Errorf("got %q, want %q", got, "hello world")
	}
}

func TestParse_VariableReference(t *testing.T) {
	t.Parallel()
	tmpl := template.MustParse("subject=${identity.principal}")
	id := &auth.Identity{
		Type:      auth.IdentityTypeCI,
		Principal: "repo:owner/repo:ref:refs/heads/main",
		Claims:    map[string]any{"repository": "owner/repo"},
	}
	got, err := tmpl.Eval(context.Background(), newScope(t, id))
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	want := "subject=repo:owner/repo:ref:refs/heads/main"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestParse_NestedClaimsRef(t *testing.T) {
	t.Parallel()
	tmpl := template.MustParse("${identity.claims.repository}")
	id := &auth.Identity{
		Type:      auth.IdentityTypeCI,
		Principal: "repo:owner/repo:ref:refs/heads/main",
		Claims:    map[string]any{"repository": "owner/repo"},
	}
	got, err := tmpl.Eval(context.Background(), newScope(t, id))
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if got != "owner/repo" {
		t.Errorf("got %q, want %q", got, "owner/repo")
	}
}

func TestParse_NowFunction(t *testing.T) {
	t.Parallel()
	tmpl := template.MustParse("issued=${now}")
	got, err := tmpl.Eval(context.Background(), newScope(t, nil))
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if got != "issued=1700000000" {
		t.Errorf("got %q, want issued=1700000000", got)
	}
}

func TestParse_NowOffsetShorthand(t *testing.T) {
	t.Parallel()
	// fixedTime returns 1700000000; +540s should produce 1700000540.
	tmpl := template.MustParse("exp=${now+540s}")
	scope := newScope(t, nil)
	if err := template.RegisterNowOffset(scope, tmpl); err != nil {
		t.Fatalf("RegisterNowOffset: %v", err)
	}
	got, err := tmpl.Eval(context.Background(), scope)
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if got != "exp=1700000540" {
		t.Errorf("got %q, want exp=1700000540", got)
	}
}

func TestParse_NestedExpression(t *testing.T) {
	t.Parallel()
	// jsonString takes a single argument that itself contains a
	// variable reference; the outer function should see the
	// fully-substituted value.
	tmpl := template.MustParse(`${jsonString:${identity.principal}}`)
	id := &auth.Identity{Type: auth.IdentityTypeCI, Principal: `repo:o/r:ref:refs/heads/main`}
	got, err := tmpl.Eval(context.Background(), newScope(t, id))
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if got != `"repo:o/r:ref:refs/heads/main"` {
		t.Errorf("got %q, want \"repo:o/r:ref:refs/heads/main\"", got)
	}
}

func TestParse_ColonInsideBraces(t *testing.T) {
	t.Parallel()
	// The colons inside the JSON literal must not be treated as
	// outer argument separators.
	tmpl, err := template.Parse(`${jsonString:{"key":"value"}}`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	got, err := tmpl.Eval(context.Background(), newScope(t, nil))
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if got != `"{\"key\":\"value\"}"` {
		t.Errorf("got %q, want %q", got, `"{\"key\":\"value\"}"`)
	}
}

func TestParse_ColonInsideStringLiteral(t *testing.T) {
	t.Parallel()
	// A colon inside a quoted string should not split the
	// argument either.
	tmpl, err := template.Parse(`${jsonString:"a:b:c"}`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	got, err := tmpl.Eval(context.Background(), newScope(t, nil))
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if got != `"\"a:b:c\""` {
		t.Errorf("got %q, want %q", got, `"\"a:b:c\""`)
	}
}

func TestParse_UnknownFunctionFailsAtEval(t *testing.T) {
	t.Parallel()
	tmpl, err := template.Parse("${nosuchfunc}")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	_, err = tmpl.Eval(context.Background(), newScope(t, nil))
	if err == nil {
		t.Fatal("expected error from unknown function, got nil")
	}
	if !strings.Contains(err.Error(), "unknown function") {
		t.Errorf("expected 'unknown function' in error, got %q", err.Error())
	}
}

func TestParse_VariableMissingFieldFailsAtEval(t *testing.T) {
	t.Parallel()
	tmpl := template.MustParse("${identity.claims.missing}")
	id := &auth.Identity{Type: auth.IdentityTypeUser, Principal: "u@e.com", Claims: map[string]any{}}
	_, err := tmpl.Eval(context.Background(), newScope(t, id))
	if err == nil {
		t.Fatal("expected error from missing claim, got nil")
	}
	if !strings.Contains(err.Error(), "no such field") {
		t.Errorf("expected 'no such field' in error, got %q", err.Error())
	}
}

func TestParse_StrayClosingBraceIsRejected(t *testing.T) {
	t.Parallel()
	if _, err := template.Parse("foo}bar"); err == nil {
		t.Fatal("expected error from stray '}', got nil")
	}
}

func TestParse_UnterminatedExprIsRejected(t *testing.T) {
	t.Parallel()
	if _, err := template.Parse("${unterminated"); err == nil {
		t.Fatal("expected error from unterminated '${', got nil")
	}
}

func TestParse_EmptyFunctionNameIsRejected(t *testing.T) {
	t.Parallel()
	if _, err := template.Parse("${}"); err == nil {
		t.Fatal("expected error from empty function name, got nil")
	}
}

func TestParse_DeeplyNestedTemplate(t *testing.T) {
	t.Parallel()
	// Three levels of nesting: jsonString wraps the value of
	// b64-encoded version of the principal.
	tmpl, err := template.Parse(`${jsonString:${b64:${identity.principal}}}`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	id := &auth.Identity{Type: auth.IdentityTypeCI, Principal: "abc"}
	got, err := tmpl.Eval(context.Background(), newScope(t, id))
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	// b64("abc") = "YWJj"; jsonString wraps with quotes.
	if got != `"YWJj"` {
		t.Errorf("got %q, want %q", got, `"YWJj"`)
	}
}

// TestParse_ErrorsCarryOffsetAndContext asserts the documented
// invariant that every parser-level error names the byte offset
// the parser had reached and includes a short context window of
// the surrounding input. Without this an operator bisecting a
// long destination template has no way to localise the failure;
// the parser does not maintain a line/column counter.
func TestParse_ErrorsCarryOffsetAndContext(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		input   string
		wantSub string // substring expected in the error context window
	}{
		{
			name:    "stray closing brace",
			input:   "ok-prefix-12345}suffix",
			wantSub: "prefix",
		},
		{
			name:    "unterminated function arg",
			input:   "${signjwt:RS256:key:{\"iss\":\"x\"",
			wantSub: "iss",
		},
		{
			name:    "empty function name",
			input:   "before-${}-after",
			wantSub: "${",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := template.Parse(tc.input)
			if err == nil {
				t.Fatalf("expected parse error, got nil")
			}
			msg := err.Error()
			if !strings.Contains(msg, "offset") {
				t.Errorf("error %q lacks offset annotation", msg)
			}
			if !strings.Contains(msg, "context") {
				t.Errorf("error %q lacks context annotation", msg)
			}
			if !strings.Contains(msg, tc.wantSub) {
				t.Errorf("error %q context should contain %q", msg, tc.wantSub)
			}
		})
	}
}

func TestParse_LiteralBracesInOutput(t *testing.T) {
	t.Parallel()
	// A template with no '${' should pass braces through verbatim.
	tmpl, err := template.Parse(`{"key":"value"}`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	got, err := tmpl.Eval(context.Background(), newScope(t, nil))
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if got != `{"key":"value"}` {
		t.Errorf("got %q, want %q", got, `{"key":"value"}`)
	}
}

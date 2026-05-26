// Package template implements the small substitution language used
// by httpTokenExchange to build per-request HTTP requests.
//
// A template string is an arbitrary mix of literal text and
// expression chunks of the form ${head[suffix]}. The head is an
// identifier; the suffix selects between two forms:
//
//   - A function call, where the suffix is a colon followed by
//     zero or more colon-separated arguments. Each argument is
//     itself a template string and may contain further function
//     calls or variable references. Function call delimiters are
//     respected at the outer level of an argument; the parser
//     tracks brace, bracket and string nesting so that a colon
//     inside a JSON literal does not split the surrounding
//     argument.
//
//   - A variable reference, where the suffix is a sequence of
//     dot-separated path components that select fields from the
//     evaluation Scope (typically the caller Identity).
//
// An expression with no suffix is a function call with zero
// arguments.
//
// Templates are parsed once at configuration load time so that
// syntax errors fail the start-up rather than the first request.
// Evaluation happens per request against a Scope that supplies the
// resolved Identity, the secret loader and the clock.
package template

import (
	"context"
	"fmt"
	"strings"
)

// Template is the parsed form of a template string.
type Template struct {
	chunks []chunk
}

// chunk is a single segment of a parsed template.
type chunk interface {
	eval(ctx context.Context, scope *Scope, sb *strings.Builder) error
}

// literal is a chunk consisting of un-substituted text.
type literal string

func (l literal) eval(_ context.Context, _ *Scope, sb *strings.Builder) error {
	sb.WriteString(string(l))
	return nil
}

// callExpr is a function-call chunk.
type callExpr struct {
	name string
	args []*Template
}

func (c *callExpr) eval(ctx context.Context, scope *Scope, sb *strings.Builder) error {
	// Lazy functions take their unevaluated argument templates so
	// they can make their own decisions about evaluation order
	// and error tolerance. The lazy registry is checked first;
	// names registered in both fall through to the lazy form,
	// though in practice the two registries have disjoint keys.
	if lazy, ok := scope.LazyFuncs[c.name]; ok {
		out, err := lazy(ctx, scope, c.args)
		if err != nil {
			return fmt.Errorf("template: %s: %w", c.name, err)
		}
		sb.WriteString(out)
		return nil
	}
	fn, ok := scope.Funcs[c.name]
	if !ok {
		return fmt.Errorf("template: unknown function %q", c.name)
	}
	args := make([]string, len(c.args))
	for i, a := range c.args {
		v, err := a.Eval(ctx, scope)
		if err != nil {
			return fmt.Errorf("template: evaluating argument %d to %s: %w", i+1, c.name, err)
		}
		args[i] = v
	}
	out, err := fn(ctx, scope, args)
	if err != nil {
		return fmt.Errorf("template: %s: %w", c.name, err)
	}
	sb.WriteString(out)
	return nil
}

// varRef is a variable-reference chunk; path[0] selects the
// top-level binding (typically "identity") and the remaining path
// components walk a nested map structure.
type varRef struct {
	path []string
}

func (v *varRef) eval(_ context.Context, scope *Scope, sb *strings.Builder) error {
	if len(v.path) == 0 {
		return fmt.Errorf("template: variable reference has empty path")
	}
	root, err := scope.lookupRoot(v.path[0])
	if err != nil {
		return err
	}
	current := root
	for i, key := range v.path[1:] {
		m, ok := current.(map[string]any)
		if !ok {
			return fmt.Errorf("template: variable reference %s: cannot select %q on non-object",
				strings.Join(v.path[:i+1], "."), key)
		}
		current, ok = m[key]
		if !ok {
			return fmt.Errorf("template: variable reference %s: no such field",
				strings.Join(v.path[:i+2], "."))
		}
	}
	switch s := current.(type) {
	case string:
		sb.WriteString(s)
	case fmt.Stringer:
		sb.WriteString(s.String())
	default:
		fmt.Fprintf(sb, "%v", current)
	}
	return nil
}

// Parse parses a template string into a Template.
func Parse(s string) (*Template, error) {
	p := &parser{input: s}
	chunks, err := p.parseTemplate(0)
	if err != nil {
		return nil, fmt.Errorf("template: parse: %w", err)
	}
	if p.pos != len(s) {
		return nil, fmt.Errorf("template: parse: stray closing brace at offset %d", p.pos)
	}
	return &Template{chunks: chunks}, nil
}

// MustParse is the panicking form of Parse, intended for tests.
func MustParse(s string) *Template {
	t, err := Parse(s)
	if err != nil {
		panic(err)
	}
	return t
}

// Eval renders the template against scope. The output is
// concatenated into a single string in the order in which the chunks
// appear in the source.
func (t *Template) Eval(ctx context.Context, scope *Scope) (string, error) {
	var sb strings.Builder
	for _, c := range t.chunks {
		if err := c.eval(ctx, scope, &sb); err != nil {
			return "", err
		}
	}
	return sb.String(), nil
}

// Validate walks t and applies each per-function validator from
// validators to every matching call expression. Validators are
// intended to run once at configuration-load time so that operator
// mistakes — wrong arg counts, statically-resolvable arguments that
// reference undeclared names — surface at broker startup rather
// than at the first /token request that exercises the template.
//
// Validators is a map from function name to the validator function
// to apply; functions absent from the map are ignored.
func (t *Template) Validate(validators map[string]Validator) error {
	return t.Walk(func(name string, args []*Template) error {
		v, ok := validators[name]
		if !ok {
			return nil
		}
		if err := v(args); err != nil {
			return fmt.Errorf("template: %s: %w", name, err)
		}
		return nil
	})
}

// AsLiteral returns the template's text and true when t consists
// solely of literal chunks (no ${...} expressions). Callers use this
// to perform configuration-time validation of arguments to template
// functions that the broker can resolve statically, such as the
// secret name in ${secret:NAME}; expressions whose argument is itself
// templated are left for evaluation time.
func (t *Template) AsLiteral() (string, bool) {
	var sb strings.Builder
	for _, c := range t.chunks {
		lit, ok := c.(literal)
		if !ok {
			return "", false
		}
		sb.WriteString(string(lit))
	}
	return sb.String(), true
}

// Walk visits every function-call expression in t, including
// arguments of nested calls, and invokes fn with the call's function
// name and unevaluated argument templates. The walk stops at the
// first error returned by fn and propagates it to the caller.
//
// Walk runs purely over the parsed AST and triggers no evaluation;
// it is intended for configuration-time validation passes that need
// to check call shape (arg counts, statically resolvable argument
// values) before any request exercises the template.
func (t *Template) Walk(fn func(name string, args []*Template) error) error {
	for _, c := range t.chunks {
		if err := walkChunk(c, fn); err != nil {
			return err
		}
	}
	return nil
}

// walkChunk implements the recursive descent used by Template.Walk.
// Non-call chunks (literals and variable references) contribute
// nothing to the walk; call expressions invoke fn and then descend
// into each argument's own chunks so that nested calls are visited
// in source order.
func walkChunk(c chunk, fn func(name string, args []*Template) error) error {
	ce, ok := c.(*callExpr)
	if !ok {
		return nil
	}
	if err := fn(ce.name, ce.args); err != nil {
		return err
	}
	for _, a := range ce.args {
		for _, sub := range a.chunks {
			if err := walkChunk(sub, fn); err != nil {
				return err
			}
		}
	}
	return nil
}

// parser is the recursive-descent parser for template strings.
type parser struct {
	input string
	pos   int
}

// errorf formats and returns a parser error tagged with the byte
// offset the parser had reached when the error fired, plus a short
// context window of the surrounding input. Operators bisecting a
// long destination template have no other way to localise a failure
// — the parser does not maintain a line/column counter — so the
// offset + context together turn an opaque "argument: unterminated"
// into something an operator can act on in seconds.
func (p *parser) errorf(format string, args ...any) error {
	msg := fmt.Sprintf(format, args...)
	return fmt.Errorf("%s (offset %d; context %q)", msg, p.pos, p.contextSlice(20))
}

// contextSlice returns a slice of p.input centred on p.pos, capped
// at radius bytes either side. The bounds clamp to the input rather
// than panicking on an EOF-adjacent position so callers can use
// contextSlice unconditionally regardless of where in the parse
// they have reached.
func (p *parser) contextSlice(radius int) string {
	start := max(p.pos-radius, 0)
	end := min(p.pos+radius, len(p.input))
	return p.input[start:end]
}

// parseTemplate parses the entire input as a top-level template.
// Brace nesting is tracked so that JSON literals like {"k":"v"} are
// accepted as a literal whole, while a stray closing brace not
// matched by an opening one (a likely typo such as ${foo}bar})
// surfaces as an error.
func (p *parser) parseTemplate(_ int) ([]chunk, error) {
	var (
		out    []chunk
		lit    strings.Builder
		braces int
	)
	flushLiteral := func() {
		if lit.Len() > 0 {
			out = append(out, literal(lit.String()))
			lit.Reset()
		}
	}
	for p.pos < len(p.input) {
		ch := p.input[p.pos]
		if ch == '$' && p.pos+1 < len(p.input) && p.input[p.pos+1] == '{' {
			flushLiteral()
			p.pos += 2
			expr, err := p.parseExpr()
			if err != nil {
				return nil, err
			}
			out = append(out, expr)
			continue
		}
		switch ch {
		case '{':
			braces++
		case '}':
			if braces == 0 {
				return nil, p.errorf("stray closing brace")
			}
			braces--
		}
		lit.WriteByte(ch)
		p.pos++
	}
	flushLiteral()
	return out, nil
}

// parseExpr parses the body of a ${...} expression up to and
// including the closing brace. The leading "${" must already have
// been consumed.
func (p *parser) parseExpr() (chunk, error) {
	name, sep, err := p.parseHead()
	if err != nil {
		return nil, err
	}
	switch sep {
	case '}':
		return &callExpr{name: name}, nil
	case '.':
		return p.parseVarRef(name)
	case ':':
		return p.parseCall(name)
	default:
		return nil, p.errorf("expression %q: unexpected separator %q", name, sep)
	}
}

// parseHead reads the leading identifier of an expression and
// returns the byte that terminated it (one of ':', '.', '}', or 0
// if the input ended before the identifier was closed).
func (p *parser) parseHead() (string, byte, error) {
	start := p.pos
	for p.pos < len(p.input) {
		ch := p.input[p.pos]
		if ch == ':' || ch == '.' || ch == '}' {
			if p.pos == start {
				return "", 0, p.errorf("expression: empty function name")
			}
			name := p.input[start:p.pos]
			p.pos++
			return name, ch, nil
		}
		p.pos++
	}
	return "", 0, p.errorf("expression starting at offset %d: unterminated", start)
}

// parseVarRef parses the rest of a variable-reference expression.
// The leading identifier and the first '.' have already been
// consumed; this function reads further dot-separated path
// components up to and including the closing brace.
func (p *parser) parseVarRef(head string) (chunk, error) {
	path := []string{head}
	start := p.pos
	for {
		if p.pos >= len(p.input) {
			return nil, p.errorf("variable reference %q: unterminated", strings.Join(path, "."))
		}
		ch := p.input[p.pos]
		if ch == '.' {
			path = append(path, p.input[start:p.pos])
			p.pos++
			start = p.pos
			continue
		}
		if ch == '}' {
			path = append(path, p.input[start:p.pos])
			p.pos++
			break
		}
		// Identifier characters: be liberal so that operators
		// can use snake_case, dashes etc. inside claim names.
		if ch == ':' {
			return nil, p.errorf("variable reference %q: unexpected ':' inside path", strings.Join(path, "."))
		}
		p.pos++
	}
	for _, c := range path {
		if c == "" {
			return nil, p.errorf("variable reference: empty path component in %v", path)
		}
	}
	return &varRef{path: path}, nil
}

// parseCall parses the rest of a function-call expression. The
// leading function name and the first ':' have already been
// consumed; this function reads colon-separated arguments up to and
// including the closing brace.
func (p *parser) parseCall(name string) (chunk, error) {
	var args []*Template
	for {
		arg, terminator, err := p.parseArg()
		if err != nil {
			return nil, fmt.Errorf("function %s: %w", name, err)
		}
		args = append(args, arg)
		switch terminator {
		case ':':
			continue
		case '}':
			return &callExpr{name: name, args: args}, nil
		default:
			return nil, p.errorf("function %s: argument terminated by %q", name, terminator)
		}
	}
}

// parseArg parses a single argument to a function call. The
// argument continues until an unmatched ':' or '}' at the outermost
// nesting level. Brace, bracket and string-literal nesting is
// tracked so that those characters appearing inside such a region
// do not terminate the argument.
func (p *parser) parseArg() (*Template, byte, error) {
	var (
		out      []chunk
		lit      strings.Builder
		braces   int
		brackets int
		inString bool
		escape   bool
	)
	flushLiteral := func() {
		if lit.Len() > 0 {
			out = append(out, literal(lit.String()))
			lit.Reset()
		}
	}
	for p.pos < len(p.input) {
		ch := p.input[p.pos]
		if inString {
			lit.WriteByte(ch)
			p.pos++
			switch {
			case escape:
				escape = false
			case ch == '\\':
				escape = true
			case ch == '"':
				inString = false
			}
			continue
		}
		if ch == '$' && p.pos+1 < len(p.input) && p.input[p.pos+1] == '{' {
			flushLiteral()
			p.pos += 2
			expr, err := p.parseExpr()
			if err != nil {
				return nil, 0, err
			}
			out = append(out, expr)
			continue
		}
		switch ch {
		case '"':
			inString = true
			lit.WriteByte(ch)
			p.pos++
			continue
		case '{':
			braces++
		case '}':
			if braces == 0 {
				flushLiteral()
				p.pos++
				return &Template{chunks: out}, '}', nil
			}
			braces--
		case '[':
			brackets++
		case ']':
			if brackets > 0 {
				brackets--
			}
		case ':':
			if braces == 0 && brackets == 0 {
				flushLiteral()
				p.pos++
				return &Template{chunks: out}, ':', nil
			}
		}
		lit.WriteByte(ch)
		p.pos++
	}
	return nil, 0, p.errorf("argument: unterminated")
}

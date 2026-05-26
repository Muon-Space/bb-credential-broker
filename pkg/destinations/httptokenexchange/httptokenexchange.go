// Package httptokenexchange implements the broker's only built-in
// destination type. Every destination of this type carries out a
// single, fully configurable HTTP request and extracts the resulting
// access token from the response body.
//
// The flexibility of this type comes from the templating language in
// the sibling template package: every string field of the request
// configuration may contain ${...} expressions that are evaluated
// per request against the calling Identity, the secret loader and
// the clock.
//
// The constructor parses every template, compiles every JMESPath
// expression, and constructs the outbound HTTP client at start-up
// so that configuration errors fail the broker's load step rather
// than the first request.
package httptokenexchange

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/jmespath/go-jmespath"

	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/destinations/httptokenexchange/template"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/secrets"
)

// requestTimeout is the upper bound on a single outbound mint
// request. The value is generous because some destination services
// perform a non-trivial amount of internal work (chained token
// exchanges, signature checks) before responding.
const requestTimeout = 30 * time.Second

// maxResponseBytes caps the size of the destination service's
// response body that the broker will read. Tokens are small; this
// limit guards against a malfunctioning upstream that would
// otherwise stream an unbounded body.
const maxResponseBytes = 1 << 20 // 1 MiB

// Config is the configuration shape for a single named
// httpTokenExchange destination.
type Config struct {
	// Request describes the HTTP request to issue when this
	// destination is invoked.
	Request RequestConfig `json:"request"`

	// Response describes how to extract the resulting token and
	// its expiry from the destination service's response.
	Response ResponseConfig `json:"response"`
}

// RequestConfig describes a single HTTP request, with all string
// fields subject to template expansion.
type RequestConfig struct {
	// Method is the HTTP method ("GET", "POST", "PUT" or
	// "PATCH"). The value is not subject to template expansion.
	Method string `json:"method"`

	// URL is the request URL. The post-expansion value must
	// parse as an absolute http or https URL.
	URL string `json:"url"`

	// Headers is the request header set. Both keys and values
	// are subject to template expansion; expanded keys are
	// canonicalised by net/http before being sent.
	Headers map[string]string `json:"headers,omitempty"`

	// Body selects between a form-encoded body, a JSON body or
	// a raw string body. At most one field may be set.
	Body *BodyConfig `json:"body,omitempty"`
}

// BodyConfig is a discriminated union over the supported request
// body shapes. At most one field may be non-empty.
type BodyConfig struct {
	// Form, when set, is the body as application/x-www-form-
	// urlencoded form fields. Values are subject to template
	// expansion; the resulting fields are URL-encoded.
	Form map[string]string `json:"form,omitempty"`

	// JSON, when set, is the body as a JSON value. The bytes
	// are first templated as a string and the result must parse
	// as valid JSON; the body is sent with Content-Type
	// application/json.
	JSON json.RawMessage `json:"json,omitempty"`

	// Raw, when set, is the body as an opaque string. Callers
	// using Raw must set Headers["Content-Type"] explicitly if
	// the destination requires one.
	Raw string `json:"raw,omitempty"`
}

// ResponseConfig describes the parts of the destination service's
// response that the broker needs to extract.
type ResponseConfig struct {
	// ExpectStatus is the HTTP status the response must have
	// for the mint to succeed. Zero defaults to 200.
	ExpectStatus int `json:"expectStatus,omitempty"`

	// TokenJSONPath is the JMESPath expression that extracts
	// the token value from the JSON-decoded response body. The
	// resolved value must be a string.
	TokenJSONPath string `json:"tokenJsonPath"`

	// ExpiresInJSONPath, when set, is the JMESPath expression
	// that extracts a number-of-seconds-from-now expiry from
	// the response body. Mutually exclusive with
	// ExpiresAtJSONPath.
	ExpiresInJSONPath string `json:"expiresInJsonPath,omitempty"`

	// ExpiresAtJSONPath, when set, is the JMESPath expression
	// that extracts an absolute RFC 3339 expiry from the
	// response body. Mutually exclusive with ExpiresInJSONPath.
	ExpiresAtJSONPath string `json:"expiresAtJsonPath,omitempty"`

	// Scheme is propagated verbatim to the worker as the
	// Token's Scheme. Empty defaults to "bearer".
	Scheme string `json:"scheme,omitempty"`
}

// Dependencies bundles the shared services that the destination
// uses at mint time.
type Dependencies struct {
	// Secrets resolves named SecretRef values emitted by
	// templated requests via the ${secret:NAME} function.
	Secrets secrets.Loader

	// NamedSecrets binds operator-chosen secret names to their
	// SecretRefs. The templating engine reads from this map at
	// evaluation time.
	NamedSecrets map[string]secrets.SecretRef

	// HTTPClient is the client used for the outbound mint
	// request. When nil, a default client with a 30s timeout
	// is constructed.
	HTTPClient *http.Client
}

// Impl is the constructed form of a single httpTokenExchange
// destination. The struct holds the pre-parsed request templates,
// the compiled JMESPath expressions, and the outbound HTTP client
// so that per-request work is limited to template evaluation and
// the round-trip itself.
type Impl struct {
	name string
	cfg  *Config
	deps Dependencies

	parsedURL     *template.Template
	parsedHeaders []parsedHeader
	parsedForm    []parsedHeader
	parsedJSON    *template.Template
	parsedRaw     *template.Template

	tokenPath     *jmespath.JMESPath
	expiresInPath *jmespath.JMESPath
	expiresAtPath *jmespath.JMESPath

	client *http.Client
}

// parsedHeader pairs a key template with its value template. We
// store these as a slice rather than a map keyed by *Template so
// that iteration order is deterministic; production callers do not
// observe the order, but tests that capture the outbound request
// benefit from stable comparisons.
type parsedHeader struct {
	key   *template.Template
	value *template.Template
}

// New constructs an Impl from cfg. Every string field that may
// contain a template is parsed once here, every JMESPath expression
// is compiled, and the outbound HTTP client is materialised so that
// configuration errors surface at start-up.
func New(name string, cfg *Config, deps Dependencies) (*Impl, error) {
	if cfg == nil {
		return nil, fmt.Errorf("nil config")
	}
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	parsedURL, err := template.Parse(cfg.Request.URL)
	if err != nil {
		return nil, fmt.Errorf("request.url: %w", err)
	}

	headers := make([]parsedHeader, 0, len(cfg.Request.Headers))
	for k, v := range cfg.Request.Headers {
		kt, err := template.Parse(k)
		if err != nil {
			return nil, fmt.Errorf("request.headers key %q: %w", k, err)
		}
		vt, err := template.Parse(v)
		if err != nil {
			return nil, fmt.Errorf("request.headers[%q]: %w", k, err)
		}
		headers = append(headers, parsedHeader{key: kt, value: vt})
	}

	out := &Impl{
		name:          name,
		cfg:           cfg,
		deps:          deps,
		parsedURL:     parsedURL,
		parsedHeaders: headers,
		client:        deps.HTTPClient,
	}
	if out.client == nil {
		out.client = &http.Client{Timeout: requestTimeout}
	}

	if cfg.Request.Body != nil {
		if err := out.parseBody(cfg.Request.Body); err != nil {
			return nil, err
		}
	}

	if out.tokenPath, err = jmespath.Compile(cfg.Response.TokenJSONPath); err != nil {
		return nil, fmt.Errorf("response.tokenJsonPath: %w", err)
	}
	if cfg.Response.ExpiresInJSONPath != "" {
		if out.expiresInPath, err = jmespath.Compile(cfg.Response.ExpiresInJSONPath); err != nil {
			return nil, fmt.Errorf("response.expiresInJsonPath: %w", err)
		}
	}
	if cfg.Response.ExpiresAtJSONPath != "" {
		if out.expiresAtPath, err = jmespath.Compile(cfg.Response.ExpiresAtJSONPath); err != nil {
			return nil, fmt.Errorf("response.expiresAtJsonPath: %w", err)
		}
	}

	if err := out.validateTemplates(); err != nil {
		return nil, err
	}

	return out, nil
}

// validateTemplates runs configuration-time checks over every
// template parsed during New. The checks catch operator mistakes
// that would otherwise surface only at the first /token request:
// references to template functions that do not exist, references
// to built-in functions with the wrong arity, and ${secret:NAME}
// expressions whose NAME is not registered in the broker's
// secrets map.
//
// Each check is expressed as a callback handed to Template.Walk so
// the AST is traversed once even when several checks apply to the
// same call expression.
func (i *Impl) validateTemplates() error {
	validators := template.DefaultValidators()
	for _, t := range i.allTemplates() {
		if t == nil {
			continue
		}
		if err := t.Walk(checkBuiltinFunction); err != nil {
			return err
		}
		if err := t.Validate(validators); err != nil {
			return err
		}
		if err := t.Walk(i.checkSecretRef); err != nil {
			return err
		}
	}
	return nil
}

// checkBuiltinFunction errors when a template references a
// function the broker has no implementation for. Without the
// check a typo like ${json:...} (when the operator meant
// ${jsonString:...}) reaches /token before surfacing; the walk
// pulls the failure forward to broker startup and to the
// `bb-credential-broker validate` subcommand.
func checkBuiltinFunction(name string, _ []*template.Template) error {
	if !template.IsBuiltinFunction(name) {
		return fmt.Errorf("${%s:...}: unknown template function", name)
	}
	return nil
}

// checkSecretRef verifies that every ${secret:NAME} expression whose
// NAME is a static literal refers to a secret that was registered in
// the broker's top-level secrets map. References whose NAME is itself
// a template (for example ${secret:${env:NAME}}) cannot be resolved
// statically and are left for evaluation time.
func (i *Impl) checkSecretRef(name string, args []*template.Template) error {
	if name != "secret" || len(args) != 1 {
		return nil
	}
	literal, ok := args[0].AsLiteral()
	if !ok {
		return nil
	}
	if _, ok := i.deps.NamedSecrets[literal]; !ok {
		return fmt.Errorf("${secret:%s}: no secret named %q is registered", literal, literal)
	}
	return nil
}

func (i *Impl) parseBody(body *BodyConfig) error {
	switch {
	case body.Form != nil:
		i.parsedForm = make([]parsedHeader, 0, len(body.Form))
		for k, v := range body.Form {
			kt, err := template.Parse(k)
			if err != nil {
				return fmt.Errorf("request.body.form key %q: %w", k, err)
			}
			vt, err := template.Parse(v)
			if err != nil {
				return fmt.Errorf("request.body.form[%q]: %w", k, err)
			}
			i.parsedForm = append(i.parsedForm, parsedHeader{key: kt, value: vt})
		}
	case body.JSON != nil:
		t, err := template.Parse(string(body.JSON))
		if err != nil {
			return fmt.Errorf("request.body.json: %w", err)
		}
		i.parsedJSON = t
	case body.Raw != "":
		t, err := template.Parse(body.Raw)
		if err != nil {
			return fmt.Errorf("request.body.raw: %w", err)
		}
		i.parsedRaw = t
	}
	return nil
}

// validateConfig performs the structural checks that don't require
// parsing templates or compiling expressions. Both of those are
// surfaced separately by New.
func validateConfig(cfg *Config) error {
	switch cfg.Request.Method {
	case "GET", "POST", "PUT", "PATCH":
	case "":
		return fmt.Errorf("request.method is required")
	default:
		return fmt.Errorf("request.method %q is not supported", cfg.Request.Method)
	}
	if cfg.Request.URL == "" {
		return fmt.Errorf("request.url is required")
	}
	if cfg.Request.Body != nil {
		set := 0
		if cfg.Request.Body.Form != nil {
			set++
		}
		if cfg.Request.Body.JSON != nil {
			set++
		}
		if cfg.Request.Body.Raw != "" {
			set++
		}
		if set > 1 {
			return fmt.Errorf("request.body: at most one of form, json, raw may be set")
		}
	}
	if cfg.Response.TokenJSONPath == "" {
		return fmt.Errorf("response.tokenJsonPath is required")
	}
	if cfg.Response.ExpiresInJSONPath != "" && cfg.Response.ExpiresAtJSONPath != "" {
		return fmt.Errorf("response: at most one of expiresInJsonPath, expiresAtJsonPath may be set")
	}
	return nil
}

// Token is the credential value produced by a successful Mint call.
// It mirrors the public destinations.Token shape; the parent
// destinations package wraps Impl in an adapter that translates
// between the two so that this child package can avoid an import
// cycle on its parent.
type Token struct {
	Value     string
	Scheme    string
	ExpiresAt time.Time
}

// Name returns the operator-chosen name of this destination
// instance. It is exposed so that audit-log payloads can attribute
// mints to the configured name without the caller threading the
// name through every call site.
func (i *Impl) Name() string { return i.name }

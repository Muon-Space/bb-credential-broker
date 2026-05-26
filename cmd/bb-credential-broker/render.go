package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"

	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/auth"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/config"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/destinations"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/secrets"
)

// renderUsage is the operator-facing usage string for the render
// subcommand. Printed both when arguments are missing and when
// --help is requested.
const renderUsage = `usage:
  bb-credential-broker render --identity FILE [--secret name=value ...] [--output request|jwt|url] <config.jsonnet> <destination>

Dispatches no HTTP requests. Replaces the broker's real secret
loader with an in-memory map seeded from --secret flags so AWS
credentials are not required. The --identity file is JSON shaped
like the broker's internal auth.Identity:

  {"type":"ci","principal":"...","claims":{"k":"v","..."}}

Output formats:

  request  the curl-friendly representation of the full HTTP
           request (method, URL, headers, body) the broker would
           dispatch; this is the default
  jwt      if the body carries a subject_token field that decodes
           as a JWT, print the JWT's header and claims
           pretty-printed; otherwise an error
  url      just the resolved URL
`

// runRender implements the render subcommand. Factored out of the
// top-level dispatcher so it can be unit-tested with a captured
// stderr buffer instead of mutating os.Stderr.
func runRender(args []string, stderr io.Writer, stdout io.Writer) int {
	fs := flag.NewFlagSet("render", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		identityFile = fs.String("identity", "", "path to identity JSON file (required)")
		output       = fs.String("output", "request", "output format: request | jwt | url")
		secretFlags  = stringSliceFlag{}
	)
	fs.Var(&secretFlags, "secret",
		"named secret value in name=value form; may be repeated to seed the in-memory loader")
	if err := fs.Parse(args); err != nil {
		// flag's default behaviour already prints the error;
		// the exit code is the only thing left to set.
		return 2
	}
	if fs.NArg() != 2 {
		_, _ = fmt.Fprint(stderr, renderUsage)
		return 2
	}
	configPath, destName := fs.Arg(0), fs.Arg(1)
	if *identityFile == "" {
		_, _ = fmt.Fprintln(stderr, "render: --identity is required")
		_, _ = fmt.Fprint(stderr, renderUsage)
		return 2
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}

	loader, err := buildRenderLoader(secretFlags)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "render:", err)
		return 1
	}

	// Build the destinations registry against the mock loader.
	// Metrics is nil here — the render path is operator-side
	// and does not contribute to broker telemetry.
	rawDestinations := cfg.Destinations
	registry, err := destinations.BuildRegistry(rawDestinations, destinations.Dependencies{
		Secrets:      loader,
		NamedSecrets: cfg.Secrets,
	})
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "render: build destinations:", err)
		return 1
	}

	dest := registry.Lookup(destName)
	if dest == nil {
		_, _ = fmt.Fprintf(stderr, "render: destination %q is not configured\n", destName)
		return 1
	}
	renderable, ok := dest.(destinations.Renderable)
	if !ok {
		_, _ = fmt.Fprintf(stderr, "render: destination %q does not implement RenderRequest\n", destName)
		return 1
	}

	identity, err := loadIdentity(*identityFile)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "render: load identity:", err)
		return 1
	}

	req, err := renderable.RenderRequest(context.Background(), identity)
	if err != nil {
		if isNotRenderable(err) {
			_, _ = fmt.Fprintf(stderr, "render: destination %q has no HTTP request to render (typically a staticSecret destination)\n", destName)
		} else {
			_, _ = fmt.Fprintln(stderr, "render:", err)
		}
		return 1
	}

	switch *output {
	case "request":
		return printRequest(stdout, req, stderr)
	case "url":
		_, _ = fmt.Fprintln(stdout, req.URL.String())
		return 0
	case "jwt":
		return printSubjectTokenJWT(stdout, req, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "render: unknown --output value %q (want request | jwt | url)\n", *output)
		return 2
	}
}

// stringSliceFlag is a flag.Value implementation that collects
// repeated --secret flags into an ordered slice. The order is
// preserved so duplicate names land in operator-supplied order.
type stringSliceFlag []string

func (s *stringSliceFlag) String() string {
	if s == nil {
		return ""
	}
	return strings.Join(*s, ",")
}

func (s *stringSliceFlag) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// buildRenderLoader assembles a secrets.MapLoader seeded from
// the operator-supplied --secret name=value flags. The MapLoader's
// key format is the canonical "aws:<arn>#<field>" form that
// secrets.Loader.Load produces for AWSSecretsManagerRef values;
// the loader transparently accepts that for both the AWS and the
// mock backends, so the same destination config works under
// either at lookup time.
//
// For the render path the operator typically does not have ARNs
// in hand, only the named secrets they want to mock. The flag
// shape is name=value where name matches a key in cfg.Secrets;
// at lookup time the broker passes the resolved SecretRef to the
// loader, and the loader walks both forms.
func buildRenderLoader(flags []string) (secrets.Loader, error) {
	m := secrets.NewMapLoader()
	for _, raw := range flags {
		idx := strings.Index(raw, "=")
		if idx < 0 {
			return nil, fmt.Errorf("--secret %q is not in name=value form", raw)
		}
		name, value := raw[:idx], raw[idx+1:]
		if name == "" {
			return nil, fmt.Errorf("--secret %q has empty name", raw)
		}
		// The MapLoader keys by canonical SecretRef form;
		// the template engine resolves a named secret to its
		// AWSSecretsManagerRef and the loader hashes the ref
		// to "aws:<arn>#<field>". Seed both common shapes so
		// operators do not have to know which canonical form
		// their config actually produces.
		m.Set("aws:"+name+"#", []byte(value))
		m.Set(name, []byte(value))
	}
	return mapLoaderShim{inner: m}, nil
}

// mapLoaderShim adapts a MapLoader so it also satisfies lookups
// keyed by the canonical "aws:<arn>#<field>" form for any ARN.
// MapLoader already keys by exact canonical form; the shim
// rewrites the lookup so an operator-supplied --secret name=value
// matches whichever ARN the config maps that name to.
type mapLoaderShim struct{ inner *secrets.MapLoader }

func (s mapLoaderShim) Load(ctx context.Context, ref secrets.SecretRef) ([]byte, error) {
	if ref.AWSSecretsManager != nil {
		// MapLoader keys this way; try the canonical first.
		if b, err := s.inner.Load(ctx, ref); err == nil {
			return b, nil
		}
		// Fall back to the operator's --secret name (the
		// secret name they supplied was likely the named-
		// secret key from cfg.Secrets, not the ARN). Synthesise
		// a SecretRef whose ARN is the name the operator used.
		if b, err := s.inner.Load(ctx, secrets.SecretRef{
			AWSSecretsManager: &secrets.AWSSecretsManagerRef{ARN: ref.AWSSecretsManager.ARN},
		}); err == nil {
			return b, nil
		}
		return nil, fmt.Errorf("render: no --secret seeded for arn=%q field=%q",
			ref.AWSSecretsManager.ARN, ref.AWSSecretsManager.Field)
	}
	return s.inner.Load(ctx, ref)
}

// loadIdentity parses an auth.Identity from a JSON file. The
// shape mirrors the broker's internal Identity struct; for the
// render path the operator hand-writes one to drive the dry-run.
func loadIdentity(path string) (*auth.Identity, error) {
	// #nosec G304 -- path is operator-supplied on the command line.
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw struct {
		Type      string         `json:"type"`
		Principal string         `json:"principal"`
		Claims    map[string]any `json:"claims"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	if raw.Type == "" || raw.Principal == "" {
		return nil, fmt.Errorf("identity file is missing type or principal")
	}
	return &auth.Identity{
		Type:      auth.IdentityType(raw.Type),
		Principal: raw.Principal,
		Claims:    raw.Claims,
	}, nil
}

// printRequest renders req in a curl-friendly form: status line,
// sorted headers, blank line, body bytes. The header sort is for
// deterministic output between runs; HTTP headers themselves are
// order-independent.
func printRequest(stdout io.Writer, req *http.Request, stderr io.Writer) int {
	_, _ = fmt.Fprintf(stdout, "%s %s HTTP/1.1\n", req.Method, req.URL.String())
	hostKey := "Host"
	if _, present := req.Header[hostKey]; !present {
		_, _ = fmt.Fprintf(stdout, "Host: %s\n", req.URL.Host)
	}
	names := make([]string, 0, len(req.Header))
	for k := range req.Header {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		for _, v := range req.Header[k] {
			_, _ = fmt.Fprintf(stdout, "%s: %s\n", k, v)
		}
	}
	_, _ = fmt.Fprintln(stdout)
	if req.Body != nil {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			_, _ = fmt.Fprintln(stderr, "render: read body:", err)
			return 1
		}
		_, _ = stdout.Write(body)
		if len(body) > 0 && body[len(body)-1] != '\n' {
			_, _ = fmt.Fprintln(stdout)
		}
	}
	return 0
}

// printSubjectTokenJWT extracts a subject_token form field from
// req.Body and pretty-prints the embedded JWT's header and claims.
// The canonical use case is verifying what claims will reach a
// downstream OIDC verifier before deploying a destination config
// change.
func printSubjectTokenJWT(stdout io.Writer, req *http.Request, stderr io.Writer) int {
	if req.Body == nil {
		_, _ = fmt.Fprintln(stderr, "render: request has no body to inspect")
		return 1
	}
	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "render: read body:", err)
		return 1
	}
	form, err := url.ParseQuery(string(bodyBytes))
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "render: body is not form-encoded; --output jwt requires a form body with a subject_token field")
		return 1
	}
	tok := form.Get("subject_token")
	if tok == "" {
		_, _ = fmt.Fprintln(stderr, "render: body has no subject_token field")
		return 1
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		_, _ = fmt.Fprintln(stderr, "render: subject_token is not a JWT (need three dot-separated parts)")
		return 1
	}
	hdr, err := decodeJWTPart(parts[0])
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "render: decode jwt header:", err)
		return 1
	}
	claims, err := decodeJWTPart(parts[1])
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "render: decode jwt claims:", err)
		return 1
	}
	_, _ = fmt.Fprintln(stdout, "header:")
	_, _ = stdout.Write(hdr)
	_, _ = fmt.Fprintln(stdout)
	_, _ = fmt.Fprintln(stdout, "claims:")
	_, _ = stdout.Write(claims)
	_, _ = fmt.Fprintln(stdout)
	return 0
}

// decodeJWTPart base64url-decodes a single JWT segment and
// returns the pretty-printed JSON contents.
func decodeJWTPart(segment string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return nil, err
	}
	var pretty any
	if err := json.Unmarshal(raw, &pretty); err != nil {
		return nil, err
	}
	return json.MarshalIndent(pretty, "", "  ")
}

// isNotRenderable reports whether err is or wraps the
// destinations.ErrNotRenderable sentinel.
func isNotRenderable(err error) bool {
	return err != nil && (err == destinations.ErrNotRenderable ||
		strings.Contains(err.Error(), destinations.ErrNotRenderable.Error()))
}

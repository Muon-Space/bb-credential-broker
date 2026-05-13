package template

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// DefaultFuncs returns a fresh registry containing the built-in
// template functions. The returned map is owned by the caller; tests
// may add or override entries before passing the map to a Scope.
func DefaultFuncs() map[string]Func {
	return map[string]Func{
		"file":       fileFunc,
		"secret":     secretFunc,
		"jsonString": jsonStringFunc,
		"signjwt":    signJWTFunc,
		"now":        nowFunc,
		"b64":        b64Func,
		"env":        envFunc,
	}
}

// fileFunc reads a file from disk at evaluation time. It is the
// primary mechanism for projecting the broker's own ServiceAccount
// JWT into outbound token-exchange requests.
//
// Argument: the file path. The path is read once per template
// evaluation; callers requiring caching should provide their own
// wrapper function.
func fileFunc(_ context.Context, _ *Scope, args []string) (string, error) {
	if len(args) != 1 {
		return "", fmt.Errorf("file: expected 1 argument, got %d", len(args))
	}
	b, err := os.ReadFile(args[0])
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// secretFunc loads a named secret via the Scope's secret loader.
//
// Argument: the operator-chosen secret name registered under the
// configuration's secrets map.
func secretFunc(ctx context.Context, scope *Scope, args []string) (string, error) {
	if len(args) != 1 {
		return "", fmt.Errorf("secret: expected 1 argument, got %d", len(args))
	}
	if scope.Secrets == nil {
		return "", fmt.Errorf("secret: no secret loader available in scope")
	}
	ref, ok := scope.NamedSecrets[args[0]]
	if !ok {
		return "", fmt.Errorf("secret: no secret named %q", args[0])
	}
	b, err := scope.Secrets.Load(ctx, ref)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// jsonStringFunc returns the JSON-string-encoded form of its
// argument. The result includes the surrounding double quotes and
// any escapes required by RFC 8259.
//
// jsonString is the standard way to embed user-controlled data into
// a JSON literal: the surrounding template emits the JSON braces
// directly, and each interpolated value is wrapped in jsonString to
// remain syntactically safe.
func jsonStringFunc(_ context.Context, _ *Scope, args []string) (string, error) {
	if len(args) != 1 {
		return "", fmt.Errorf("jsonString: expected 1 argument, got %d", len(args))
	}
	b, err := json.Marshal(args[0])
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// nowFunc returns the current Unix epoch in seconds, optionally
// offset by a Go-style duration string.
//
// Forms:
//
//	${now}              the current time
//	${now:DUR}          the current time plus DUR
//	${now+DUR}          equivalent shorthand for the above
//
// The shorthand form is detected by parsing this expression via the
// "now+DUR" pseudo-function name; both forms are dispatched here.
func nowFunc(_ context.Context, scope *Scope, args []string) (string, error) {
	t := scope.Now()
	if len(args) == 0 {
		return strconv.FormatInt(t.Unix(), 10), nil
	}
	if len(args) != 1 {
		return "", fmt.Errorf("now: expected 0 or 1 arguments, got %d", len(args))
	}
	d, err := time.ParseDuration(args[0])
	if err != nil {
		return "", fmt.Errorf("now: parse duration: %w", err)
	}
	return strconv.FormatInt(t.Add(d).Unix(), 10), nil
}

// b64Func base64-url-encodes its argument without padding.
func b64Func(_ context.Context, _ *Scope, args []string) (string, error) {
	if len(args) != 1 {
		return "", fmt.Errorf("b64: expected 1 argument, got %d", len(args))
	}
	return base64.RawURLEncoding.EncodeToString([]byte(args[0])), nil
}

// envFunc reads an environment variable. Lookups happen at
// evaluation time so that operators can override values without
// reloading configuration; in practice every meaningful value comes
// from configuration directly and ${env:} is reserved for the few
// cases where the deployment manager only knows the value at start.
func envFunc(_ context.Context, _ *Scope, args []string) (string, error) {
	if len(args) != 1 {
		return "", fmt.Errorf("env: expected 1 argument, got %d", len(args))
	}
	return os.Getenv(args[0]), nil
}

// signJWTFunc signs a JSON Web Token with one of the algorithms
// from the limited supported set and returns the compact
// serialisation.
//
// Arguments:
//
//	[0] alg     One of RS256, RS384, RS512, ES256, ES384, ES512, EdDSA.
//	[1] key     The private key, encoded as a PEM block. Both
//	            PKCS#1 and PKCS#8 RSA forms are accepted, as is
//	            SEC1 EC and PKCS#8 EC.
//	[2] claims  The JWT claim set, encoded as a JSON object.
func signJWTFunc(_ context.Context, _ *Scope, args []string) (string, error) {
	if len(args) != 3 {
		return "", fmt.Errorf("signjwt: expected 3 arguments, got %d", len(args))
	}
	alg, keyPEM, claimsJSON := args[0], args[1], args[2]

	method := jwt.GetSigningMethod(alg)
	if method == nil {
		return "", fmt.Errorf("signjwt: unsupported algorithm %q", alg)
	}

	key, err := parsePrivateKey([]byte(keyPEM))
	if err != nil {
		return "", fmt.Errorf("signjwt: parse key: %w", err)
	}

	var claims jwt.MapClaims
	dec := json.NewDecoder(strings.NewReader(claimsJSON))
	dec.UseNumber()
	if err := dec.Decode(&claims); err != nil {
		return "", fmt.Errorf("signjwt: parse claims: %w", err)
	}

	tok := jwt.NewWithClaims(method, claims)
	signed, err := tok.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("signjwt: sign: %w", err)
	}
	return signed, nil
}

// parsePrivateKey accepts a PEM-encoded private key in any of the
// common forms used for JWT signing. The returned value is the
// crypto-package private key type appropriate for the encoded
// algorithm.
func parsePrivateKey(pemBytes []byte) (any, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		switch k := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
			return k, nil
		default:
			return nil, fmt.Errorf("PKCS#8 key has unsupported type %T", key)
		}
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q", block.Type)
	}
}

// nowOffsetFunc handles the ${now+DUR} shorthand. The dispatcher in
// Scope's parser does not know about this form by default; callers
// register entries of the form "now+DUR" by using the nowOffset
// helper below or by relying on Eval to fall through to it.
//
// The pseudo-function name carries the duration; see RegisterNowOffset
// for the wiring used by the standard configuration.
func nowOffsetFunc(dur time.Duration) Func {
	return func(_ context.Context, scope *Scope, args []string) (string, error) {
		if len(args) != 0 {
			return "", fmt.Errorf("now+%s: expected 0 arguments, got %d", dur, len(args))
		}
		return strconv.FormatInt(scope.Now().Add(dur).Unix(), 10), nil
	}
}

// RegisterNowOffset wires every "now+DUR" form encountered in the
// supplied template into the Scope's function registry. Templates
// that use ${now+DUR} with novel durations require a corresponding
// registry entry; this function walks the AST and inserts them on
// demand.
//
// Returning an error is the operator's signal that one of the
// duration suffixes did not parse.
func RegisterNowOffset(s *Scope, t *Template) error {
	for _, c := range t.chunks {
		if err := registerNowOffsetIn(s, c); err != nil {
			return err
		}
	}
	return nil
}

func registerNowOffsetIn(s *Scope, c chunk) error {
	switch c := c.(type) {
	case *callExpr:
		if strings.HasPrefix(c.name, "now+") {
			suffix := strings.TrimPrefix(c.name, "now+")
			d, err := time.ParseDuration(suffix)
			if err != nil {
				return fmt.Errorf("template: invalid duration in ${now+%s}: %w", suffix, err)
			}
			s.Funcs[c.name] = nowOffsetFunc(d)
		}
		for _, a := range c.args {
			for _, sub := range a.chunks {
				if err := registerNowOffsetIn(s, sub); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

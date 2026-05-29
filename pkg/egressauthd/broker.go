package egressauthd

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// MintedToken is the credential the broker returns from /token,
// projected into the shape the proxy needs to build an Authorization
// header. The fields mirror the broker's
// tokenResponse body.
type MintedToken struct {
	// Token is the raw credential value.
	Token string

	// ExpiresAt is the absolute expiry the broker reported. Zero
	// means the broker did not report an expiry; the cache then
	// applies a conservative default TTL.
	ExpiresAt time.Time

	// Scheme is the Authorization scheme the credential is presented
	// with (for example "bearer"). The proxy title-cases it into the
	// header value.
	Scheme string

	// Username is the basic-auth username paired with Token when
	// Scheme is "basic"; empty otherwise.
	Username string
}

// ErrBrokerDenied is returned when the broker responds 403 to a /token
// request: the grant does not grant the requested destination (the
// grant's granted_destinations set, fixed at /delegate, did not include
// it). The proxy maps it to a fail-closed 403 to the action.
var ErrBrokerDenied = errors.New("egressauthd: broker denied destination for grant")

// MintRequest is the input to BrokerClient.Mint:
// the per-action delegation grant plus the destination to mint for. The
// broker's /token body names the grant field "nonce"; the wire struct
// below maps Grant onto it so this in-process type can speak the
// build's vocabulary ("grant") while matching the broker exactly.
type MintRequest struct {
	// Grant is the broker delegation grant (the action's nonce). It is
	// sent as the "nonce" field of the /token request body.
	Grant string

	// Destination is the broker destination name to mint a credential
	// for. The broker mints only if the grant was scoped to it.
	Destination string
}

// BrokerClient is the contract the proxy needs of the broker. Defining
// it as an interface lets the proxy and token cache be tested against a
// fake broker without HTTP plumbing.
type BrokerClient interface {
	// Mint exchanges the action's grant for a credential at the
	// broker's /token endpoint, scoped to the requested destination. It
	// returns ErrBrokerDenied on a 403 and a wrapped transport/decode
	// error otherwise.
	Mint(ctx context.Context, req MintRequest) (*MintedToken, error)
}

// httpBrokerClient is the production BrokerClient. It POSTs to
// {BrokerTokenURL}/token with the action's grant in the request body.
// Unlike the /delegate path there is no Authorization header: the grant
// itself is the bearer of authority, and the broker gates /token by
// source CIDR plus the grant's validity and scope.
type httpBrokerClient struct {
	endpoint string
	client   *http.Client
}

// tokenRequestBody is the JSON body the broker's /token endpoint
// accepts. It mirrors the broker's handlers.tokenRequest exactly:
// {"nonce", "destination"}.
type tokenRequestBody struct {
	Nonce       string `json:"nonce"`
	Destination string `json:"destination"`
}

// tokenResponseBody is the JSON body /token returns on success. It
// mirrors the broker's handlers.tokenResponse: {token, expires_at,
// scheme, username}.
type tokenResponseBody struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	Scheme    string    `json:"scheme"`
	Username  string    `json:"username"`
}

// NewBrokerClient constructs an httpBrokerClient. When caBundleFile is
// non-empty its certificates are added to the system roots for the
// broker TLS connection (the broker's ALB / in-cluster certificate may
// chain to a private CA).
func NewBrokerClient(brokerTokenURL, caBundleFile string) (BrokerClient, error) {
	if brokerTokenURL == "" {
		return nil, fmt.Errorf("egressauthd: broker token URL is required")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if caBundleFile != "" {
		// #nosec G304 -- caBundleFile is operator-supplied configuration.
		pem, err := os.ReadFile(caBundleFile)
		if err != nil {
			return nil, fmt.Errorf("egressauthd: read broker CA bundle %s: %w", caBundleFile, err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("egressauthd: broker CA bundle %s contained no certificates", caBundleFile)
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &httpBrokerClient{
		endpoint: strings.TrimRight(brokerTokenURL, "/") + "/token",
		client:   &http.Client{Timeout: 15 * time.Second, Transport: transport},
	}, nil
}

// Mint implements BrokerClient.
func (c *httpBrokerClient) Mint(ctx context.Context, req MintRequest) (*MintedToken, error) {
	body, err := json.Marshal(tokenRequestBody{
		Nonce:       req.Grant,
		Destination: req.Destination,
	})
	if err != nil {
		return nil, fmt.Errorf("egressauthd: marshal token request: %w", err)
	}

	// #nosec G704 -- c.endpoint is derived from operator-supplied
	// broker_token_url configuration, not from request-time taint.
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("egressauthd: build token request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	// #nosec G704 -- request target is operator-configured broker_token_url.
	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("egressauthd: token request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		// fall through to decode
	case http.StatusForbidden:
		// The grant does not grant this destination.
		return nil, ErrBrokerDenied
	default:
		// Any other status (401 source gate, 410 expired/invalid grant,
		// 404 unknown destination, 502 upstream mint failure) is a
		// fail-closed error; the proxy surfaces a 5xx and does not
		// forward.
		excerpt := readExcerpt(resp.Body, 256)
		return nil, fmt.Errorf("egressauthd: broker returned HTTP %d: %s", resp.StatusCode, excerpt)
	}

	var decoded tokenResponseBody
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return nil, fmt.Errorf("egressauthd: decode token response: %w", err)
	}
	if decoded.Token == "" {
		return nil, fmt.Errorf("egressauthd: broker returned an empty token")
	}
	scheme := decoded.Scheme
	if scheme == "" {
		scheme = "bearer"
	}
	return &MintedToken{
		Token:     decoded.Token,
		ExpiresAt: decoded.ExpiresAt,
		Scheme:    scheme,
		Username:  decoded.Username,
	}, nil
}

// readExcerpt reads up to n bytes from r and returns them as a string,
// trimming trailing whitespace. It is used to surface a bounded prefix
// of an upstream error body in logs without copying an unbounded body.
func readExcerpt(r io.Reader, n int) string {
	buf := make([]byte, n)
	read, _ := io.ReadFull(io.LimitReader(r, int64(n)), buf)
	return strings.TrimSpace(string(buf[:read]))
}

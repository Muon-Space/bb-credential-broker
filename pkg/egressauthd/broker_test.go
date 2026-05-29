package egressauthd

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestHTTPBrokerClient_Mint exercises the real /token wire call against
// a fake broker: it asserts the request hits /token, the body carries
// the grant as "nonce" plus the destination (matching the broker's
// tokenRequest), and the response is decoded into a MintedToken.
func TestHTTPBrokerClient_Mint(t *testing.T) {
	t.Parallel()

	var gotPath string
	var gotBody tokenRequestBody
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if r.URL.Path != "/token" || r.Method != http.MethodPost {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tokenResponseBody{
			Token:     "minted-token",
			Scheme:    "bearer",
			ExpiresAt: time.Now().Add(time.Hour),
		})
	}))
	defer srv.Close()

	client, err := NewBrokerClient(srv.URL, "")
	if err != nil {
		t.Fatalf("NewBrokerClient: %v", err)
	}

	tok, err := client.Mint(context.Background(), MintRequest{
		Grant:       "grant-nonce-abc",
		Destination: "registry",
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if gotPath != "/token" {
		t.Errorf("path: got %q, want /token", gotPath)
	}
	if tok.Token != "minted-token" {
		t.Errorf("token: got %q, want minted-token", tok.Token)
	}
	if tok.Scheme != "bearer" {
		t.Errorf("scheme: got %q, want bearer", tok.Scheme)
	}
	// The grant must be sent as "nonce" and the destination verbatim,
	// matching the broker's /token request body.
	if gotBody.Nonce != "grant-nonce-abc" || gotBody.Destination != "registry" {
		t.Errorf("request body mismatch: %+v", gotBody)
	}
}

// TestHTTPBrokerClient_BasicSchemePassesUsername confirms a basic-auth
// destination's username survives the decode (git/OCI PAT case).
func TestHTTPBrokerClient_BasicSchemePassesUsername(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tokenResponseBody{
			Token:    "pat-value",
			Scheme:   "basic",
			Username: "x-access-token",
		})
	}))
	defer srv.Close()

	client, err := NewBrokerClient(srv.URL, "")
	if err != nil {
		t.Fatalf("NewBrokerClient: %v", err)
	}
	tok, err := client.Mint(context.Background(), MintRequest{Grant: "g", Destination: "git-host"})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if tok.Scheme != "basic" || tok.Username != "x-access-token" {
		t.Errorf("got scheme=%q username=%q, want basic / x-access-token", tok.Scheme, tok.Username)
	}
}

// TestHTTPBrokerClient_DeniedMapsToSentinel confirms a 403 from the
// broker (the grant does not grant the destination) becomes
// ErrBrokerDenied so the proxy can fail closed with a 403 rather than a
// generic 5xx.
func TestHTTPBrokerClient_DeniedMapsToSentinel(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	client, err := NewBrokerClient(srv.URL, "")
	if err != nil {
		t.Fatalf("NewBrokerClient: %v", err)
	}
	_, err = client.Mint(context.Background(), MintRequest{Grant: "g", Destination: "d"})
	if !errors.Is(err, ErrBrokerDenied) {
		t.Errorf("err: got %v, want ErrBrokerDenied", err)
	}
}

// TestHTTPBrokerClient_ExpiredGrantIsError confirms a 410 Gone (the
// broker's response to an invalid/expired grant) surfaces as a generic
// fail-closed error, not a denial.
func TestHTTPBrokerClient_ExpiredGrantIsError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nonce is not valid", http.StatusGone)
	}))
	defer srv.Close()

	client, err := NewBrokerClient(srv.URL, "")
	if err != nil {
		t.Fatalf("NewBrokerClient: %v", err)
	}
	_, err = client.Mint(context.Background(), MintRequest{Grant: "g", Destination: "d"})
	if err == nil || errors.Is(err, ErrBrokerDenied) {
		t.Errorf("err: got %v, want a non-denial fail-closed error", err)
	}
}

// TestHTTPBrokerClient_ServerErrorIsError confirms a non-403 error
// status surfaces as a generic error (the proxy fails closed with 5xx).
func TestHTTPBrokerClient_ServerErrorIsError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	client, err := NewBrokerClient(srv.URL, "")
	if err != nil {
		t.Fatalf("NewBrokerClient: %v", err)
	}
	_, err = client.Mint(context.Background(), MintRequest{Grant: "g", Destination: "d"})
	if err == nil || errors.Is(err, ErrBrokerDenied) {
		t.Errorf("err: got %v, want a non-denial error", err)
	}
}

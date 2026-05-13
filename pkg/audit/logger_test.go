package audit_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/audit"
)

func TestLogger_DelegateSuccess(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	l := audit.NewLogger(&buf)
	l.Log(context.Background(), audit.Event{
		Time:                time.Unix(1700000000, 0),
		Op:                  audit.OperationDelegate,
		IdentityType:        "ci",
		IdentityPrincipal:   "repo:owner/repo:ref:refs/heads/main",
		GrantedDestinations: []string{"alpha", "beta"},
		Success:             true,
	})

	var got map[string]any
	if err := json.NewDecoder(strings.NewReader(buf.String())).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["op"] != "delegate" {
		t.Errorf("op: got %v, want %q", got["op"], "delegate")
	}
	if got["identity_type"] != "ci" {
		t.Errorf("identity_type: got %v, want %q", got["identity_type"], "ci")
	}
	if got["ok"] != true {
		t.Errorf("ok: got %v, want true", got["ok"])
	}
	dests, ok := got["granted_destinations"].([]any)
	if !ok || len(dests) != 2 {
		t.Errorf("granted_destinations: got %v", got["granted_destinations"])
	}
}

func TestLogger_TokenFailure(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	l := audit.NewLogger(&buf)
	l.Log(context.Background(), audit.Event{
		Time:        time.Unix(1700000000, 0),
		Op:          audit.OperationToken,
		Destination: "alpha",
		Success:     false,
		Error:       "destination not configured",
	})

	var got map[string]any
	if err := json.NewDecoder(strings.NewReader(buf.String())).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["op"] != "token" {
		t.Errorf("op: got %v, want %q", got["op"], "token")
	}
	if got["ok"] != false {
		t.Errorf("ok: got %v, want false", got["ok"])
	}
	if got["error"] != "destination not configured" {
		t.Errorf("error: got %v", got["error"])
	}
	if _, ok := got["granted_destinations"]; ok {
		t.Errorf("token records should omit granted_destinations; got %v", got["granted_destinations"])
	}
}

func TestLogger_OmitsEmptyOptionalFields(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	l := audit.NewLogger(&buf)
	l.Log(context.Background(), audit.Event{
		Time:    time.Unix(1700000000, 0),
		Op:      audit.OperationDelegate,
		Success: true,
	})

	var got map[string]any
	if err := json.NewDecoder(strings.NewReader(buf.String())).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, key := range []string{"identity_type", "identity_principal", "destination", "granted_destinations", "error"} {
		if _, ok := got[key]; ok {
			t.Errorf("expected key %q to be omitted, got %v", key, got[key])
		}
	}
}

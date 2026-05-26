package secrets_test

import (
	"encoding/json"
	"strings"
	"testing"

	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/secrets"
)

// TestSecretRef_UnmarshalIsStrict pins the invariant that a typo
// inside a SecretRef's backend block (here the AWS Secrets Manager
// ref) surfaces as a decoding error rather than being silently
// ignored. The check exists because json.Unmarshal does not
// propagate DisallowUnknownFields through a custom UnmarshalJSON
// implementation; SecretRef.UnmarshalJSON installs its own strict
// decoder to compensate.
func TestSecretRef_UnmarshalIsStrict(t *testing.T) {
	t.Parallel()
	const typoed = `{"awsSecretsManager":{"arn":"arn:x","feild":"private_key"}}`
	var ref secrets.SecretRef
	err := json.Unmarshal([]byte(typoed), &ref)
	if err == nil {
		t.Fatalf("expected typo to be rejected; got %+v", ref)
	}
	if !strings.Contains(err.Error(), "feild") && !strings.Contains(err.Error(), "unknown field") {
		t.Errorf("error %q should name the unknown field", err.Error())
	}
}

// TestSecretRef_UnmarshalAcceptsValidPayload guards the strict
// decoder against false-positives: a well-formed SecretRef must
// still round-trip cleanly through UnmarshalJSON.
func TestSecretRef_UnmarshalAcceptsValidPayload(t *testing.T) {
	t.Parallel()
	const valid = `{"awsSecretsManager":{"arn":"arn:aws:x","field":"private_key"}}`
	var ref secrets.SecretRef
	if err := json.Unmarshal([]byte(valid), &ref); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if ref.AWSSecretsManager == nil || ref.AWSSecretsManager.ARN != "arn:aws:x" || ref.AWSSecretsManager.Field != "private_key" {
		t.Errorf("unexpected ref shape: %+v", ref)
	}
}

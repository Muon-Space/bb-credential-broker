// Package secrets contains the abstractions used by the broker to
// fetch the secret material required to mint downstream credentials.
//
// Secrets are referenced indirectly throughout the broker's
// configuration: each entry under the top-level secrets map binds a
// short name to a SecretRef, and other configuration fragments (such
// as templated destination requests) refer to those names. This
// indirection keeps the actual storage location of each secret in a
// single auditable place and frees the templating language from
// having to express the full ref schema.
package secrets

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// SecretRef describes how to obtain the bytes of a single secret.
//
// SecretRef is a discriminated union: exactly one of the type-specific
// fields must be non-nil. Adding support for a new secret backend is
// done by adding a new field here together with the corresponding
// loader implementation.
type SecretRef struct {
	// AWSSecretsManager loads the secret from an AWS Secrets
	// Manager secret value. When the underlying value is a JSON
	// document, the Field selector picks a single string field.
	AWSSecretsManager *AWSSecretsManagerRef `json:"awsSecretsManager,omitempty"`
}

// AWSSecretsManagerRef identifies a single secret value held in AWS
// Secrets Manager. ARN must be the full secret ARN (not just the
// secret name) so that the broker's IAM policy can grant the precise
// resource without inferring region or account.
type AWSSecretsManagerRef struct {
	// ARN is the full Amazon Resource Name of the secret.
	ARN string `json:"arn"`

	// Field is an optional JSON field selector. When set, the
	// secret value is parsed as a JSON object and the named field
	// is returned. When empty, the entire raw secret value is
	// returned.
	Field string `json:"field,omitempty"`
}

// Validate returns an error if the SecretRef has zero or more than
// one type-specific field set, or if the chosen type's required
// fields are missing.
func (r *SecretRef) Validate() error {
	switch {
	case r == nil:
		return fmt.Errorf("secret ref is nil")
	case r.AWSSecretsManager != nil:
		if r.AWSSecretsManager.ARN == "" {
			return fmt.Errorf("awsSecretsManager.arn is required")
		}
		return nil
	default:
		return fmt.Errorf("secret ref has no recognised backend; expected one of: awsSecretsManager")
	}
}

// UnmarshalJSON enforces that the input either omits the SecretRef
// entirely or specifies exactly one backend, and uses a strict
// decoder so that a typo'd field inside the chosen backend (a
// common operator mistake — "feild" instead of "field", for
// example) surfaces as a configuration error rather than being
// silently ignored. The strict decoder is required here because
// json.Unmarshal does NOT propagate the outer decoder's
// DisallowUnknownFields setting through to custom UnmarshalJSON
// implementations.
//
// Callers that also need semantic validation (exactly one backend
// set, required fields populated) should also call Validate.
func (r *SecretRef) UnmarshalJSON(data []byte) error {
	type alias SecretRef
	var a alias
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil {
		return err
	}
	*r = SecretRef(a)
	return nil
}

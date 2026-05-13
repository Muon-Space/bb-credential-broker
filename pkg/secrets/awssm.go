package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// AWSSecretsManagerAPI is the subset of the AWS Secrets Manager
// client that the loader depends on. Defining the dependency as an
// interface keeps the loader testable without standing up a real AWS
// client.
type AWSSecretsManagerAPI interface {
	GetSecretValue(ctx context.Context, input *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

// AWSSecretsManagerLoader fetches secret values from AWS Secrets
// Manager and caches them in memory for a configurable TTL.
//
// The loader caches the entire JSON-decoded value of each secret
// keyed by ARN and serves field selections from the cached value. It
// is therefore expected that all consumers of a single ARN agree on
// whether the underlying secret value is JSON or opaque bytes.
type AWSSecretsManagerLoader struct {
	client AWSSecretsManagerAPI
	ttl    time.Duration

	mu      sync.Mutex
	entries map[string]*awsSMEntry
}

type awsSMEntry struct {
	value     []byte
	parsed    map[string]string
	expiresAt time.Time
}

// NewAWSSecretsManagerLoader constructs a loader backed by the given
// AWS Secrets Manager client. Cached entries expire after ttl.
func NewAWSSecretsManagerLoader(client AWSSecretsManagerAPI, ttl time.Duration) *AWSSecretsManagerLoader {
	return &AWSSecretsManagerLoader{
		client:  client,
		ttl:     ttl,
		entries: map[string]*awsSMEntry{},
	}
}

// Load implements Loader. The given ref's AWSSecretsManager subref
// must be non-nil; refs that target other backends are rejected.
func (l *AWSSecretsManagerLoader) Load(ctx context.Context, ref SecretRef) ([]byte, error) {
	if ref.AWSSecretsManager == nil {
		return nil, fmt.Errorf("awssm: ref does not target AWS Secrets Manager")
	}
	r := ref.AWSSecretsManager

	entry, err := l.entry(ctx, r.ARN)
	if err != nil {
		return nil, err
	}

	if r.Field == "" {
		return entry.value, nil
	}
	if entry.parsed == nil {
		return nil, fmt.Errorf("awssm: secret %s does not contain a JSON object; cannot select field %q", r.ARN, r.Field)
	}
	v, ok := entry.parsed[r.Field]
	if !ok {
		return nil, fmt.Errorf("awssm: secret %s has no field %q", r.ARN, r.Field)
	}
	return []byte(v), nil
}

func (l *AWSSecretsManagerLoader) entry(ctx context.Context, arn string) (*awsSMEntry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if e, ok := l.entries[arn]; ok && time.Now().Before(e.expiresAt) {
		return e, nil
	}

	out, err := l.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: &arn})
	if err != nil {
		return nil, fmt.Errorf("awssm: get %s: %w", arn, err)
	}

	e := &awsSMEntry{expiresAt: time.Now().Add(l.ttl)}
	switch {
	case out.SecretString != nil:
		e.value = []byte(*out.SecretString)
	case out.SecretBinary != nil:
		e.value = out.SecretBinary
	default:
		return nil, fmt.Errorf("awssm: secret %s returned no value", arn)
	}

	// Best-effort JSON parse so field selection works without a
	// second API round-trip. Failure is fine; opaque secrets
	// simply leave parsed nil and field selection becomes an
	// error.
	var parsed map[string]string
	if err := json.Unmarshal(e.value, &parsed); err == nil {
		e.parsed = parsed
	}

	l.entries[arn] = e
	return e, nil
}

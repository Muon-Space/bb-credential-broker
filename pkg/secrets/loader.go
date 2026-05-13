package secrets

import (
	"context"
	"fmt"
	"sync"
)

// Loader fetches the bytes of a single SecretRef. Implementations
// must be safe for concurrent use by multiple goroutines and should
// cache results where it is sound to do so.
type Loader interface {
	// Load returns the raw bytes of the secret identified by ref.
	// The returned slice must not be retained or mutated by the
	// caller; implementations are free to return a shared buffer.
	Load(ctx context.Context, ref SecretRef) ([]byte, error)
}

// LoaderFor selects the appropriate backend-specific loader for the
// given SecretRef and dispatches to it. It implements Loader on top
// of one or more typed loaders supplied by the caller.
type LoaderFor struct {
	awsSecretsManager Loader
}

// NewLoader constructs a LoaderFor that dispatches AWS Secrets
// Manager refs to the supplied loader. Additional backends can be
// wired in by calling the corresponding setter methods before the
// LoaderFor is used.
func NewLoader(awsSecretsManager Loader) *LoaderFor {
	return &LoaderFor{awsSecretsManager: awsSecretsManager}
}

// Load implements Loader.
func (l *LoaderFor) Load(ctx context.Context, ref SecretRef) ([]byte, error) {
	if err := ref.Validate(); err != nil {
		return nil, fmt.Errorf("loader: %w", err)
	}
	switch {
	case ref.AWSSecretsManager != nil:
		if l.awsSecretsManager == nil {
			return nil, fmt.Errorf("loader: awsSecretsManager backend is not configured")
		}
		return l.awsSecretsManager.Load(ctx, ref)
	default:
		return nil, fmt.Errorf("loader: no backend handles ref")
	}
}

// MapLoader is a Loader implementation backed by an in-memory map
// keyed by the canonical string form of the ref. It is intended for
// use in tests; production callers should use the backend-specific
// loaders.
type MapLoader struct {
	mu      sync.RWMutex
	entries map[string][]byte
}

// NewMapLoader constructs an empty MapLoader.
func NewMapLoader() *MapLoader {
	return &MapLoader{entries: map[string][]byte{}}
}

// Set associates the given bytes with the supplied key. The key
// should be in the same canonical form that the corresponding ref
// would produce; for AWS Secrets Manager refs that is "<arn>#<field>".
func (m *MapLoader) Set(key string, value []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[key] = value
}

// Load implements Loader by looking up the canonical form of ref in
// the map.
func (m *MapLoader) Load(_ context.Context, ref SecretRef) ([]byte, error) {
	if err := ref.Validate(); err != nil {
		return nil, err
	}
	key := canonicalKey(ref)
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.entries[key]
	if !ok {
		return nil, fmt.Errorf("map loader: no entry for %s", key)
	}
	return v, nil
}

func canonicalKey(ref SecretRef) string {
	switch {
	case ref.AWSSecretsManager != nil:
		return fmt.Sprintf("aws:%s#%s", ref.AWSSecretsManager.ARN, ref.AWSSecretsManager.Field)
	default:
		return ""
	}
}

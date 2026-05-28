package app

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/secrets"
)

// retryLoader is a secrets.Loader that fails the first failUntil
// calls with errProvided and succeeds afterward with the supplied
// PEM bytes. It pins call ordering with an atomic counter so the
// retry-loop tests assert exactly which attempt the load
// succeeds on.
type retryLoader struct {
	failUntil  int32
	calls      int32
	errFn      func() error
	successPEM []byte
}

func (l *retryLoader) Load(_ context.Context, _ secrets.SecretRef) ([]byte, error) {
	n := atomic.AddInt32(&l.calls, 1)
	if n <= l.failUntil {
		return nil, l.errFn()
	}
	return l.successPEM, nil
}

// generateRSAPEM returns a PEM-encoded PKCS#1 RSA private key
// suitable for seeding the retry-loader's success branch.
func generateRSAPEM(t *testing.T) []byte {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
}

func TestLoadBrokerSigner_RetrySucceedsAfterTransientFailures(t *testing.T) {
	t.Parallel()
	loader := &retryLoader{
		failUntil:  2, // fail attempts 1 and 2, succeed on 3
		errFn:      func() error { return errors.New("simulated AccessDeniedException") },
		successPEM: generateRSAPEM(t),
	}
	ref := secrets.SecretRef{
		AWSSecretsManager: &secrets.AWSSecretsManagerRef{ARN: "arn:test"},
	}
	s, err := loadBrokerSignerWithBackoff(context.Background(), loader,
		[]secrets.SecretRef{ref}, 5, time.Millisecond)
	if err != nil {
		t.Fatalf("loadBrokerSignerWithBackoff: %v", err)
	}
	if s == nil {
		t.Fatal("expected non-nil Signer")
	}
	if got := atomic.LoadInt32(&loader.calls); got != 3 {
		t.Errorf("loader call count: got %d, want 3 (two failures then success)", got)
	}
}

func TestLoadBrokerSigner_RetryGivesUpAfterBudget(t *testing.T) {
	t.Parallel()
	loader := &retryLoader{
		failUntil: 100, // never succeed within the test budget
		errFn:     func() error { return errors.New("simulated AccessDeniedException") },
	}
	ref := secrets.SecretRef{
		AWSSecretsManager: &secrets.AWSSecretsManagerRef{ARN: "arn:test"},
	}
	_, err := loadBrokerSignerWithBackoff(context.Background(), loader,
		[]secrets.SecretRef{ref}, 4, time.Millisecond)
	if err == nil {
		t.Fatal("expected error after budget exhausted, got nil")
	}
	if got := atomic.LoadInt32(&loader.calls); got != 4 {
		t.Errorf("loader call count: got %d, want 4 (attempts capped at budget)", got)
	}
}

func TestLoadBrokerSigner_RetryHonoursContextCancellation(t *testing.T) {
	t.Parallel()
	loader := &retryLoader{
		failUntil: 100,
		errFn:     func() error { return errors.New("simulated AccessDeniedException") },
	}
	ref := secrets.SecretRef{
		AWSSecretsManager: &secrets.AWSSecretsManagerRef{ARN: "arn:test"},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancelled so the first sleep returns immediately
	_, err := loadBrokerSignerWithBackoff(ctx, loader,
		[]secrets.SecretRef{ref}, 10, 100*time.Millisecond)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
	// At least one attempt fires before the sleep; cancel hits the
	// first backoff. The loader may be called 1 or 2 times
	// depending on scheduler; both indicate cancellation worked.
	if got := atomic.LoadInt32(&loader.calls); got < 1 || got > 2 {
		t.Errorf("loader call count: got %d, want 1 or 2 (cancellation aborted retry loop)", got)
	}
}

// TestLoadBrokerSigner_FirstAttemptSucceedsNoRetry confirms the
// no-failure path makes exactly one call and does not sleep,
// since waiting between healthy attempts would be wasted time.
func TestLoadBrokerSigner_FirstAttemptSucceedsNoRetry(t *testing.T) {
	t.Parallel()
	loader := &retryLoader{
		failUntil:  0, // succeed on attempt 1
		successPEM: generateRSAPEM(t),
	}
	ref := secrets.SecretRef{
		AWSSecretsManager: &secrets.AWSSecretsManagerRef{ARN: "arn:test"},
	}
	start := time.Now()
	_, err := loadBrokerSignerWithBackoff(context.Background(), loader,
		[]secrets.SecretRef{ref}, 5, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("loadBrokerSignerWithBackoff: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Errorf("first-attempt-success path slept %v; should be near-instant", elapsed)
	}
	if got := atomic.LoadInt32(&loader.calls); got != 1 {
		t.Errorf("loader call count: got %d, want 1", got)
	}
}

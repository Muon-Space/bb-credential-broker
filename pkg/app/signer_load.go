package app

import (
	"context"
	"log/slog"
	"time"

	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/secrets"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/signer"
)

// brokerSignerLoadAttempts is the maximum number of times the
// broker tries to fetch its signing-key secrets at startup before
// giving up. The default targets the IAM-propagation window:
// terraform applying a fresh IRSA policy that grants the broker
// access to a new secret typically takes 30-60 seconds to
// propagate. A broker pod that starts during that window would
// otherwise exit immediately on AccessDenied, trip
// KubePodNotReady alerts before kubelet gets around to
// restarting it, and look like an outage on dashboards.
const brokerSignerLoadAttempts = 5

// brokerSignerLoadInitialBackoff is the wait between the first
// and second attempt; subsequent attempts double the backoff so
// the full sequence covers 2 + 4 + 8 + 16 + 32 = 62 seconds.
// The shape matches the upper end of AWS IAM propagation
// latency observed in practice.
const brokerSignerLoadInitialBackoff = 2 * time.Second

// loadBrokerSigner wraps signer.LoadMulti with exponential
// backoff so transient secret-load failures (the canonical case
// being AWS IAM policy propagation racing with pod startup) do
// not surface as a broker boot failure. The retry budget is
// bounded by both attempt count and ctx cancellation; after the
// budget is exhausted the original error is returned and the
// broker exits, surfacing the underlying problem to the
// operator.
//
// Retry-at-startup is deliberate. The /token path does NOT
// retry — there the broker has already authenticated the caller
// and any delay translates into request latency for a real
// build. Retries belong only at the one-shot startup
// secret-fetch.
func loadBrokerSigner(ctx context.Context, loader secrets.Loader, refs []secrets.SecretRef) (*signer.Signer, error) {
	return loadBrokerSignerWithBackoff(ctx, loader, refs, brokerSignerLoadAttempts, brokerSignerLoadInitialBackoff)
}

// loadBrokerSignerWithBackoff is the test-friendly form of
// loadBrokerSigner: it accepts the attempt count and initial
// backoff as parameters so unit tests can exercise the retry
// loop without paying the production 62-second budget.
func loadBrokerSignerWithBackoff(ctx context.Context, loader secrets.Loader, refs []secrets.SecretRef, attempts int, initialBackoff time.Duration) (*signer.Signer, error) {
	backoff := initialBackoff
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		s, err := signer.LoadMulti(ctx, loader, refs)
		if err == nil {
			return s, nil
		}
		lastErr = err
		if attempt == attempts {
			break
		}
		slog.Warn("broker signer load failed; will retry",
			"attempt", attempt,
			"max_attempts", attempts,
			"next_backoff", backoff,
			"error", err)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
		}
		backoff *= 2
	}
	return nil, lastErr
}

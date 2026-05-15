package staticsecret_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/auth"
	"muonspace.ghe.com/Muon-Space/bb-credential-broker/pkg/destinations/staticsecret"
)

// writeSecret stages a secret file with the supplied bytes and
// returns its path. Tests use it to construct an Impl backed by a
// real file on disk.
func writeSecret(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	return path
}

func TestNew_RejectsNilConfig(t *testing.T) {
	t.Parallel()
	if _, err := staticsecret.New("d", nil); err == nil {
		t.Fatal("New(nil): expected error, got nil")
	}
}

func TestNew_RejectsEmptyFile(t *testing.T) {
	t.Parallel()
	if _, err := staticsecret.New("d", &staticsecret.Config{}); err == nil {
		t.Fatal("New with empty File: expected error, got nil")
	}
}

func TestNew_RejectsMissingFile(t *testing.T) {
	t.Parallel()
	cfg := &staticsecret.Config{File: filepath.Join(t.TempDir(), "missing")}
	if _, err := staticsecret.New("d", cfg); err == nil {
		t.Fatal("New with missing file: expected error, got nil")
	}
}

func TestNew_RejectsEmptySecretFile(t *testing.T) {
	t.Parallel()
	cfg := &staticsecret.Config{File: writeSecret(t, "")}
	if _, err := staticsecret.New("d", cfg); err == nil {
		t.Fatal("New with empty secret file: expected error, got nil")
	}
}

func TestNew_RejectsWhitespaceOnlySecret(t *testing.T) {
	t.Parallel()
	cfg := &staticsecret.Config{File: writeSecret(t, "   \n\n")}
	if _, err := staticsecret.New("d", cfg); err == nil {
		t.Fatal("New with whitespace-only secret: expected error, got nil")
	}
}

func TestNew_RejectsBadCacheTTL(t *testing.T) {
	t.Parallel()
	cfg := &staticsecret.Config{File: writeSecret(t, "ghp_xxx"), CacheTTL: "not-a-duration"}
	if _, err := staticsecret.New("d", cfg); err == nil {
		t.Fatal("New with bad CacheTTL: expected error, got nil")
	}
}

func TestNew_RejectsZeroCacheTTL(t *testing.T) {
	t.Parallel()
	cfg := &staticsecret.Config{File: writeSecret(t, "ghp_xxx"), CacheTTL: "0s"}
	if _, err := staticsecret.New("d", cfg); err == nil {
		t.Fatal("New with zero CacheTTL: expected error, got nil")
	}
}

func TestMint_ReturnsFileContents(t *testing.T) {
	t.Parallel()
	cfg := &staticsecret.Config{File: writeSecret(t, "ghp_secret_value")}
	d, err := staticsecret.New("ghe-pat", cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	tok, err := d.Mint(context.Background(), &auth.Identity{Type: auth.IdentityTypeCI, Principal: "p"})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if tok.Value != "ghp_secret_value" {
		t.Errorf("Value: got %q, want %q", tok.Value, "ghp_secret_value")
	}
}

func TestMint_TrimsTrailingWhitespace(t *testing.T) {
	t.Parallel()
	// Common case: kubectl create secret --from-file=token=./pat.txt
	// with pat.txt produced by `echo "ghp_..." > pat.txt` ends in
	// "\n". Less common: trailing spaces, CRLF line endings.
	for _, suffix := range []string{"\n", "\r\n", "  \n", "\t\n"} {
		cfg := &staticsecret.Config{File: writeSecret(t, "ghp_value"+suffix)}
		d, err := staticsecret.New("d", cfg)
		if err != nil {
			t.Fatalf("New (suffix %q): %v", suffix, err)
		}
		tok, err := d.Mint(context.Background(), nil)
		if err != nil {
			t.Fatalf("Mint (suffix %q): %v", suffix, err)
		}
		if tok.Value != "ghp_value" {
			t.Errorf("Value with suffix %q: got %q, want %q", suffix, tok.Value, "ghp_value")
		}
	}
}

func TestMint_PreservesInternalWhitespace(t *testing.T) {
	t.Parallel()
	// The trim is one-sided. A credential whose interior happens
	// to contain spaces or newlines (rare for PATs but possible
	// for some token formats) must round-trip exactly.
	cfg := &staticsecret.Config{File: writeSecret(t, "first line\nsecond line")}
	d, err := staticsecret.New("d", cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	tok, err := d.Mint(context.Background(), nil)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if tok.Value != "first line\nsecond line" {
		t.Errorf("Value: got %q, want %q", tok.Value, "first line\nsecond line")
	}
}

func TestMint_RereadsFileEachCall(t *testing.T) {
	t.Parallel()
	// Operator-driven rotation: the underlying Secret may change
	// at any time without restarting the broker. The next Mint
	// should observe the new value.
	path := writeSecret(t, "v1")
	d, err := staticsecret.New("d", &staticsecret.Config{File: path})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	first, err := d.Mint(context.Background(), nil)
	if err != nil {
		t.Fatalf("Mint #1: %v", err)
	}
	if first.Value != "v1" {
		t.Fatalf("Value #1: got %q, want %q", first.Value, "v1")
	}
	if err := os.WriteFile(path, []byte("v2"), 0o600); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	second, err := d.Mint(context.Background(), nil)
	if err != nil {
		t.Fatalf("Mint #2: %v", err)
	}
	if second.Value != "v2" {
		t.Errorf("Value #2: got %q, want %q (broker did not re-read after rotation)", second.Value, "v2")
	}
}

func TestMint_DefaultsScheme(t *testing.T) {
	t.Parallel()
	d, err := staticsecret.New("d", &staticsecret.Config{File: writeSecret(t, "x")})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	tok, err := d.Mint(context.Background(), nil)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if tok.Scheme != staticsecret.DefaultScheme {
		t.Errorf("Scheme: got %q, want %q", tok.Scheme, staticsecret.DefaultScheme)
	}
}

func TestMint_HonoursConfiguredScheme(t *testing.T) {
	t.Parallel()
	cfg := &staticsecret.Config{
		File:     writeSecret(t, "ghp_xxx"),
		Scheme:   "basic",
		Username: "x-access-token",
	}
	d, err := staticsecret.New("d", cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	tok, err := d.Mint(context.Background(), nil)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if tok.Scheme != "basic" {
		t.Errorf("Scheme: got %q, want %q", tok.Scheme, "basic")
	}
	if tok.Username != "x-access-token" {
		t.Errorf("Username: got %q, want %q", tok.Username, "x-access-token")
	}
}

func TestMint_AdvertisesExpiresAt(t *testing.T) {
	t.Parallel()
	cfg := &staticsecret.Config{File: writeSecret(t, "x"), CacheTTL: "30m"}
	d, err := staticsecret.New("d", cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	frozen := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	d.SetNow(func() time.Time { return frozen })
	tok, err := d.Mint(context.Background(), nil)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	want := frozen.Add(30 * time.Minute)
	if !tok.ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt: got %v, want %v", tok.ExpiresAt, want)
	}
}

func TestMint_DefaultsCacheTTLToOneHour(t *testing.T) {
	t.Parallel()
	d, err := staticsecret.New("d", &staticsecret.Config{File: writeSecret(t, "x")})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	frozen := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	d.SetNow(func() time.Time { return frozen })
	tok, err := d.Mint(context.Background(), nil)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	want := frozen.Add(staticsecret.DefaultCacheTTL)
	if !tok.ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt: got %v, want %v", tok.ExpiresAt, want)
	}
}

func TestMint_ReturnsErrorWhenFileVanishesAfterConstruction(t *testing.T) {
	t.Parallel()
	path := writeSecret(t, "x")
	d, err := staticsecret.New("d", &staticsecret.Config{File: path})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, err := d.Mint(context.Background(), nil); err == nil {
		t.Fatal("Mint after file removal: expected error, got nil")
	}
}

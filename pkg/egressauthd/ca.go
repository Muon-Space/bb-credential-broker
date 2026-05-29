package egressauthd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"
)

// ephemeralCA is a per-action signing CA used by the MITM proxy to
// mint leaf certificates for the upstream hosts the action connects to.
// A fresh CA is generated per action so the trust the action is told to
// extend (via SSL_CERT_FILE / pip's --cert, etc.) is scoped to that
// action's lifetime and never shared across builds.
//
// The CA never leaves the sidecar except as the public PEM the worker
// hands to the action; the private key signs leaves in-process only.
type ephemeralCA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte

	mu     sync.Mutex
	leaves map[string]*tls.Certificate
}

// newEphemeralCA generates a fresh self-signed CA certificate and key.
// ttl bounds the CA's NotAfter so a leaked public bundle cannot be used
// to validate a long-lived forgery; it is set from the action's
// lifetime by the caller.
func newEphemeralCA(ttl time.Duration) (*ephemeralCA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("egressauthd: generate CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	if ttl <= 0 {
		ttl = time.Hour
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "egress-authd ephemeral CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(ttl),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("egressauthd: create CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("egressauthd: parse CA certificate: %w", err)
	}
	return &ephemeralCA{
		cert:    cert,
		key:     key,
		certPEM: encodeCertPEM(der),
		leaves:  map[string]*tls.Certificate{},
	}, nil
}

// leafFor returns a TLS certificate valid for host, signed by the CA,
// minting and caching one on first use. The same leaf is reused for the
// life of the CA so repeated connections to a host do not re-sign.
func (c *ephemeralCA) leafFor(host string) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if leaf, ok := c.leaves[host]; ok {
		return leaf, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("egressauthd: generate leaf key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    c.cert.NotBefore,
		NotAfter:     c.cert.NotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	// A CONNECT target may be an IP literal (rare for our destinations,
	// common in tests). TLS verification requires the SAN type to match
	// the dialled name, so set an IP SAN for literals and a DNS SAN
	// otherwise.
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, fmt.Errorf("egressauthd: sign leaf for %s: %w", host, err)
	}
	leaf := &tls.Certificate{
		Certificate: [][]byte{der, c.cert.Raw},
		PrivateKey:  key,
	}
	c.leaves[host] = leaf
	return leaf, nil
}

// randomSerial returns a positive 128-bit random certificate serial.
func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("egressauthd: generate serial: %w", err)
	}
	return serial, nil
}

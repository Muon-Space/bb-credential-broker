package egressauthd

import "encoding/pem"

// encodeCertPEM wraps a DER-encoded certificate in a PEM block. It is
// used to hand the per-action CA's public certificate to the worker so
// the action can be told to trust it.
func encodeCertPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

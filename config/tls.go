package config

import (
	"crypto/tls"
	"fmt"
	"strings"
)

// The TLS versions a variant can be pinned to. Its server and the client both
// offer only that one, so that a run measures the version it says it does
// rather than whatever the two ends would have agreed on.
const (
	TLS11 = "1.1"
	TLS12 = "1.2"
	TLS13 = "1.3"
)

// TLSVersions is every version, newest first: the order a report's tables
// for them are written in.
var TLSVersions = []string{TLS13, TLS12, TLS11}

// ParseTLSVersion turns a version as TLSVersions names it into crypto/tls's.
func ParseTLSVersion(s string) (uint16, error) {
	switch strings.TrimSpace(s) {
	case TLS11:
		return tls.VersionTLS11, nil
	case TLS12:
		return tls.VersionTLS12, nil
	case TLS13:
		return tls.VersionTLS13, nil
	}
	return 0, fmt.Errorf("unsupported TLS version %q, want %v, %v or %v", s, TLS11, TLS12, TLS13)
}

// The certificate keys -key takes, for the servers. The key is most of what a
// full handshake costs the server - an ECDSA P-256 signature is an order of
// magnitude cheaper than an RSA 2048 one - so the Connections table means
// nothing without it, and every report records the one the client saw.
const (
	KeyECDSA   = "ecdsa"
	KeyRSA     = "rsa"
	KeyEd25519 = "ed25519"
)

// DefaultKey is what -key defaults to: ECDSA P-256, what most sites serve and
// what a certificate authority issues by default today.
const DefaultKey = KeyECDSA

// ValidateKey checks a -key value.
func ValidateKey(key string) error {
	switch key {
	case KeyECDSA, KeyRSA, KeyEd25519:
		return nil
	}
	return fmt.Errorf("unsupported certificate key %q, want %v, %v or %v", key, KeyECDSA, KeyRSA, KeyEd25519)
}

// ServerName is the name every server's certificate is issued to, and the
// SNI every client sends, whatever address it dials.
const ServerName = "go-tls-benchmark"

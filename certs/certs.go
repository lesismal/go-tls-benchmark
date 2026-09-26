// Package certs issues the servers their certificates.
//
// Every server issues itself a fresh self-signed certificate at startup, of
// the key type -key names, for config.ServerName. Nothing is read from or
// written to disk, so there is nothing to generate before a run or to keep in
// step between two nodes. The clients do not verify it: what the benchmark
// measures is the server's side of the handshake, and a client spending CPU
// on a chain check it shares the machine with would only take CPU from the
// server on a single-node run.
package certs

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"time"

	"go-tls-benchmark/config"
)

// SelfSigned issues a self-signed certificate with a new key of type key.
func SelfSigned(key string) (tls.Certificate, error) {
	var (
		priv crypto.Signer
		err  error
	)
	switch key {
	case config.KeyECDSA:
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case config.KeyRSA:
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
	case config.KeyEd25519:
		_, priv, err = ed25519.GenerateKey(rand.Reader)
	default:
		err = config.ValidateKey(key)
	}
	if err != nil {
		return tls.Certificate{}, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return tls.Certificate{}, err
	}
	usage := x509.KeyUsageDigitalSignature
	if key == config.KeyRSA {
		// TLS 1.2's RSA key exchange encrypts to the key rather than signing
		// with it. The cipher suites the benchmark negotiates are all ECDHE,
		// but a certificate that allows it costs nothing.
		usage |= x509.KeyUsageKeyEncipherment
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: config.ServerName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              usage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{config.ServerName, "localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, priv.Public(), priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create %v certificate: %w", key, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: leaf}, nil
}

// KeyName is how a report names the key of a certificate the client was
// served: the key -key would have to be given to issue it, with its size,
// e.g. "ecdsa-p256" or "rsa-2048".
func KeyName(cert *x509.Certificate) string {
	if cert == nil {
		return "-"
	}
	switch pub := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		return fmt.Sprintf("%v-p%d", config.KeyECDSA, pub.Curve.Params().BitSize)
	case *rsa.PublicKey:
		return fmt.Sprintf("%v-%d", config.KeyRSA, pub.N.BitLen())
	case ed25519.PublicKey:
		return config.KeyEd25519
	}
	return cert.PublicKeyAlgorithm.String()
}

package certs

import (
	"crypto/tls"
	"net"
	"testing"

	"go-tls-benchmark/config"
)

// Every key -key takes issues a certificate a client completes a handshake
// against, in both versions -tls takes, and the client names the key the way
// the reports do.
func TestSelfSignedHandshakes(t *testing.T) {
	for key, want := range map[string]string{
		config.KeyECDSA:   "ecdsa-p256",
		config.KeyRSA:     "rsa-2048",
		config.KeyEd25519: "ed25519",
	} {
		cert, err := SelfSigned(key)
		if err != nil {
			t.Fatalf("SelfSigned(%v): %v", key, err)
		}
		for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
			// A socket rather than net.Pipe: a TLS 1.3 server writes its
			// session ticket as the last step of its handshake, which an
			// unbuffered pipe holds until the client reads it.
			serverConn, clientConn := socketPair(t)
			server := tls.Server(serverConn, &tls.Config{
				Certificates: []tls.Certificate{cert}, MinVersion: version, MaxVersion: version})
			client := tls.Client(clientConn, &tls.Config{
				ServerName: config.ServerName, InsecureSkipVerify: true, MinVersion: version, MaxVersion: version})
			errc := make(chan error, 1)
			go func() { errc <- server.Handshake() }()
			if err := client.Handshake(); err != nil {
				t.Fatalf("%v, %v: client handshake: %v", key, tls.VersionName(version), err)
			}
			if err := <-errc; err != nil {
				t.Fatalf("%v, %v: server handshake: %v", key, tls.VersionName(version), err)
			}
			state := client.ConnectionState()
			if state.Version != version {
				t.Errorf("%v: negotiated %v, want %v", key, tls.VersionName(state.Version), tls.VersionName(version))
			}
			if got := KeyName(state.PeerCertificates[0]); got != want {
				t.Errorf("KeyName of a %v certificate = %q, want %q", key, got, want)
			}
			client.Close()
			server.Close()
		}
	}
	if _, err := SelfSigned("dsa"); err == nil {
		t.Error(`SelfSigned("dsa") = nil error, want one`)
	}
	if KeyName(nil) != "-" {
		t.Errorf("KeyName(nil) = %q, want -", KeyName(nil))
	}
}

func socketPair(t *testing.T) (net.Conn, net.Conn) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	return server, client
}

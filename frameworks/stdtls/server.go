// Command stdtls is the standard library's TLS echo server: crypto/tls over a
// net.Listener, a goroutine per connection, which is how a Go program serves
// TLS without a framework.
package main

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"go-tls-benchmark/config"
	"go-tls-benchmark/frameworks"
	"go-tls-benchmark/logging"
)

// handshakeTimeout bounds a handshake, as fib's tls package bounds its own by
// default, so that a client that connects and never finishes costs a
// goroutine for no longer on one server than on the other.
const handshakeTimeout = 10 * time.Second

func main() {
	frameworks.Init(config.StdTLS)
	control := frameworks.StartControlServer()
	defer control.Close()

	tlsConfig := frameworks.TLSConfig()
	lns := frameworks.ListenAll()
	for _, ln := range lns {
		go serve(tls.NewListener(ln, tlsConfig))
	}

	frameworks.WaitSignal()
	for _, ln := range lns {
		ln.Close()
	}
}

func serve(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			logging.Printf("accept failed: %v", err)
			return
		}
		go echo(c.(*tls.Conn))
	}
}

// echo writes back whatever the connection reads, until it closes. The buffer
// is the connection's own for as long as it is open, which is how a
// goroutine-per-connection server is written: crypto/tls hands back at most
// what the buffer holds of a record's plaintext per Read and keeps the rest
// for the next one.
func echo(c *tls.Conn) {
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
	err := c.HandshakeContext(ctx)
	cancel()
	if err != nil {
		return
	}

	buf := make([]byte, *frameworks.Payload)
	for {
		n, err := c.Read(buf)
		if n > 0 {
			if _, err := c.Write(buf[:n]); err != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

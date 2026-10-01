// Command fib is github.com/lesismal/fib's TLS echo server: the engine's event
// loop does the I/O, and fib/tls runs crypto/tls in front of a handler that
// sends back whatever plaintext it is handed.
package main

import (
	"flag"

	"go-tls-benchmark/config"
	"go-tls-benchmark/frameworks"
	"go-tls-benchmark/logging"

	fib "github.com/lesismal/fib"
	fibtls "github.com/lesismal/fib/tls"
)

// fib's own, so defined here rather than among the flags in frameworks, which
// every server takes: script/server.sh passes it to this server alone, from
// BENCH_FIB_SOCKET_SYSCALLS in script/config.sh.
var socketSyscalls = flag.Bool("socketsyscalls", true,
	`read and write sockets with recvfrom, sendto and sendmsg rather than read, write and writev (fib.Config.SocketSyscalls; Linux only)`)

func main() {
	frameworks.Init(config.Fib)
	control := frameworks.StartControlServer()
	defer control.Close()

	addrs := frameworks.ServerAddrs()

	echo := fib.HandlerFuncs{
		// The same handler as without TLS: fibtls hands it plaintext, and
		// Send encrypts. Send copies what it is given, so data can go back to
		// the engine as soon as it returns.
		Data: func(c *fib.Connection, data []byte) {
			if c.Send(data) != nil {
				c.Close()
			}
		},
	}
	handler := &serverHandler{
		Handler: fibtls.NewServer(frameworks.TLSConfig(), echo),
		nodelay: *frameworks.Nodelay,
	}

	// One engine bound to every benchmark port. A server per port would give
	// each one its own event loop but also its own descriptor table, buffer
	// pools and outbound budget, none of which the ports have any reason not
	// to share.
	serverConfig := fib.DefaultConfig()
	serverConfig.Network = "tcp4"
	serverConfig.Addrs = addrs
	serverConfig.SocketSyscalls = *socketSyscalls
	logging.Printf("%v server: socketsyscalls=%v", frameworks.Framework(), serverConfig.SocketSyscalls)
	engine, err := fib.Bind(serverConfig, handler)
	if err != nil {
		logging.Fatalf("bind %d addresses failed: %v", len(addrs), err)
	}
	logging.Printf("%v server: listening on %d ports, %v to %v", frameworks.Framework(), len(addrs), addrs[0], addrs[len(addrs)-1])
	go func() {
		if err := engine.Run(); err != nil {
			logging.Printf("server exit: %v", err)
		}
	}()

	frameworks.WaitSignal()
	engine.Stop()
}

// serverHandler sets TCP_NODELAY to -nodelay on each connection before the TLS
// handler sees it, whichever way -nodelay points: fib turns the option on for
// every TCP connection it accepts, so -nodelay=false needs a call too.
type serverHandler struct {
	fib.Handler
	nodelay bool
}

func (h *serverHandler) OnOpen(c *fib.Connection) {
	if err := c.SetNoDelay(h.nodelay); err != nil {
		c.Close()
		return
	}
	h.Handler.OnOpen(c)
}

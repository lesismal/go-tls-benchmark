// Package frameworks is what every benchmark server shares: the flags
// script/benchmark.sh forwards to them, the TLS configuration, the listeners
// on the framework's benchmark ports, and the control server that the clients
// read the server's pid, CPU and memory from.
package frameworks

import (
	"crypto/tls"
	"errors"
	"flag"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"go-tls-benchmark/certs"
	"go-tls-benchmark/config"
	"go-tls-benchmark/logging"

	"github.com/libp2p/go-reuseport"
)

// The flags script/benchmark.sh forwards to every server. Each server defines
// all of them, whether or not it has a use for each, since one it did not
// define would stop it with "flag provided but not defined".
var (
	Nodelay    = flag.Bool("nodelay", true, `tcp nodelay`)
	reuse      = flag.Bool("reuseport", true, `reuse port`)
	Payload    = flag.Int("b", 1024, `expected message size, which sizes the servers' read buffers`)
	memLimit   = flag.Int64("m", 1024*1024*1024*2, `memory limit`)
	variant    = flag.String("f", "", `framework: the variant of this server to run, e.g. "fib-tls13", which pins its TLS version and its ports; empty runs the TLS 1.3 one`)
	certKey    = flag.String("key", config.DefaultKey, `certificate key: "ecdsa" (P-256), "rsa" (2048) or "ed25519"`)
	framework  string
	tlsVersion string
)

// Init parses the flags and applies the ones every server shares. base is the
// server's name as config knows it, e.g. config.Fib; -f picks which of its
// variants this process is.
func Init(base string) {
	flag.Parse()
	if *variant == "" {
		*variant = config.VariantName(base, config.TLS13)
	}
	v, ok := config.FindVariant(*variant)
	if !ok || v.Base != base {
		var names []string
		for _, v := range config.Variants {
			if v.Base == base {
				names = append(names, v.Name)
			}
		}
		logging.Fatalf("-f=%v: not a variant of %v, want one of %v", *variant, base, names)
	}
	framework, tlsVersion = v.Name, v.Version
	debug.SetMemoryLimit(*memLimit)
	logging.Printf("%v server: nodelay=%v, reuseport=%v, payload=%v, memory limit=%v, tls=%v, key=%v",
		framework, *Nodelay, *reuse, *Payload, *memLimit, tlsVersion, *certKey)
}

// Framework is the variant this server runs as, e.g. "fib-tls13".
func Framework() string {
	return framework
}

// TLSConfig is the configuration every server serves: a certificate issued at
// startup with the -key key, and the variant's TLS version as both the lowest
// and the highest, so that a client cannot talk the server into another one. Nothing
// else is set, so the cipher suites, curves and session tickets are crypto/tls's
// defaults, and every server has the same ones.
func TLSConfig() *tls.Config {
	version, err := config.ParseTLSVersion(tlsVersion)
	if err != nil {
		logging.Fatalf("%v: %v", framework, err)
	}
	if err := config.ValidateKey(*certKey); err != nil {
		logging.Fatalf("-key: %v", err)
	}
	cert, err := certs.SelfSigned(*certKey)
	if err != nil {
		logging.Fatalf("issuing the certificate failed: %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   version,
		MaxVersion:   version,
	}
}

// ServerAddrs is the addresses the framework's server listens on for the
// benchmark.
func ServerAddrs() []string {
	addrs, err := config.GetFrameworkServerAddrs(framework)
	if err != nil {
		logging.Fatalf("GetFrameworkServerAddrs(%v) failed: %v", framework, err)
	}
	return addrs
}

// Listen listens on addr, with SO_REUSEPORT unless -reuseport=false, and sets
// -nodelay on every connection it accepts. Go sets TCP_NODELAY on every TCP
// connection itself, so the wrapper only has anything to do for
// -nodelay=false.
func Listen(network, addr string) (net.Listener, error) {
	var (
		ln  net.Listener
		err error
	)
	if *reuse {
		ln, err = reuseport.Listen(network, addr)
	} else {
		ln, err = net.Listen(network, addr)
	}
	if err != nil || *Nodelay {
		return ln, err
	}
	return &noDelayListener{Listener: ln}, nil
}

// ListenAll listens on every one of the framework's benchmark ports.
func ListenAll() []net.Listener {
	addrs := ServerAddrs()
	lns := make([]net.Listener, 0, len(addrs))
	for _, addr := range addrs {
		ln, err := Listen("tcp", addr)
		if err != nil {
			logging.Fatalf("listen %v failed: %v", addr, err)
		}
		lns = append(lns, ln)
	}
	logging.Printf("%v server: listening on %d ports, %v to %v",
		framework, len(addrs), addrs[0], addrs[len(addrs)-1])
	return lns
}

type noDelayListener struct {
	net.Listener
}

func (l *noDelayListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if tc, ok := c.(interface{ SetNoDelay(bool) error }); ok {
		_ = tc.SetNoDelay(false)
	}
	return c, nil
}

// StartControlServer serves the control routes on the framework's control
// port, on a plaintext net/http server of its own; see
// config.GetFrameworkControlServerAddr.
func StartControlServer() *http.Server {
	addr, err := config.GetFrameworkControlServerAddr(framework)
	if err != nil {
		logging.Fatalf("GetFrameworkControlServerAddr(%v) failed: %v", framework, err)
	}
	mux := http.NewServeMux()
	HandleCommon(mux)
	server := &http.Server{Addr: addr, Handler: mux}
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logging.Fatalf("control server on %v exit: %v", addr, err)
		}
	}()
	return server
}

// WaitSignal blocks until the server is told to stop: SIGINT, which
// script/killone.sh sends, or SIGTERM.
func WaitSignal() {
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)
	<-interrupt
	logging.Printf("%v server: exit", framework)
}

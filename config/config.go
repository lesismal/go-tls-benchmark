package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"go-tls-benchmark/logging"

	"github.com/lesismal/perf"
)

type InitArgs struct {
	PsInterval time.Duration
}

// The servers this benchmark knows, by the name their binary is built from:
// frameworks/<base>. What a run measures is a variant of one - a base and
// the one TLS version its server is pinned to - named "<base>-tls<version>",
// e.g. fib-tls13; see Variants.
const (
	// Fib is github.com/lesismal/fib's engine with its tls package in front
	// of the echo handler: crypto/tls does the cryptography, the engine's
	// event loop does the I/O.
	Fib = "fib"
	// RustLS is rustls on tokio, through tokio-rustls, with aws-lc-rs as its
	// cryptography: a task per connection on tokio's multi-threaded runtime.
	RustLS = "rustls"
	// StdTLS is the standard library: crypto/tls over net, a goroutine per
	// connection.
	StdTLS = "stdtls"
)

// BaseLangs is the programming language each base's server is written in, as
// the reports' Lang column shows it.
var BaseLangs = map[string]string{
	Fib:    "go",
	RustLS: "rust",
	StdTLS: "go",
}

// Variant is one framework as a run measures it: a base server pinned to one
// TLS version, with its own ports, so that every variant of every base can be
// up at once on a server node.
type Variant struct {
	Name    string
	Base    string
	Version string // as TLSVersions names it, e.g. "1.3"
	Ports   string // "first:last" benchmark port
}

// Variants is every framework, in framework-name order, which is also the
// order of FrameworkList, of the frameworks list in script/config.sh, and of
// the rows of a -sort=framework report.
//
// The Go servers speak TLS 1.1 to 1.3; rustls implements only 1.2 and 1.3.
// TLS 1.0 is left out: crypto/tls still speaks it, but it and 1.1 were
// deprecated together (RFC 8996) and negotiate the same cipher suites, so a
// 1.0 variant would measure nothing 1.1 does not.
//
// Each variant has a block of a hundred ports from 12001 on: its fifty
// benchmark ports at the start of the block - fifty, so that a client dialing
// a million connections from one address does not run out of ephemeral ports
// towards any one of them - and its control port right after them (see
// GetFrameworkControlServerAddr). A new variant takes the next hundred after
// the last block handed out, so that no range moves when one is added, and all
// of them fit in one small range, which a run reserves out of the client's
// ephemeral ports (server_port_range in script/config.sh).
//
// frameworks/rustls and benchcli-rustls cannot import this table, so each
// carries its own copy of it, which TestRustTablesMatch holds to this one.
var Variants = []Variant{
	{"fib-tls11", Fib, TLS11, "12001:12050"},
	{"fib-tls12", Fib, TLS12, "12101:12150"},
	{"fib-tls13", Fib, TLS13, "12201:12250"},
	{"rustls-tls12", RustLS, TLS12, "12301:12350"},
	{"rustls-tls13", RustLS, TLS13, "12401:12450"},
	{"stdtls-tls11", StdTLS, TLS11, "12501:12550"},
	{"stdtls-tls12", StdTLS, TLS12, "12601:12650"},
	{"stdtls-tls13", StdTLS, TLS13, "12701:12750"},
}

// VariantName is the name of base's variant pinned to version, e.g.
// VariantName("fib", "1.3") is "fib-tls13".
func VariantName(base, version string) string {
	return base + "-tls" + strings.ReplaceAll(version, ".", "")
}

// FindVariant is the variant named name.
func FindVariant(name string) (Variant, bool) {
	for _, v := range Variants {
		if v.Name == name {
			return v, true
		}
	}
	return Variant{}, false
}

// Ports is the range of benchmark ports each framework listens on, by
// variant name; see Variants.
var Ports = func() map[string]string {
	m := make(map[string]string, len(Variants))
	for _, v := range Variants {
		m[v.Name] = v.Ports
	}
	return m
}()

// FrameworkList is every framework, in framework-name order. It is also the
// row order of a -sort=framework report, which is what puts a framework on the
// same row in every table and across runs, whatever it scored.
var FrameworkList = func() []string {
	names := make([]string, 0, len(Variants))
	for _, v := range Variants {
		names = append(names, v.Name)
	}
	return names
}()

// Langs is the language of every framework's server, by variant name.
var Langs = func() map[string]string {
	m := make(map[string]string, len(Variants))
	for _, v := range Variants {
		m[v.Name] = BaseLangs[v.Base]
	}
	return m
}()

// FrameworkVersion is the TLS version framework is pinned to, as TLSVersions
// names it, or "" for a framework Variants does not know.
func FrameworkVersion(framework string) string {
	v, _ := FindVariant(framework)
	return v.Version
}

// FrameworkLang is framework's language, or "-" for a framework Langs does
// not know, such as one a report file names that this build has dropped.
func FrameworkLang(framework string) string {
	if lang, ok := Langs[framework]; ok {
		return lang
	}
	return "-"
}

// HasPprof reports whether framework's server serves /debug/pprof/: only the
// Go ones do, on the net/http control server they share.
func HasPprof(framework string) bool {
	return FrameworkLang(framework) == "go"
}

func GetFrameworkBenchmarkPorts(framework string) ([]int, error) {
	portRange, ok := Ports[framework]
	if !ok {
		return nil, fmt.Errorf("unknown framework %q", framework)
	}
	bounds := strings.Split(portRange, ":")
	minPort, err := strconv.Atoi(bounds[0])
	if err != nil {
		return nil, err
	}
	maxPort, err := strconv.Atoi(bounds[1])
	if err != nil {
		return nil, err
	}
	ports := []int{}
	for i := minPort; i <= maxPort; i++ {
		ports = append(ports, i)
	}
	return ports, nil
}

// GetFrameworkServerAddrs is the addresses a server listens on for the
// benchmark: every interface, one address per port.
func GetFrameworkServerAddrs(framework string) ([]string, error) {
	ports, err := GetFrameworkBenchmarkPorts(framework)
	if err != nil {
		return nil, err
	}
	addrs := make([]string, 0, len(ports))
	for _, port := range ports {
		addrs = append(addrs, fmt.Sprintf(":%d", port))
	}
	return addrs, nil
}

// GetFrameworkControlServerAddr is the address a server's control routes -
// /init, /ps and the pprof ones - listen on: the port after its last
// benchmark port. Every framework serves them there, in plaintext, on a
// net/http server of its own, so that the routes a client reads its resource
// columns from are the same code for all of them and never queue behind
// benchmark traffic, and so that the benchmark ports carry nothing but TLS.
func GetFrameworkControlServerAddr(framework string) (string, error) {
	port, err := frameworkControlPort(framework)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(":%d", port), nil
}

// urlHost brackets a bare IPv6 literal so that it can carry a port in a URL.
// BENCH_SERVER_HOST may be an address or a hostname.
func urlHost(ip string) string {
	if strings.Contains(ip, ":") && !strings.HasPrefix(ip, "[") {
		return "[" + ip + "]"
	}
	return ip
}

// GetFrameworkBenchmarkAddrs is the host:port a client dials for each of the
// framework's benchmark ports.
func GetFrameworkBenchmarkAddrs(framework, ip string) ([]string, error) {
	ports, err := GetFrameworkBenchmarkPorts(framework)
	if err != nil {
		return nil, err
	}
	host := strings.Trim(ip, "[]")
	addrs := make([]string, 0, len(ports))
	for _, port := range ports {
		addrs = append(addrs, net.JoinHostPort(host, strconv.Itoa(port)))
	}
	return addrs, nil
}

// Control requests - /init and /ps - go to a port of their own, but they
// still arrive at a process that may be working through the backlog of a
// just-finished rate test with a hundred thousand connections, which can make
// it slow to accept or to answer. So retry, patiently, and say what failed
// when it still does.
const (
	controlAttempts = 4
	controlTimeout  = 30 * time.Second
	controlBackoff  = 2 * time.Second
)

// One client for every control request, so a retry can reuse a connection the
// server has already accepted.
var controlClient = &http.Client{Timeout: controlTimeout}

// controlRequest sends one control request, retrying a transport failure up to
// attempts times. A reply the server actually produced is returned as it is,
// including a 404: the route is not there and waiting will not put it there.
func controlRequest(url string, body []byte, attempts int) ([]byte, error) {
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		if attempt > 1 {
			time.Sleep(time.Duration(attempt-1) * controlBackoff)
		}
		data, answered, err := controlOnce(url, body)
		if err == nil {
			return data, nil
		}
		lastErr = fmt.Errorf("%v: %w", url, err)
		if answered {
			break
		}
		if attempt < attempts {
			logging.Printf("control request failed, retrying (%d/%d): %v", attempt, attempts, lastErr)
		}
	}
	return nil, lastErr
}

// controlOnce reports whether the server answered at all, so that the caller
// can tell a route that is missing from a server that is too busy to reply.
func controlOnce(url string, body []byte) (data []byte, answered bool, err error) {
	var res *http.Response
	if body == nil {
		res, err = controlClient.Get(url)
	} else {
		res, err = controlClient.Post(url, "", bytes.NewReader(body))
	}
	if err != nil {
		return nil, false, err
	}
	defer res.Body.Close()
	data, err = io.ReadAll(res.Body)
	if err != nil {
		return nil, false, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, true, fmt.Errorf("%v: %s", res.Status, bytes.TrimSpace(data))
	}
	return data, true, nil
}

// frameworkControlPort is the port a framework's control routes listen on:
// the one after its last benchmark port.
func frameworkControlPort(framework string) (int, error) {
	ports, err := GetFrameworkBenchmarkPorts(framework)
	if err != nil {
		return 0, err
	}
	return ports[len(ports)-1] + 1, nil
}

// FrameworkControlAddr is the base URL of those routes, as a client reaches
// them.
func FrameworkControlAddr(framework, ip string) (string, error) {
	port, err := frameworkControlPort(framework)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("http://%v:%v", urlHost(ip), port), nil
}

func InitAndGetFrameworkPid(framework, ip string, args *InitArgs) (int, string, error) {
	pprofAddr, err := FrameworkControlAddr(framework, ip)
	if err != nil {
		return -1, "", err
	}
	serverAddr := pprofAddr + "/init"

	data, _ := json.Marshal(args)
	// A failed /init is not just a missing pid: it is a server that never
	// started sampling, so every CPU and MEM column of the run would be 0.
	body, err := controlRequest(serverAddr, data, controlAttempts)
	if err != nil {
		return -1, "", err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(body)))

	return pid, pprofAddr, err
}

// GetFrameworkPsInfo reads the server's CPU and memory samples. It returns
// the counter it managed to read alongside an error as well as instead of
// one, so that samples which did arrive are still reported: an error here
// means the resource columns are incomplete, not that they are all missing.
func GetFrameworkPsInfo(framework, ip string) (*perf.PSCounter, error) {
	controlAddr, err := FrameworkControlAddr(framework, ip)
	if err != nil {
		return nil, err
	}
	serverAddr := controlAddr + "/ps"

	body, err := controlRequest(serverAddr, nil, controlAttempts)
	if err != nil {
		return nil, err
	}

	psCounter := &perf.PSCounter{}
	err = json.Unmarshal(body, psCounter)
	if err != nil {
		return nil, fmt.Errorf("%v: %w", serverAddr, err)
	}
	if psCounter.CPUAvg() <= 0 {
		// The request went through, so the sampler is what did not: either
		// /init never reached this server, or nothing has been sampled yet
		// because the phase was shorter than one -pi interval.
		return psCounter, fmt.Errorf("%v: answered with no CPU samples, so either /init did not"+
			" reach it or the phase was shorter than the -pi sampling interval", serverAddr)
	}

	return psCounter, nil
}

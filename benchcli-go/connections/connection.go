package connections

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"go-tls-benchmark/benchcli-go/report"
	"go-tls-benchmark/certs"
	"go-tls-benchmark/config"
	"go-tls-benchmark/logging"

	"github.com/lesismal/perf"
)

// Conn is one TLS connection to the server. Only one goroutine reads a Conn
// at a time: the echo benchmark hands a Conn to one worker at a time, and the
// rate benchmark gives each one a reader goroutine of its own, while writers
// write it from another, which crypto/tls allows.
type Conn struct {
	*tls.Conn
	Addr string

	// Broken is set once a round trip on the connection has failed. A failed
	// one leaves the stream at an unknown point, so the connection cannot
	// carry another; Redial replaces it.
	Broken bool

	cs *Connections
}

// Redial replaces a broken connection with a new one to the same address.
func (c *Conn) Redial() error {
	c.Conn.Close()
	conn, err := c.cs.dial(c.Addr)
	if err != nil {
		return err
	}
	c.Conn = conn
	c.Broken = false
	return nil
}

type Connections struct {
	Framework      string
	Ip             string
	Concurrency    int
	NumConnections int
	DialTimeout    time.Duration
	RetryInterval  time.Duration
	RetryTimes     int
	EnalbeTPN      bool
	Percents       []int
	// NoDelay is the TCP_NODELAY every connection is set to once dialed.
	NoDelay bool
	// TLSVersion is the only version the client offers.
	TLSVersion uint16
	// Where the CPU and MEM columns come from; see config.SetupPS. A full
	// handshake is mostly CPU, the certificate key's signature above all, so
	// this phase is sampled like the others.
	PsSource config.PSSource

	// Params is what the first handshake negotiated, as the reports' Summary
	// shows it: the servers pick the certificate, and crypto/tls on both ends
	// the rest.
	Params report.TLSParams

	// All connected connections
	conns []*Conn

	Calculator *perf.Calculator

	mux         sync.Mutex
	serverIdx   uint32
	serverAddrs []string
	tlsConfig   *tls.Config
	paramsOnce  sync.Once
}

func New(framework, ip string, numConns int) *Connections {
	return &Connections{
		Framework:      framework,
		Ip:             ip,
		NumConnections: numConns,
	}
}

// Run dials the connections, each one a TCP connection and a full TLS
// handshake on it. The client keeps no session cache, so no handshake is a
// resumption: what this measures is the rate the server completes full
// handshakes at, which for TLS is the expensive part of taking a client on.
func (cs *Connections) Run() {
	cs.init()
	defer cs.clean()

	logging.Printf("Dial Connections: [%v]", cs.NumConnections)
	logging.Printf("Dial Concurrency: [%v]", cs.Concurrency)
	done := make(chan struct{})
	logDone := make(chan struct{})

	go func() {
		defer func() {
			logging.Printf("Connections done: %v Success, %v Failed",
				atomic.LoadInt64(&cs.Calculator.Success), atomic.LoadInt64(&cs.Calculator.Failed))
			close(logDone)
		}()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for i := 1; true; i++ {
			select {
			case <-done:
				return
			case <-ticker.C:
				logging.Printf("%03d seconds passed, %v Connected ...", i, atomic.LoadInt64(&cs.Calculator.Success))
			}
		}
	}()

	logging.Printf("Connections start ...")
	if cs.PsSource != nil {
		cs.PsSource.Mark()
	}
	cs.Calculator.Benchmark(cs.Concurrency, cs.NumConnections, cs.doOnce, cs.Percents)

	close(done)
	<-logDone
	if len(cs.Calculator.FailedErrors) > 0 {
		logging.Printf("Connections errors: %v", cs.Calculator.FailedErrors)
	}
	logging.Printf("TLS: %v, %v, %v, certificate %v",
		cs.Params.Version, cs.Params.CipherSuite, cs.Params.KeyExchange, cs.Params.CertKey)
}

func (cs *Connections) Conns() []*Conn {
	return cs.conns
}

func (cs *Connections) Stop() {
	for _, c := range cs.conns {
		c.Close()
	}
}

func (cs *Connections) Report() report.Report {
	r := &report.ConnectionsReport{
		BenchClient: "benchcli-go",
		Framework:   cs.Framework,
		Lang:        config.FrameworkLang(cs.Framework),
		TPS:         cs.Calculator.TPS(),
		Min:         cs.Calculator.Min,
		Avg:         cs.Calculator.Avg,
		Max:         cs.Calculator.Max,

		Used:        int64(cs.Calculator.Used),
		Total:       cs.NumConnections,
		Success:     cs.Calculator.Success,
		Failed:      cs.Calculator.Failed,
		Concurrency: cs.Concurrency,
	}
	r.SetTLS(cs.Params)
	if cs.EnalbeTPN {
		r.TP50 = cs.Calculator.TPN(50)
		r.TP75 = cs.Calculator.TPN(75)
		r.TP90 = cs.Calculator.TPN(90)
		r.TP95 = cs.Calculator.TPN(95)
		r.TP99 = cs.Calculator.TPN(99)
	}
	if cs.PsSource != nil {
		counter, err := cs.PsSource.PsInfo()
		if err != nil {
			logging.Printf("Connections: resource statistics for %v incomplete, CPU EER and MEM EER will read 0: %v",
				cs.Framework, err)
		}
		if counter != nil {
			r.CPUMin = counter.CPUMin()
			r.CPUAvg = counter.CPUAvg()
			r.CPUMax = counter.CPUMax()
			r.MEMRSSMin = counter.MEMRSSMin()
			r.MEMRSSAvg = counter.MEMRSSAvg()
			r.MEMRSSMax = counter.MEMRSSMax()
			r.CPUEER = report.CPUEER(float64(r.TPS), r.CPUAvg)
			r.MEMEER = report.MEMEER(float64(r.TPS), r.MEMRSSAvg)
		}
	}
	return r
}

func (cs *Connections) init() {
	if cs.NumConnections <= 0 {
		cs.NumConnections = 1000
	}
	if cs.Concurrency <= 0 {
		cs.Concurrency = runtime.NumCPU() * 1000
	}
	if cs.Concurrency > cs.NumConnections {
		cs.Concurrency = cs.NumConnections
	}
	if cs.DialTimeout <= 0 {
		cs.DialTimeout = time.Second * 1
	}
	if cs.RetryInterval <= 0 {
		cs.RetryInterval = time.Second / 10
	}
	if cs.RetryTimes <= 0 {
		cs.RetryTimes = 3
	}
	if cs.TLSVersion == 0 {
		cs.TLSVersion = tls.VersionTLS13
	}
	if cs.EnalbeTPN {
		cs.Percents = []int{50, 75, 90, 95, 99}
	}
	cs.Params = report.TLSParams{Version: "-", CipherSuite: "-", KeyExchange: "-", CertKey: "-"}

	cs.Calculator = perf.NewCalculator(fmt.Sprintf("%v-Connect", cs.Framework))

	addrs, err := config.GetFrameworkBenchmarkAddrs(cs.Framework, cs.Ip)
	if err != nil {
		logging.Fatalf("GetFrameworkBenchmarkAddrs(%v) failed: %v", cs.Framework, err)
	}
	cs.serverAddrs = addrs
	cs.tlsConfig = &tls.Config{
		ServerName: config.ServerName,
		// See package certs: the server's side of the handshake is what is
		// measured, and the client verifying a self-signed chain would only
		// take CPU from it on a single-node run.
		InsecureSkipVerify: true,
		MinVersion:         cs.TLSVersion,
		MaxVersion:         cs.TLSVersion,
		// No ClientSessionCache, so every handshake is a full one.
	}
	cs.conns = make([]*Conn, 0, cs.NumConnections)
}

func (cs *Connections) clean() {
	cs.serverAddrs = nil
}

// dial connects to addr and completes a TLS handshake on the connection.
func (cs *Connections) dial(addr string) (*tls.Conn, error) {
	dialer := &net.Dialer{Timeout: cs.DialTimeout}
	raw, err := dialer.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	if tc, ok := raw.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(cs.NoDelay)
	}
	conn := tls.Client(raw, cs.tlsConfig)
	ctx, cancel := context.WithTimeout(context.Background(), cs.DialTimeout)
	err = conn.HandshakeContext(ctx)
	cancel()
	if err != nil {
		raw.Close()
		return nil, err
	}
	cs.paramsOnce.Do(func() {
		state := conn.ConnectionState()
		cs.Params = report.TLSParams{
			Version:     tls.VersionName(state.Version),
			CipherSuite: tls.CipherSuiteName(state.CipherSuite),
			KeyExchange: state.CurveID.String(),
			CertKey:     "-",
		}
		if len(state.PeerCertificates) > 0 {
			cs.Params.CertKey = certs.KeyName(state.PeerCertificates[0])
		}
	})
	return conn, nil
}

// doOnce dials one connection, retrying on failure.
func (cs *Connections) doOnce() error {
	var err error
	for i := 0; i < cs.RetryTimes; i++ {
		if i > 0 {
			time.Sleep(cs.RetryInterval)
		}
		addr := cs.serverAddrs[atomic.AddUint32(&cs.serverIdx, 1)%uint32(len(cs.serverAddrs))]
		var conn *tls.Conn
		conn, err = cs.dial(addr)
		if err == nil {
			c := &Conn{Conn: conn, Addr: addr, cs: cs}
			cs.mux.Lock()
			cs.conns = append(cs.conns, c)
			cs.mux.Unlock()
			return nil
		}
	}
	return err
}

package benchpipeline

import (
	"context"
	"crypto/rand"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"go-tls-benchmark/benchcli-go/connections"
	"go-tls-benchmark/benchcli-go/protocol"
	"go-tls-benchmark/benchcli-go/report"
	"go-tls-benchmark/config"
	"go-tls-benchmark/logging"

	"github.com/lesismal/perf"
	"golang.org/x/time/rate"
)

// BenchPipeline is echo at a rate the client sets: every connection is sent
// SendRate messages a second, written a batch at a time without waiting for
// the echoes of the ones before, and a goroutine per connection reads the
// echoes back as they come. A connection with more than a few batches
// unanswered is skipped until the server catches up, so a server slower than
// the rate is measured by what it answered rather than by how deep a queue
// the client could build in front of it.
//
// A batch is one Write, so crypto/tls seals it into as few records as it
// fits in: one, at the default -rbs of 16KB, which is a record's largest.
type BenchPipeline struct {
	Framework   string
	Ip          string
	Duration    time.Duration
	Concurrency int
	SendRate    int
	BatchSize   int
	// Pipeline is how many messages go into one write, or 0 for as many as
	// fit in BatchSize bytes and divide SendRate.
	Pipeline   int
	Payload    int
	SendLimit  int
	PsInterval time.Duration
	TLS        report.TLSParams

	ServerPid int
	PsCounter *perf.PSCounter
	// Where the CPU and MEM columns come from; see config.SetupPS.
	PsSource config.PSSource

	Conns []*connections.Conn

	wbuffer []byte

	limitFn    func()
	checkValid bool

	batch       int
	batchBuffer []byte
	tickRate    int

	sendTimes int64
	sendBytes int64
	recvTimes int64
	recvBytes int64

	onBenchmark  func()
	pprofDataCPU []byte
	pprofDataMEM []byte
}

type conn struct {
	*connections.Conn
	sendCnt int64
	recvCnt int64
}

// maxBatchesInFlight is how many batches a connection may have unanswered
// before it is skipped for a tick.
const maxBatchesInFlight = 4

func New(framework string, serverPid int, ip string, conns []*connections.Conn, checkValid bool) *BenchPipeline {
	return &BenchPipeline{
		Framework:  framework,
		Ip:         ip,
		Conns:      conns,
		limitFn:    func() {},
		checkValid: checkValid,
		ServerPid:  serverPid,
	}
}

func (br *BenchPipeline) Run() {
	br.init()
	defer br.clean()

	conns := make([]*conn, 0, len(br.Conns))
	for _, c := range br.Conns {
		if c.Broken {
			if err := c.Redial(); err != nil {
				logging.Printf("%v: redial %v failed, leaving the connection out: %v", report.BenchPipelineName, c.Addr, err)
				continue
			}
		}
		conns = append(conns, &conn{Conn: c})
	}

	connTeams := make([][]*conn, br.Concurrency)
	for i, c := range conns {
		connTeams[i%len(connTeams)] = append(connTeams[i%len(connTeams)], c)
	}

	logging.Printf("%v for %.2f seconds, %d messages per write ...", report.BenchPipelineName, br.Duration.Seconds(), br.batch)

	readers := sync.WaitGroup{}
	for _, c := range conns {
		readers.Add(1)
		go func() {
			defer readers.Done()
			br.readEchoes(c)
		}()
	}

	if br.onBenchmark != nil {
		br.onBenchmark()
	}
	if br.PsSource != nil {
		br.PsSource.Mark()
	}

	// Every writer writes its batches on exactly the ticks the duration holds,
	// the last of them right at its end. Stopping on a timer set for the
	// duration instead raced that last tick, and a run lost it on a random
	// share of its writers - up to one tick's worth of the whole rate. done
	// is only the backstop for a writer that has fallen behind, half a tick
	// after the last one was due.
	interval := time.Second / time.Duration(br.tickRate)
	ticks := int(br.Duration / interval)
	done := make(chan struct{})
	time.AfterFunc(br.Duration+interval/2, func() {
		close(done)
	})

	writers := sync.WaitGroup{}
	for _, team := range connTeams {
		writers.Add(1)
		go func() {
			defer writers.Done()
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for i := 0; i < ticks; i++ {
				select {
				case <-done:
					return
				case <-ticker.C:
					br.doOnce(team)
				}
			}
		}()
	}
	writers.Wait()

	// The last batch written is still on its way back when the duration is
	// up. Give the server one tick more to answer what it was sent, which is
	// how long it would have had before the next batch, and no longer: a
	// server slower than the rate is measured by what it answered in time,
	// not by how long it took to drain. Then snapshot the counters and
	// unblock the readers.
	grace := time.NewTimer(interval)
	for atomic.LoadInt64(&br.recvTimes) < atomic.LoadInt64(&br.sendTimes) {
		select {
		case <-grace.C:
			goto snapshot
		case <-time.After(time.Millisecond):
		}
	}
	grace.Stop()
snapshot:
	recvTimes, recvBytes := atomic.LoadInt64(&br.recvTimes), atomic.LoadInt64(&br.recvBytes)
	for _, c := range conns {
		c.SetReadDeadline(time.Now())
	}
	readers.Wait()
	br.recvTimes, br.recvBytes = recvTimes, recvBytes

	logging.Printf("%v for %.2f seconds done", report.BenchPipelineName, br.Duration.Seconds())
}

func (br *BenchPipeline) Stop() {

}

func (br *BenchPipeline) OnBenchmark(f func()) {
	br.onBenchmark = f
}

func (br *BenchPipeline) SetPprofData(cpu, mem []byte) {
	br.pprofDataCPU = cpu
	br.pprofDataMEM = mem
}

func (br *BenchPipeline) Report() *report.BenchRateReport {
	r := &report.BenchRateReport{
		BenchClient: "benchcli-go",
		Framework:   br.Framework,
		Lang:        config.FrameworkLang(br.Framework),
		Duration:    br.Duration.Nanoseconds(),
		Connections: len(br.Conns),
		Concurrency: br.Concurrency,
		SendRate:    br.SendRate,
		Pipeline:    br.batch,
		Payload:     br.Payload,
		SendTimes:   br.sendTimes,
		SendBytes:   br.sendBytes,
		RecvTimes:   br.recvTimes,
		RecvBytes:   br.recvBytes,
	}
	r.SetTLS(br.TLS)
	r.SetPprofData(br.pprofDataCPU, br.pprofDataMEM)
	var psErr error
	br.PsCounter, psErr = br.psInfo()
	if psErr != nil {
		logging.Printf("%v: resource statistics for %v incomplete, CPU EER and MEM EER will read 0: %v",
			report.BenchPipelineName, br.Framework, psErr)
	}
	if br.PsCounter != nil {
		r.CPUMin = br.PsCounter.CPUMin()
		r.CPUAvg = br.PsCounter.CPUAvg()
		r.CPUMax = br.PsCounter.CPUMax()
		r.MEMRSSMin = br.PsCounter.MEMRSSMin()
		r.MEMRSSAvg = br.PsCounter.MEMRSSAvg()
		r.MEMRSSMax = br.PsCounter.MEMRSSMax()
		tps := report.RateTPS(r.RecvTimes, r.Duration)
		r.CPUEER = report.CPUEER(tps, r.CPUAvg)
		r.MEMEER = report.MEMEER(tps, r.MEMRSSAvg)
	}
	r.TPS = int64(math.Floor(report.RateTPS(r.RecvTimes, r.Duration)))
	return r
}

// psInfo reads the server's resource samples from wherever this run takes
// them; see BenchEcho.psInfo.
func (br *BenchPipeline) psInfo() (*perf.PSCounter, error) {
	if br.PsSource != nil {
		return br.PsSource.PsInfo()
	}
	return config.GetFrameworkPsInfo(br.Framework, br.Ip)
}

func (br *BenchPipeline) init() {
	if br.Duration <= 0 {
		br.Duration = time.Second * 10
	}
	if br.Concurrency <= 0 {
		br.Concurrency = 50000
	}
	if br.Concurrency > len(br.Conns) {
		br.Concurrency = len(br.Conns)
	}
	if br.Concurrency <= 0 {
		logging.Fatalf("%v: no connections to run on", report.BenchPipelineName)
	}
	if br.SendRate <= 0 {
		br.SendRate = 1
	}
	if br.Payload <= 0 {
		br.Payload = 1024
	}

	br.wbuffer = make([]byte, br.Payload)
	rand.Read(br.wbuffer)
	if err := protocol.ValidatePipeline(br.Pipeline, br.SendRate); err != nil {
		logging.Fatalf("%v: %v", report.BenchPipelineName, err)
	}
	if br.Pipeline > 0 {
		br.batchBuffer, br.batch, br.tickRate = protocol.PipelineBuffers(br.wbuffer, br.SendRate, br.Pipeline)
	} else {
		br.batchBuffer, br.batch, br.tickRate = protocol.BatchBuffers(br.wbuffer, br.SendRate, br.BatchSize)
	}
	if br.tickRate <= 0 || len(br.batchBuffer) == 0 {
		logging.Fatalf("%v got a wrong tickRate: %v, or batchBuffer: %v", report.BenchPipelineName, br.tickRate, len(br.batchBuffer))
	}

	if br.PsInterval <= 0 {
		br.PsInterval = time.Second
	}

	if br.SendLimit > 0 {
		limiter := rate.NewLimiter(rate.Every(1*time.Second), br.SendLimit)
		br.limitFn = func() {
			limiter.WaitN(context.Background(), br.batch)
		}
	}
}

func (br *BenchPipeline) clean() {
	br.limitFn = func() {}
}

func (br *BenchPipeline) doOnce(conns []*conn) {
	for _, c := range conns {
		if atomic.LoadInt64(&c.sendCnt)-atomic.LoadInt64(&c.recvCnt) >= int64(br.batch*maxBatchesInFlight) {
			continue
		}
		br.limitFn()
		if _, err := c.Write(br.batchBuffer); err == nil {
			atomic.AddInt64(&br.sendTimes, int64(br.batch))
			atomic.AddInt64(&br.sendBytes, int64(br.batch*br.Payload))
			atomic.AddInt64(&c.sendCnt, int64(br.batch))
		}
	}
}

// readEchoes counts the echoes on one connection until it fails, which is how
// the run ends it: Run sets a read deadline once the duration is up. The
// stream is the messages back to back with nothing between them, so an echo
// is counted once its last byte has arrived, whatever records it came in.
func (br *BenchPipeline) readEchoes(c *conn) {
	buf := make([]byte, 16<<10)
	// How far into the message at the front of the stream the bytes read so
	// far have got.
	offset := 0
	for {
		n, err := c.Read(buf)
		if n > 0 {
			data := buf[:n]
			if br.checkValid && !protocol.MatchesRepeated(data, br.wbuffer, offset) {
				c.Broken = true
				logging.Printf("%v: %v echoed bytes that were not sent, leaving the connection out",
					report.BenchPipelineName, c.Addr)
				return
			}
			offset += n
			if msgs := offset / br.Payload; msgs > 0 {
				offset -= msgs * br.Payload
				atomic.AddInt64(&c.recvCnt, int64(msgs))
				atomic.AddInt64(&br.recvTimes, int64(msgs))
				atomic.AddInt64(&br.recvBytes, int64(msgs*br.Payload))
			}
		}
		if err != nil {
			c.Broken = true
			return
		}
	}
}

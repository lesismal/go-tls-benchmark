package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime/debug"
	"time"

	"go-tls-benchmark/benchcli-go/benchecho"
	"go-tls-benchmark/benchcli-go/benchpipeline"
	"go-tls-benchmark/benchcli-go/connections"
	"go-tls-benchmark/benchcli-go/protocol"
	"go-tls-benchmark/benchcli-go/report"
	"go-tls-benchmark/config"
	"go-tls-benchmark/logging"
)

var (
	nodelay = flag.Bool("nodelay", true, `tcp nodelay`)

	// The servers' flags, which script/benchmark.sh hands both sides: the
	// client has no use for them, and defines them so that one command line
	// works for both.
	_ = flag.Bool("reuseport", true, `server only: reuse port`)
	_ = flag.String("key", config.DefaultKey, `server only: certificate key; the client reports the one it is served`)

	// Client Proc
	memLimit = flag.Int64("m", 1024*1024*1024*4, `memory limit`)

	// Server Side
	framework = flag.String("f", "stdtls-tls13", `framework: the variant to benchmark, e.g. "fib-tls13", whose TLS version is the only one the client offers`)
	ip        = flag.String("ip", "127.0.0.1", `ip, e.g. "127.0.0.1"`)

	// Connection
	numConnections    = flag.Int("c", 10000, "client: num of connections")
	dialConcurrency   = flag.Int("dc", 2000, "client: dial concurrency: how many goroutines used to do dialing")
	dialTimeout       = flag.Duration("dt", 5*time.Second, "client: dial timeout, which also bounds the TLS handshake")
	dialRetries       = flag.Int("dr", 5, "client: dial retry times")
	dialRetryInterval = flag.Duration("dri", 100*time.Millisecond, "client; dial retry interval")

	// BenchEcho && BenchPipeline
	payload    = flag.Int("b", 1024, `benchmark: message size of benchecho and benchpipeline, which the server echoes back`)
	checkValid = flag.Bool("check", false, `benchmark: whether to check the validity of the response data`)
	psInterval = flag.Int("pi", 1000, `benchmark: ps interval of every benchmark, 1000 ms by default`)
	psMode     = flag.String("ps", config.PSModeAuto, `benchmark: where the server's CPU and MEM samples come from: `+
		`"auto" samples the server here when it runs on this machine and asks it over HTTP when it does not, `+
		`"local" always samples here, "remote" always asks`)
	enableTPN = flag.Bool("tpn", true, `benchmark: whether enable TPN caculation`)

	// BenchEcho
	echoConcurrency   = flag.Int("ec", 10000, "benchecho: concurrency: how many goroutines used to do the echo test")
	echoTimes         = flag.Int("en", 2000000, `benchecho: benchmark times`)
	echoTPSLimit      = flag.Int("el", 0, `benchecho: TPS limitation per second`)
	echoPprof         = flag.Bool("ep", false, `benchecho: generate pprof report`)
	echoPprofDuration = flag.Int("epd", 5, `benchecho: pprof duration`)

	// BenchPipeline
	rateEnabled       = flag.Bool("rate", false, `benchpipeline: whether run benchpipeline`)
	rateConcurrency   = flag.Int("rc", 10000, "benchpipeline: concurrency: how many goroutines used to write the pipelined messages")
	rateDuration      = flag.Int("rd", 10, `benchpipeline: how long to spend to do the test`)
	rateSendRate      = flag.Int("rr", 200, "benchpipeline: how many messages can be sent to 1 conn every second")
	rateBatchSize     = flag.Int("rbs", 1024*16, "benchpipeline: how many bytes of pipelined messages can be written to 1 conn every time, when -rpl is 0")
	ratePipeline      = flag.Int("rpl", 0, "benchpipeline: how many messages are merged into one write to 1 conn, which must divide -rr; 0 takes as many as fit in -rbs bytes")
	rateSendLimit     = flag.Int("rl", 0, `benchpipeline: message sending limitation per second`)
	ratePprof         = flag.Bool("rp", false, `benchpipeline: generate pprof report`)
	ratePprofDuration = flag.Int("rpd", 5, `benchpipeline: pprof duration`)

	// for report generation
	genReport  = flag.Bool("r", false, `make report`)
	preffix    = flag.String("preffix", "", `report file preffix, e.g. "1m_connections_"`)
	suffix     = flag.String("suffix", "", `report file suffix, e.g. "_20060102150405"`)
	reportSort = flag.String("sort", report.DefaultSort, `report row order: "result" ranks the best result first, "framework" keeps the framework order`)
)

func main() {
	wd, _ := os.Getwd()
	logging.Println("pwd:", wd)

	flag.Parse()

	report.Init(*enableTPN)

	// Checked even when no report is being generated, so that a run started
	// with a misspelled -sort fails before it spends the benchmark rather
	// than after.
	if err := report.ValidateSort(*reportSort); err != nil {
		logging.Fatalf("%v", err)
	}
	if err := config.ValidatePSMode(*psMode); err != nil {
		logging.Fatalf("%v", err)
	}

	if *genReport {
		generateReports()
		return
	}

	// Checked before the connections are dialed, for the same reason as -sort.
	if *rateEnabled {
		if err := protocol.ValidatePipeline(*ratePipeline, max(*rateSendRate, 1)); err != nil {
			logging.Fatalf("-rpl=%v: %v", *ratePipeline, err)
		}
	}

	if _, err := config.GetFrameworkBenchmarkPorts(*framework); err != nil {
		logging.Fatalf("-f=%v: %v, want one of %v", *framework, err, config.FrameworkList)
	}
	version, err := config.ParseTLSVersion(config.FrameworkVersion(*framework))
	if err != nil {
		logging.Fatalf("-f=%v: %v", *framework, err)
	}

	debug.SetMemoryLimit(*memLimit)

	logging.Print(logging.LongLine)
	defer logging.Print(logging.LongLine)

	logging.Printf("Benchmark [%v]: %v connections, %v payload, %v times", *framework, *numConnections, *payload, *echoTimes)
	logging.Print(logging.ShortLine)

	// How the server's CPU and MEM - and so CPU EER and MEM EER - are sampled,
	// settled before the connections are dialed so that the handshakes are
	// sampled too; each benchmark then marks where its own phase starts. On a
	// run whose server is on this machine the client samples the process
	// itself and the server is never asked; see config.SetupPS.
	psSetup, psErr := config.SetupPS(*framework, *ip, *psMode, time.Millisecond*time.Duration(*psInterval))
	defer psSetup.Source.Stop()
	serverPid, pprofAddr := psSetup.ServerPid, psSetup.PprofAddr
	if psErr != nil {
		logging.Printf("SetupPS(%v) failed: %v", *framework, psErr)
	}

	cs := connections.New(*framework, *ip, *numConnections)
	cs.Concurrency = *dialConcurrency
	cs.DialTimeout = *dialTimeout
	cs.RetryTimes = *dialRetries
	cs.RetryInterval = *dialRetryInterval
	cs.EnalbeTPN = *enableTPN
	cs.NoDelay = *nodelay
	cs.TLSVersion = version
	cs.PsSource = psSetup.Source
	cs.Run()
	defer cs.Stop()
	csReport := cs.Report()
	saveReport(csReport)
	logging.Print(logging.ShortLine)
	logging.Print(csReport.String(*enableTPN))
	logging.Print("\n")
	logging.Print(logging.ShortLine)

	cpuProfileUrlEcho := ""
	cpuProfileUrlRate := ""
	memProfileUrl := ""
	// Only a Go server serves /debug/pprof/; any other is not asked for a
	// profile at all, rather than asked and logged as failing every run.
	hasPprof := config.HasPprof(*framework)
	if !hasPprof {
		logging.Printf("%v: %v server, no /debug/pprof/, pprof profiles are not fetched",
			*framework, config.FrameworkLang(*framework))
		logging.Print(logging.ShortLine)
	}
	if hasPprof && pprofAddr != "" {
		cpuProfileUrl := pprofAddr + "/debug/pprof/profile"
		cpuProfileUrlEcho = cpuProfileUrl + fmt.Sprintf("?seconds=%v", *echoPprofDuration)
		cpuProfileUrlRate = cpuProfileUrl + fmt.Sprintf("?seconds=%v", *ratePprofDuration)
		fmt.Printf("pprof cpu :\n  curl --output ./cpu_profile %v\n", cpuProfileUrl)
		fmt.Printf("  go tool pprof -http=:6060 ./cpu_profile\n")
		memProfileUrl = pprofAddr + "/debug/pprof/heap"
		fmt.Printf("pprof heap:\n  curl --output ./mem_profile %v\n", memProfileUrl)
		fmt.Printf("  go tool pprof -http=:6061 ./mem_profile\n")
		logging.Print(logging.ShortLine)
	}
	be := benchecho.New(*framework, serverPid, *echoTimes, *ip, cs.Conns(), *checkValid)
	be.PsSource = psSetup.Source
	be.Concurrency = *echoConcurrency
	be.Payload = *payload
	be.Total = *echoTimes
	be.Limit = *echoTPSLimit
	be.EnalbeTPN = *enableTPN
	be.TLS = cs.Params
	if *echoPprof && hasPprof {
		be.OnWarmup(func() {
			time.AfterFunc(time.Second*2, func() {
				cpu, err := httpGet(cpuProfileUrlEcho)
				if err != nil {
					fmt.Printf("BenchEcho: [pprof cpu] httpGet failed: %v\n", err)
					return
				}

				mem, err := httpGet(memProfileUrl)
				if err != nil {
					fmt.Printf("BenchEcho: [pprof mem] httpGet failed: %v\n", err)
					return
				}
				be.SetPprofData(cpu, mem)
			})
		})
	}
	be.Run()
	defer be.Stop()
	beReport := be.Report()
	beReport.Pprof = *echoPprof
	saveReport(beReport)
	logging.Print(logging.ShortLine)
	logging.Print(beReport.String(*enableTPN))
	logging.Print("\n")
	logging.Print(logging.ShortLine)

	if *rateEnabled {
		br := benchpipeline.New(*framework, serverPid, *ip, cs.Conns(), *checkValid)
		br.PsSource = psSetup.Source
		br.Concurrency = *rateConcurrency
		br.Duration = time.Second * time.Duration(*rateDuration)
		br.SendRate = *rateSendRate
		br.BatchSize = *rateBatchSize
		br.Pipeline = *ratePipeline
		br.Payload = *payload
		br.SendLimit = *rateSendLimit
		br.TLS = cs.Params
		if *ratePprof && hasPprof {
			br.OnBenchmark(func() {
				time.AfterFunc(time.Second*2, func() {
					cpu, err := httpGet(cpuProfileUrlRate)
					if err != nil {
						fmt.Printf("%v: [pprof cpu] httpGet failed: %v\n", report.BenchPipelineName, err)
						return
					}

					mem, err := httpGet(memProfileUrl)
					if err != nil {
						fmt.Printf("%v: [pprof mem] httpGet failed: %v\n", report.BenchPipelineName, err)
						return
					}
					br.SetPprofData(cpu, mem)
				})
			})
		}
		br.Run()
		defer br.Stop()
		brReport := br.Report()
		brReport.Pprof = *ratePprof
		saveReport(brReport)
		logging.Print(logging.ShortLine)
		logging.Print(brReport.String(*enableTPN))
		logging.Print("\n")
		logging.Print(logging.ShortLine)
	}
}

// saveReport writes one report and says so when it cannot, rather than
// letting a row go missing from the report files without a word in the log.
func saveReport(r report.Report) {
	if err := report.ToFile(r, *preffix, *suffix); err != nil {
		logging.Printf("%v: writing the %v report failed: %v", r.Name(), r.Type(), err)
	}
}

// generateReports writes the Summary table and the three report tables, each
// to its own .md file and to the console, where each one gets a rule above it
// and its name, and a blank line on either side of its table.
func generateReports() {
	sections := []struct{ name, data string }{
		{"Summary", report.GenerateSummary(*preffix, *suffix)},
		{"Connections", report.GenerateConnectionsReports(*preffix, *suffix, *enableTPN, *reportSort, nil)},
		{"BenchEcho", report.GenerateBenchEchoReports(*preffix, *suffix, *enableTPN, *reportSort, nil)},
		{report.BenchPipelineName, report.GenerateBenchRateReports(*preffix, *suffix, *enableTPN, *reportSort, nil)},
	}
	for _, section := range sections {
		filename := report.Filename(section.name, *preffix, *suffix+".md")
		if err := report.WriteFile(filename, section.data); err != nil {
			logging.Printf("writing %v failed: %v", filename, err)
		}
		logging.Print(report.ConsoleSection(*preffix+section.name+*suffix, section.data))
	}
	logging.Print(logging.LongLine)
}

func httpGet(url string) ([]byte, error) {
	res, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%v: %v", url, res.Status)
	}
	return io.ReadAll(res.Body)
}

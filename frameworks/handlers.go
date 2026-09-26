package frameworks

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/pprof"
	"os"
	"sync/atomic"
	"time"

	"go-tls-benchmark/config"
	"go-tls-benchmark/logging"

	"github.com/lesismal/perf"
)

var (
	psCounter *perf.PSCounter
	psStarted atomic.Bool
)

// HandleCommon registers the control routes: pprof, /init, which starts the
// server sampling its own CPU and memory and answers with its pid, and /ps,
// which answers with those samples.
func HandleCommon(mux *http.ServeMux) {
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	var err error
	psCounter, err = perf.NewPSCounter(os.Getpid())
	if err != nil {
		logging.Fatalf("perf.NewPSCounter failed: %v", err)
	}

	mux.HandleFunc("/init", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var args config.InitArgs
		json.Unmarshal(body, &args)
		// Once, however many times /init arrives: a client that retried the
		// request because its own read failed can deliver it twice, and a
		// second Start would reset the sample slices under the goroutines
		// already appending to them.
		if psStarted.CompareAndSwap(false, true) {
			go func() {
				psCounter.Start(perf.PSCountOptions{
					CountCPU: true,
					CountMEM: true,
					CountIO:  true,
					CountNET: true,
					Interval: args.PsInterval,
				})
				time.Sleep(args.PsInterval)
			}()
		} else {
			logging.Printf("/init called again; the ps counter is already running")
		}

		fmt.Fprintf(w, "%d", os.Getpid())
	})

	mux.HandleFunc("/ps", func(w http.ResponseWriter, r *http.Request) {
		b, _ := json.Marshal(psCounter)
		w.Write(b)
	})
}

package report

import "fmt"

var (
	ConnectionsReportMarkdownHeaders = []string{}
)

// ConnectionsReport is ranked by TPS (rank:"1"), the rate the server completed
// full TLS handshakes at, TCP connect included, which is what this benchmark
// measures. Rows with the same TPS are ranked by CPU EER (rank:"2"), the
// handshakes per second the server completed for each percent of a CPU core
// it spent, which for TLS is mostly the certificate key's signatures, and rows
// that tie on that too by MEM EER (rank:"3").
type ConnectionsReport struct {
	Framework   string  `json:"Framework" md:"Framework"`
	Lang        string  `json:"Lang" md:"Lang"`
	BenchClient string  `json:"BenchClient" md:"Client" fmt:"client" summary:"Client"`
	TLSVersion  string  `json:"TLSVersion" md:"-"`
	CipherSuite string  `json:"CipherSuite" md:"-" summary:"Cipher Suite" summaryby:"TLSVersion"`
	KeyExchange string  `json:"KeyExchange" md:"-" summary:"Key Exchange" summaryby:"TLSVersion"`
	CertKey     string  `json:"CertKey" md:"Cert Key" summary:"Cert Key"`
	TPS         int64   `json:"TPS" md:"TPS" rank:"1"`
	CPUEER      float64 `json:"CPUEER" md:"CPU EER" rank:"2"`
	MEMEER      float64 `json:"MEMEER" md:"MEM EER" rank:"3"`
	Min         int64   `json:"Min" md:"Min" fmt:"duration" tpn:"opt"`
	Avg         int64   `json:"Avg" md:"Avg" fmt:"duration" tpn:"opt"`
	Max         int64   `json:"Max" md:"Max" fmt:"duration" tpn:"opt"`
	TP50        int64   `json:"TP50" md:"-" fmt:"duration" tpn:"opt"`
	TP75        int64   `json:"TP75" md:"-" fmt:"duration" tpn:"opt"`
	TP90        int64   `json:"TP90" md:"-" fmt:"duration" tpn:"opt"`
	TP95        int64   `json:"TP95" md:"TP95" fmt:"duration" tpn:"opt"`
	TP99        int64   `json:"TP99" md:"TP99" fmt:"duration" tpn:"opt"`
	Used        int64   `json:"Used" md:"Used" fmt:"duration"`
	Total       int     `json:"Total" md:"Total"`
	Success     int64   `json:"Success" md:"Success"`
	Failed      int64   `json:"Failed" md:"Failed"`
	Concurrency int     `json:"Concurrency" md:"Concurrency" summary:"Dial Concurrency"`
	CPUMin      float64 `json:"CPUMin" md:"-" fmt:"cpu"`
	CPUAvg      float64 `json:"CPUAvg" md:"CPU Avg" fmt:"cpu"`
	CPUMax      float64 `json:"CPUMax" md:"CPU Max" fmt:"cpu"`
	MEMRSSMin   uint64  `json:"MEMMin" md:"-" fmt:"mem"`
	MEMRSSAvg   uint64  `json:"MEMAvg" md:"MEM Avg" fmt:"mem"`
	MEMRSSMax   uint64  `json:"MEMMax" md:"MEM Max" fmt:"mem"`
}

func (r *ConnectionsReport) Type() string {
	return "Connections"
}

func (r *ConnectionsReport) Name() string {
	return fmt.Sprintf("%s-Connections", r.Framework)
}

func (r *ConnectionsReport) Headers() []string {
	return ConnectionsReportMarkdownHeaders
}

func (r *ConnectionsReport) Fields(enableTPN bool) []string {
	return ObjFieldValues(r, enableTPN)
}

func (r *ConnectionsReport) PprofCPU() []byte {
	return nil
}

func (r *ConnectionsReport) PprofMEM() []byte {
	return nil
}

func (r *ConnectionsReport) String(enableTPN bool) string {
	return ObjString(r, enableTPN)
}

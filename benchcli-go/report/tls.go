package report

// TLSParams is what a run's handshakes negotiated. Every report carries it,
// as the Summary's TLS rows: they are the run's parameters as much as the
// payload is, and a handshake rate means nothing without the key it was
// signed with.
type TLSParams struct {
	Version     string
	CipherSuite string
	KeyExchange string
	CertKey     string
}

func (r *ConnectionsReport) SetTLS(p TLSParams) {
	r.TLSVersion, r.CipherSuite, r.KeyExchange, r.CertKey = p.Version, p.CipherSuite, p.KeyExchange, p.CertKey
}

func (r *BenchEchoReport) SetTLS(p TLSParams) {
	r.TLSVersion, r.CipherSuite, r.KeyExchange, r.CertKey = p.Version, p.CipherSuite, p.KeyExchange, p.CertKey
}

func (r *BenchRateReport) SetTLS(p TLSParams) {
	r.TLSVersion, r.CipherSuite, r.KeyExchange, r.CertKey = p.Version, p.CipherSuite, p.KeyExchange, p.CertKey
}

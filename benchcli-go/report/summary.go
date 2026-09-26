package report

import (
	"reflect"
	"sort"
	"strings"
)

// Project is the name of this benchmark, the first row of the Summary table,
// so that a report read on its own says which benchmark it is from.
const Project = "GO-TLS-BENCHMARK"

// SummaryParameters is the order the Summary table lists the run's parameters
// in, and what each one means: the names the report fields are tagged
// summary:"<name>" with. A tagged name missing from here still gets a row,
// after these, with no description.
var SummaryParameters = []SummaryParameter{
	{"Client", "The benchmark client the load came from"},
	{"Cipher Suite", "Cipher suite the handshakes of that TLS version negotiated"},
	{"Key Exchange", "Key exchange the handshakes of that TLS version negotiated"},
	{"Cert Key", "The servers' certificate key (-key on the servers), which signs every full handshake"},
	{"Conns", "TLS connections dialed (-c) and used by every benchmark"},
	{"Payload", "Message size in bytes (-b), which the server echoes back"},
	{"Dial Concurrency", "Connections dialed, each with a full handshake, at once in Connections (-dc)"},
	{"Echo Concurrency", "Connections with a message in flight at once in BenchEcho (-ec)"},
	{"Echo Total", "Message round trips BenchEcho makes in all (-en)"},
	{"Echo Pprof", "Go servers' pprof CPU/heap profiles fetched in BenchEcho (-ep)"},
	{"Rate Concurrency", "Goroutines writing BenchPipeline's batches, over all connections (-rc)"},
	{"Rate Duration", "How long BenchPipeline sends for (-rd)"},
	{"Rate SendRate", "Messages sent to each connection per second in BenchPipeline (-rr)"},
	{"Rate Pipeline", "Messages merged into one write per connection in BenchPipeline (-rpl)"},
	{"Rate Pprof", "Go servers' pprof CPU/heap profiles fetched in BenchPipeline (-rp)"},
}

// SummaryParameter is one row of the Summary table: the parameter's name and
// what it means.
type SummaryParameter struct {
	Name        string
	Description string
}

// summaryValue is one value a parameter took, and the frameworks it took it
// for, in the order they were read.
type summaryValue struct {
	value      string
	frameworks []string
}

// Summary is the table of the run's parameters, after the Project, taken off the summary-tagged
// fields of every row of every report. A parameter every row agrees on - the
// client, the payload, the concurrency a flag set - reads as that value. One
// the rows disagree on lists each value with the frameworks that had it:
//
//	20000 (fasthttp, fib); 19998 (nethttp)
//
// The table is left-aligned, so that a long value reads from its start.
func Summary(tables ...[]Report) string {
	values := map[string][]summaryValue{}
	var names []string
	for _, reports := range tables {
		for _, r := range reports {
			value := reflect.Indirect(reflect.ValueOf(r))
			typ := value.Type()
			framework := value.FieldByName("Framework").String()
			for i := 0; i < typ.NumField(); i++ {
				field := typ.Field(i)
				name := field.Tag.Get("summary")
				if name == "" {
					continue
				}
				// A parameter that differs with another field of the row -
				// the cipher suite with the TLS version - is one row per
				// value of that field: "Cipher Suite (TLS 1.3)".
				if by := field.Tag.Get("summaryby"); by != "" {
					qualifier := value.FieldByName(by).String()
					if qualifier == "" {
						continue
					}
					name += " (" + qualifier + ")"
				}
				if _, seen := values[name]; !seen {
					names = append(names, name)
				}
				// A report written before the field existed has nothing to
				// say about it, rather than an empty value to disagree with.
				if cell := cellString(field, value.Field(i)); cell != "" {
					values[name] = addSummaryValue(values[name], cell, framework)
				}
			}
		}
	}
	if len(names) == 0 {
		return ""
	}

	rows := [][]string{{"Project", Project, "The benchmark this run is from"}}
	for _, name := range summaryOrder(names) {
		if len(values[name]) == 0 {
			continue
		}
		rows = append(rows, []string{name, summaryString(values[name]), summaryDescription(name)})
	}
	return markdownTableAligned([]string{"Parameter", "Value", "Description"}, rows, true)
}

// summaryDescription is what SummaryParameters says a parameter means, or
// nothing for one it does not list. A qualified name, "Cipher Suite (TLS
// 1.3)", means what its parameter does.
func summaryDescription(name string) string {
	name = summaryBase(name)
	for _, p := range SummaryParameters {
		if p.Name == name {
			return p.Description
		}
	}
	return ""
}

func addSummaryValue(values []summaryValue, value, framework string) []summaryValue {
	for i := range values {
		if values[i].value == value {
			for _, f := range values[i].frameworks {
				if f == framework {
					return values
				}
			}
			values[i].frameworks = append(values[i].frameworks, framework)
			return values
		}
	}
	return append(values, summaryValue{value, []string{framework}})
}

func summaryString(values []summaryValue) string {
	if len(values) == 1 {
		return values[0].value
	}
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = v.value + " (" + strings.Join(v.frameworks, ", ") + ")"
	}
	return strings.Join(parts, "; ")
}

// summaryOrder puts names in SummaryParameters order, and any it does not
// list after them in the order they were found.
func summaryOrder(names []string) []string {
	found := map[string]bool{}
	for _, name := range names {
		found[name] = true
	}
	ordered := make([]string, 0, len(names))
	for _, p := range SummaryParameters {
		if found[p.Name] {
			ordered = append(ordered, p.Name)
			delete(found, p.Name)
		}
		// Its qualified rows, newest TLS version first, as the tables are.
		var qualified []string
		for _, name := range names {
			if found[name] && name != p.Name && summaryBase(name) == p.Name {
				qualified = append(qualified, name)
				delete(found, name)
			}
		}
		sort.Sort(sort.Reverse(sort.StringSlice(qualified)))
		ordered = append(ordered, qualified...)
	}
	for _, name := range names {
		if found[name] {
			ordered = append(ordered, name)
		}
	}
	return ordered
}

// summaryBase is the parameter a qualified Summary name is of: "Cipher Suite"
// for "Cipher Suite (TLS 1.3)".
func summaryBase(name string) string {
	if i := strings.Index(name, " ("); i > 0 && strings.HasSuffix(name, ")") {
		return name[:i]
	}
	return name
}

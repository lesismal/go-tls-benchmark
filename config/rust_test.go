package config

import (
	"os"
	"regexp"
	"strconv"
	"testing"
)

// benchcli-rustls and the rustls server cannot import this package, so each
// carries its own copy of Variants: the client every framework's, the server
// its own. They have to be this package's, row for row, or the client dials
// ports nothing listens on, labels its reports with the wrong language or
// offers the wrong version, and the server listens where no client dials.
func TestRustTablesMatch(t *testing.T) {
	client := rustRows(t, "../benchcli-rustls/src/config.rs",
		`\("([a-z0-9-]+)", "([a-z+]+)", "([0-9.]+)", (\d+), (\d+)\),`)
	if len(client) != len(Variants) {
		t.Fatalf("benchcli-rustls lists %d frameworks, Variants %d", len(client), len(Variants))
	}
	for i, row := range client {
		v := Variants[i]
		ports, _ := GetFrameworkBenchmarkPorts(v.Name)
		want := []string{v.Name, Langs[v.Name], v.Version, strconv.Itoa(ports[0]), strconv.Itoa(ports[len(ports)-1])}
		if !equalRows(row, want) {
			t.Errorf("benchcli-rustls row %d is %v, want %v", i, row, want)
		}
	}

	server := rustRows(t, "../frameworks/rustls/src/main.rs",
		`\("([a-z0-9-]+)", "([0-9.]+)", (\d+), (\d+)\),`)
	var want [][]string
	for _, v := range Variants {
		if v.Base == RustLS {
			ports, _ := GetFrameworkBenchmarkPorts(v.Name)
			want = append(want, []string{v.Name, v.Version, strconv.Itoa(ports[0]), strconv.Itoa(ports[len(ports)-1])})
		}
	}
	if len(server) != len(want) {
		t.Fatalf("the rustls server lists %d variants, Variants %d", len(server), len(want))
	}
	for i := range want {
		if !equalRows(server[i], want[i]) {
			t.Errorf("rustls server row %d is %v, want %v", i, server[i], want[i])
		}
	}
}

func rustRows(t *testing.T, path, pattern string) [][]string {
	t.Helper()
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rows [][]string
	for _, m := range regexp.MustCompile(pattern).FindAllStringSubmatch(string(src), -1) {
		rows = append(rows, m[1:])
	}
	return rows
}

func equalRows(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

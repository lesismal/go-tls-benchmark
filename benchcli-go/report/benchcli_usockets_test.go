package report

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

// benchcli-usockets writes the report files this package reads, building each
// one field by field, so every JSON name the structs here carry has to be one
// it writes - a missing one reads as zero without a word.
func TestUSocketsClientWritesEveryField(t *testing.T) {
	src, err := os.ReadFile("../../benchcli-usockets/main.cpp")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []interface{}{ConnectionsReport{}, BenchEchoReport{}, BenchRateReport{}} {
		typ := reflect.TypeOf(r)
		for i := 0; i < typ.NumField(); i++ {
			name := typ.Field(i).Tag.Get("json")
			if name == "-" || name == "" {
				continue
			}
			if !strings.Contains(string(src), `"`+name+`"`) {
				t.Errorf("%v: benchcli-usockets never writes %q", typ.Name(), name)
			}
		}
	}
}

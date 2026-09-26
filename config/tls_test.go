package config

import (
	"crypto/tls"
	"testing"
)

func TestParseTLSVersion(t *testing.T) {
	for in, want := range map[string]uint16{TLS11: tls.VersionTLS11, TLS12: tls.VersionTLS12, TLS13: tls.VersionTLS13} {
		if got, err := ParseTLSVersion(in); err != nil || got != want {
			t.Errorf("ParseTLSVersion(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"", "1.0", "1.4", "tls1.3"} {
		if _, err := ParseTLSVersion(in); err == nil {
			t.Errorf("ParseTLSVersion(%q) = nil error, want one", in)
		}
	}
	for _, v := range Variants {
		if _, err := ParseTLSVersion(v.Version); err != nil {
			t.Errorf("%v: %v", v.Name, err)
		}
	}
}

func TestValidateKey(t *testing.T) {
	for _, key := range []string{KeyECDSA, KeyRSA, KeyEd25519, DefaultKey} {
		if err := ValidateKey(key); err != nil {
			t.Errorf("ValidateKey(%q) = %v", key, err)
		}
	}
	if ValidateKey("dsa") == nil {
		t.Error(`ValidateKey("dsa") = nil, want an error`)
	}
}

// A variant's name is its base and its version, which the scripts read back
// out of it (framework_base and framework_version in script/config.sh).
func TestVariantNames(t *testing.T) {
	for _, v := range Variants {
		if got := VariantName(v.Base, v.Version); got != v.Name {
			t.Errorf("VariantName(%v, %v) = %v, want %v", v.Base, v.Version, got, v.Name)
		}
		if _, ok := BaseLangs[v.Base]; !ok {
			t.Errorf("%v: base %v has no language", v.Name, v.Base)
		}
		if FrameworkVersion(v.Name) != v.Version {
			t.Errorf("FrameworkVersion(%v) = %v", v.Name, FrameworkVersion(v.Name))
		}
	}
	if FrameworkVersion("fib") != "" {
		t.Error("a base is not a framework")
	}
}

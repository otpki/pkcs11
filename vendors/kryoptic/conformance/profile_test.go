package conformance

import (
	_ "embed"
	"strings"
	"testing"
)

//go:embed docker/Dockerfile
var dockerfile string

func TestProfile(t *testing.T) {
	profile := Profile()
	profile.Module = "/test/libkryoptic_pkcs11.so"
	if err := profile.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(profile.Cases) != 202 {
		t.Fatalf("cases = %d, want 202", len(profile.Cases))
	}
}

func TestDockerfileSelectsOpenSSLBinding(t *testing.T) {
	for _, required := range []string{
		"KRYOPTIC_OPENSSL_SOURCES=/opt/openssl-src",
		"--features standard,pqc,ossl/ossl-sys",
	} {
		if !strings.Contains(dockerfile, required) {
			t.Errorf("Dockerfile does not contain %q", required)
		}
	}
}

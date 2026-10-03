package conformance

import (
	_ "embed"
	"strings"
	"testing"

	base "github.com/otpki/pkcs11/conformance"
)

//go:embed docker/softhsm2.conf
var softHSMConfig string

//go:embed docker/Dockerfile
var dockerfile string

func TestProfile(t *testing.T) {
	profile := Profile()
	profile.Module = "/test/libsofthsm2.so"
	if err := profile.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(profile.Cases) != 109 {
		t.Fatalf("cases = %d, want 109", len(profile.Cases))
	}
	knownDisabled := map[string]bool{
		"lms": true, "hss": true, "xmss": true, "xmssmt": true, "idle-session-recovery": true,
	}
	for _, testCase := range profile.Cases {
		if testCase.Requirement == base.Disabled && !knownDisabled[testCase.Name] {
			t.Errorf("unexpected disabled case %q", testCase.Name)
		}
	}
}

func TestDockerfileEnablesPQC(t *testing.T) {
	for _, required := range []string{
		"FROM debian:trixie AS softhsm-build",
		"--enable-mldsa",
		"--enable-mlkem",
	} {
		if !strings.Contains(dockerfile, required) {
			t.Errorf("Dockerfile does not contain %q", required)
		}
	}
}

func TestProfileRequiresAdvertisedPQC(t *testing.T) {
	requirements := make(map[string]base.Requirement)
	for _, testCase := range Profile().Cases {
		requirements[testCase.Name] = testCase.Requirement
	}
	for _, name := range []string{
		"ml-dsa-44-direct", "ml-dsa-65-direct", "ml-dsa-87-direct",
		"ml-kem-512", "ml-kem-768", "ml-kem-1024",
	} {
		if requirements[name] != base.Required {
			t.Errorf("%s requirement = %v, want required", name, requirements[name])
		}
	}
	for _, name := range []string{"ml-dsa-44-prehash", "ml-dsa-65-prehash", "ml-dsa-87-prehash"} {
		if requirements[name] != base.Optional {
			t.Errorf("%s requirement = %v, want optional", name, requirements[name])
		}
	}
}

func TestConfigurationEnablesAllMechanisms(t *testing.T) {
	if !strings.Contains(softHSMConfig, "slots.mechanisms = ALL") {
		t.Fatal("SoftHSM configuration does not enable every compiled mechanism")
	}
}

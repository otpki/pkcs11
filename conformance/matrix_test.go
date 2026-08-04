package conformance

import (
	"testing"

	pkcs11 "github.com/otpki/pkcs11"
)

func TestHardwareMatrixCoversEveryDriverAlgorithm(t *testing.T) {
	covered := make(map[pkcs11.Algorithm]bool, len(hardwareMatrix))
	for _, testCase := range HardwareMatrix() {
		if testCase.Algorithm != "" {
			covered[testCase.Algorithm] = true
		}
	}
	for _, algorithm := range pkcs11.AllAlgorithms() {
		if !covered[algorithm] {
			t.Errorf("hardware matrix does not cover %q", algorithm)
		}
	}
}

func TestHardwareMatrixReturnsIndependentCases(t *testing.T) {
	first := HardwareMatrix(Case{Name: "extra", Kind: "runtime"})
	second := HardwareMatrix()
	if len(first) != len(second)+1 {
		t.Fatalf("override matrix length = %d, baseline = %d", len(first), len(second))
	}
	first[0].Name = "mutated"
	if second[0].Name == "mutated" {
		t.Fatal("HardwareMatrix returned shared case storage")
	}
}

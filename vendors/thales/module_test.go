package thales

import (
	"testing"

	pkcs11 "github.com/otpki/pkcs11"
)

func TestLunaExternalMuCatalog(t *testing.T) {
	definition := NewLuna().Definition()
	value, ok := definition.Catalog.Mechanisms["ml-dsa-external-mu"]
	if !ok || uint(value) != MechanismExternalMuMLDSA {
		t.Fatalf("external-mu mechanism = %#x, %t", uint(value), ok)
	}
}

func TestNewExternalMu(t *testing.T) {
	input := make([]byte, 64)
	for index := range input {
		input[index] = byte(index)
	}
	mu, err := NewExternalMu(input)
	if err != nil {
		t.Fatal(err)
	}
	input[0] = 0xff
	if mu[0] != 0 {
		t.Fatal("NewExternalMu did not make an independent copy")
	}
	if _, err := NewExternalMu(make([]byte, 63)); err == nil {
		t.Fatal("expected 64-byte mu validation")
	}
	_ = pkcs11.HedgePreferred // Tie this helper to the root PQC option vocabulary.
}

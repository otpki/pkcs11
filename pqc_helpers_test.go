package pkcs11

import (
	"crypto"
	"testing"
)

func TestPQCIsIntegratedIntoDriver(t *testing.T) {
	if !IsPQCSignature(AlgorithmMLDSA65) || !IsPQCKEM(AlgorithmMLKEM768) {
		t.Fatal("standard PKCS #11 3.2 PQC classification failed")
	}
	opts := PQCPrehash(crypto.SHA512, []byte("ctx"), HedgeRequired)
	if !opts.Prehashed || opts.Hash != crypto.SHA512 || opts.Hedge != HedgeRequired {
		t.Fatalf("unexpected options: %#v", opts)
	}
}

package pkcs11

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"encoding/asn1"
	"math/big"
	"testing"

	"github.com/otpki/pkcs11/raw"
)

func TestPrepareSignatureInputRSAPKCS1v15(t *testing.T) {
	digest := bytes.Repeat([]byte{0x5a}, crypto.SHA256.Size())
	got, err := prepareSignatureInput(Intent{Algorithm: AlgorithmRSA, Hash: crypto.SHA256, Prehashed: true, RSAPadding: RSAPaddingPKCS1v15}, digest)
	if err != nil {
		t.Fatal(err)
	}
	want := append(append([]byte(nil), rsaDigestInfoPrefixes[crypto.SHA256]...), digest...)
	if !bytes.Equal(got, want) {
		t.Fatalf("DigestInfo = %x, want %x", got, want)
	}
}

func TestPrepareSignatureInputPSSLeavesDigestUnchanged(t *testing.T) {
	digest := bytes.Repeat([]byte{0x23}, crypto.SHA384.Size())
	got, err := prepareSignatureInput(Intent{Algorithm: AlgorithmRSA, Hash: crypto.SHA384, Prehashed: true, RSAPadding: RSAPaddingPSS}, digest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, digest) {
		t.Fatalf("PSS input changed: %x", got)
	}
}

func TestPrepareSignatureInputRejectsWrongDigestLength(t *testing.T) {
	_, err := prepareSignatureInput(Intent{Algorithm: AlgorithmRSA, Hash: crypto.SHA256, Prehashed: true, RSAPadding: RSAPaddingPKCS1v15}, make([]byte, 31))
	if err == nil {
		t.Fatal("expected digest length error")
	}
}

func TestPSSSaltLength(t *testing.T) {
	public := &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 2047), E: 65537}
	got, err := pssSaltLength(public, crypto.SHA256, rsa.PSSSaltLengthAuto)
	if err != nil {
		t.Fatal(err)
	}
	if got != 222 {
		t.Fatalf("automatic salt length = %d, want 222", got)
	}
	got, err = pssSaltLength(public, crypto.SHA256, rsa.PSSSaltLengthEqualsHash)
	if err != nil || got != 32 {
		t.Fatalf("equals-hash salt length = %d, %v", got, err)
	}
}

func TestECDSADERToRawRejectsInvalidIntegers(t *testing.T) {
	for _, test := range []struct {
		name string
		r    *big.Int
		s    *big.Int
	}{
		{name: "negative", r: big.NewInt(-1), s: big.NewInt(1)},
		{name: "zero", r: big.NewInt(0), s: big.NewInt(1)},
		{name: "oversize", r: new(big.Int).Lsh(big.NewInt(1), 256), s: big.NewInt(1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			der, err := asn1.Marshal(struct{ R, S *big.Int }{test.r, test.s})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ecdsaDERToRaw(der, 32); err == nil {
				t.Fatal("expected invalid ECDSA integer error")
			}
		})
	}
}

func TestResolvePQCPrehashRequiresHash(t *testing.T) {
	device := testDevice(adapterDefinition{name: "generic"}, map[raw.MechanismType]raw.MechanismInfo{
		raw.MechanismType(raw.CKM_HASH_ML_DSA): {Flags: raw.CKF_SIGN},
	})
	_, err := ResolveRoute(device, Intent{Operation: OperationSign, Algorithm: AlgorithmMLDSA44, Prehashed: true})
	if err == nil {
		t.Fatal("expected missing PQC prehash algorithm error")
	}
}

func TestIsPKCS1PaddingError(t *testing.T) {
	if !isPKCS1PaddingError(raw.Error(raw.CKR_ENCRYPTED_DATA_INVALID)) {
		t.Fatal("encrypted-data-invalid should be treated as a padding error")
	}
	if isPKCS1PaddingError(raw.Error(raw.CKR_DEVICE_ERROR)) {
		t.Fatal("device errors must not be suppressed")
	}
}

func TestECDSARawToDERRejectsZeroScalars(t *testing.T) {
	if _, err := ecdsaRawToDER(make([]byte, 64)); err == nil {
		t.Fatal("expected zero-scalar rejection")
	}
}

func TestSignatureIntentDefaults(t *testing.T) {
	rsaIntent, err := signatureIntent(OperationSign, AlgorithmRSA, SignatureOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if rsaIntent.Hash != crypto.SHA256 || rsaIntent.RSAPadding != RSAPaddingPSS || rsaIntent.Prehashed {
		t.Fatalf("RSA defaults = %#v", rsaIntent)
	}

	ecdsaIntent, err := signatureIntent(OperationVerify, AlgorithmECDSAP384, SignatureOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if ecdsaIntent.Hash != crypto.SHA384 || ecdsaIntent.Prehashed {
		t.Fatalf("ECDSA defaults = %#v", ecdsaIntent)
	}

	pqcIntent, err := signatureIntent(OperationSign, AlgorithmMLDSA65, PQCDirect([]byte("ctx"), HedgeRequired))
	if err != nil {
		t.Fatal(err)
	}
	if pqcIntent.Hash != 0 || pqcIntent.Prehashed || pqcIntent.Hedge != HedgeRequired || string(pqcIntent.Context) != "ctx" {
		t.Fatalf("PQC defaults = %#v", pqcIntent)
	}
}

func TestSignatureIntentRejectsMismatchedAlgorithmAndExternalMuMisuse(t *testing.T) {
	if _, err := signatureIntent(OperationSign, AlgorithmRSA, SignatureOptions{Algorithm: AlgorithmMLDSA65}); err == nil {
		t.Fatal("expected algorithm mismatch")
	}
	if _, err := signatureIntent(OperationSign, AlgorithmRSA, SignatureOptions{ExternalMu: true}); err == nil {
		t.Fatal("expected external-mu algorithm error")
	}
	if _, err := signatureIntent(OperationSign, AlgorithmMLDSA65, SignatureOptions{ExternalMu: true, Prehashed: true}); err == nil {
		t.Fatal("expected external-mu/prehash conflict")
	}
}

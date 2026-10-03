package pkcs11

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"math/big"
	"slices"
	"testing"

	"github.com/otpki/pkcs11/raw"
)

func TestPrepareSignatureInputRSAPKCS1v15(t *testing.T) {
	digest := bytes.Repeat([]byte{0x5a}, crypto.SHA256.Size())
	got, err := prepareSignatureInput(Intent{Algorithm: AlgorithmRSA, Hash: crypto.SHA256, Prehashed: true, RSAPadding: RSAPaddingPKCS1v15}, digest)
	if err != nil {
		t.Fatal(err)
	}
	want := slices.Concat(rsaDigestInfoPrefixes[crypto.SHA256], digest)
	if !bytes.Equal(got, want) {
		t.Fatalf("DigestInfo = %x, want %x", got, want)
	}
}

// TestPrepareSignatureInputRSAPKCS1v15SHA3 checks each SHA-3 DigestInfo prefix
// against crypto/rsa: the library-encoded EMSA-PKCS1-v1_5 payload is signed with
// a raw private-key operation and Go's verifier accepts it only when the prefix
// matches its own table.
func TestPrepareSignatureInputRSAPKCS1v15SHA3(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	emLen := (key.N.BitLen() + 7) / 8
	for _, hash := range []crypto.Hash{crypto.SHA3_224, crypto.SHA3_256, crypto.SHA3_384, crypto.SHA3_512} {
		t.Run(hash.String(), func(t *testing.T) {
			digest := bytes.Repeat([]byte{0x5a}, hash.Size())
			encoded, err := prepareSignatureInput(Intent{Algorithm: AlgorithmRSA, Hash: hash, Prehashed: true, RSAPadding: RSAPaddingPKCS1v15}, digest)
			if err != nil {
				t.Fatal(err)
			}
			em := make([]byte, 0, emLen)
			em = append(em, 0x00, 0x01)
			em = append(em, bytes.Repeat([]byte{0xff}, emLen-len(encoded)-3)...)
			em = append(em, 0x00)
			em = append(em, encoded...)
			signature := new(big.Int).Exp(new(big.Int).SetBytes(em), key.D, key.N).FillBytes(make([]byte, emLen))
			if err := rsa.VerifyPKCS1v15(&key.PublicKey, hash, digest, signature); err != nil {
				t.Fatalf("crypto/rsa rejected the %s DigestInfo: %v", hash, err)
			}
		})
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

func TestSignMessageIntentRoutesCombinedMechanisms(t *testing.T) {
	public := &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 2047), E: 65537}
	device := testDevice(adapterDefinition{name: "generic"}, map[raw.MechanismType]raw.MechanismInfo{
		raw.MechanismType(raw.CKM_RSA_PKCS):            {Flags: raw.CKF_SIGN},
		raw.MechanismType(raw.CKM_SHA256_RSA_PKCS):     {Flags: raw.CKF_SIGN},
		raw.MechanismType(raw.CKM_RSA_PKCS_PSS):        {Flags: raw.CKF_SIGN},
		raw.MechanismType(raw.CKM_SHA256_RSA_PKCS_PSS): {Flags: raw.CKF_SIGN},
		raw.MechanismType(raw.CKM_SHA3_256_RSA_PKCS):   {Flags: raw.CKF_SIGN},
		raw.MechanismType(raw.CKM_ECDSA):               {Flags: raw.CKF_SIGN},
		raw.MechanismType(raw.CKM_ECDSA_SHA384):        {Flags: raw.CKF_SIGN},
		raw.MechanismType(raw.CKM_EDDSA):               {Flags: raw.CKF_SIGN},
		raw.MechanismType(raw.CKM_ML_DSA):              {Flags: raw.CKF_SIGN},
		raw.MechanismType(raw.CKM_HASH_ML_DSA):         {Flags: raw.CKF_SIGN},
		raw.MechanismType(raw.CKM_HASH_ML_DSA_SHA512):  {Flags: raw.CKF_SIGN},
		raw.MechanismType(raw.CKM_HSS):                 {Flags: raw.CKF_SIGN},
	})
	message := []byte("message-level input")
	for _, test := range []struct {
		name      string
		signer    *Signer
		opts      crypto.SignerOpts
		mechanism uint
		prehashed bool
	}{
		{
			"rsa pkcs1v15 hashes the message on token",
			&Signer{algorithm: AlgorithmRSA, publicKey: public},
			crypto.SHA256, raw.CKM_SHA256_RSA_PKCS, false,
		},
		{
			"rsa pss keeps pss options and hashes on token",
			&Signer{algorithm: AlgorithmRSA, publicKey: public},
			&rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: rsa.PSSSaltLengthEqualsHash},
			raw.CKM_SHA256_RSA_PKCS_PSS, false,
		},
		{
			"rsa pkcs1v15 hashes sha3-256 on token",
			&Signer{algorithm: AlgorithmRSA, publicKey: public},
			SignatureOptions{Hash: crypto.SHA3_256, RSAPadding: RSAPaddingPKCS1v15},
			raw.CKM_SHA3_256_RSA_PKCS, false,
		},
		{
			"ecdsa zero hash falls back to the curve default",
			&Signer{algorithm: AlgorithmECDSAP384},
			crypto.Hash(0), raw.CKM_ECDSA_SHA384, false,
		},
		{
			"mldsa prehashed option becomes the internal hash variant",
			&Signer{algorithm: AlgorithmMLDSA65},
			SignatureOptions{Hash: crypto.SHA512, Prehashed: true},
			raw.CKM_HASH_ML_DSA_SHA512, false,
		},
		{
			"ed25519 prehashed option selects the ph variant",
			&Signer{algorithm: AlgorithmEd25519},
			SignatureOptions{Prehashed: true, Context: []byte("ctx")},
			raw.CKM_EDDSA, true,
		},
		{
			"ed25519 options carry context through",
			&Signer{algorithm: AlgorithmEd25519},
			&ed25519.Options{Hash: crypto.SHA512, Context: "ctx"},
			raw.CKM_EDDSA, true,
		},
		{
			"lms signs the message directly",
			&Signer{algorithm: AlgorithmLMS},
			crypto.Hash(0), raw.CKM_HSS, false,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			intent, err := test.signer.signIntent(message, test.opts, true)
			if err != nil {
				t.Fatalf("signIntent: %v", err)
			}
			if intent.Prehashed != test.prehashed {
				t.Fatalf("intent.Prehashed = %v, want %v", intent.Prehashed, test.prehashed)
			}
			route, err := ResolveRoute(device, intent)
			if err != nil {
				t.Fatalf("ResolveRoute: %v", err)
			}
			if route.Mechanism == nil || route.Mechanism.Mechanism != test.mechanism {
				t.Fatalf("mechanism = %#v, want %#x", route.Mechanism, test.mechanism)
			}
		})
	}

	// Stateful HBS algorithms sign messages directly; a nonzero hash must
	// produce a routing error rather than silently hashing the message.
	lms := &Signer{algorithm: AlgorithmLMS}
	intent, err := lms.signIntent(message, crypto.SHA256, true)
	if err != nil {
		t.Fatalf("signIntent: %v", err)
	}
	if _, err := ResolveRoute(device, intent); err == nil {
		t.Fatal("expected LMS hash routing rejection")
	}
}

func TestMessageDigestFallback(t *testing.T) {
	if !crypto.SHA3_256.Available() {
		t.Fatal("crypto/sha3 is not linked into the library; the message-level SHA-3 fallback is unreachable")
	}
	public := &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 2047), E: 65537}
	// This token exposes only the raw and externally prehashed mechanisms;
	// the combined hash-and-sign variants are absent.
	rawOnly := testDevice(adapterDefinition{name: "generic"}, map[raw.MechanismType]raw.MechanismInfo{
		raw.MechanismType(raw.CKM_RSA_PKCS):     {Flags: raw.CKF_SIGN},
		raw.MechanismType(raw.CKM_RSA_PKCS_PSS): {Flags: raw.CKF_SIGN},
		raw.MechanismType(raw.CKM_ECDSA):        {Flags: raw.CKF_SIGN},
		raw.MechanismType(raw.CKM_HASH_ML_DSA):  {Flags: raw.CKF_SIGN},
		raw.MechanismType(raw.CKM_EDDSA):        {Flags: raw.CKF_SIGN},
	})
	message := []byte("message-level input")
	for _, test := range []struct {
		name      string
		signer    *Signer
		opts      crypto.SignerOpts
		mechanism uint
		hash      crypto.Hash
		ok        bool
	}{
		{
			"rsa falls back to the raw mechanism",
			&Signer{algorithm: AlgorithmRSA, publicKey: public},
			crypto.SHA256, raw.CKM_RSA_PKCS, crypto.SHA256, true,
		},
		{
			"rsa pss falls back to raw pss",
			&Signer{algorithm: AlgorithmRSA, publicKey: public},
			&rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: rsa.PSSSaltLengthEqualsHash},
			raw.CKM_RSA_PKCS_PSS, crypto.SHA256, true,
		},
		{
			"rsa pkcs1v15 falls back for sha3-256",
			&Signer{algorithm: AlgorithmRSA, publicKey: public},
			crypto.SHA3_256, raw.CKM_RSA_PKCS, crypto.SHA3_256, true,
		},
		{
			"rsa pss falls back for sha3-256",
			&Signer{algorithm: AlgorithmRSA, publicKey: public},
			&rsa.PSSOptions{Hash: crypto.SHA3_256, SaltLength: rsa.PSSSaltLengthEqualsHash},
			raw.CKM_RSA_PKCS_PSS, crypto.SHA3_256, true,
		},
		{
			"ecdsa message-level sha3-256 falls back to the raw mechanism",
			&Signer{algorithm: AlgorithmECDSAP256},
			crypto.SHA3_256, raw.CKM_ECDSA, crypto.SHA3_256, true,
		},
		{
			"ecdsa falls back to the raw mechanism",
			&Signer{algorithm: AlgorithmECDSAP384},
			crypto.Hash(0), raw.CKM_ECDSA, crypto.SHA384, true,
		},
		{
			"mldsa falls back to the externally prehashed mechanism",
			&Signer{algorithm: AlgorithmMLDSA65},
			SignatureOptions{Hash: crypto.SHA512, Prehashed: true},
			raw.CKM_HASH_ML_DSA, crypto.SHA512, true,
		},
		{
			"ed25519 has no external digest form",
			&Signer{algorithm: AlgorithmEd25519},
			crypto.Hash(0), 0, 0, false,
		},
		{
			"lms has no digest form",
			&Signer{algorithm: AlgorithmLMS},
			crypto.Hash(0), 0, 0, false,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			intent, err := test.signer.signIntent(message, test.opts, true)
			if err != nil {
				t.Fatalf("signIntent: %v", err)
			}
			fallback, hash, ok := test.signer.messageDigestFallback(intent)
			if ok != test.ok {
				t.Fatalf("fallback ok = %v, want %v", ok, test.ok)
			}
			if !ok {
				return
			}
			if !fallback.Prehashed || hash != test.hash {
				t.Fatalf("fallback intent = %#v hash %v", fallback, hash)
			}
			route, err := ResolveRoute(rawOnly, fallback)
			if err != nil {
				t.Fatalf("ResolveRoute fallback: %v", err)
			}
			if route.Mechanism == nil || route.Mechanism.Mechanism != test.mechanism {
				t.Fatalf("fallback mechanism = %#v, want %#x", route.Mechanism, test.mechanism)
			}
		})
	}

	// Callers that dictated the input shape or mechanism get no fallback.
	rsaSigner := &Signer{algorithm: AlgorithmRSA, publicKey: public}
	for _, opts := range []crypto.SignerOpts{
		SignatureOptions{Prehashed: true, Hash: crypto.SHA256},
		SignatureOptions{MechanismOverride: new(uint)},
	} {
		intent, err := rsaSigner.signIntent(message, opts, false)
		if err != nil {
			t.Fatalf("signIntent: %v", err)
		}
		if _, _, ok := rsaSigner.messageDigestFallback(intent); ok {
			t.Fatalf("opts %#v must not produce a digest fallback", opts)
		}
	}
}

func TestSignDigestIntentKeepsPrehashedContract(t *testing.T) {
	public := &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 2047), E: 65537}
	signer := &Signer{algorithm: AlgorithmRSA, publicKey: public}
	intent, err := signer.signIntent(make([]byte, crypto.SHA256.Size()), crypto.SHA256, false)
	if err != nil {
		t.Fatalf("signIntent: %v", err)
	}
	if !intent.Prehashed || intent.RSAPadding != RSAPaddingPKCS1v15 {
		t.Fatalf("digest intent = %#v", intent)
	}

	mldsa := &Signer{algorithm: AlgorithmMLDSA65}
	intent, err = mldsa.signIntent(make([]byte, crypto.SHA512.Size()), SignatureOptions{Hash: crypto.SHA512, Prehashed: true}, false)
	if err != nil {
		t.Fatalf("signIntent: %v", err)
	}
	if !intent.Prehashed {
		t.Fatalf("digest-level ML-DSA intent must stay prehashed: %#v", intent)
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

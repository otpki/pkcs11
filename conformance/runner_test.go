package conformance

import (
	"crypto"
	"errors"
	"fmt"
	"testing"

	"github.com/otpki/pkcs11/raw"
)

func TestIsUnsupported(t *testing.T) {
	unsupported := []error{
		raw.Error(raw.CKR_FUNCTION_NOT_SUPPORTED),
		fmt.Errorf("wrapped: %w", raw.Error(raw.CKR_MECHANISM_INVALID)),
		errors.New("algorithm is not advertised by the token"),
		errors.New("unsupported algorithm"),
		errors.New(`pkcs11: token has neither standard mechanism 0x1c nor usable alias "ml-dsa-key-pair-gen" for key-pair generation`),
		errors.New(`pkcs11: adapter "generic" does not define key-type alias "dilithium" for dilithium-2`),
		errors.New(`pkcs11: adapter "generic" does not define parameter-set alias "kyber-768" for kyber-768`),
		errors.New(`pkcs11: adapter "generic" requires vendor mechanism alias "custom", but it is unavailable`),
	}
	for _, err := range unsupported {
		if !IsUnsupported(err) {
			t.Fatalf("expected unsupported: %v", err)
		}
	}
	for _, err := range []error{nil, raw.Error(raw.CKR_DEVICE_ERROR), errors.New("transport timeout")} {
		if IsUnsupported(err) {
			t.Fatalf("unexpected unsupported classification: %v", err)
		}
	}
	for _, err := range []error{
		raw.Error(raw.CKR_MECHANISM_PARAM_INVALID),
		raw.Error(raw.CKR_KEY_TYPE_INCONSISTENT),
		raw.Error(raw.CKR_TEMPLATE_INCONSISTENT),
		raw.Error(raw.CKR_ATTRIBUTE_TYPE_INVALID),
		raw.Error(raw.CKR_ATTRIBUTE_VALUE_INVALID),
		raw.Error(raw.CKR_DOMAIN_PARAMS_INVALID),
	} {
		if IsUnsupported(err) {
			t.Fatalf("driver or template defect must fail instead of skip: %v", err)
		}
	}
}

func TestRequirementSemantics(t *testing.T) {
	// The full operation runner requires a native module. Lock the result rules
	// indirectly by checking the capability classifier used by Optional and
	// Forbidden cases; operational errors must never be silently skipped.
	if IsUnsupported(raw.Error(raw.CKR_USER_NOT_LOGGED_IN)) {
		t.Fatal("authentication failure must fail, not skip")
	}
	if IsUnsupported(raw.Error(raw.CKR_SESSION_HANDLE_INVALID)) {
		t.Fatal("stale session must fail or recover, not skip")
	}
}

func TestHashByName(t *testing.T) {
	tests := []struct {
		name     string
		fallback crypto.Hash
		want     crypto.Hash
	}{
		{name: "", fallback: crypto.SHA384, want: crypto.SHA384},
		{name: "default", fallback: crypto.SHA512, want: crypto.SHA512},
		{name: "sha1", want: crypto.SHA1},
		{name: "SHA-1", want: crypto.SHA1},
		{name: "sha256", want: crypto.SHA256},
		{name: "sha-384", want: crypto.SHA384},
		{name: "SHA512", want: crypto.SHA512},
		{name: "sha3-224", want: crypto.SHA3_224},
		{name: "sha3-256", want: crypto.SHA3_256},
		{name: "sha3-384", want: crypto.SHA3_384},
		{name: "SHA3-512", want: crypto.SHA3_512},
		{name: "direct", want: 0},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := hashByName(test.name, test.fallback)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("hashByName(%q) = %v, want %v", test.name, got, test.want)
			}
		})
	}

	if _, err := hashByName("sha999", crypto.SHA256); err == nil {
		t.Fatal("unknown hash name was accepted")
	}
	if digest, err := hashInput(crypto.SHA1, []byte("sha1-registration")); err != nil {
		t.Fatalf("SHA-1 was not linked into the conformance binary: %v", err)
	} else if len(digest) != crypto.SHA1.Size() {
		t.Fatalf("SHA-1 digest length = %d, want %d", len(digest), crypto.SHA1.Size())
	}
}

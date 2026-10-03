package pkcs11

import (
	"strings"
	"testing"

	"github.com/otpki/pkcs11/raw"
)

func TestMechanismDescriptionDoesNotExposeOAEPLabel(t *testing.T) {
	label := []byte("secret-label")
	description := mechanismDescription(raw.NewMechanism(raw.CKM_RSA_PKCS_OAEP, raw.OAEPParams{
		HashAlg:    raw.CKM_SHA256,
		MGF:        raw.CKG_MGF1_SHA256,
		Source:     raw.CKZ_DATA_SPECIFIED,
		SourceData: label,
	}))
	if !strings.Contains(description, "label=12B") {
		t.Fatalf("description = %q", description)
	}
	if strings.Contains(description, string(label)) {
		t.Fatalf("description exposes OAEP label: %q", description)
	}
}

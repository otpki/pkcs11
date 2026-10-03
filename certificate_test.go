package pkcs11

import (
	"crypto/x509"
	"math/big"
	"testing"

	"github.com/otpki/pkcs11/raw"
)

func TestCertificateTemplate(t *testing.T) {
	cert := &x509.Certificate{
		Raw:                     []byte{0x30, 0x01, 0x00},
		RawSubject:              []byte{0x30, 0x00},
		RawIssuer:               []byte{0x30, 0x00},
		RawSubjectPublicKeyInfo: []byte{0x30, 0x02, 0x00, 0x00},
		SerialNumber:            big.NewInt(42),
	}
	attributes, err := certificateTemplate(cert, CertificateImportOptions{Label: "signing", ID: []byte{1, 2, 3}})
	if err != nil {
		t.Fatalf("certificateTemplate: %v", err)
	}
	byType := make(map[uint]*raw.Attribute)
	for _, attribute := range attributes {
		byType[attribute.Type] = attribute
	}
	if class, ok := raw.ULong(byType[raw.CKA_CLASS].Value); !ok || class != raw.CKO_CERTIFICATE {
		t.Fatalf("CKA_CLASS = %d, %v", class, ok)
	}
	if string(byType[raw.CKA_LABEL].Value) != "signing" {
		t.Fatalf("label = %q", byType[raw.CKA_LABEL].Value)
	}
	if string(byType[raw.CKA_VALUE].Value) != string(cert.Raw) {
		t.Fatal("CKA_VALUE does not contain certificate DER")
	}
	if _, ok := byType[raw.CKA_TRUSTED]; ok {
		t.Fatal("CKA_TRUSTED should be omitted unless explicitly configured")
	}
}

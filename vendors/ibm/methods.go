package ibm

import (
	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/raw"
)

// ObjectAttributes requests the EP11 parameter-set and ML-KEM public-key
// attributes needed for algorithm inference and diagnostics.
func (*Module) ObjectAttributes() []uint {
	return []uint{AttributeParameterSet, AttributeMLKEMPK}
}

// InferAlgorithm maps IBM proprietary key types and parameter-set attributes
// back to the vendor-neutral algorithms exposed by the root client.
func (*Module) InferAlgorithm(metadata pkcs11.VendorObjectMetadata) (pkcs11.Algorithm, bool) {
	set, _ := pkcs11.AttributeULong(metadata.Attributes, AttributeParameterSet)
	switch metadata.KeyType {
	case KeyTypeMLDSA:
		switch set {
		case raw.CKP_ML_DSA_44:
			return pkcs11.AlgorithmMLDSA44, true
		case raw.CKP_ML_DSA_65:
			return pkcs11.AlgorithmMLDSA65, true
		case raw.CKP_ML_DSA_87:
			return pkcs11.AlgorithmMLDSA87, true
		}
	case KeyTypeMLKEM:
		switch set {
		case raw.CKP_ML_KEM_512:
			return pkcs11.AlgorithmMLKEM512, true
		case raw.CKP_ML_KEM_768:
			return pkcs11.AlgorithmMLKEM768, true
		case raw.CKP_ML_KEM_1024:
			return pkcs11.AlgorithmMLKEM1024, true
		}
	}
	return "", false
}

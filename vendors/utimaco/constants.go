// Package utimaco provides the Utimaco CryptoServer/u.trust/CP5 vendor module
// and the QuantumProtect PKCS #11 extension surface.
package utimaco

import pkcs11 "github.com/otpki/pkcs11"

const (
	// ID is the stable VendorModule identifier used for every Utimaco product
	// variant handled by this package. The selected AdapterInfo.Variant reports
	// CryptoServer, u.trust, CP5, and QuantumProtect distinctions.
	ID pkcs11.AdapterFamily = "utimaco"

	// MechanismHBSBase is QuantumProtect's hash-based-signature mechanism namespace base.
	MechanismHBSBase uint = 0xC0A20000
	// MechanismLatticeBase is QuantumProtect's legacy Dilithium/Kyber mechanism namespace base.
	MechanismLatticeBase uint = 0xC0A30000
	// MechanismMLBase is QuantumProtect's ML-DSA/ML-KEM mechanism namespace base.
	MechanismMLBase uint = 0xC0A50000

	// MechanismDilithiumKeyPairGen generates a legacy Dilithium key pair.
	MechanismDilithiumKeyPairGen uint = MechanismLatticeBase | 0x0001
	// MechanismKyberKeyPairGen generates a legacy Kyber key pair.
	MechanismKyberKeyPairGen uint = MechanismLatticeBase | 0x0002
	// MechanismDilithiumSign signs with a legacy Dilithium private key.
	MechanismDilithiumSign uint = MechanismLatticeBase | 0x3001
	// MechanismDilithiumVerify verifies a legacy Dilithium signature.
	MechanismDilithiumVerify uint = MechanismLatticeBase | 0x4001
	// MechanismKyberEncapsulate performs legacy Kyber encapsulation.
	MechanismKyberEncapsulate uint = MechanismLatticeBase | 0x9001
	// MechanismKyberDecapsulate performs legacy Kyber decapsulation.
	MechanismKyberDecapsulate uint = MechanismLatticeBase | 0x9002

	// MechanismMLDSAKeyPairGen generates an ML-DSA key pair.
	MechanismMLDSAKeyPairGen uint = MechanismMLBase | 0x0001
	// MechanismMLKEMKeyPairGen generates an ML-KEM key pair.
	MechanismMLKEMKeyPairGen uint = MechanismMLBase | 0x0002
	// MechanismMLDSASign signs with ML-DSA using the QuantumProtect parameter block.
	MechanismMLDSASign uint = MechanismMLBase | 0x3001
	// MechanismMLDSAExternalMuSign signs a caller-provided 64-byte ML-DSA mu value.
	MechanismMLDSAExternalMuSign uint = MechanismMLBase | 0x3005
	// MechanismMLDSAVerify verifies an ML-DSA signature.
	MechanismMLDSAVerify uint = MechanismMLBase | 0x4001
	// MechanismMLDSAExternalMuVerify verifies an ML-DSA signature over external mu.
	MechanismMLDSAExternalMuVerify uint = MechanismMLBase | 0x4005
	// MechanismMLDSAWrapAESKWP wraps an ML-DSA key using AES-KWP.
	MechanismMLDSAWrapAESKWP uint = MechanismMLBase | 0x5001
	// MechanismMLDSAUnwrapAESKWP unwraps an ML-DSA key using AES-KWP.
	MechanismMLDSAUnwrapAESKWP uint = MechanismMLBase | 0x6001
	// MechanismMLKEMEncapsulate performs ML-KEM encapsulation through C_DeriveKey.
	MechanismMLKEMEncapsulate uint = MechanismMLBase | 0x9001
	// MechanismMLKEMDecapsulate performs ML-KEM decapsulation through C_DeriveKey.
	MechanismMLKEMDecapsulate uint = MechanismMLBase | 0x9002
	// MechanismMLDSAExportPublicKey exports the serialized ML-DSA public key.
	MechanismMLDSAExportPublicKey uint = MechanismMLBase | 0x9003
	// MechanismMLKEMExportPublicKey exports the serialized ML-KEM public key.
	MechanismMLKEMExportPublicKey uint = MechanismMLBase | 0x9004
	// MechanismMLDSASHAKE256 selects QuantumProtect's ML-DSA SHAKE-256 helper operation.
	MechanismMLDSASHAKE256 uint = MechanismMLBase | 0xD001

	// MechanismHSSKeyGen generates an HSS key from provider randomness.
	MechanismHSSKeyGen uint = MechanismHBSBase | 0x0001
	// MechanismHSSKeyGenSeed generates an HSS key from caller-supplied seed material.
	MechanismHSSKeyGenSeed uint = MechanismHBSBase | 0x0002
	// MechanismXMSSKeyGen generates an XMSS or XMSSMT key from provider randomness.
	MechanismXMSSKeyGen uint = MechanismHBSBase | 0x0003
	// MechanismXMSSKeyGenSeed generates an XMSS or XMSSMT key from caller seed material.
	MechanismXMSSKeyGenSeed uint = MechanismHBSBase | 0x0004
	// MechanismLMSKeyGen generates a single-level LMS key from provider randomness.
	MechanismLMSKeyGen uint = MechanismHBSBase | 0x0005
	// MechanismLMSKeyGenSeed generates a single-level LMS key from caller seed material.
	MechanismLMSKeyGenSeed uint = MechanismHBSBase | 0x0006

	// MechanismHSSGetPublicKey derives the temporary HSS verification carrier.
	MechanismHSSGetPublicKey uint = MechanismHBSBase | 0x9001
	// MechanismXMSSGetPublicKey derives the temporary XMSS/XMSSMT verification carrier.
	MechanismXMSSGetPublicKey uint = MechanismHBSBase | 0x9002
	// MechanismLMSGetPublicKey derives the temporary LMS verification carrier.
	MechanismLMSGetPublicKey uint = MechanismHBSBase | 0x9003

	// MechanismHSSSign signs with a stateful HSS key.
	MechanismHSSSign uint = MechanismHBSBase | 0x3001
	// MechanismXMSSSign signs with a stateful XMSS/XMSSMT key.
	MechanismXMSSSign uint = MechanismHBSBase | 0x3002
	// MechanismLMSSign signs with a stateful LMS key.
	MechanismLMSSign uint = MechanismHBSBase | 0x3003

	// MechanismHSSVerify verifies an HSS signature.
	MechanismHSSVerify uint = MechanismHBSBase | 0x4001
	// MechanismXMSSVerify verifies an XMSS/XMSSMT signature.
	MechanismXMSSVerify uint = MechanismHBSBase | 0x4002
	// MechanismLMSVerify verifies an LMS signature.
	MechanismLMSVerify uint = MechanismHBSBase | 0x4003

	// KeyTypeDilithium is QuantumProtect's legacy Dilithium key type.
	KeyTypeDilithium uint = MechanismDilithiumKeyPairGen
	// KeyTypeKyber is QuantumProtect's legacy Kyber key type.
	KeyTypeKyber uint = MechanismKyberKeyPairGen
	// KeyTypeMLDSA is QuantumProtect's ML-DSA key type.
	KeyTypeMLDSA uint = MechanismMLDSAKeyPairGen
	// KeyTypeMLKEM is QuantumProtect's ML-KEM key type.
	KeyTypeMLKEM uint = MechanismMLKEMKeyPairGen

	// AttributeCustomData contains QuantumProtect public key data and, for
	// derive-based ML-KEM encapsulation, the generated ciphertext.
	AttributeCustomData uint = 0x80D00001

	// MLDSAFlagHasContext marks a QuantumProtect signature parameter block with context data.
	MLDSAFlagHasContext uint32 = 0xF2040000
	// MLDSAFlagPreHash selects QuantumProtect ML-DSA prehash input semantics.
	MLDSAFlagPreHash uint32 = 0xF2040001
	// MLDSAFlagSigPacked selects QuantumProtect's packed signature representation.
	MLDSAFlagSigPacked uint32 = 0xF2040002
)

// ParameterSet is QuantumProtect's compact ML-DSA/ML-KEM parameter selector.
type ParameterSet uint32

const (
	// ParameterSet44Or512 selects ML-DSA-44 or ML-KEM-512 according to the mechanism.
	ParameterSet44Or512 ParameterSet = 1
	// ParameterSet65Or768 selects ML-DSA-65 or ML-KEM-768 according to the mechanism.
	ParameterSet65Or768 ParameterSet = 2
	// ParameterSet87Or1024 selects ML-DSA-87 or ML-KEM-1024 according to the mechanism.
	ParameterSet87Or1024 ParameterSet = 3
)

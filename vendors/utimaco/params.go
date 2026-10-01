package utimaco

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// GenerateParameters is QuantumProtect's big-endian u4u4v2* key-generation
// record. Attributes and Seed are optional serialized VDM fields.
type GenerateParameters struct {
	Flags      uint32
	Set        ParameterSet
	Attributes []byte
	Seed       []byte
}

// MarshalBinary encodes the exact parameter bytes consumed by the vendor
// C_GenerateKeyPair mechanisms.
func (p GenerateParameters) MarshalBinary() ([]byte, error) {
	if err := validateParameterSet(p.Set); err != nil {
		return nil, err
	}
	if len(p.Attributes) > 0xffff {
		return nil, errors.New("utimaco: generation attributes exceed 65535 bytes")
	}
	out := make([]byte, 10+len(p.Attributes)+len(p.Seed))
	binary.BigEndian.PutUint32(out[0:4], p.Flags)
	binary.BigEndian.PutUint32(out[4:8], uint32(p.Set))
	binary.BigEndian.PutUint16(out[8:10], uint16(len(p.Attributes)))
	copy(out[10:], p.Attributes)
	copy(out[10+len(p.Attributes):], p.Seed)
	return out, nil
}

// SignatureParameters is the common flags/type prefix used by direct,
// prehashed, and external-mu ML-DSA sign and verify mechanisms.
type SignatureParameters struct {
	Flags uint32
	Set   ParameterSet
}

// MarshalBinary encodes the QuantumProtect u4u4 signature prefix.
func (p SignatureParameters) MarshalBinary() ([]byte, error) {
	if err := validateParameterSet(p.Set); err != nil {
		return nil, err
	}
	out := make([]byte, 8)
	binary.BigEndian.PutUint32(out[0:4], p.Flags)
	binary.BigEndian.PutUint32(out[4:8], uint32(p.Set))
	return out, nil
}

// EncapsulationParameters is QuantumProtect's u4u4v2 ML-KEM encapsulation
// request. PublicKey is the raw recipient key obtained from CKA_UTI_CUSTOM_DATA.
type EncapsulationParameters struct {
	Flags     uint32
	Set       ParameterSet
	PublicKey []byte
}

// MarshalBinary encodes the derive-based encapsulation parameter block.
func (p EncapsulationParameters) MarshalBinary() ([]byte, error) {
	if err := validateParameterSet(p.Set); err != nil {
		return nil, err
	}
	if len(p.PublicKey) > 0xffff {
		return nil, errors.New("utimaco: public key exceeds 65535 bytes")
	}
	out := make([]byte, 10+len(p.PublicKey))
	binary.BigEndian.PutUint32(out[0:4], p.Flags)
	binary.BigEndian.PutUint32(out[4:8], uint32(p.Set))
	binary.BigEndian.PutUint16(out[8:10], uint16(len(p.PublicKey)))
	copy(out[10:], p.PublicKey)
	return out, nil
}

// DecapsulationParameters is QuantumProtect's u4u4v2v2 ML-KEM decapsulation
// request. PrivateKey is normally empty because C_DeriveKey's base-key handle
// identifies the resident private key.
type DecapsulationParameters struct {
	Flags      uint32
	Set        ParameterSet
	PrivateKey []byte
	Ciphertext []byte
}

// MarshalBinary encodes the derive-based decapsulation parameter block.
func (p DecapsulationParameters) MarshalBinary() ([]byte, error) {
	if err := validateParameterSet(p.Set); err != nil {
		return nil, err
	}
	if len(p.PrivateKey) > 0xffff || len(p.Ciphertext) > 0xffff {
		return nil, errors.New("utimaco: ML-KEM vector exceeds 65535 bytes")
	}
	out := make([]byte, 12+len(p.PrivateKey)+len(p.Ciphertext))
	binary.BigEndian.PutUint32(out[0:4], p.Flags)
	binary.BigEndian.PutUint32(out[4:8], uint32(p.Set))
	offset := 8
	binary.BigEndian.PutUint16(out[offset:offset+2], uint16(len(p.PrivateKey)))
	offset += 2
	copy(out[offset:], p.PrivateKey)
	offset += len(p.PrivateKey)
	binary.BigEndian.PutUint16(out[offset:offset+2], uint16(len(p.Ciphertext)))
	offset += 2
	copy(out[offset:], p.Ciphertext)
	return out, nil
}

// KeyWrapParameters is the u4u4 record used by QuantumProtect's ML-DSA
// AES-KWP wrap and unwrap mechanisms.
type KeyWrapParameters struct {
	Flags uint32
	Set   ParameterSet
}

// MarshalBinary encodes the wrap/unwrap parameter block.
func (p KeyWrapParameters) MarshalBinary() ([]byte, error) {
	return SignatureParameters(p).MarshalBinary()
}

func validateParameterSet(set ParameterSet) error {
	if set < ParameterSet44Or512 || set > ParameterSet87Or1024 {
		return fmt.Errorf("utimaco: invalid parameter-set selector %d", set)
	}
	return nil
}

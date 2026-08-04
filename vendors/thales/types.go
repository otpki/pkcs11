package thales

import "fmt"

// ExternalMu is the fixed-size ML-DSA representative accepted by Luna's
// CKM_EXTMU_ML_DSA mechanism.
type ExternalMu [64]byte

// NewExternalMu validates and copies a 64-byte ML-DSA mu value.
func NewExternalMu(value []byte) (ExternalMu, error) {
	var result ExternalMu
	if len(value) != len(result) {
		return result, fmt.Errorf("thales: external mu must be 64 bytes, got %d", len(value))
	}
	copy(result[:], value)
	return result, nil
}

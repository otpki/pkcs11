package utimaco

import (
	"errors"
	"fmt"
)

// HBSRandomSource selects the QuantumProtect hash-based-signature key source.
type HBSRandomSource byte

const (
	// HBSRandomPseudo requests the simulator/provider pseudorandom source.
	HBSRandomPseudo HBSRandomSource = 0
	// HBSRandomReal requests the provider's real hardware random source.
	HBSRandomReal HBSRandomSource = 1
)

// HSSGenerateParameters is the compact QuantumProtect HSS/LMS generation
// record: random-source byte, level count, one LMS/LM-OTS byte pair per level,
// and a two-byte big-endian auxiliary-data size.
type HSSGenerateParameters struct {
	RandomSource HBSRandomSource
	LMSTypes     []byte
	LMOTSTypes   []byte
	AuxSize      uint16
}

// MarshalBinary serializes the HSS/LMS generation record.
func (p HSSGenerateParameters) MarshalBinary() ([]byte, error) {
	if len(p.LMSTypes) == 0 || len(p.LMSTypes) > 8 {
		return nil, errors.New("utimaco: HSS requires between 1 and 8 levels")
	}
	if len(p.LMSTypes) != len(p.LMOTSTypes) {
		return nil, errors.New("utimaco: HSS LMS and LM-OTS level counts differ")
	}
	if p.RandomSource != HBSRandomPseudo && p.RandomSource != HBSRandomReal {
		return nil, fmt.Errorf("utimaco: invalid HBS random source %d", p.RandomSource)
	}
	out := make([]byte, 4+2*len(p.LMSTypes))
	out[0] = byte(p.RandomSource)
	out[1] = byte(len(p.LMSTypes))
	offset := 2
	for index := range p.LMSTypes {
		out[offset] = p.LMSTypes[index]
		out[offset+1] = p.LMOTSTypes[index]
		offset += 2
	}
	out[offset] = byte(p.AuxSize >> 8)
	out[offset+1] = byte(p.AuxSize)
	return out, nil
}

// XMSSGenerateParameters is QuantumProtect's fixed five-byte XMSS/XMSSMT
// generation record.
type XMSSGenerateParameters struct {
	RandomSource HBSRandomSource
	MultiTree    bool
	OID          byte
	AuxSize      uint16
}

// MarshalBinary serializes the XMSS/XMSSMT generation record.
func (p XMSSGenerateParameters) MarshalBinary() ([]byte, error) {
	if p.RandomSource != HBSRandomPseudo && p.RandomSource != HBSRandomReal {
		return nil, fmt.Errorf("utimaco: invalid HBS random source %d", p.RandomSource)
	}
	if p.OID == 0 {
		return nil, errors.New("utimaco: XMSS OID selector is required")
	}
	multiTree := byte(0)
	if p.MultiTree {
		multiTree = 1
	}
	return []byte{byte(p.RandomSource), multiTree, p.OID, byte(p.AuxSize >> 8), byte(p.AuxSize)}, nil
}

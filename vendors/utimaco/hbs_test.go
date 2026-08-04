package utimaco

import (
	"bytes"
	"testing"
)

func TestHSSGenerateParameters(t *testing.T) {
	got, err := (HSSGenerateParameters{
		RandomSource: HBSRandomPseudo,
		LMSTypes:     []byte{6, 7},
		LMOTSTypes:   []byte{3, 4},
		AuxSize:      0x1234,
	}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0, 2, 6, 3, 7, 4, 0x12, 0x34}
	if !bytes.Equal(got, want) {
		t.Fatalf("encoding = %x, want %x", got, want)
	}
	if _, err := (HSSGenerateParameters{LMSTypes: []byte{1}, LMOTSTypes: nil}).MarshalBinary(); err == nil {
		t.Fatal("expected level-count error")
	}
}

func TestXMSSGenerateParameters(t *testing.T) {
	got, err := (XMSSGenerateParameters{RandomSource: HBSRandomReal, MultiTree: true, OID: 9, AuxSize: 0x1234}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{1, 1, 9, 0x12, 0x34}
	if !bytes.Equal(got, want) {
		t.Fatalf("encoding = %x, want %x", got, want)
	}
	if _, err := (XMSSGenerateParameters{OID: 0}).MarshalBinary(); err == nil {
		t.Fatal("expected missing OID error")
	}
}

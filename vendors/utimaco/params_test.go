package utimaco

import (
	"bytes"
	"testing"
)

func TestQuantumProtectParameterEncodings(t *testing.T) {
	tests := []struct {
		name string
		got  []byte
		want []byte
	}{
		{
			name: "generation",
			got: mustMarshal(t, func() ([]byte, error) {
				return (GenerateParameters{Flags: 1, Set: ParameterSet65Or768}).MarshalBinary()
			}),
			want: []byte{0, 0, 0, 1, 0, 0, 0, 2, 0, 0},
		},
		{
			name: "signature",
			got: mustMarshal(t, func() ([]byte, error) {
				return (SignatureParameters{Flags: MLDSAFlagPreHash, Set: ParameterSet87Or1024}).MarshalBinary()
			}),
			want: []byte{0xf2, 0x04, 0x00, 0x01, 0, 0, 0, 3},
		},
		{
			name: "encapsulation",
			got: mustMarshal(t, func() ([]byte, error) {
				return (EncapsulationParameters{Set: ParameterSet44Or512, PublicKey: []byte{1, 2, 3}}).MarshalBinary()
			}),
			want: []byte{0, 0, 0, 0, 0, 0, 0, 1, 0, 3, 1, 2, 3},
		},
		{
			name: "decapsulation",
			got: mustMarshal(t, func() ([]byte, error) {
				return (DecapsulationParameters{Set: ParameterSet65Or768, Ciphertext: []byte{4, 5}}).MarshalBinary()
			}),
			want: []byte{0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 2, 4, 5},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if !bytes.Equal(test.got, test.want) {
				t.Fatalf("encoding = %x, want %x", test.got, test.want)
			}
		})
	}
}

func TestQuantumProtectParameterValidation(t *testing.T) {
	if _, err := (GenerateParameters{Set: 0}).MarshalBinary(); err == nil {
		t.Fatal("expected invalid parameter-set error")
	}
	if _, err := (EncapsulationParameters{Set: ParameterSet44Or512, PublicKey: make([]byte, 1<<16)}).MarshalBinary(); err == nil {
		t.Fatal("expected oversized public-key error")
	}
}

func mustMarshal(t *testing.T, marshal func() ([]byte, error)) []byte {
	t.Helper()
	value, err := marshal()
	if err != nil {
		t.Fatal(err)
	}
	return value
}

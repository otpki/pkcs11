package raw

import (
	"encoding/binary"
	"testing"
)

func TestNativeStructBuilderLP64AndWindowsLLP64(t *testing.T) {
	tests := []struct {
		name string
		abi  NativeABI
		want int
		ptr  int
	}{
		{"lp64", NativeABI{ULongSize: 8, PointerSize: 8, ByteOrder: binary.LittleEndian}, 32, 16},
		{"windows-llp64-pack1", NativeABI{ULongSize: 4, PointerSize: 8, Pack: 1, ByteOrder: binary.LittleEndian}, 17, 5},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			b := NewNativeStructBuilder(test.abi)
			b.AddULong(7)
			b.AddBool(true)
			b.AddPointer([]byte{1, 2, 3})
			b.AddULong(9)
			layout := b.Layout()
			if len(layout.Root) != test.want {
				t.Fatalf("root size = %d, want %d", len(layout.Root), test.want)
			}
			if len(layout.Pointers) != 1 || layout.Pointers[0].Offset != test.ptr {
				t.Fatalf("pointers = %#v", layout.Pointers)
			}
		})
	}
}

func TestNativeStructBuilderUsesLargestActualFieldAlignment(t *testing.T) {
	abi := NativeABI{ULongSize: 8, PointerSize: 8, ByteOrder: binary.LittleEndian}

	onlyBytes := NewNativeStructBuilder(abi)
	onlyBytes.AddFixed([]byte{1, 2, 3})
	if got := len(onlyBytes.Layout().Root); got != 3 {
		t.Fatalf("fixed-byte-only structure size = %d, want 3", got)
	}

	mixed := NewNativeStructBuilder(abi)
	mixed.AddByte(1)
	mixed.AddULong(2)
	if got := len(mixed.Layout().Root); got != 16 {
		t.Fatalf("byte/CK_ULONG structure size = %d, want 16", got)
	}

	packed := NewNativeStructBuilder(NativeABI{ULongSize: 4, PointerSize: 8, Pack: 1, ByteOrder: binary.LittleEndian})
	packed.AddByte(1)
	packed.AddPointer([]byte{2})
	if got := len(packed.Layout().Root); got != 9 {
		t.Fatalf("packed byte/pointer structure size = %d, want 9", got)
	}
}

func TestWindowsCKULongOverflowPanicsBeforeNativeEncoding(t *testing.T) {
	abi := NativeABI{ULongSize: 4, PointerSize: 8, Pack: 1, ByteOrder: binary.LittleEndian}
	if uint64(^uint32(0)) == uint64(^uint(0)) {
		t.Skip("host uint is not wider than Windows CK_ULONG")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("expected an out-of-range CK_ULONG value to panic")
		}
	}()
	_ = abi.ulongArgument(uint64ToUint(uint64(^uint32(0)) + 1))
}

func uint64ToUint(value uint64) uint { return uint(value) }

package raw

import (
	"encoding/binary"
	"runtime"
	"strconv"
)

// NativeABI describes the C data model used by a PKCS #11 module. The
// supported native transports target little-endian amd64 and arm64. Windows
// uses LLP64 (32-bit CK_ULONG with 64-bit pointers), while Linux and macOS use
// LP64. Unsupported OS/architecture combinations still compile but return
// ErrNativeUnavailable when a module is opened.
type NativeABI struct {
	ULongSize   int
	PointerSize int
	Pack        int
	ByteOrder   binary.ByteOrder
}

// HostNativeABI returns the ABI used by the currently compiled binary.
func HostNativeABI() NativeABI {
	pointerSize := strconv.IntSize / 8
	ulongSize := pointerSize
	pack := 0
	if runtime.GOOS == "windows" {
		ulongSize = 4
		pack = 1
	}
	return NativeABI{ULongSize: ulongSize, PointerSize: pointerSize, Pack: pack, ByteOrder: binary.LittleEndian}
}

// NativePointer is a relocation in a native mechanism parameter. Offset is the
// location of a native pointer in Root. Data is copied into a separate
// backend-owned block and its stable address is written at Offset.
type NativePointer struct {
	Offset int
	Data   []byte
}

// NativeParameterLayout is a pointer-safe description of a native C struct.
// The raw package copies Root and every relocation into one native arena
// immediately before the PKCS #11 call. The cgo transport uses C-owned blocks;
// PureGo uses pinned Go blocks. The complete arena remains alive for the
// operation, including multipart operations whose provider retains the
// mechanism parameter after the Init call returns.
type NativeParameterLayout struct {
	Root     []byte
	Pointers []NativePointer
}

// NativeParameterMarshaler is implemented by typed standard and vendor
// mechanism parameter structures that contain native pointers.
type NativeParameterMarshaler interface {
	MarshalPKCS11Native(NativeABI) (NativeParameterLayout, error)
}

// NativeStructBuilder constructs a native structure with correct LP64/LLP64
// sizing, alignment and pointer relocations.
type NativeStructBuilder struct {
	abi          NativeABI
	root         []byte
	pointers     []NativePointer
	maxAlignment int
}

func NewNativeStructBuilder(abi NativeABI) *NativeStructBuilder {
	if abi.ByteOrder == nil {
		abi.ByteOrder = binary.LittleEndian
	}
	return &NativeStructBuilder{abi: abi, maxAlignment: 1}
}

func (b *NativeStructBuilder) alignment(size int) int {
	if b.abi.Pack > 0 && b.abi.Pack < size {
		return b.abi.Pack
	}
	return size
}

func (b *NativeStructBuilder) align(size int) {
	alignment := b.alignment(size)
	if alignment > b.maxAlignment {
		b.maxAlignment = alignment
	}
	if alignment <= 1 {
		return
	}
	padding := (-len(b.root)) & (alignment - 1)
	if padding > 0 {
		b.root = append(b.root, make([]byte, padding)...)
	}
}

func (b *NativeStructBuilder) AddByte(value byte) {
	b.align(1)
	b.root = append(b.root, value)
}
func (b *NativeStructBuilder) AddBool(value bool) {
	if value {
		b.AddByte(1)
	} else {
		b.AddByte(0)
	}
}

func (b *NativeStructBuilder) AddULong(value uint) {
	b.align(b.abi.ULongSize)
	start := len(b.root)
	b.root = append(b.root, make([]byte, b.abi.ULongSize)...)
	b.abi.putULong(b.root, start, value)
}

func (b *NativeStructBuilder) AddPointer(data []byte) {
	b.align(b.abi.PointerSize)
	offset := len(b.root)
	b.root = append(b.root, make([]byte, b.abi.PointerSize)...)
	if len(data) != 0 {
		b.pointers = append(b.pointers, NativePointer{Offset: offset, Data: append([]byte(nil), data...)})
	}
}

func (b *NativeStructBuilder) AddFixed(data []byte) {
	b.align(1)
	b.root = append(b.root, data...)
}

func (b *NativeStructBuilder) Layout() NativeParameterLayout {
	if b.maxAlignment > 1 {
		padding := (-len(b.root)) & (b.maxAlignment - 1)
		if padding > 0 {
			b.root = append(b.root, make([]byte, padding)...)
		}
	}
	return NativeParameterLayout{Root: append([]byte(nil), b.root...), Pointers: append([]NativePointer(nil), b.pointers...)}
}

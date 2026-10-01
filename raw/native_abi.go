package raw

import (
	"errors"
	"fmt"
	"math"
	"slices"
	"unsafe"
)

// nativeBlock is one backend-owned allocation exposed through a byte view.
// The cgo backend allocates it with calloc; the PureGo backend allocates and
// pins a Go byte slice. Shared ABI encoders do not need to know which ownership
// model produced the block.
type nativeBlock struct {
	pointer uintptr
	bytes   []byte
	release func()
}

// nativeArena owns every allocation needed by one native call or retained
// multipart mechanism. Its zero value is ready for use. Secret buffers are
// wiped before backend-specific release/unpin operations run.
type nativeArena struct {
	blocks  []nativeBlock
	secrets [][]byte
	closed  bool
}

func (a *nativeArena) alloc(length int) (uintptr, []byte, error) {
	if a == nil || a.closed {
		return 0, nil, errors.New("pkcs11: native arena is closed")
	}
	if length < 0 {
		return 0, nil, fmt.Errorf("pkcs11: negative native allocation %d", length)
	}
	if length == 0 {
		return 0, nil, nil
	}

	block, err := allocateNativeBlock(length)
	if err != nil {
		return 0, nil, err
	}
	if block.pointer == 0 || len(block.bytes) != length {
		if block.release != nil {
			block.release()
		}
		return 0, nil, fmt.Errorf("pkcs11: native allocator returned an invalid %d-byte block", length)
	}
	a.blocks = append(a.blocks, block)
	return block.pointer, block.bytes, nil
}

func (a *nativeArena) copy(value []byte) (uintptr, []byte, error) {
	if len(value) == 0 {
		return 0, nil, nil
	}
	pointer, buffer, err := a.alloc(len(value))
	if err != nil {
		return 0, nil, err
	}
	copy(buffer, value)
	return pointer, buffer, nil
}

func (a *nativeArena) copySecret(value []byte) (uintptr, []byte, error) {
	pointer, buffer, err := a.copy(value)
	if err == nil && len(buffer) != 0 {
		a.secrets = append(a.secrets, buffer)
	}
	return pointer, buffer, err
}

func (a *nativeArena) close() {
	if a == nil || a.closed {
		return
	}
	a.closed = true

	// Wipe credentials and secret inputs while the native memory is still valid.
	for _, secret := range a.secrets {
		clear(secret)
	}

	// Release in reverse allocation order. This is not required by Cryptoki,
	// but it mirrors ordinary stack-like ownership and keeps nested relocations
	// alive until their parent structures are no longer observable.
	for _, block := range slices.Backward(a.blocks) {
		if release := block.release; release != nil {
			release()
		}
	}
	a.blocks = nil
	a.secrets = nil
}

func nativePointer(value []byte) uintptr {
	if len(value) == 0 {
		return 0
	}
	return uintptr(unsafe.Pointer(&value[0]))
}

// nativeBytes creates a temporary Go view over memory whose address came from
// the native PKCS #11 ABI. The address may refer to a pinned Go allocation, a
// vendor-owned function table, or a vendor-owned output buffer. Converting such
// an address back from uintptr is an intentional FFI boundary that the Go
// checkptr instrumentation cannot prove safe from Go allocation metadata alone.
// Every caller must validate the pointer and bound the length before using the
// returned slice; the slice must never outlive the native allocation or arena
// that owns it.
//
//go:nocheckptr
func nativeBytes(pointer uintptr, length int) []byte {
	if pointer == 0 || length <= 0 {
		return nil
	}

	// Reinterpret the address bits through an unsafe.Pointer-sized value rather
	// than using a direct uintptr-to-pointer conversion. Native module addresses
	// are not derived from Go pointer arithmetic, so the usual provenance rule
	// cannot be expressed to the compiler. Keeping this conversion in one
	// nocheckptr helper makes that exceptional FFI boundary auditable and keeps
	// the rest of the package compatible with go vet's unsafeptr analyzer.
	nativePointer := *(*unsafe.Pointer)(unsafe.Pointer(&pointer))
	return unsafe.Slice((*byte)(nativePointer), length)
}

func copyNativeBytes(pointer uintptr, length uint) []byte {
	if pointer == 0 || length == 0 {
		return nil
	}
	size, err := HostNativeABI().checkedLength(length)
	if err != nil {
		return nil
	}
	return append([]byte(nil), nativeBytes(pointer, size)...)
}

func nativeCString(pointer uintptr) string {
	if pointer == 0 {
		return ""
	}
	// Interface names are required to be NUL-terminated. Bound the scan so a
	// malformed module cannot make the driver walk arbitrary process memory.
	const maximum = 4 << 10
	bytes := nativeBytes(pointer, maximum)
	for index, value := range bytes {
		if value == 0 {
			return string(bytes[:index])
		}
	}
	return string(bytes)
}

func alignUp(offset, alignment int) int {
	if alignment <= 1 {
		return offset
	}
	return (offset + alignment - 1) &^ (alignment - 1)
}

func (abi NativeABI) fieldAlignment(size int) int {
	if size <= 1 {
		return 1
	}
	if abi.Pack > 0 && abi.Pack < size {
		return abi.Pack
	}
	return size
}

// nativeLayoutBuilder calculates C-compatible field offsets for the host data
// model. Windows Cryptoki structures are packed to one byte; Unix targets use
// the natural alignment of CK_ULONG and pointers.
type nativeLayoutBuilder struct {
	abi       NativeABI
	offset    int
	alignment int
}

func newNativeLayoutBuilder(abi NativeABI) *nativeLayoutBuilder {
	return &nativeLayoutBuilder{abi: abi, alignment: 1}
}

func (b *nativeLayoutBuilder) add(size, alignment int) int {
	if b.abi.Pack > 0 && b.abi.Pack < alignment {
		alignment = b.abi.Pack
	}
	if alignment < 1 {
		alignment = 1
	}
	b.offset = alignUp(b.offset, alignment)
	result := b.offset
	b.offset += size
	if alignment > b.alignment {
		b.alignment = alignment
	}
	return result
}

func (b *nativeLayoutBuilder) addByte() int          { return b.add(1, 1) }
func (b *nativeLayoutBuilder) addFixed(size int) int { return b.add(size, 1) }
func (b *nativeLayoutBuilder) addULong() int {
	return b.add(b.abi.ULongSize, b.abi.fieldAlignment(b.abi.ULongSize))
}

func (b *nativeLayoutBuilder) addPointer() int {
	return b.add(b.abi.PointerSize, b.abi.fieldAlignment(b.abi.PointerSize))
}
func (b *nativeLayoutBuilder) addVersion() int { return b.add(2, 1) }
func (b *nativeLayoutBuilder) size() int       { return alignUp(b.offset, b.alignment) }

func (abi NativeABI) requireULong(value uint) {
	if abi.ULongSize == 4 && uint64(value) > uint64(math.MaxUint32) {
		// Raw method signatures historically use uint for Cryptoki scalar values.
		// On Windows, CK_ULONG remains 32 bits even though Go uint is 64 bits.
		// Refuse to silently truncate an invalid value before crossing the ABI.
		panic(fmt.Sprintf("pkcs11: value %d does not fit 32-bit CK_ULONG", value))
	}
}

func (abi NativeABI) putULong(buffer []byte, offset int, value uint) {
	abi.requireULong(value)
	switch abi.ULongSize {
	case 4:
		abi.ByteOrder.PutUint32(buffer[offset:], uint32(value))
	case 8:
		abi.ByteOrder.PutUint64(buffer[offset:], uint64(value))
	default:
		panic(fmt.Sprintf("pkcs11: unsupported CK_ULONG size %d", abi.ULongSize))
	}
}

func (abi NativeABI) getULong(buffer []byte, offset int) uint {
	switch abi.ULongSize {
	case 4:
		return uint(abi.ByteOrder.Uint32(buffer[offset:]))
	case 8:
		return uint(abi.ByteOrder.Uint64(buffer[offset:]))
	default:
		panic(fmt.Sprintf("pkcs11: unsupported CK_ULONG size %d", abi.ULongSize))
	}
}

func (abi NativeABI) putPointer(buffer []byte, offset int, value uintptr) {
	switch abi.PointerSize {
	case 4:
		abi.ByteOrder.PutUint32(buffer[offset:], uint32(value))
	case 8:
		abi.ByteOrder.PutUint64(buffer[offset:], uint64(value))
	default:
		panic(fmt.Sprintf("pkcs11: unsupported pointer size %d", abi.PointerSize))
	}
}

func (abi NativeABI) getPointer(buffer []byte, offset int) uintptr {
	switch abi.PointerSize {
	case 4:
		return uintptr(abi.ByteOrder.Uint32(buffer[offset:]))
	case 8:
		return uintptr(abi.ByteOrder.Uint64(buffer[offset:]))
	default:
		panic(fmt.Sprintf("pkcs11: unsupported pointer size %d", abi.PointerSize))
	}
}

//nolint:unused // used by the purego backend in native_context_purego.go
func (abi NativeABI) pointerAt(address uintptr) uintptr {
	return abi.getPointer(nativeBytes(address, abi.PointerSize), 0)
}

func (abi NativeABI) ulongArgument(value uint) uintptr {
	abi.requireULong(value)
	if abi.ULongSize == 4 {
		return uintptr(uint32(value))
	}
	return uintptr(value)
}

//nolint:unused // used by the purego backend in native_context_purego.go
func (abi NativeABI) ulongResult(value uintptr) uint {
	if abi.ULongSize == 4 {
		return uint(uint32(value))
	}
	return uint(value)
}

func (abi NativeABI) checkedLength(value uint) (int, error) {
	if uint64(value) > uint64(math.MaxInt) {
		return 0, fmt.Errorf("pkcs11: native length %d exceeds Go address space", value)
	}
	return int(value), nil
}

func (abi NativeABI) maxULong() uint {
	if abi.ULongSize == 4 {
		return uint(^uint32(0))
	}
	return ^uint(0)
}

func checkedProduct(left, right uint) (uint, error) {
	if right != 0 && left > ^uint(0)/right {
		return 0, fmt.Errorf("pkcs11: native allocation size overflow: %d * %d", left, right)
	}
	product := left * right
	if _, err := HostNativeABI().checkedLength(product); err != nil {
		return 0, err
	}
	return product, nil
}

// functionTableFirstPointerOffset returns the offset of C_Initialize after the
// two-byte CK_VERSION header and any ABI-required alignment.
func functionTableFirstPointerOffset(abi NativeABI) int {
	builder := newNativeLayoutBuilder(abi)
	builder.addVersion()
	return builder.addPointer()
}

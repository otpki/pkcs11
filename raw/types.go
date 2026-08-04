package raw

import "strings"

type SlotID uint
type SessionHandle uint
type ObjectHandle uint
type MechanismType uint
type AttributeType uint
type Flags uint
type UserType uint
type State uint
type Notification uint
type ValidationFlagsType uint

type Version struct {
	Major uint8
	Minor uint8
}

func (v Version) AtLeast(w Version) bool {
	return v.Major > w.Major || (v.Major == w.Major && v.Minor >= w.Minor)
}

type InterfaceInfo struct {
	Name    string
	Version Version
	Flags   uint
}

// FunctionListInfo describes an interface returned by C_GetInterface or
// C_GetFunctionList. Pointer is an opaque native CK_FUNCTION_LIST pointer that
// remains valid only while the owning Ctx is open. It is provided for complete
// ABI access and diagnostics; normal callers should use Ctx methods.
type FunctionListInfo struct {
	InterfaceInfo
	Pointer uintptr
}

type Info struct {
	CryptokiVersion    Version
	ManufacturerID     string
	Flags              uint
	LibraryDescription string
	LibraryVersion     Version
}

type SlotInfo struct {
	SlotDescription string
	ManufacturerID  string
	Flags           uint
	HardwareVersion Version
	FirmwareVersion Version
}

type TokenInfo struct {
	Label              string
	ManufacturerID     string
	Model              string
	SerialNumber       string
	Flags              uint
	MaxSessionCount    uint
	SessionCount       uint
	MaxRwSessionCount  uint
	RwSessionCount     uint
	MaxPinLen          uint
	MinPinLen          uint
	TotalPublicMemory  uint
	FreePublicMemory   uint
	TotalPrivateMemory uint
	FreePrivateMemory  uint
	HardwareVersion    Version
	FirmwareVersion    Version
	UTCTime            string
}

type SessionInfo struct {
	SlotID      SlotID
	State       State
	Flags       uint
	DeviceError uint
}

type MechanismInfo struct {
	MinKeySize uint
	MaxKeySize uint
	Flags      uint
}

type AsyncData struct {
	Version          uint
	Value            []byte
	Scalar           uint
	Object           ObjectHandle
	AdditionalObject ObjectHandle
}

func trimPadded(v []byte) string {
	return strings.TrimRight(string(v), " \x00")
}

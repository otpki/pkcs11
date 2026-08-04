//go:build windows

package raw

// Windows uses LLP64: CK_ULONG is 32 bits even when pointers and Go uint are
// 64 bits. Keep the public sentinel a constant while preserving that ABI value.
const ckUnavailableInformation uint = 0xffffffff

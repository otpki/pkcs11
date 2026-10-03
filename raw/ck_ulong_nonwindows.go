//go:build !windows

package raw

// Unix PKCS #11 ABIs define CK_ULONG as unsigned long. On every supported
// 64-bit Unix target, that is the same width as Go uint. the expression also
// remains correct when the package is compiled for a 32-bit diagnostic target.
const ckUnavailableInformation uint = ^uint(0)

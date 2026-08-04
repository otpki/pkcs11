#ifndef OTPKI_PKCS11_PLATFORM_H
#define OTPKI_PKCS11_PLATFORM_H 1

/*
 * The pinned OASIS headers deliberately leave five declaration macros to the
 * consumer. These definitions describe the ordinary C ABI used by the cgo
 * bridge, layout probes, and mock modules in this repository. The shared Go
 * marshaller reproduces the same validated layouts for both native transports.
 */
#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DEFINE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif

/*
 * Cryptoki uses one-byte structure packing on Windows. CRYPTOKI_FORCE_WIN32 is
 * used by cross-platform ABI tests to validate the packed LLP64 layout without
 * requiring a Windows C compiler.
 */
#if (defined(_WIN32) || defined(CRYPTOKI_FORCE_WIN32)) && !defined(PACKED_STRUCTURES)
#define PACKED_STRUCTURES 1
#endif

#ifdef PACKED_STRUCTURES
#pragma pack(push, 1)
#include "oasis/3.2/pkcs11.h"
#pragma pack(pop)
#else
#include "oasis/3.2/pkcs11.h"
#endif


#endif /* OTPKI_PKCS11_PLATFORM_H */

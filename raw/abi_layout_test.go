package raw

import (
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

const nativeABIProbeSource = `
#include <stdio.h>
#include <stddef.h>
#include "platform.h"
#define SZ(T) printf("size.%s=%zu\n", #T, sizeof(T))
#define OF(T,F) printf("off.%s.%s=%zu\n", #T, #F, offsetof(T,F))
int main(void) {
  SZ(CK_INFO); OF(CK_INFO,cryptokiVersion); OF(CK_INFO,manufacturerID); OF(CK_INFO,flags); OF(CK_INFO,libraryDescription); OF(CK_INFO,libraryVersion);
  SZ(CK_SLOT_INFO); OF(CK_SLOT_INFO,slotDescription); OF(CK_SLOT_INFO,manufacturerID); OF(CK_SLOT_INFO,flags); OF(CK_SLOT_INFO,hardwareVersion); OF(CK_SLOT_INFO,firmwareVersion);
  SZ(CK_TOKEN_INFO); OF(CK_TOKEN_INFO,label); OF(CK_TOKEN_INFO,manufacturerID); OF(CK_TOKEN_INFO,model); OF(CK_TOKEN_INFO,serialNumber); OF(CK_TOKEN_INFO,flags); OF(CK_TOKEN_INFO,ulMaxSessionCount); OF(CK_TOKEN_INFO,ulFreePrivateMemory); OF(CK_TOKEN_INFO,hardwareVersion); OF(CK_TOKEN_INFO,firmwareVersion); OF(CK_TOKEN_INFO,utcTime);
  SZ(CK_SESSION_INFO); OF(CK_SESSION_INFO,slotID); OF(CK_SESSION_INFO,state); OF(CK_SESSION_INFO,flags); OF(CK_SESSION_INFO,ulDeviceError);
  SZ(CK_MECHANISM_INFO); OF(CK_MECHANISM_INFO,ulMinKeySize); OF(CK_MECHANISM_INFO,ulMaxKeySize); OF(CK_MECHANISM_INFO,flags);
  SZ(CK_ATTRIBUTE); OF(CK_ATTRIBUTE,type); OF(CK_ATTRIBUTE,pValue); OF(CK_ATTRIBUTE,ulValueLen);
  SZ(CK_MECHANISM); OF(CK_MECHANISM,mechanism); OF(CK_MECHANISM,pParameter); OF(CK_MECHANISM,ulParameterLen);
  SZ(CK_INTERFACE); OF(CK_INTERFACE,pInterfaceName); OF(CK_INTERFACE,pFunctionList); OF(CK_INTERFACE,flags);
  SZ(CK_C_INITIALIZE_ARGS); OF(CK_C_INITIALIZE_ARGS,CreateMutex); OF(CK_C_INITIALIZE_ARGS,flags); OF(CK_C_INITIALIZE_ARGS,pReserved);
  SZ(CK_RSA_PKCS_PSS_PARAMS); OF(CK_RSA_PKCS_PSS_PARAMS,hashAlg); OF(CK_RSA_PKCS_PSS_PARAMS,mgf); OF(CK_RSA_PKCS_PSS_PARAMS,sLen);
  SZ(CK_RSA_PKCS_OAEP_PARAMS); OF(CK_RSA_PKCS_OAEP_PARAMS,hashAlg); OF(CK_RSA_PKCS_OAEP_PARAMS,mgf); OF(CK_RSA_PKCS_OAEP_PARAMS,source); OF(CK_RSA_PKCS_OAEP_PARAMS,pSourceData); OF(CK_RSA_PKCS_OAEP_PARAMS,ulSourceDataLen);
  SZ(CK_AES_CTR_PARAMS); OF(CK_AES_CTR_PARAMS,ulCounterBits); OF(CK_AES_CTR_PARAMS,cb);
  SZ(CK_GCM_PARAMS); OF(CK_GCM_PARAMS,pIv); OF(CK_GCM_PARAMS,ulIvLen); OF(CK_GCM_PARAMS,ulIvBits); OF(CK_GCM_PARAMS,pAAD); OF(CK_GCM_PARAMS,ulAADLen); OF(CK_GCM_PARAMS,ulTagBits);
  SZ(CK_ECDH1_DERIVE_PARAMS); OF(CK_ECDH1_DERIVE_PARAMS,kdf); OF(CK_ECDH1_DERIVE_PARAMS,ulSharedDataLen); OF(CK_ECDH1_DERIVE_PARAMS,pSharedData); OF(CK_ECDH1_DERIVE_PARAMS,ulPublicDataLen); OF(CK_ECDH1_DERIVE_PARAMS,pPublicData);
  SZ(CK_EDDSA_PARAMS); OF(CK_EDDSA_PARAMS,phFlag); OF(CK_EDDSA_PARAMS,ulContextDataLen); OF(CK_EDDSA_PARAMS,pContextData);
  SZ(CK_SIGN_ADDITIONAL_CONTEXT); OF(CK_SIGN_ADDITIONAL_CONTEXT,hedgeVariant); OF(CK_SIGN_ADDITIONAL_CONTEXT,pContext); OF(CK_SIGN_ADDITIONAL_CONTEXT,ulContextLen);
  SZ(CK_HASH_SIGN_ADDITIONAL_CONTEXT); OF(CK_HASH_SIGN_ADDITIONAL_CONTEXT,hedgeVariant); OF(CK_HASH_SIGN_ADDITIONAL_CONTEXT,pContext); OF(CK_HASH_SIGN_ADDITIONAL_CONTEXT,ulContextLen); OF(CK_HASH_SIGN_ADDITIONAL_CONTEXT,hash);
  SZ(CK_ASYNC_DATA); OF(CK_ASYNC_DATA,ulVersion); OF(CK_ASYNC_DATA,pValue); OF(CK_ASYNC_DATA,ulValue); OF(CK_ASYNC_DATA,hObject); OF(CK_ASYNC_DATA,hAdditionalObject);
  SZ(CK_FUNCTION_LIST); OF(CK_FUNCTION_LIST,version); OF(CK_FUNCTION_LIST,C_Initialize); OF(CK_FUNCTION_LIST,C_WaitForSlotEvent);
  SZ(CK_FUNCTION_LIST_3_0); OF(CK_FUNCTION_LIST_3_0,C_GetInterfaceList); OF(CK_FUNCTION_LIST_3_0,C_MessageVerifyFinal);
  SZ(CK_FUNCTION_LIST_3_2); OF(CK_FUNCTION_LIST_3_2,C_EncapsulateKey); OF(CK_FUNCTION_LIST_3_2,C_UnwrapKeyAuthenticated);
  return 0;
}
`

func addStandardParameterLayoutFacts(facts map[string]int, abi NativeABI) {
	builder := newNativeLayoutBuilder(abi)
	facts["off.CK_RSA_PKCS_PSS_PARAMS.hashAlg"] = builder.addULong()
	facts["off.CK_RSA_PKCS_PSS_PARAMS.mgf"] = builder.addULong()
	facts["off.CK_RSA_PKCS_PSS_PARAMS.sLen"] = builder.addULong()
	facts["size.CK_RSA_PKCS_PSS_PARAMS"] = builder.size()

	builder = newNativeLayoutBuilder(abi)
	facts["off.CK_RSA_PKCS_OAEP_PARAMS.hashAlg"] = builder.addULong()
	facts["off.CK_RSA_PKCS_OAEP_PARAMS.mgf"] = builder.addULong()
	facts["off.CK_RSA_PKCS_OAEP_PARAMS.source"] = builder.addULong()
	facts["off.CK_RSA_PKCS_OAEP_PARAMS.pSourceData"] = builder.addPointer()
	facts["off.CK_RSA_PKCS_OAEP_PARAMS.ulSourceDataLen"] = builder.addULong()
	facts["size.CK_RSA_PKCS_OAEP_PARAMS"] = builder.size()

	builder = newNativeLayoutBuilder(abi)
	facts["off.CK_AES_CTR_PARAMS.ulCounterBits"] = builder.addULong()
	facts["off.CK_AES_CTR_PARAMS.cb"] = builder.addFixed(16)
	facts["size.CK_AES_CTR_PARAMS"] = builder.size()

	gcm := nativeGCMParameterLayout(abi)
	facts["off.CK_GCM_PARAMS.pIv"] = gcm.iv
	facts["off.CK_GCM_PARAMS.ulIvLen"] = gcm.ivLength
	facts["off.CK_GCM_PARAMS.ulIvBits"] = gcm.ivBits
	facts["off.CK_GCM_PARAMS.pAAD"] = gcm.aad
	facts["off.CK_GCM_PARAMS.ulAADLen"] = gcm.aadLength
	facts["off.CK_GCM_PARAMS.ulTagBits"] = gcm.tagBits
	facts["size.CK_GCM_PARAMS"] = gcm.size

	builder = newNativeLayoutBuilder(abi)
	facts["off.CK_ECDH1_DERIVE_PARAMS.kdf"] = builder.addULong()
	facts["off.CK_ECDH1_DERIVE_PARAMS.ulSharedDataLen"] = builder.addULong()
	facts["off.CK_ECDH1_DERIVE_PARAMS.pSharedData"] = builder.addPointer()
	facts["off.CK_ECDH1_DERIVE_PARAMS.ulPublicDataLen"] = builder.addULong()
	facts["off.CK_ECDH1_DERIVE_PARAMS.pPublicData"] = builder.addPointer()
	facts["size.CK_ECDH1_DERIVE_PARAMS"] = builder.size()

	builder = newNativeLayoutBuilder(abi)
	facts["off.CK_EDDSA_PARAMS.phFlag"] = builder.addByte()
	facts["off.CK_EDDSA_PARAMS.ulContextDataLen"] = builder.addULong()
	facts["off.CK_EDDSA_PARAMS.pContextData"] = builder.addPointer()
	facts["size.CK_EDDSA_PARAMS"] = builder.size()

	builder = newNativeLayoutBuilder(abi)
	facts["off.CK_SIGN_ADDITIONAL_CONTEXT.hedgeVariant"] = builder.addULong()
	facts["off.CK_SIGN_ADDITIONAL_CONTEXT.pContext"] = builder.addPointer()
	facts["off.CK_SIGN_ADDITIONAL_CONTEXT.ulContextLen"] = builder.addULong()
	facts["size.CK_SIGN_ADDITIONAL_CONTEXT"] = builder.size()

	builder = newNativeLayoutBuilder(abi)
	facts["off.CK_HASH_SIGN_ADDITIONAL_CONTEXT.hedgeVariant"] = builder.addULong()
	facts["off.CK_HASH_SIGN_ADDITIONAL_CONTEXT.pContext"] = builder.addPointer()
	facts["off.CK_HASH_SIGN_ADDITIONAL_CONTEXT.ulContextLen"] = builder.addULong()
	facts["off.CK_HASH_SIGN_ADDITIONAL_CONTEXT.hash"] = builder.addULong()
	facts["size.CK_HASH_SIGN_ADDITIONAL_CONTEXT"] = builder.size()
}

func sharedLayoutFacts(abi NativeABI) map[string]int {
	facts := make(map[string]int)
	info := nativeInfoLayout(abi)
	facts["off.CK_INFO.cryptokiVersion"] = info.cryptoki
	facts["off.CK_INFO.manufacturerID"] = info.manufacturer
	facts["off.CK_INFO.flags"] = info.flags
	facts["off.CK_INFO.libraryDescription"] = info.description
	facts["off.CK_INFO.libraryVersion"] = info.libraryVersion
	facts["size.CK_INFO"] = info.size

	slot := nativeSlotInfoLayout(abi)
	facts["off.CK_SLOT_INFO.slotDescription"] = slot.description
	facts["off.CK_SLOT_INFO.manufacturerID"] = slot.manufacturer
	facts["off.CK_SLOT_INFO.flags"] = slot.flags
	facts["off.CK_SLOT_INFO.hardwareVersion"] = slot.hardware
	facts["off.CK_SLOT_INFO.firmwareVersion"] = slot.firmware
	facts["size.CK_SLOT_INFO"] = slot.size

	token := nativeTokenInfoLayout(abi)
	facts["off.CK_TOKEN_INFO.label"] = token.label
	facts["off.CK_TOKEN_INFO.manufacturerID"] = token.manufacturer
	facts["off.CK_TOKEN_INFO.model"] = token.model
	facts["off.CK_TOKEN_INFO.serialNumber"] = token.serial
	facts["off.CK_TOKEN_INFO.flags"] = token.flags
	facts["off.CK_TOKEN_INFO.ulMaxSessionCount"] = token.ulongs[0]
	facts["off.CK_TOKEN_INFO.ulFreePrivateMemory"] = token.ulongs[9]
	facts["off.CK_TOKEN_INFO.hardwareVersion"] = token.hardware
	facts["off.CK_TOKEN_INFO.firmwareVersion"] = token.firmware
	facts["off.CK_TOKEN_INFO.utcTime"] = token.utc
	facts["size.CK_TOKEN_INFO"] = token.size

	session := nativeSessionInfoLayout(abi)
	facts["off.CK_SESSION_INFO.slotID"] = session.slot
	facts["off.CK_SESSION_INFO.state"] = session.state
	facts["off.CK_SESSION_INFO.flags"] = session.flags
	facts["off.CK_SESSION_INFO.ulDeviceError"] = session.deviceError
	facts["size.CK_SESSION_INFO"] = session.size

	mechanismInfo := nativeMechanismInfoLayout(abi)
	facts["off.CK_MECHANISM_INFO.ulMinKeySize"] = mechanismInfo.min
	facts["off.CK_MECHANISM_INFO.ulMaxKeySize"] = mechanismInfo.max
	facts["off.CK_MECHANISM_INFO.flags"] = mechanismInfo.flags
	facts["size.CK_MECHANISM_INFO"] = mechanismInfo.size

	attribute := nativeAttributeLayout(abi)
	facts["off.CK_ATTRIBUTE.type"] = attribute.typ
	facts["off.CK_ATTRIBUTE.pValue"] = attribute.value
	facts["off.CK_ATTRIBUTE.ulValueLen"] = attribute.length
	facts["size.CK_ATTRIBUTE"] = attribute.size

	mechanism := nativeMechanismLayout(abi)
	facts["off.CK_MECHANISM.mechanism"] = mechanism.mechanism
	facts["off.CK_MECHANISM.pParameter"] = mechanism.parameter
	facts["off.CK_MECHANISM.ulParameterLen"] = mechanism.length
	facts["size.CK_MECHANISM"] = mechanism.size

	iface := interfaceStructLayout(abi)
	facts["off.CK_INTERFACE.pInterfaceName"] = iface.name
	facts["off.CK_INTERFACE.pFunctionList"] = iface.functionList
	facts["off.CK_INTERFACE.flags"] = iface.flags
	facts["size.CK_INTERFACE"] = iface.size

	initialize := initializeArgsLayout(abi)
	facts["off.CK_C_INITIALIZE_ARGS.CreateMutex"] = 0
	facts["off.CK_C_INITIALIZE_ARGS.flags"] = initialize.flags
	facts["off.CK_C_INITIALIZE_ARGS.pReserved"] = initialize.flags + abi.ULongSize
	facts["size.CK_C_INITIALIZE_ARGS"] = initialize.size

	addStandardParameterLayoutFacts(facts, abi)

	async := nativeAsyncDataLayout(abi)
	facts["off.CK_ASYNC_DATA.ulVersion"] = async.version
	facts["off.CK_ASYNC_DATA.pValue"] = async.value
	facts["off.CK_ASYNC_DATA.ulValue"] = async.scalar
	facts["off.CK_ASYNC_DATA.hObject"] = async.object
	facts["off.CK_ASYNC_DATA.hAdditionalObject"] = async.additionalObject
	facts["size.CK_ASYNC_DATA"] = async.size

	first := functionTableFirstPointerOffset(abi)
	baseCount := int(functionGetInterfaceList)
	v30Count := int(functionEncapsulateKey)
	v32Count := int(functionCount)
	facts["off.CK_FUNCTION_LIST.version"] = 0
	facts["off.CK_FUNCTION_LIST.C_Initialize"] = first
	facts["off.CK_FUNCTION_LIST.C_WaitForSlotEvent"] = first + (baseCount-1)*abi.PointerSize
	facts["size.CK_FUNCTION_LIST"] = first + baseCount*abi.PointerSize
	facts["off.CK_FUNCTION_LIST_3_0.C_GetInterfaceList"] = first + baseCount*abi.PointerSize
	facts["off.CK_FUNCTION_LIST_3_0.C_MessageVerifyFinal"] = first + (v30Count-1)*abi.PointerSize
	facts["size.CK_FUNCTION_LIST_3_0"] = first + v30Count*abi.PointerSize
	facts["off.CK_FUNCTION_LIST_3_2.C_EncapsulateKey"] = first + v30Count*abi.PointerSize
	facts["off.CK_FUNCTION_LIST_3_2.C_UnwrapKeyAuthenticated"] = first + (v32Count-1)*abi.PointerSize
	facts["size.CK_FUNCTION_LIST_3_2"] = first + v32Count*abi.PointerSize
	return facts
}

func compileNativeABIProbe(t *testing.T) map[string]int {
	t.Helper()
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("native C ABI probe currently runs on Unix hosts")
	}
	compiler := os.Getenv("CC")
	if compiler == "" {
		compiler = "cc"
	}
	if _, err := exec.LookPath(compiler); err != nil {
		t.Skipf("C compiler is unavailable: %v", err)
	}
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	source := filepath.Join(directory, "abi_probe.c")
	binary := filepath.Join(directory, "abi_probe")
	if err := os.WriteFile(source, []byte(nativeABIProbeSource), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(compiler, "-std=c11", "-I", filepath.Join(workingDirectory, "internal", "cryptoki"), source, "-o", binary)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compile native ABI probe: %v\n%s", err, output)
	}
	output, err := exec.Command(binary).Output()
	if err != nil {
		t.Fatalf("run native ABI probe: %v", err)
	}
	facts := make(map[string]int)
	for line := range strings.Lines(string(output)) {
		line = strings.TrimSuffix(line, "\n")
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("malformed ABI probe line %q", line)
		}
		parsed, err := strconv.Atoi(value)
		if err != nil {
			t.Fatalf("parse ABI probe line %q: %v", line, err)
		}
		facts[key] = parsed
	}
	return facts
}

func TestSharedLayoutsMatchPinnedOASISHeaders(t *testing.T) {
	actual := sharedLayoutFacts(HostNativeABI())
	native := compileNativeABIProbe(t)
	for name, want := range native {
		got, ok := actual[name]
		if !ok {
			t.Errorf("shared native layout does not define %s", name)
			continue
		}
		if got != want {
			t.Errorf("%s = %d, want native C offset/size %d", name, got, want)
		}
	}
	for name := range actual {
		if _, ok := native[name]; !ok {
			t.Errorf("native ABI probe does not cover %s", name)
		}
	}
}

func TestPinnedHeadersCompileForWindowsLLP64(t *testing.T) {
	compiler, err := exec.LookPath("clang")
	if err != nil {
		t.Skipf("Clang is unavailable: %v", err)
	}
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(workingDirectory, "internal", "cryptoki", "abi_layout_test.c")
	include := filepath.Join(workingDirectory, "internal", "cryptoki")
	for _, target := range []string{"x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc"} {
		t.Run(target, func(t *testing.T) {
			command := exec.Command(
				compiler,
				"--target="+target,
				"-std=c11",
				"-Wall",
				"-Wextra",
				"-Werror",
				"-fdeclspec",
				"-DCRYPTOKI_FORCE_WIN32",
				"-I", include,
				"-fsyntax-only", source,
			)
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("compile Windows LLP64 ABI assertions: %v\n%s", err, output)
			}
		})
	}
}

func TestWindowsLLP64PackedLayout(t *testing.T) {
	abi := NativeABI{ULongSize: 4, PointerSize: 8, Pack: 1, ByteOrder: binary.LittleEndian}
	facts := sharedLayoutFacts(abi)
	expected := map[string]int{
		"size.CK_INFO": 72, "off.CK_INFO.flags": 34, "off.CK_INFO.libraryDescription": 38,
		"size.CK_SLOT_INFO": 104, "off.CK_SLOT_INFO.flags": 96, "off.CK_SLOT_INFO.hardwareVersion": 100,
		"size.CK_TOKEN_INFO": 160, "off.CK_TOKEN_INFO.flags": 96, "off.CK_TOKEN_INFO.ulMaxSessionCount": 100, "off.CK_TOKEN_INFO.ulFreePrivateMemory": 136, "off.CK_TOKEN_INFO.utcTime": 144,
		"size.CK_SESSION_INFO": 16, "size.CK_MECHANISM_INFO": 12,
		"size.CK_ATTRIBUTE": 16, "off.CK_ATTRIBUTE.pValue": 4, "off.CK_ATTRIBUTE.ulValueLen": 12,
		"size.CK_MECHANISM": 16, "off.CK_MECHANISM.pParameter": 4, "off.CK_MECHANISM.ulParameterLen": 12,
		"size.CK_INTERFACE": 20, "off.CK_INTERFACE.pFunctionList": 8, "off.CK_INTERFACE.flags": 16,
		"size.CK_C_INITIALIZE_ARGS": 44, "off.CK_C_INITIALIZE_ARGS.flags": 32, "off.CK_C_INITIALIZE_ARGS.pReserved": 36,
		"size.CK_RSA_PKCS_PSS_PARAMS":  12,
		"size.CK_RSA_PKCS_OAEP_PARAMS": 24, "off.CK_RSA_PKCS_OAEP_PARAMS.pSourceData": 12, "off.CK_RSA_PKCS_OAEP_PARAMS.ulSourceDataLen": 20,
		"size.CK_AES_CTR_PARAMS": 20, "off.CK_AES_CTR_PARAMS.cb": 4,
		"size.CK_GCM_PARAMS": 32, "off.CK_GCM_PARAMS.ulIvLen": 8, "off.CK_GCM_PARAMS.pAAD": 16, "off.CK_GCM_PARAMS.ulTagBits": 28,
		"size.CK_ECDH1_DERIVE_PARAMS": 28, "off.CK_ECDH1_DERIVE_PARAMS.pSharedData": 8, "off.CK_ECDH1_DERIVE_PARAMS.pPublicData": 20,
		"size.CK_EDDSA_PARAMS": 13, "off.CK_EDDSA_PARAMS.ulContextDataLen": 1, "off.CK_EDDSA_PARAMS.pContextData": 5,
		"size.CK_SIGN_ADDITIONAL_CONTEXT": 16, "off.CK_SIGN_ADDITIONAL_CONTEXT.pContext": 4,
		"size.CK_HASH_SIGN_ADDITIONAL_CONTEXT": 20, "off.CK_HASH_SIGN_ADDITIONAL_CONTEXT.hash": 16,
		"size.CK_ASYNC_DATA": 24, "off.CK_ASYNC_DATA.pValue": 4,
		"off.CK_FUNCTION_LIST.C_Initialize": 2, "size.CK_FUNCTION_LIST": 546,
		"off.CK_FUNCTION_LIST_3_0.C_GetInterfaceList": 546, "size.CK_FUNCTION_LIST_3_0": 738,
		"off.CK_FUNCTION_LIST_3_2.C_EncapsulateKey": 738, "off.CK_FUNCTION_LIST_3_2.C_UnwrapKeyAuthenticated": 826, "size.CK_FUNCTION_LIST_3_2": 834,
	}
	for name, want := range expected {
		if got := facts[name]; got != want {
			t.Errorf("%s = %d, want %d", name, got, want)
		}
	}
}

func TestNativeUnavailableInformationUsesCKULongWidth(t *testing.T) {
	if got := (NativeABI{ULongSize: 4}).maxULong(); got != uint(^uint32(0)) {
		t.Fatalf("32-bit CK_ULONG maximum = %#x", got)
	}
	if strconv.IntSize == 64 {
		if got := (NativeABI{ULongSize: 8}).maxULong(); got != ^uint(0) {
			t.Fatalf("64-bit CK_ULONG maximum = %#x", got)
		}
	}
}

func TestGeneratedFunctionMetadataMatchesTableBoundaries(t *testing.T) {
	if functionGetInterfaceList != 68 || functionEncapsulateKey != 92 || functionCount != 104 {
		t.Fatalf("function table boundaries = base:%d v3:%d total:%d", functionGetInterfaceList, functionEncapsulateKey, functionCount)
	}
	for id, metadata := range functionTableMetadata {
		if metadata.name == "" {
			t.Errorf("function %d has no name", id)
		}
		if metadata.arguments == 0 && metadata.name != "" {
			// Cryptoki 3.2 currently has no zero-argument function. Keeping this
			// assertion makes an OASIS header update explicit.
			t.Errorf("%s unexpectedly has zero arguments", metadata.name)
		}
	}
}

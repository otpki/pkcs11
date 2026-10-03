/* Load the Rust library using the same C headers an application would use.
 * No proxy or configuration is needed for these interface discovery checks. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>

#define CK_PTR *
#define CK_DECLARE_FUNCTION(result, name) result name
#define CK_DECLARE_FUNCTION_POINTER(result, name) result (*name)
#define CK_CALLBACK_FUNCTION(result, name) result (*name)
#define NULL_PTR 0
#include "../../raw/internal/cryptoki/oasis/3.2/pkcs11.h"

int main(int argc, char **argv) {
    assert(argc == 2);
    void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!library) {
        fprintf(stderr, "%s\n", dlerror());
        return 1;
    }
    CK_C_GetFunctionList legacy = (CK_C_GetFunctionList)dlsym(library, "C_GetFunctionList");
    CK_C_GetInterfaceList list = (CK_C_GetInterfaceList)dlsym(library, "C_GetInterfaceList");
    CK_C_GetInterface get = (CK_C_GetInterface)dlsym(library, "C_GetInterface");
    assert(legacy && list && get);
    CK_FUNCTION_LIST_PTR old = NULL_PTR;
    assert(legacy(&old) == CKR_OK && old);
    assert(old->version.major == 2 && old->version.minor == 40);
    CK_ULONG count = 0;
    assert(list(NULL_PTR, &count) == CKR_OK && count == 4);
    CK_INTERFACE interfaces[4];
    assert(list(interfaces, &count) == CKR_OK && count == 4);
    const CK_BYTE majors[] = {3, 3, 3, 2}, minors[] = {2, 1, 0, 40};
    for (CK_ULONG i = 0; i < count; i++) {
        assert(!strcmp((char *)interfaces[i].pInterfaceName, "PKCS 11"));
        assert(interfaces[i].flags == 0);
        CK_VERSION *version = (CK_VERSION *)interfaces[i].pFunctionList;
        assert(version->major == majors[i] && version->minor == minors[i]);
        CK_INTERFACE_PTR selected = NULL_PTR;
        assert(get((CK_UTF8CHAR_PTR)"PKCS 11", version, &selected, 0) == CKR_OK);
        assert(selected && selected->pFunctionList == interfaces[i].pFunctionList);
    }
    assert(interfaces[3].pFunctionList == old);
    CK_INTERFACE_PTR selected = NULL_PTR;
    assert(get(NULL_PTR, NULL_PTR, &selected, 0) == CKR_OK);
    CK_FUNCTION_LIST_3_2_PTR table = (CK_FUNCTION_LIST_3_2_PTR)selected->pFunctionList;
    assert(table->version.major == 3 && table->version.minor == 2);
    assert(table->C_Initialize == old->C_Initialize);
    /* Compare every field at the offset supplied by the bundled header.
     * C_GetInfo is version-specific, so its address intentionally differs. */
#define CK_PKCS11_FUNCTION_INFO(name) \
    assert(table->name != NULL_PTR); \
    if (strcmp(#name, "C_GetInfo")) assert((void *)table->name == dlsym(library, #name));
#include "../../raw/internal/cryptoki/oasis/3.2/pkcs11f.h"
#undef CK_PKCS11_FUNCTION_INFO
    CK_FLAGS flags = 0;
    assert(table->C_GetSessionValidationFlags(1, 0, &flags) == CKR_CRYPTOKI_NOT_INITIALIZED);
    assert(table->C_UnwrapKeyAuthenticated(1, NULL_PTR, 0, NULL_PTR, 0, NULL_PTR,
           0, NULL_PTR, 0, NULL_PTR) == CKR_CRYPTOKI_NOT_INITIALIZED);
    assert(dlclose(library) == 0);
    puts("PASS: all 104 PKCS#11 3.2 table entries match the bundled C headers");
    return 0;
}

#ifndef P11X_BRIDGE_H
#define P11X_BRIDGE_H 1

#include <stddef.h>
#include <stdint.h>
#include "platform.h"

// State owned by this bridge rather than by the PKCS#11 module. `functions`
// points into the loaded module and must never be freed by this code. It is
// valid only while `library` remains loaded. The selected_* fields describe
// the interface that supplied that table, not necessarily every interface a
// module exports.
typedef struct p11x_ctx {
    void *library;
    void *functions;
    CK_VERSION selected_version;
    CK_FLAGS selected_flags;
    char *selected_name;
    CK_C_GetInterface get_interface;
    CK_C_GetFunctionList get_function_list;
} p11x_ctx;

// Platform-specific dynamic-loader primitives. On failure, the open/symbol
// helpers write a best-effort, NUL-terminated diagnostic into `error`.
void *p11x_dlopen(const char *path, char *error, size_t error_len);
void *p11x_dlsym(void *handle, const char *symbol, char *error, size_t error_len);
void p11x_dlclose(void *handle);

// Load a module and discover its interface-selection entry points. Opening
// does not initialize the module or choose a function table; callers must
// select an interface (or the legacy table) before making PKCS#11 calls.
p11x_ctx *p11x_open(const char *path, char *error, size_t error_len);
// Releases the copied interface name and unloads the module.
void p11x_close(p11x_ctx *ctx);
// Select a PKCS#11 v3 named/versioned interface through C_GetInterface.
CK_RV p11x_select_interface(p11x_ctx *ctx, const char *name,
                            CK_BYTE major, CK_BYTE minor, CK_FLAGS flags);
// Select the pre-v3 default function table through C_GetFunctionList.
CK_RV p11x_select_legacy(p11x_ctx *ctx);
// Read metadata recorded by the successful selection; NULL contexts yield
// zero values (or an empty string) so these accessors are cgo-friendly.
CK_BYTE p11x_version_major(const p11x_ctx *ctx);
CK_BYTE p11x_version_minor(const p11x_ctx *ctx);
CK_FLAGS p11x_interface_flags(const p11x_ctx *ctx);
const char *p11x_interface_name(const p11x_ctx *ctx);

// Return the common function-table prefix. Every selected PKCS#11 interface
// starts with CK_FUNCTION_LIST, so this cast is safe after selection.
static inline CK_FUNCTION_LIST_PTR p11x_base(p11x_ctx *ctx) {
    return ctx && ctx->functions ? (CK_FUNCTION_LIST_PTR)ctx->functions : NULL;
}

// v3.0 and v3.2 extend the base function table. Do not cast an older table:
// accessing an extension member would read past the module-provided object.
static inline CK_FUNCTION_LIST_3_0_PTR p11x_v3(p11x_ctx *ctx) {
    if (!ctx || !ctx->functions || ctx->selected_version.major < 3) return NULL;
    return (CK_FUNCTION_LIST_3_0_PTR)ctx->functions;
}

static inline CK_FUNCTION_LIST_3_2_PTR p11x_v32(p11x_ctx *ctx) {
    if (!ctx || !ctx->functions || ctx->selected_version.major < 3 ||
        (ctx->selected_version.major == 3 && ctx->selected_version.minor < 2)) return NULL;
    return (CK_FUNCTION_LIST_3_2_PTR)ctx->functions;
}

#include "calls_gen.h"

#endif
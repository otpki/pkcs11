#include "bridge.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// The module's interface-name buffer is owned by the module. Keep a private
// copy so metadata remains usable without relying on that buffer's lifetime.
static char *p11x_strdup(const char *value) {
    if (!value) return NULL;
    size_t size = strlen(value) + 1;
    char *copy = (char *)malloc(size);
    if (copy) memcpy(copy, value, size);
    return copy;
}

// Error buffers are optional throughout the bridge. snprintf guarantees that
// a supplied nonzero-length buffer is terminated, including on truncation.
static void p11x_set_error(char *error, size_t error_len, const char *message) {
    if (!error || error_len == 0) return;
    if (!message) message = "unknown dynamic loader error";
    snprintf(error, error_len, "%s", message);
}

// Load only the two PKCS#11 discovery exports. A module may implement either
// the v3 C_GetInterface path or the legacy C_GetFunctionList path.
p11x_ctx *p11x_open(const char *path, char *error, size_t error_len) {
    if (!path || !path[0]) {
        p11x_set_error(error, error_len, "PKCS#11 module path is empty");
        return NULL;
    }

    p11x_ctx *ctx = (p11x_ctx *)calloc(1, sizeof(*ctx));
    if (!ctx) {
        p11x_set_error(error, error_len, "out of memory");
        return NULL;
    }

    ctx->library = p11x_dlopen(path, error, error_len);
    if (!ctx->library) {
        free(ctx);
        return NULL;
    }

    ctx->get_interface = (CK_C_GetInterface)p11x_dlsym(
      ctx->library, "C_GetInterface", NULL, 0);
    ctx->get_function_list = (CK_C_GetFunctionList)p11x_dlsym(
      ctx->library, "C_GetFunctionList", NULL, 0);

    if (!ctx->get_interface && !ctx->get_function_list) {
        p11x_set_error(error, error_len,
            "module exports neither C_GetInterface nor C_GetFunctionList");
        p11x_dlclose(ctx->library);
        free(ctx);
        return NULL;
    }
    return ctx;
}

// Function tables returned by a module are borrowed references. Release the
// copied metadata, unload the library, and never attempt to free the table.
void p11x_close(p11x_ctx *ctx) {
    if (!ctx) return;
    free(ctx->selected_name);
    if (ctx->library) p11x_dlclose(ctx->library);
    memset(ctx, 0, sizeof(*ctx));
    free(ctx);
}

// Ask a v3 module for a particular interface. The module chooses the actual
// table version returned; record that version from its leading base struct.
CK_RV p11x_select_interface(p11x_ctx *ctx, const char *name,
                            CK_BYTE major, CK_BYTE minor, CK_FLAGS flags) {
    if (!ctx || !ctx->get_interface) return CKR_FUNCTION_NOT_SUPPORTED;
    CK_VERSION version = {major, minor};
    CK_INTERFACE_PTR iface = NULL;
    CK_RV rv = ctx->get_interface(
      name && name[0] ? (CK_UTF8CHAR_PTR)name : NULL,
      &version, &iface, flags);
    if (rv != CKR_OK) return rv;
    if (!iface || !iface->pFunctionList) return CKR_GENERAL_ERROR;

    free(ctx->selected_name);
    ctx->selected_name = NULL;
    if (iface->pInterfaceName) {
        ctx->selected_name = p11x_strdup((const char *)iface->pInterfaceName);
    }
    ctx->functions = iface->pFunctionList;
    ctx->selected_version = ((CK_FUNCTION_LIST_PTR)ctx->functions)->version;
    ctx->selected_flags = iface->flags;
    return CKR_OK;
}

// Legacy modules expose one un-named function table. Label it consistently
// for callers inspecting metadata through p11x_interface_name.
CK_RV p11x_select_legacy(p11x_ctx *ctx) {
    if (!ctx || !ctx->get_function_list) return CKR_FUNCTION_NOT_SUPPORTED;
    CK_FUNCTION_LIST_PTR functions = NULL;
    CK_RV rv = ctx->get_function_list(&functions);
    if (rv != CKR_OK) return rv;
    if (!functions) return CKR_GENERAL_ERROR;

    free(ctx->selected_name);
    ctx->selected_name = p11x_strdup("PKCS 11");
    ctx->functions = functions;
    ctx->selected_version = functions->version;
    ctx->selected_flags = 0;
    return CKR_OK;
}

// These accessors intentionally tolerate NULL so Go callers can query a
// failed or not-yet-created context without an extra C-side null check.
CK_BYTE p11x_version_major(const p11x_ctx *ctx) {
    return ctx ? ctx->selected_version.major : 0;
}

CK_BYTE p11x_version_minor(const p11x_ctx *ctx) {
    return ctx ? ctx->selected_version.minor : 0;
}

CK_FLAGS p11x_interface_flags(const p11x_ctx *ctx) {
    return ctx ? ctx->selected_flags : 0;
}

const char *p11x_interface_name(const p11x_ctx *ctx) {
    return ctx && ctx->selected_name ? ctx->selected_name : "";
}

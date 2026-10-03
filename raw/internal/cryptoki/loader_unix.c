//go:build !windows

#include "bridge.h"
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

// Copy loader diagnostics before another dl* call can overwrite dlerror's
// thread-local state. The shared bridge API permits callers to omit it.
static void copy_error(char *error, size_t error_len, const char *message) {
    if (!error || error_len == 0) return;
    snprintf(error, error_len, "%s", message ? message : "dynamic loader error");
}


void *p11x_dlopen(const char *path, char *error, size_t error_len) {
    dlerror();
    // RTLD_NOW reports missing dependencies at load time. RTLD_LOCAL prevents a
    // token module's symbols from unintentionally satisfying later global lookups.
    void *handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!handle) copy_error(error, error_len, dlerror());
    return handle;
}

// POSIX requires clearing dlerror before dlsym, then reading it afterwards:
// NULL can be a valid symbol address and is not alone an error indicator.
void *p11x_dlsym(void *handle, const char *symbol, char *error, size_t error_len) {
    dlerror();
    void *value = dlsym(handle, symbol);
    const char *message = dlerror();
    if (message) {
        copy_error(error, error_len, message);
        return NULL;
    }
    return value;
}

// The bridge guarantees this is only called for a non-null loaded handle.
void p11x_dlclose(void *handle) {
    if (handle) dlclose(handle);
}

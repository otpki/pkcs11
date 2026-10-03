//go:build windows

#include "bridge.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

// Translate a Win32 error code while it is still available to a human-readable
// message. FormatMessage allocates the buffer, so it must be released locally.
static void win_error(char *error, size_t error_len, DWORD code) {
  if (!error || error_len == 0) return;
  char *message = NULL;
  FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                 FORMAT_MESSAGE_IGNORE_INSERTS, NULL, code, 0,
                 (LPSTR)&message, 0, NULL);
  snprintf(error, error_len, "%s", message ? message : "Windows loader error");
  if (message) LocalFree(message);
}

// Module paths enter the Go API as UTF-8. Convert to UTF-16 and use the wide
// loader entry point so non-ASCII paths work independently of the code page.
void *p11x_dlopen(const char *path, char *error, size_t error_len) {
  if (!path) {
    if (error && error_len) snprintf(error, error_len, "%s", "module path is null");
    return NULL;
  }
  int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1,
                                   NULL, 0);
  if (length <= 0) {
    win_error(error, error_len, GetLastError());
    return NULL;
  }
  wchar_t *wide = (wchar_t *)calloc((size_t)length, sizeof(wchar_t));
  if (!wide) {
    if (error && error_len) snprintf(error, error_len, "%s", "out of memory");
    return NULL;
  }
  if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, wide,
                          length) <= 0) {
    DWORD code = GetLastError();
    free(wide);
    win_error(error, error_len, code);
    return NULL;
  }
  HMODULE handle = LoadLibraryW(wide);
  free(wide);
  if (!handle) win_error(error, error_len, GetLastError());
  return (void *)handle;
}

// GetProcAddress returns a FARPROC. this bridge stores all discovered exports
// as opaque pointers and casts them to the p11 signatures in bridge.c.
void *p11x_dlsym(void *handle, const char *symbol, char *error, size_t error_len) {
  FARPROC proc = GetProcAddress((HMODULE)handle, symbol);
  if (!proc) win_error(error, error_len, GetLastError());
  return (void *)proc;
}

// Balance the successful LoadLibraryW call made by p11x_dlopen
void p11x_dlclose(void *handle) {
  if (handle) FreeLibrary((HMODULE)handle);
}

//go:build cgo && !pkcs11_purego && (linux || darwin || windows) && (amd64 || arm64)

package raw

import "testing"

// ensure the backend switching is actually accurate
func TestDefaultBackendUsesCGOWhenEnabled(t *testing.T) {
	if got := ActiveNativeBackend(); got != NativeBackendCGO {
		t.Fatalf("ActiveNativeBackend() = %q, want %q", got, NativeBackendCGO)
	}
	if !NativeAvailable() {
		t.Fatal("cgo backend unexpectedly reports native loading unavailable")
	}
}

//go:build !cgo || pkcs11_purego

package raw

import "testing"

// ensure the backend switching is actually accurate
func TestFallbackBackendUsesPureGo(t *testing.T) {
	if got := ActiveNativeBackend(); got != NativeBackendPureGo {
		t.Fatalf("ActiveNativeBackend() = %q, want %q", got, NativeBackendPureGo)
	}
}

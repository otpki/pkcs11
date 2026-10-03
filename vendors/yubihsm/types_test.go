package yubihsm

import (
	"testing"

	"github.com/otpki/pkcs11/raw"
)

func TestWrapFormatNativeLayout(t *testing.T) {
	abi := raw.HostNativeABI()
	layout, err := WrapFormatTemplate.MarshalPKCS11Native(abi)
	if err != nil {
		t.Fatal(err)
	}
	if len(layout.Root) != abi.ULongSize || len(layout.Pointers) != 0 {
		t.Fatalf("layout = root:%d pointers:%d", len(layout.Root), len(layout.Pointers))
	}
}

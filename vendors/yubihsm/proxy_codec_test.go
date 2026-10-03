package yubihsm

import (
	"testing"

	"github.com/otpki/pkcs11/proxy"
)

func TestWrapFormatProxyCodec(t *testing.T) {
	module := New()
	provider, ok := module.(interface{ ProxyParameterCodecs() []proxy.ParameterCodec })
	if !ok {
		t.Fatal("YubiHSM module does not expose proxy codecs")
	}
	registry, err := proxy.NewCodecRegistry(provider.ProxyParameterCodecs()...)
	if err != nil {
		t.Fatal(err)
	}
	codecs := registry.Descriptors()
	if len(codecs) != 1 || codecs[0].Version != 1 {
		t.Fatalf("codec descriptors = %#v", codecs)
	}
}

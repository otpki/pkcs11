package ibm

import (
	"reflect"
	"testing"

	"github.com/otpki/pkcs11/proxy"
	"github.com/otpki/pkcs11/raw"
)

func TestMLKEMProxyCodecRoundTrip(t *testing.T) {
	module := New()
	provider, ok := module.(interface{ ProxyParameterCodecs() []proxy.ParameterCodec })
	if !ok {
		t.Fatal("IBM module does not expose proxy codecs")
	}
	codecs := provider.ProxyParameterCodecs()
	if len(codecs) != 1 {
		t.Fatalf("proxy codecs = %d, want 1", len(codecs))
	}
	codec := codecs[0]
	if codec.ID() != mlkemProxyCodecID || codec.Version() != 1 {
		t.Fatalf("codec descriptor = %q@%d", codec.ID(), codec.Version())
	}

	input := &MLKEMParams{
		Version: 1, Mode: MLKEMDecapsulate, KDF: raw.CKD_SHA256_KDF,
		Prepend: true, Cipher: []byte{1, 2, 3}, SharedData: []byte{4, 5}, Secret: 42,
	}
	payload, matched, err := codec.Encode(input)
	if err != nil {
		t.Fatal(err)
	}
	if !matched {
		t.Fatal("IBM ML-KEM parameter was not claimed")
	}
	decoded, err := codec.Decode(payload)
	if err != nil {
		t.Fatal(err)
	}
	output, ok := decoded.(*MLKEMParams)
	if !ok {
		t.Fatalf("decoded type = %T", decoded)
	}
	if !reflect.DeepEqual(output, input) {
		t.Fatalf("round trip = %#v, want %#v", output, input)
	}

	if _, matched, err := codec.Encode("not-ibm"); err != nil || matched {
		t.Fatalf("unowned value = matched:%v err:%v", matched, err)
	}
}

package yubihsm

import (
	"encoding/json"
	"errors"

	"github.com/otpki/pkcs11/proxy"
)

const wrapFormatProxyCodecID = "yubihsm:aes-ccm-wrap-format:v1"

type wrapFormatProxyCodec struct{}

func (wrapFormatProxyCodec) ID() string      { return wrapFormatProxyCodecID }
func (wrapFormatProxyCodec) Version() uint32 { return 1 }

func (wrapFormatProxyCodec) Encode(value any) ([]byte, bool, error) {
	var format WrapFormat
	switch typed := value.(type) {
	case WrapFormat:
		format = typed
	case *WrapFormat:
		if typed == nil {
			return nil, true, errors.New("yubihsm: nil wrap format")
		}
		format = *typed
	default:
		return nil, false, nil
	}
	encoded, err := json.Marshal(format)
	return encoded, true, err
}

func (wrapFormatProxyCodec) Decode(payload []byte) (any, error) {
	var format WrapFormat
	if err := json.Unmarshal(payload, &format); err != nil {
		return nil, err
	}
	return format, nil
}

// ProxyParameterCodecs exposes architecture-independent transport for the
// YubiHSM AES-CCM wrap-format selector. The broker still creates the native
// CK_ULONG representation for its own ABI immediately before the local call.
func (*Module) ProxyParameterCodecs() []proxy.ParameterCodec {
	return []proxy.ParameterCodec{wrapFormatProxyCodec{}}
}

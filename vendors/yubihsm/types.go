package yubihsm

import "github.com/otpki/pkcs11/raw"

// WrapFormat selects the YubiHSM AES-CCM wrapping payload format.
type WrapFormat uint

const (
	// WrapFormatOpaque requests the native opaque YubiHSM wrap representation.
	WrapFormatOpaque WrapFormat = iota
	// WrapFormatTemplate requests the template-bearing YubiHSM wrap representation.
	WrapFormatTemplate
)

// MarshalPKCS11Native implements raw.NativeParameterMarshaler.
func (f WrapFormat) MarshalPKCS11Native(abi raw.NativeABI) (raw.NativeParameterLayout, error) {
	builder := raw.NewNativeStructBuilder(abi)
	builder.AddULong(uint(f))
	return builder.Layout(), nil
}

package ibm

import (
	"encoding/json"
	"fmt"

	"github.com/otpki/pkcs11/proxy"
)

const mlkemProxyCodecID = "ibm:hpcs:ml-kem-params:v1"

type mlkemProxyCodec struct{}

func (mlkemProxyCodec) ID() string      { return mlkemProxyCodecID }
func (mlkemProxyCodec) Version() uint32 { return 1 }

func (mlkemProxyCodec) Encode(value any) ([]byte, bool, error) {
	parameters, ok := value.(*MLKEMParams)
	if !ok {
		return nil, false, nil
	}
	if parameters == nil {
		return nil, true, fmt.Errorf("ibm: nil ML-KEM parameters")
	}
	encoded, err := json.Marshal(parameters)
	return encoded, true, err
}

func (mlkemProxyCodec) Decode(payload []byte) (any, error) {
	var parameters MLKEMParams
	if err := json.Unmarshal(payload, &parameters); err != nil {
		return nil, err
	}
	return &parameters, nil
}

// ProxyParameterCodecs exposes architecture-independent transport for IBM's
// pointer-bearing ML-KEM parameter record. Native relocation still occurs only
// on the broker host immediately before the local HSM call.
func (*Module) ProxyParameterCodecs() []proxy.ParameterCodec {
	return []proxy.ParameterCodec{mlkemProxyCodec{}}
}

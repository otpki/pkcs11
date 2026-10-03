package proxy

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"

	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/raw"
)

// ParameterCodec transports a vendor-defined mechanism parameter in a semantic,
// architecture-independent form. Encode returns matched=false when the codec
// does not own value. Decode must return the same logical parameter type that a
// local raw.Module call expects; native ABI marshaling remains on the proxy host.
type ParameterCodec interface {
	// ID is a stable, globally unique semantic codec name.
	ID() string
	// Version changes whenever the payload schema or decoded Go semantics change.
	Version() uint32
	Encode(value any) (payload []byte, matched bool, err error)
	Decode(payload []byte) (any, error)
}

// VendorCodecProvider may be implemented by a VendorModule that exposes
// architecture-independent codecs for proprietary pointer-bearing parameters.
type VendorCodecProvider interface {
	ProxyParameterCodecs() []ParameterCodec
}

func codecsFromVendors(vendors ...pkcs11.VendorModule) []ParameterCodec {
	var result []ParameterCodec
	for _, vendor := range vendors {
		provider, ok := vendor.(VendorCodecProvider)
		if !ok || provider == nil {
			continue
		}
		result = append(result, provider.ProxyParameterCodecs()...)
	}
	return result
}

func combinedCodecs(codecs []ParameterCodec, vendors []pkcs11.VendorModule) []ParameterCodec {
	result := slices.Clone(codecs)
	return append(result, codecsFromVendors(vendors...)...)
}

// CodecDescriptor identifies one semantic vendor-parameter wire schema.
// Client and server descriptor sets must match exactly during the describe handshake.
type CodecDescriptor struct {
	// ID is the codec's globally stable semantic name.
	ID string `json:"id"`
	// Version changes whenever payload encoding or decoded Go semantics change.
	Version uint32 `json:"version"`
}

type codecKey struct {
	id      string
	version uint32
}

// CodecRegistry is an immutable set of versioned vendor parameter codecs.
type CodecRegistry struct {
	ordered []ParameterCodec
	byKey   map[codecKey]ParameterCodec
}

// NewCodecRegistry validates and copies codecs. Codec IDs are part of the wire
// contract and must remain stable across client and server deployments.
func NewCodecRegistry(codecs ...ParameterCodec) (*CodecRegistry, error) {
	registry := &CodecRegistry{byKey: make(map[codecKey]ParameterCodec)}
	for _, codec := range codecs {
		if codec == nil {
			continue
		}
		id := strings.TrimSpace(codec.ID())
		if id == "" {
			return nil, errors.New("pkcs11 proxy: parameter codec ID is required")
		}
		version := codec.Version()
		if version == 0 {
			return nil, fmt.Errorf("pkcs11 proxy: parameter codec %q has version 0", id)
		}
		key := codecKey{id: id, version: version}
		if _, exists := registry.byKey[key]; exists {
			return nil, fmt.Errorf("pkcs11 proxy: duplicate parameter codec %q version %d", id, version)
		}
		registry.byKey[key] = codec
		registry.ordered = append(registry.ordered, codec)
	}
	slices.SortFunc(registry.ordered, func(left, right ParameterCodec) int {
		return cmp.Or(cmp.Compare(left.ID(), right.ID()), cmp.Compare(left.Version(), right.Version()))
	})
	return registry, nil
}

// Descriptors returns the stable codec IDs and versions advertised during handshake.
// Descriptors returns a stable, defensive snapshot used for client/server
// compatibility negotiation and managed-module registry identity.
func (registry *CodecRegistry) Descriptors() []CodecDescriptor {
	if registry == nil {
		return nil
	}
	result := make([]CodecDescriptor, 0, len(registry.ordered))
	for _, codec := range registry.ordered {
		result = append(result, CodecDescriptor{ID: strings.TrimSpace(codec.ID()), Version: codec.Version()})
	}
	return result
}

// codecDescriptorsMissing returns the server-published descriptors the
// client's registry does not implement. Extra client codecs are inert — the
// client drives every invocation, so offering a superset never makes the
// server send a parameter the client cannot decode. The handshake only needs
// the client to cover the server's set.
func codecDescriptorsMissing(client, server []CodecDescriptor) []CodecDescriptor {
	provided := make(map[CodecDescriptor]struct{}, len(client))
	for _, descriptor := range client {
		provided[descriptor] = struct{}{}
	}
	var missing []CodecDescriptor
	for _, descriptor := range server {
		if _, ok := provided[descriptor]; !ok {
			missing = append(missing, descriptor)
		}
	}
	return missing
}

func emptyCodecRegistry() *CodecRegistry {
	return &CodecRegistry{byKey: make(map[codecKey]ParameterCodec)}
}

const (
	parameterNil             = "nil"
	parameterBytes           = "bytes"
	parameterUint            = "uint"
	parameterPSS             = "pkcs11:pss"
	parameterOAEP            = "pkcs11:oaep"
	parameterAESCTR          = "pkcs11:aes-ctr"
	parameterGCM             = "pkcs11:gcm"
	parameterECDH            = "pkcs11:ecdh1"
	parameterEdDSA           = "pkcs11:eddsa"
	parameterSignContext     = "pkcs11:sign-context"
	parameterHashSignContext = "pkcs11:hash-sign-context"
	parameterOpaque          = "pkcs11:opaque-bytes"
	parameterVendorPrefix    = "vendor:"
)

type parameterValue struct {
	Kind         string `json:"kind"`
	Uint         uint64 `json:"uint,omitempty"`
	Data         []byte `json:"data,omitempty"`
	Pointer      bool   `json:"pointer,omitempty"`
	CodecVersion uint32 `json:"codec_version,omitempty"`
}

func encodeJSONParameter(kind string, value any, pointer bool) (parameterValue, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return parameterValue{}, fmt.Errorf("pkcs11 proxy: encode %s parameter: %w", kind, err)
	}
	return parameterValue{Kind: kind, Data: data, Pointer: pointer}, nil
}

func encodeParameter(value any, registry *CodecRegistry) (parameterValue, error) {
	if value == nil {
		return parameterValue{Kind: parameterNil}, nil
	}
	switch typed := value.(type) {
	case []byte:
		return parameterValue{Kind: parameterBytes, Data: slices.Clone(typed)}, nil
	case uint:
		return parameterValue{Kind: parameterUint, Uint: uint64(typed)}, nil
	case raw.PSSParams:
		return encodeJSONParameter(parameterPSS, typed, false)
	case *raw.PSSParams:
		if typed == nil {
			return parameterValue{Kind: parameterNil}, nil
		}
		return encodeJSONParameter(parameterPSS, typed, true)
	case raw.OAEPParams:
		return encodeJSONParameter(parameterOAEP, typed, false)
	case *raw.OAEPParams:
		if typed == nil {
			return parameterValue{Kind: parameterNil}, nil
		}
		return encodeJSONParameter(parameterOAEP, typed, true)
	case raw.AESCTRParams:
		return encodeJSONParameter(parameterAESCTR, typed, false)
	case *raw.AESCTRParams:
		if typed == nil {
			return parameterValue{Kind: parameterNil}, nil
		}
		return encodeJSONParameter(parameterAESCTR, typed, true)
	case raw.GCMParams:
		return encodeJSONParameter(parameterGCM, typed, false)
	case *raw.GCMParams:
		if typed == nil {
			return parameterValue{Kind: parameterNil}, nil
		}
		return encodeJSONParameter(parameterGCM, typed, true)
	case raw.ECDH1DeriveParams:
		return encodeJSONParameter(parameterECDH, typed, false)
	case *raw.ECDH1DeriveParams:
		if typed == nil {
			return parameterValue{Kind: parameterNil}, nil
		}
		return encodeJSONParameter(parameterECDH, typed, true)
	case raw.EdDSAParams:
		return encodeJSONParameter(parameterEdDSA, typed, false)
	case *raw.EdDSAParams:
		if typed == nil {
			return parameterValue{Kind: parameterNil}, nil
		}
		return encodeJSONParameter(parameterEdDSA, typed, true)
	case raw.SignAdditionalContext:
		return encodeJSONParameter(parameterSignContext, typed, false)
	case *raw.SignAdditionalContext:
		if typed == nil {
			return parameterValue{Kind: parameterNil}, nil
		}
		return encodeJSONParameter(parameterSignContext, typed, true)
	case raw.HashSignAdditionalContext:
		return encodeJSONParameter(parameterHashSignContext, typed, false)
	case *raw.HashSignAdditionalContext:
		if typed == nil {
			return parameterValue{Kind: parameterNil}, nil
		}
		return encodeJSONParameter(parameterHashSignContext, typed, true)
	case raw.UnsafeParameter, *raw.UnsafeParameter:
		return parameterValue{}, errors.New("pkcs11 proxy: UnsafeParameter cannot cross a process or ABI boundary")
	}
	// Vendor selectors are often named unsigned integer types whose native ABI is
	// exactly one CK_ULONG. Preserve the semantic integer rather than requiring a
	// codec solely because the Go type has a distinct name.
	reflected := reflect.ValueOf(value)
	if reflected.IsValid() {
		switch reflected.Kind() {
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
			return parameterValue{Kind: parameterUint, Uint: reflected.Uint()}, nil
		}
	}
	if registry == nil {
		registry = emptyCodecRegistry()
	}
	for _, codec := range registry.ordered {
		payload, matched, err := codec.Encode(value)
		if err != nil {
			return parameterValue{}, fmt.Errorf("pkcs11 proxy: encode vendor parameter with %q: %w", codec.ID(), err)
		}
		if matched {
			return parameterValue{Kind: parameterVendorPrefix + codec.ID(), CodecVersion: codec.Version(), Data: payload}, nil
		}
	}
	if marshaler, ok := value.(raw.ParameterMarshaler); ok {
		data, err := marshaler.MarshalPKCS11Parameter()
		if err != nil {
			return parameterValue{}, err
		}
		return parameterValue{Kind: parameterOpaque, Data: slices.Clone(data)}, nil
	}
	if _, ok := value.(raw.NativeParameterMarshaler); ok {
		return parameterValue{}, fmt.Errorf("pkcs11 proxy: native pointer-bearing parameter %T requires a registered semantic ParameterCodec", value)
	}
	return parameterValue{}, fmt.Errorf("pkcs11 proxy: unsupported mechanism parameter %T", value)
}

func decodeJSONParameter[T any](encoded parameterValue) (any, error) {
	var value T
	if err := json.Unmarshal(encoded.Data, &value); err != nil {
		return nil, err
	}
	if encoded.Pointer {
		return &value, nil
	}
	return value, nil
}

func decodeParameter(encoded parameterValue, registry *CodecRegistry) (any, error) {
	switch encoded.Kind {
	case parameterNil:
		return nil, nil
	case parameterBytes, parameterOpaque:
		return slices.Clone(encoded.Data), nil
	case parameterUint:
		if uint64(uint(encoded.Uint)) != encoded.Uint {
			return nil, errors.New("pkcs11 proxy: uint parameter overflows this client")
		}
		return uint(encoded.Uint), nil
	case parameterPSS:
		return decodeJSONParameter[raw.PSSParams](encoded)
	case parameterOAEP:
		return decodeJSONParameter[raw.OAEPParams](encoded)
	case parameterAESCTR:
		return decodeJSONParameter[raw.AESCTRParams](encoded)
	case parameterGCM:
		return decodeJSONParameter[raw.GCMParams](encoded)
	case parameterECDH:
		return decodeJSONParameter[raw.ECDH1DeriveParams](encoded)
	case parameterEdDSA:
		return decodeJSONParameter[raw.EdDSAParams](encoded)
	case parameterSignContext:
		return decodeJSONParameter[raw.SignAdditionalContext](encoded)
	case parameterHashSignContext:
		return decodeJSONParameter[raw.HashSignAdditionalContext](encoded)
	}
	id, ok := strings.CutPrefix(encoded.Kind, parameterVendorPrefix)
	if !ok {
		return nil, fmt.Errorf("pkcs11 proxy: unknown parameter kind %q", encoded.Kind)
	}
	if registry == nil {
		registry = emptyCodecRegistry()
	}
	codec := registry.byKey[codecKey{id: id, version: encoded.CodecVersion}]
	if codec == nil {
		return nil, fmt.Errorf("pkcs11 proxy: server/client does not provide parameter codec %q version %d", id, encoded.CodecVersion)
	}
	return codec.Decode(encoded.Data)
}

func copyParameterUpdate(destination any, source any) {
	switch dst := destination.(type) {
	case *raw.GCMParams:
		switch src := source.(type) {
		case *raw.GCMParams:
			if dst != nil && src != nil {
				*dst = *src
				dst.IV = slices.Clone(src.IV)
				dst.AAD = slices.Clone(src.AAD)
			}
		case raw.GCMParams:
			if dst != nil {
				*dst = src
				dst.IV = slices.Clone(src.IV)
				dst.AAD = slices.Clone(src.AAD)
			}
		}
	default:
		destinationValue := reflect.ValueOf(destination)
		if !destinationValue.IsValid() || destinationValue.Kind() != reflect.Pointer || destinationValue.IsNil() {
			return
		}
		sourceValue := reflect.ValueOf(source)
		if !sourceValue.IsValid() {
			return
		}
		if sourceValue.Kind() == reflect.Pointer {
			if sourceValue.IsNil() {
				return
			}
			sourceValue = sourceValue.Elem()
		}
		if sourceValue.Type().AssignableTo(destinationValue.Elem().Type()) {
			destinationValue.Elem().Set(sourceValue)
		}
	}
}

package proxy

import (
	"context"
	"errors"
	"fmt"

	"github.com/otpki/pkcs11/raw"
)

const protocolVersion uint32 = 3

const (
	methodDescribe = "@describe"
	methodDestroy  = "@destroy"
)

type request struct {
	Version          uint32
	Target           string
	Revision         string
	ClientID         [16]byte
	RequestID        [16]byte
	Epoch            [16]byte
	Method           string
	Arguments        []wireValue
	Auth             []byte
	DeadlineUnixNano int64
}

type parameterUpdate struct {
	Session   uint64
	Operation string
	Parameter parameterValue
}

type argumentUpdate struct {
	Index int
	Value wireValue
}

type response struct {
	Version         uint32
	Epoch           [16]byte
	Results         []wireValue
	ArgumentUpdates []argumentUpdate
	Updates         []parameterUpdate
	Error           *wireError
}

type wireError struct {
	Code           string
	Message        string
	RV             uint64
	HasRV          bool
	OutcomeUnknown bool
}

// ErrOutcomeUnknown means the connection failed after a non-idempotent request
// may have reached the proxy. Retrying could duplicate a key generation,
// signature, object mutation, or stateful operation.
var ErrOutcomeUnknown = errors.New("pkcs11 proxy: operation outcome is unknown")

// RemoteError is a non-CK_RV error reported by the proxy transport or broker.
type RemoteError struct {
	Code    string
	Message string
}

// Error implements error.
// Error formats the broker error code and its sanitized message.
func (e *RemoteError) Error() string {
	if e == nil {
		return "pkcs11 proxy: remote error"
	}
	if e.Code == "" {
		return e.Message
	}
	return fmt.Sprintf("pkcs11 proxy: %s: %s", e.Code, e.Message)
}

func encodeError(err error) *wireError {
	if err == nil {
		return nil
	}
	code := ""
	switch {
	case errors.Is(err, ErrActivationRequired):
		code = "activation_required"
	case errors.Is(err, ErrActivationInconclusive):
		code = "activation_inconclusive"
	case errors.Is(err, ErrClientActivationUnsupported):
		code = "client_activation_unsupported"
	}
	var rv raw.Error
	if errors.As(err, &rv) {
		return &wireError{Code: code, Message: err.Error(), RV: uint64(rv), HasRV: true}
	}
	if code != "" {
		return &wireError{Code: code, Message: err.Error()}
	}
	if errors.Is(err, ErrOutcomeUnknown) {
		return &wireError{Code: "outcome_unknown", Message: err.Error(), OutcomeUnknown: true}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return &wireError{Code: "deadline_exceeded", Message: context.DeadlineExceeded.Error()}
	}
	if errors.Is(err, context.Canceled) {
		return &wireError{Code: "context_canceled", Message: context.Canceled.Error()}
	}
	var remote *RemoteError
	if errors.As(err, &remote) {
		return &wireError{Code: remote.Code, Message: remote.Message}
	}
	return &wireError{Code: "internal", Message: err.Error()}
}

func decodeError(encoded *wireError) error {
	if encoded == nil {
		return nil
	}
	var base error
	if encoded.HasRV {
		if encoded.RV > uint64(^uint(0)) {
			return &RemoteError{Code: "invalid_rv", Message: encoded.Message}
		}
		base = raw.Error(uint(encoded.RV))
	}
	switch encoded.Code {
	case "activation_required":
		if base != nil {
			return errors.Join(ErrActivationRequired, base)
		}
		return ErrActivationRequired
	case "activation_inconclusive":
		if base != nil {
			return errors.Join(ErrActivationInconclusive, base)
		}
		return ErrActivationInconclusive
	case "client_activation_unsupported":
		remote := &RemoteError{Code: encoded.Code, Message: encoded.Message}
		if base != nil {
			return errors.Join(ErrClientActivationUnsupported, base, remote)
		}
		return errors.Join(ErrClientActivationUnsupported, remote)
	}
	if base != nil {
		return base
	}
	if encoded.OutcomeUnknown {
		return fmt.Errorf("%w: %s", ErrOutcomeUnknown, encoded.Message)
	}
	switch encoded.Code {
	case "deadline_exceeded":
		return context.DeadlineExceeded
	case "context_canceled":
		return context.Canceled
	default:
		return &RemoteError{Code: encoded.Code, Message: encoded.Message}
	}
}

type describeResult struct {
	Path      string
	Interface raw.InterfaceInfo
	Epoch     [16]byte
	Codecs    []CodecDescriptor
}

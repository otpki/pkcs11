package proxy

import (
	"context"
	"errors"
	"fmt"

	"github.com/otpki/pkcs11/raw"
)

const protocolVersion uint32 = 1

const (
	methodDescribe   = "@describe"
	methodDestroy    = "@destroy"
	methodListRoutes = "@routes"
	// methodBatch carries a JSON-encoded []batchCall inside a single bytes
	// argument. The broker executes each call through the ordinary request
	// path with a derived request ID, so dedup, authorization, and error
	// handling behave exactly as if the calls had arrived on separate
	// connections — only the round-trips are saved.
	methodBatch = "@batch"
	// maxBatchCalls bounds the calls a single batch envelope may carry.
	maxBatchCalls = 256
)

type request struct {
	Version          uint32
	Target           string
	Revision         string
	ClientID         [16]byte
	RequestID        [16]byte
	ServerID         [16]byte
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
	// Batch carries one result per call when the request method is @batch.
	// Servers only populate it for batch requests, so older clients — which
	// never send @batch — never observe the field.
	Batch []batchResult
}

// batchCall is one method invocation inside a @batch envelope. Arguments are
// wire values exactly as they would appear in a standalone request.
type batchCall struct {
	Method    string
	Arguments []wireValue
}

// batchResult mirrors the per-call fields of response without version or
// epoch; the envelope carries those once for the whole batch.
type batchResult struct {
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

// ErrTargetLost means the logical client can no longer use its pinned proxy
// state. This includes a wrong broker, changed target generation, removed route,
// unreachable pinned replica, or drain race. Open a new Client to recover.
var ErrTargetLost = errors.New("pkcs11 proxy: remote logical target state was lost")

// RemoteError is a non-CK_RV error reported by the proxy transport or broker.
type RemoteError struct {
	Code    string
	Message string
}

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
	if rv, ok := errors.AsType[raw.Error](err); ok {
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
	if remote, ok := errors.AsType[*RemoteError](err); ok {
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
	case "wrong_server", "target_epoch_mismatch", "target_not_found", "revision_mismatch", "server_draining":
		// The remote logical application state is unrecoverable on this
		// process: it either never lived here, was replaced underneath the
		// client, or the draining replica refused to establish it. Callers
		// detect the failure boundary with ErrTargetLost.
		return errors.Join(ErrTargetLost, &RemoteError{Code: encoded.Code, Message: encoded.Message})
	default:
		return &RemoteError{Code: encoded.Code, Message: encoded.Message}
	}
}

type describeResult struct {
	Path      string
	Interface raw.InterfaceInfo
	// ServerID identifies the answering proxy process. Combined with Epoch it
	// fixes the lifetime of the establishing logical client.
	ServerID [16]byte
	Epoch    [16]byte
	// AcceptingNewClients is false while the server is draining: new logical
	// clients must select another endpoint, while already-pinned clients keep
	// using this process until it stops.
	AcceptingNewClients bool
	// Attribute values keep the HSM host's CK_ULONG layout. A native client
	// needs this width to translate integer attributes across Windows/Unix.
	AttributeULongSize    uint
	AttributeLittleEndian bool
	Codecs                []CodecDescriptor
}

// RouteInfo is the broker-published description of one configured route. It
// carries only non-secret token metadata: clients copy ID and Revision into
// proxy.Target to select the route, and the token fields identify which
// physical token the route is bound to. The local module path is deliberately
// never disclosed.
type RouteInfo struct {
	ID       string `json:"id"`
	Revision string `json:"revision"`
	// SlotID is the physical slot the managed client is bound to. Remote
	// clients do not use it — every route presents its token as remote slot 1.
	SlotID         raw.SlotID `json:"slot_id"`
	TokenLabel     string     `json:"token_label"`
	TokenSerial    string     `json:"token_serial"`
	Model          string     `json:"model"`
	ManufacturerID string     `json:"manufacturer_id"`
	// LoginRequired reports the bound token's CKF_LOGIN_REQUIRED flag. when
	// true, callers must complete a PIN login before token operations succeed.
	// Servers older than this field decode it as false, clients that need the
	// definitive value can fall back to the token info.
	LoginRequired bool `json:"login_required"`
}

// routeCatalog is the wire payload returned by the server-scoped @routes method.
type routeCatalog struct {
	Routes []RouteInfo
}

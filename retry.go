package pkcs11

import (
	"errors"
	"time"

	"github.com/otpki/pkcs11/raw"
)

// RecoveryAction describes the minimum managed recovery required after an error.
type RecoveryAction uint8

const (
	// RecoveryNone means the error is returned without automatic recovery.
	RecoveryNone RecoveryAction = iota
	// RecoveryReplaceSession discards the current session and invalidates handle caches.
	RecoveryReplaceSession
	// RecoveryRelogin clears remembered login state before acquiring another session.
	RecoveryRelogin
	// RecoveryReinitialize reinitializes the shared native module and advances its generation.
	RecoveryReinitialize
	// RecoveryRediscover reinitializes the module and repeats slot, token, and adapter discovery.
	RecoveryRediscover
)

// RetryPolicy controls bounded replay of complete managed operations. The
// callback passed to withSession may be replayed from its beginning; callers
// must set Idempotent=false for operations that cannot safely be repeated.
type RetryPolicy struct {
	// MaxAttempts includes the initial call. Values less than one use the default.
	MaxAttempts int
	// InitialBackoff is the delay before the first replay. Negative values disable it.
	InitialBackoff time.Duration
	// MaxBackoff caps exponential growth. Non-positive values use the default cap.
	MaxBackoff time.Duration
	// RetryGeneralErrors permits CKR_GENERAL_ERROR and CKR_FUNCTION_FAILED to
	// trigger session replacement. Enable it only for providers known to use
	// those broad errors for transient transport failures.
	RetryGeneralErrors bool
}

// DefaultRetryPolicy returns the bounded retry and exponential-backoff defaults.
func DefaultRetryPolicy() RetryPolicy {
	return RetryPolicy{MaxAttempts: 3, InitialBackoff: 20 * time.Millisecond, MaxBackoff: 500 * time.Millisecond}
}

func (p RetryPolicy) normalized() RetryPolicy {
	defaults := DefaultRetryPolicy()
	if p.MaxAttempts <= 0 {
		p.MaxAttempts = defaults.MaxAttempts
	}
	if p.InitialBackoff < 0 {
		p.InitialBackoff = 0
	}
	if p.MaxBackoff <= 0 {
		p.MaxBackoff = defaults.MaxBackoff
	}
	return p
}

// delay returns the backoff after the numbered failed attempt. The caller checks
// the context while waiting; no timer is created when the result is zero.
func (p RetryPolicy) delay(attempt int) time.Duration {
	p = p.normalized()
	d := p.InitialBackoff
	for i := 1; i < attempt && d < p.MaxBackoff; i++ {
		d *= 2
		if d > p.MaxBackoff {
			d = p.MaxBackoff
		}
	}
	return d
}

// ClassifyError maps standard PKCS #11 errors to a conservative recovery action.
func ClassifyError(err error, retryGeneral bool) RecoveryAction {
	if err == nil {
		return RecoveryNone
	}
	// These errors are tied to a stale session or cached object handle. The
	// managed recovery path replaces the session and invalidates object caches.
	for _, value := range []uint{
		raw.CKR_SESSION_CLOSED,
		raw.CKR_SESSION_HANDLE_INVALID,
		raw.CKR_OBJECT_HANDLE_INVALID,
		raw.CKR_KEY_HANDLE_INVALID,
	} {
		if raw.IsError(err, value) {
			return RecoveryReplaceSession
		}
	}
	// Login recovery is intentionally ordered after stale-handle recovery: a
	// replaced session must be authenticated again through the normal pool path.
	if raw.IsError(err, raw.CKR_USER_NOT_LOGGED_IN) {
		return RecoveryRelogin
	}
	for _, value := range []uint{raw.CKR_CRYPTOKI_NOT_INITIALIZED, raw.CKR_DEVICE_REMOVED, raw.CKR_DEVICE_ERROR} {
		if raw.IsError(err, value) {
			return RecoveryReinitialize
		}
	}
	for _, value := range []uint{raw.CKR_TOKEN_NOT_PRESENT, raw.CKR_TOKEN_NOT_RECOGNIZED} {
		if raw.IsError(err, value) {
			return RecoveryRediscover
		}
	}
	if retryGeneral && (raw.IsError(err, raw.CKR_GENERAL_ERROR) || raw.IsError(err, raw.CKR_FUNCTION_FAILED)) {
		return RecoveryReplaceSession
	}
	return RecoveryNone
}

func classifyDeviceError(device Device, err error, retryGeneral bool) RecoveryAction {
	return classifyVendorError(device, err, retryGeneral)
}

func retryable(err error, retryGeneral bool) bool {
	return ClassifyError(err, retryGeneral) != RecoveryNone && !errors.Is(err, contextCanceledSentinel)
}

// An internal marker used to avoid importing context only for an errors.Is
// branch in hot retry classification. Context cancellation is checked before
// this helper is reached.
var contextCanceledSentinel = errors.New("pkcs11: context canceled")

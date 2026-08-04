package proxy

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/otpki/pkcs11/raw"
)

// PhysicalLoginMode selects where the credential used for the broker's
// physical HSM login comes from.
//
// The zero value is inferred conservatively: a configured PhysicalPIN selects
// PhysicalLoginServerManaged, while a token advertising
// CKF_PROTECTED_AUTHENTICATION_PATH selects PhysicalLoginProtectedPath. A
// target that wants client-supplied activation must opt in explicitly with
// PhysicalLoginClientActivated so accidentally omitting a server credential
// never changes the trust model.
type PhysicalLoginMode string

const (
	// PhysicalLoginServerManaged uses LoginPolicy.PhysicalPIN. This is the
	// original proxy behavior and supports automatic relogin after a session or
	// module generation change.
	PhysicalLoginServerManaged PhysicalLoginMode = "server-managed"
	// PhysicalLoginClientActivated uses the PIN from the first authorized remote
	// C_Login/C_LoginUser request that transitions an inactive target to active.
	// The broker does not retain the PIN after that request. If physical login is
	// later lost, the target fails closed until another authorized client supplies
	// a PIN.
	PhysicalLoginClientActivated PhysicalLoginMode = "client-activated"
	// PhysicalLoginProtectedPath passes a nil PIN and relies on the token's
	// protected authentication path. The selected token must advertise
	// CKF_PROTECTED_AUTHENTICATION_PATH.
	PhysicalLoginProtectedPath PhysicalLoginMode = "protected-path"
)

// ActivationState describes whether a broker target currently has usable
// physical HSM login state.
type ActivationState string

const (
	// ActivationInactive means private operations require a new physical
	// activation. Public PKCS #11 operations may still be available.
	ActivationInactive ActivationState = "inactive"
	// ActivationActivating means one request is currently performing the physical
	// login. Other request-scoped connections wait on that attempt rather than
	// submitting additional PINs to the HSM.
	ActivationActivating ActivationState = "activating"
	// ActivationActive means the control session anchors the configured physical
	// identity and worker sessions may use that login according to provider scope.
	ActivationActive ActivationState = "active"
)

const defaultActivationFailureCooldown = time.Second

// ActivationStatus is a secret-free operational snapshot. It never contains a
// PIN, PIN hash, activation credential, object identity, or request payload.
type ActivationStatus struct {
	State       ActivationState `json:"state"`
	Generation  uint64          `json:"generation"`
	ActivatedAt time.Time       `json:"activated_at"`
	ActivatedBy string          `json:"activated_by,omitempty"`
	FailedAt    time.Time       `json:"failed_at"`
	RetryAfter  time.Time       `json:"retry_after"`
}

// ErrActivationRequired indicates that a client-activated target has no usable
// physical HSM login and the caller must perform an audited C_Login/C_LoginUser
// with the real HSM PIN.
var ErrActivationRequired = errors.New("pkcs11 proxy: physical HSM activation is required")

// ErrActivationInconclusive indicates that the HSM reported an already-logged-
// in state while the broker itself considered the target inactive. In
// client-activated mode that response does not prove the supplied PIN was
// correct, so the broker fails closed rather than granting activation.
var ErrActivationInconclusive = errors.New("pkcs11 proxy: physical HSM activation was inconclusive")

// ErrClientActivationUnsupported indicates that a provider requires
// per-session physical login. A broker that does not retain the client PIN
// cannot safely authenticate future worker sessions for such a provider.
var ErrClientActivationUnsupported = errors.New("pkcs11 proxy: client-supplied activation requires token-wide login")

func activationRequiredError() error {
	return errors.Join(ErrActivationRequired, raw.Error(raw.CKR_USER_NOT_LOGGED_IN))
}

func activationInconclusiveError() error {
	return errors.Join(ErrActivationInconclusive, raw.Error(raw.CKR_USER_ALREADY_LOGGED_IN))
}

func clientActivationUnsupportedError(message string) error {
	if message == "" {
		message = ErrClientActivationUnsupported.Error()
	}
	return errors.Join(ErrClientActivationUnsupported, &RemoteError{
		Code:    "client_activation_unsupported",
		Message: message,
	})
}

func sanitizeActivationFailure(err error) error {
	if err == nil {
		return nil
	}
	var rv raw.Error
	hasRV := errors.As(err, &rv)
	switch {
	case errors.Is(err, ErrActivationRequired):
		if hasRV {
			return errors.Join(ErrActivationRequired, rv)
		}
		return ErrActivationRequired
	case errors.Is(err, ErrActivationInconclusive):
		if hasRV {
			return errors.Join(ErrActivationInconclusive, rv)
		}
		return ErrActivationInconclusive
	case errors.Is(err, ErrClientActivationUnsupported):
		if hasRV {
			return errors.Join(ErrClientActivationUnsupported, rv)
		}
		return ErrClientActivationUnsupported
	case hasRV:
		return rv
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	}
	var remote *RemoteError
	if errors.As(err, &remote) {
		return &RemoteError{Code: remote.Code, Message: "activation request was rejected"}
	}
	return &RemoteError{Code: "activation_failed", Message: "physical HSM activation failed"}
}

type activationAttempt struct {
	done           chan struct{}
	err            error
	retryFollowers bool
	epoch          uint64
}

// activationCoordinator collapses simultaneous activation attempts from many
// pods into one physical C_Login. It stores only state, timestamps, principal,
// and a sanitized error. It never stores the supplied PIN.
type activationCoordinator struct {
	mu sync.Mutex

	state       ActivationState
	generation  uint64
	epoch       uint64
	activatedAt time.Time
	activatedBy string
	failedAt    time.Time
	retryAfter  time.Time
	lastFailure error
	attempt     *activationAttempt
}

func newActivationCoordinator() activationCoordinator {
	return activationCoordinator{state: ActivationInactive}
}

func (coordinator *activationCoordinator) snapshot() ActivationStatus {
	if coordinator == nil {
		return ActivationStatus{State: ActivationInactive}
	}
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	return ActivationStatus{
		State:       coordinator.state,
		Generation:  coordinator.generation,
		ActivatedAt: coordinator.activatedAt,
		ActivatedBy: coordinator.activatedBy,
		FailedAt:    coordinator.failedAt,
		RetryAfter:  coordinator.retryAfter,
	}
}

func (coordinator *activationCoordinator) activeGeneration() (uint64, bool) {
	if coordinator == nil {
		return 0, false
	}
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	return coordinator.generation, coordinator.state == ActivationActive
}

// ensure returns the current activation generation. Exactly one caller runs
// activate. Followers wait on the same attempt with their own context and never
// submit their PIN to the HSM.
func (coordinator *activationCoordinator) ensure(
	ctx context.Context,
	principal string,
	failureCooldown time.Duration,
	authorizeLeader func() error,
	activate func() error,
) (uint64, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		coordinator.mu.Lock()
		if coordinator.state == ActivationActive {
			generation := coordinator.generation
			coordinator.mu.Unlock()
			return generation, nil
		}
		if attempt := coordinator.attempt; attempt != nil {
			done := attempt.done
			coordinator.mu.Unlock()
			select {
			case <-done:
				if attempt.retryFollowers {
					// The selected leader was not authorized to activate this
					// target. Followers re-contend instead of inheriting that
					// principal-specific denial.
					continue
				}
				if attempt.err != nil {
					return 0, attempt.err
				}
				// Recheck state: activation may have been invalidated immediately
				// after the leader completed.
				continue
			case <-ctx.Done():
				return 0, ctx.Err()
			}
		}
		now := time.Now()
		if coordinator.lastFailure != nil && !coordinator.retryAfter.IsZero() && now.Before(coordinator.retryAfter) {
			err := coordinator.lastFailure
			coordinator.mu.Unlock()
			return 0, err
		}
		// The cooldown has expired. Drop the retained error before beginning a
		// new attempt so failure state never lives longer than configured.
		coordinator.lastFailure = nil
		coordinator.retryAfter = time.Time{}
		attempt := &activationAttempt{done: make(chan struct{}), epoch: coordinator.epoch}
		coordinator.attempt = attempt
		coordinator.state = ActivationActivating
		coordinator.mu.Unlock()

		// Only the selected leader receives the physical-activation policy check.
		// When it is denied, followers re-contend instead of receiving the denial
		// or entering the PIN-failure cooldown. No credential reaches the HSM.
		if authorizeLeader != nil {
			if err := authorizeLeader(); err != nil {
				coordinator.mu.Lock()
				attempt.err = err
				attempt.retryFollowers = true
				coordinator.attempt = nil
				coordinator.state = ActivationInactive
				close(attempt.done)
				coordinator.mu.Unlock()
				return 0, err
			}
		}

		// A module, control-session, or target-generation invalidation may occur
		// while the leader is waiting on external authorization. Do not submit a
		// PIN through an attempt that belongs to the obsolete epoch.
		coordinator.mu.Lock()
		invalidated := attempt.epoch != coordinator.epoch
		if invalidated {
			err := raw.Error(raw.CKR_USER_NOT_LOGGED_IN)
			attempt.err = err
			coordinator.attempt = nil
			coordinator.state = ActivationInactive
			close(attempt.done)
			coordinator.mu.Unlock()
			return 0, err
		}
		coordinator.mu.Unlock()

		err := activate()
		completed := time.Now()

		coordinator.mu.Lock()
		if err == nil && attempt.epoch != coordinator.epoch {
			// Physical state changed while the native call was in flight. Even if
			// that call returned success, the broker cannot safely publish the
			// resulting login as current.
			err = raw.Error(raw.CKR_USER_NOT_LOGGED_IN)
		}
		attempt.err = err
		coordinator.attempt = nil
		if err == nil {
			coordinator.generation++
			coordinator.state = ActivationActive
			coordinator.activatedAt = completed
			coordinator.activatedBy = principal
			coordinator.failedAt = time.Time{}
			coordinator.retryAfter = time.Time{}
			coordinator.lastFailure = nil
		} else {
			coordinator.state = ActivationInactive
			coordinator.activatedAt = time.Time{}
			coordinator.activatedBy = ""
			coordinator.failedAt = completed
			if failureCooldown > 0 {
				// Retain only for the bounded cooldown window. Client activation
				// failures originate after secret-free authorization and raw HSM
				// calls; server-managed mode defaults to no retention so a custom
				// credential-provider error is not kept in target state.
				coordinator.lastFailure = sanitizeActivationFailure(err)
				coordinator.retryAfter = completed.Add(failureCooldown)
			} else {
				coordinator.lastFailure = nil
				coordinator.retryAfter = time.Time{}
			}
		}
		close(attempt.done)
		generation := coordinator.generation
		coordinator.mu.Unlock()
		return generation, err
	}
}

// invalidate marks established physical login unusable. A client-activated
// target increments its generation so all existing logical grants become stale
// without synchronously acquiring every logical client's authentication lock.
func (coordinator *activationCoordinator) invalidate(invalidateGeneration bool) {
	if coordinator == nil {
		return
	}
	coordinator.mu.Lock()
	coordinator.epoch++
	if coordinator.state == ActivationActive && invalidateGeneration {
		coordinator.generation++
	}
	coordinator.state = ActivationInactive
	coordinator.activatedAt = time.Time{}
	coordinator.activatedBy = ""
	coordinator.mu.Unlock()
}

func (policy LoginPolicy) resolvePhysicalMode(token raw.TokenInfo) (PhysicalLoginMode, error) {
	mode := policy.Mode
	protected := token.Flags&raw.CKF_PROTECTED_AUTHENTICATION_PATH != 0
	if mode == "" {
		switch {
		case policy.PhysicalPIN != nil:
			mode = PhysicalLoginServerManaged
		case protected:
			mode = PhysicalLoginProtectedPath
		default:
			return "", fmt.Errorf("Login.Mode is required when PhysicalPIN is not configured; use %q for client-supplied activation", PhysicalLoginClientActivated)
		}
	}

	switch mode {
	case PhysicalLoginServerManaged:
		if policy.PhysicalPIN == nil {
			return "", fmt.Errorf("Login.PhysicalPIN is required in %q mode", mode)
		}
	case PhysicalLoginClientActivated:
		if policy.PhysicalPIN != nil {
			return "", fmt.Errorf("Login.PhysicalPIN must be nil in %q mode", mode)
		}
		if policy.EagerPhysicalLogin {
			return "", fmt.Errorf("EagerPhysicalLogin is incompatible with %q mode because no client PIN is available at target startup", mode)
		}
	case PhysicalLoginProtectedPath:
		if policy.PhysicalPIN != nil {
			return "", fmt.Errorf("Login.PhysicalPIN must be nil in %q mode", mode)
		}
		if !protected {
			return "", fmt.Errorf("%q mode requires CKF_PROTECTED_AUTHENTICATION_PATH", mode)
		}
	default:
		return "", fmt.Errorf("unsupported physical login mode %q", mode)
	}
	return mode, nil
}

package pkcs11

import (
	"context"
	"runtime"
	"slices"

	"github.com/otpki/pkcs11/raw"
)

// Secret is a mutable byte buffer for short-lived credentials such as PINs. Destroy overwrites the
// buffer in place. Callers should return a fresh Secret from each PINProvider call.
//
// Destroy is best effort because Go and vendor libraries may make temporary copies.
type Secret []byte

// NewSecret copies value into a mutable credential buffer.
func NewSecret(value []byte) Secret {
	return append(Secret(nil), value...)
}

// Clone returns an independent copy that can be destroyed separately.
func (s Secret) Clone() Secret { return NewSecret(s) }

// Destroy overwrites the secret in place.
func (s Secret) Destroy() {
	for i := range s {
		s[i] = 0
	}
	runtime.KeepAlive(s)
}

// PINPurpose identifies why the managed driver is requesting a credential.
type PINPurpose string

const (
	// PINPurposeLogin requests the normal user or security-officer credential.
	PINPurposeLogin PINPurpose = "login"
	// PINPurposeContextSpecific requests per-operation authentication for an
	// object marked CKA_ALWAYS_AUTHENTICATE.
	PINPurposeContextSpecific PINPurpose = "context-specific-login"
	// PINPurposeInitialize requests a new user PIN during C_InitPIN.
	PINPurposeInitialize PINPurpose = "initialize-pin"
	// PINPurposeChangeOld requests the current PIN during a PIN change.
	PINPurposeChangeOld PINPurpose = "change-pin-old"
	// PINPurposeChangeNew requests the replacement PIN during a PIN change.
	PINPurposeChangeNew PINPurpose = "change-pin-new"
)

// PINRequest describes the token, role, and purpose for a credential request.
type PINRequest struct {
	// Purpose identifies the operation that needs a credential.
	Purpose PINPurpose
	// SlotID is the selected token-bearing slot.
	SlotID raw.SlotID
	// Token is a point-in-time token-information snapshot for provider policy or UI.
	Token raw.TokenInfo
	// UserType is the CKU_* role passed to the login operation.
	UserType uint
	// Attempt is one-based and permits providers to implement retry-aware prompting.
	Attempt int
	// Username is used by PKCS #11 3.x C_LoginUser when configured.
	Username string
}

// PINProvider supplies a fresh, destroyable credential for one authentication attempt.
// It may be called concurrently by independent session pools and should honor ctx.
type PINProvider func(context.Context, PINRequest) (Secret, error)

// StaticPIN returns a provider backed by a copied string value. Prefer a secret
// manager in production: the original Go string cannot be wiped, and the provider
// intentionally retains a private byte copy for its lifetime.
func StaticPIN(pin string) PINProvider {
	value := []byte(pin)
	return func(context.Context, PINRequest) (Secret, error) {
		return NewSecret(value), nil
	}
}

// StaticPINBytes returns a provider backed by a private copy of pin. Destroying
// an individual returned Secret does not erase the provider's retained source copy.
func StaticPINBytes(pin []byte) PINProvider {
	value := slices.Clone(pin)
	return func(context.Context, PINRequest) (Secret, error) {
		return NewSecret(value), nil
	}
}

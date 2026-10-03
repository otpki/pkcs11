package proxy

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/internal/testmock"
	"github.com/otpki/pkcs11/raw"
)

// Vendor-defined return values used by the vendorCodeModule fixture. They
// mirror the Securosys Primus codes: providers in this class report standard
// login-state conditions in the CKR_VENDOR_DEFINED range instead of the
// standard values the broker acts on.
const (
	vendorCodeWrongPIN    = 0x8000000B
	vendorCodeNotLoggedIn = 0x8000000C
	vendorCodeUnreachable = 0x80005015
)

// vendorCodeSource wraps a module source so the resulting module reports
// login-state failures through vendor-defined return values, emulating a
// provider that does not surface the standard CKR codes.
type vendorCodeSource struct{ inner pkcs11.ModuleSource }

func (s vendorCodeSource) OpenModule(ctx context.Context) (raw.Module, error) {
	module, err := s.inner.OpenModule(ctx)
	if err != nil {
		return nil, err
	}
	return vendorCodeModule{Module: module}, nil
}

func (s vendorCodeSource) RegistryKey() string { return "vendor-code:" + s.inner.RegistryKey() }
func (s vendorCodeSource) String() string      { return s.inner.String() + " (vendor codes)" }

// vendorCodeModule remaps the standard login-state results a provider would
// report in its vendor range. The rest of the raw.Module surface is untouched.
type vendorCodeModule struct{ raw.Module }

func vendorCode(err error) error {
	switch {
	case raw.IsError(err, raw.CKR_PIN_INCORRECT):
		return raw.Error(vendorCodeWrongPIN)
	case raw.IsError(err, raw.CKR_USER_NOT_LOGGED_IN):
		return raw.Error(vendorCodeNotLoggedIn)
	case raw.IsError(err, raw.CKR_DEVICE_ERROR):
		return raw.Error(vendorCodeUnreachable)
	}
	return err
}

func (m vendorCodeModule) Login(session raw.SessionHandle, userType uint, pin []byte) error {
	return vendorCode(m.Module.Login(session, userType, pin))
}

func (m vendorCodeModule) LoginUser(session raw.SessionHandle, userType uint, pin []byte, username string) error {
	return vendorCode(m.Module.LoginUser(session, userType, pin, username))
}

func (m vendorCodeModule) Logout(session raw.SessionHandle) error {
	return vendorCode(m.Module.Logout(session))
}

func (m vendorCodeModule) CreateObject(session raw.SessionHandle, attributes []*raw.Attribute) (raw.ObjectHandle, error) {
	object, err := m.Module.CreateObject(session, attributes)
	return object, vendorCode(err)
}

// proxyVendorCodeVendor is the test VendorModule that owns the translation
// table for the vendorCodeModule fixture, standing in for vendors/securosys.
type proxyVendorCodeVendor struct{ pkcs11.VendorBase }

func (proxyVendorCodeVendor) Definition() pkcs11.VendorDefinition {
	return pkcs11.VendorDefinition{
		ID:       pkcs11.AdapterFamily("internal-proxy-vendor-code-test"),
		Name:     "OTPKI proxy vendor-code test module",
		Priority: 10_000,
		Source:   "internal proxy fixture",
		Match:    pkcs11.VendorMatchSpec{Manufacturers: []string{"otpki test"}},
	}
}

func (proxyVendorCodeVendor) TranslateError(_ pkcs11.VendorErrorContext, err error) error {
	code, ok := errors.AsType[raw.Error](err)
	if !ok {
		return err
	}
	switch uint(code) {
	case vendorCodeWrongPIN:
		return pkcs11.TranslateVendorError(err, raw.CKR_PIN_INCORRECT)
	case vendorCodeNotLoggedIn:
		return pkcs11.TranslateVendorError(err, raw.CKR_USER_NOT_LOGGED_IN)
	case vendorCodeUnreachable:
		return pkcs11.TranslateVendorError(err, raw.CKR_DEVICE_ERROR)
	}
	return err
}

func vendorCodeTarget(source pkcs11.ModuleSource) TargetConfig {
	slot := raw.SlotID(1)
	return TargetConfig{
		ID: "vendor-code-hsm", Revision: "v1",
		Client: pkcs11.Config{
			Module:  source,
			Token:   pkcs11.TokenSelector{SlotID: &slot},
			Vendors: []pkcs11.VendorModule{proxyVendorCodeVendor{}},
		},
		Sessions: SessionBudget{MaxPhysicalTotal: 4, MaxClients: 32},
		Login: LoginPolicy{
			Mode:             PhysicalLoginClientActivated,
			Authenticate:     func(context.Context, LoginAttempt) error { return nil },
			AllowedUserTypes: []uint{raw.CKU_USER},
		},
	}
}

func newVendorCodeBroker(t *testing.T, audit func(AuditEvent)) (string, pkcs11.ModuleSource) {
	t.Helper()
	source := vendorCodeSource{inner: testmock.Source{Name: "vendor-codes-" + t.Name(), Tokens: 1}}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(context.Background(), ServerConfig{
		Listener: listener, AllowInsecure: true,
		Audit: AuditSinkFunc(func(_ context.Context, event AuditEvent) {
			if audit != nil {
				audit(event)
			}
		}),
	}, vendorCodeTarget(source))
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	go func() { _ = server.Serve(context.Background()) }()
	t.Cleanup(func() { _ = server.Close(context.Background()) })
	return listener.Addr().String(), source
}

func vendorCodeClientTarget(address string) Target {
	return Target{
		ConfigID: "vendor-code-test", Revision: "v1", Route: "vendor-code-hsm",
		Endpoints: []string{address}, AllowInsecure: true,
		RequestTimeout: 5 * time.Second, MaxAttempts: 1,
	}
}

// TestForwardedVendorNotLoggedInInvalidatesActivation is the Primus logout
// scenario: the HSM drops the login out-of-band, a forwarded call returns the
// vendor code 0x8000000C, and the broker invalidates the client-activated
// login instead of silently re-authenticating.
func TestForwardedVendorNotLoggedInInvalidatesActivation(t *testing.T) {
	var activations atomic.Int64
	address, source := newVendorCodeBroker(t, func(event AuditEvent) {
		if event.Type == "activation" {
			activations.Add(1)
		}
	})
	target := vendorCodeClientTarget(address)

	client := openRemoteRaw(t, target)
	session := openVirtualSession(t, client, remoteSlot(t, client), true)
	if err := client.Login(session, raw.CKU_USER, []byte(testmock.DefaultPIN)); err != nil {
		t.Fatalf("activation login: %v", err)
	}
	if got := activations.Load(); got != 1 {
		t.Fatalf("physical activations = %d, want 1", got)
	}

	// Drop the token-side login underneath the broker, the way a Primus HSM
	// restart or cluster failover does.
	admin := testmockAdmin(t, source)
	lease, err := admin.AcquireRawSession(context.Background(), pkcs11.RawSessionOptions{ReadWrite: true, Operation: "out-of-band-logout"})
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.Call(context.Background(), "oob-logout", func(module raw.Module, session raw.SessionHandle) error {
		return module.Logout(session)
	}); err != nil {
		t.Fatalf("out-of-band logout: %v", err)
	}
	_ = lease.Close(context.Background())

	// The forwarded call returns vendor 0x8000000C; translation must let the
	// broker invalidate the activation instead of silently re-logging in.
	_, err = client.CreateObject(session, []*raw.Attribute{
		raw.NewAttribute(raw.CKA_CLASS, raw.CKO_DATA),
		raw.NewAttribute(raw.CKA_PRIVATE, true),
		raw.NewAttribute(raw.CKA_LABEL, "vendor-code-probe"),
	})
	if !errors.Is(err, ErrActivationRequired) || !raw.IsError(err, raw.CKR_USER_NOT_LOGGED_IN) {
		t.Fatalf("private write after vendor logout = %v, want ErrActivationRequired and CKR_USER_NOT_LOGGED_IN", err)
	}
	if got := activations.Load(); got != 1 {
		t.Fatalf("forwarded vendor error caused a silent relogin: activations = %d", got)
	}

	// The next logical login reactivates with exactly one physical login.
	if err := client.Login(session, raw.CKU_USER, []byte(testmock.DefaultPIN)); err != nil {
		t.Fatalf("reactivation login: %v", err)
	}
	if got := activations.Load(); got != 2 {
		t.Fatalf("physical activations after re-login = %d, want 2", got)
	}
}

// TestVendorWrongPINPhysicalLoginReachesClientAsStandard covers the physical
// login path: the control-session C_Login returns vendor 0x8000000B, the remote
// client sees CKR_PIN_INCORRECT, and the attempt is audited as
// activation_failure.
func TestVendorWrongPINPhysicalLoginReachesClientAsStandard(t *testing.T) {
	var failures atomic.Int64
	address, _ := newVendorCodeBroker(t, func(event AuditEvent) {
		if event.Type == "activation_failure" {
			failures.Add(1)
		}
	})
	target := vendorCodeClientTarget(address)

	client := openRemoteRaw(t, target)
	session := openVirtualSession(t, client, remoteSlot(t, client), true)
	err := client.Login(session, raw.CKU_USER, []byte("9999"))
	if !raw.IsError(err, raw.CKR_PIN_INCORRECT) {
		t.Fatalf("vendor wrong-PIN login = %v, want CKR_PIN_INCORRECT", err)
	}
	if got := failures.Load(); got != 1 {
		t.Fatalf("activation_failure audit events = %d, want 1", got)
	}
}

// TestEncodeErrorCarriesTranslatedStandardRV proves the wire encoder resolves
// the standard value of a translated vendor error while the message keeps the
// vendor-defined code for diagnostics.
func TestEncodeErrorCarriesTranslatedStandardRV(t *testing.T) {
	err := pkcs11.TranslateVendorError(raw.Error(vendorCodeNotLoggedIn), raw.CKR_USER_NOT_LOGGED_IN)
	encoded := encodeError(err)
	if encoded == nil || !encoded.HasRV || encoded.RV != uint64(raw.CKR_USER_NOT_LOGGED_IN) {
		t.Fatalf("encoded = %+v, want RV=CKR_USER_NOT_LOGGED_IN", encoded)
	}
	if !strings.Contains(encoded.Message, "vendor 0x8000000C") {
		t.Fatalf("wire message %q lost the vendor value", encoded.Message)
	}
	if decoded := decodeError(encoded); !raw.IsError(decoded, raw.CKR_USER_NOT_LOGGED_IN) {
		t.Fatalf("decoded = %v, want CKR_USER_NOT_LOGGED_IN", decoded)
	}

	// A translated error joined with ErrActivationRequired keeps both markers
	// on the wire and decodes back to both.
	joined := encodeError(errors.Join(err, activationRequiredError()))
	if joined == nil || joined.Code != "activation_required" || !joined.HasRV ||
		joined.RV != uint64(raw.CKR_USER_NOT_LOGGED_IN) {
		t.Fatalf("joined encoded = %+v, want activation_required + CKR_USER_NOT_LOGGED_IN", joined)
	}
	decoded := decodeError(joined)
	if !errors.Is(decoded, ErrActivationRequired) || !raw.IsError(decoded, raw.CKR_USER_NOT_LOGGED_IN) {
		t.Fatalf("decoded join = %v, want ErrActivationRequired + CKR_USER_NOT_LOGGED_IN", decoded)
	}
}

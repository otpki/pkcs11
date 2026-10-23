//go:build !windows

package proxy

import (
	"context"
	"errors"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/internal/testmock"
	"github.com/otpki/pkcs11/raw"
)

// Count calls at the module boundary, including rejected PINs. Activation audit
// counts alone would miss a context-specific login that bypassed the PIN gate.
type pinRotationTestModule struct {
	raw.Module
	logins   atomic.Int64
	logouts  atomic.Int64
	mu       sync.Mutex
	loginErr error
}

func (module *pinRotationTestModule) Login(session raw.SessionHandle, userType uint, pin []byte) error {
	module.logins.Add(1)
	module.mu.Lock()
	err := module.loginErr
	module.loginErr = nil
	module.mu.Unlock()
	if err != nil {
		return err
	}
	return module.Module.Login(session, userType, pin)
}

func (module *pinRotationTestModule) LoginUser(session raw.SessionHandle, userType uint, pin []byte, _ string) error {
	return module.Login(session, userType, pin)
}

func (module *pinRotationTestModule) Logout(session raw.SessionHandle) error {
	module.logouts.Add(1)
	return module.Module.Logout(session)
}

func (module *pinRotationTestModule) failNextLogin(err error) {
	module.mu.Lock()
	module.loginErr = err
	module.mu.Unlock()
}

type pinRotationTestSource struct {
	name   string
	base   *testmock.Module
	module *pinRotationTestModule
}

func (source pinRotationTestSource) OpenModule(ctx context.Context) (raw.Module, error) {
	_, err := (testmock.SharedSource{Name: source.name, Module: source.base}).OpenModule(ctx)
	return source.module, err
}

func (source pinRotationTestSource) RegistryKey() string { return "pin-rotation-test:" + source.name }
func (source pinRotationTestSource) String() string      { return source.RegistryKey() }

type pinRotationFixture struct {
	module *pinRotationTestModule
	source pinRotationTestSource
	broker *brokerTarget
	target Target
	mu     sync.Mutex
	events []AuditEvent
}

func newPINRotationFixture(t *testing.T, mutate func(*TargetConfig)) *pinRotationFixture {
	t.Helper()
	base := testmock.New(t.Name(), 1)
	fixture := &pinRotationFixture{
		module: &pinRotationTestModule{Module: base},
	}
	fixture.source = pinRotationTestSource{name: t.Name(), base: base, module: fixture.module}
	config := testmockPINTarget(t, fixture.source, func(config *TargetConfig) {
		// Advance the coordinator's timestamps explicitly in these tests. Keeping
		// a long real interval makes them independent of scheduler speed under -race.
		config.Login.PINRotationInterval = time.Hour
		config.Login.ActivationFailureCooldown = time.Minute
		if mutate != nil {
			mutate(config)
		}
	})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(context.Background(), ServerConfig{
		Listener: listener, AllowInsecure: true,
		Audit: AuditSinkFunc(func(_ context.Context, event AuditEvent) {
			if event.Type == "pin_rotation" {
				fixture.mu.Lock()
				fixture.events = append(fixture.events, event)
				fixture.mu.Unlock()
			}
		}),
	}, config)
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(context.Background()) }()
	t.Cleanup(func() {
		_ = server.Close(context.Background())
		if err := <-serveDone; err != nil {
			t.Errorf("serve: %v", err)
		}
	})
	server.targetsMu.RLock()
	fixture.broker = server.targets[config.ID]
	server.targetsMu.RUnlock()
	fixture.target = haTarget(listener.Addr().String())
	return fixture
}

func (fixture *pinRotationFixture) client(t *testing.T) (*Client, raw.SessionHandle) {
	t.Helper()
	client := openRemoteRaw(t, fixture.target)
	return client, openVirtualSession(t, client, remoteSlot(t, client), true)
}

func (fixture *pinRotationFixture) allowRotation() {
	fixture.broker.activation.mu.Lock()
	fixture.broker.activation.attemptedAt = time.Now().Add(-2 * fixture.broker.login.PINRotationInterval)
	fixture.broker.activation.mu.Unlock()
}

func (fixture *pinRotationFixture) expireCooldown() {
	fixture.broker.activation.mu.Lock()
	fixture.broker.activation.retryAfter = time.Now().Add(-time.Second)
	fixture.broker.activation.mu.Unlock()
}

func (fixture *pinRotationFixture) changeTokenPIN(t *testing.T) {
	t.Helper()
	admin := testmockAdmin(t, fixture.source)
	lease, err := admin.AcquireRawSession(context.Background(), pkcs11.RawSessionOptions{ReadWrite: true, Operation: "test-rotate-pin"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lease.Close(context.Background()) }()
	if err := lease.Call(context.Background(), "test-set-pin", func(module raw.Module, session raw.SessionHandle) error {
		return module.SetPIN(session, []byte(testmock.DefaultPIN), []byte("5678"))
	}); err != nil {
		t.Fatalf("out-of-band SetPIN: %v", err)
	}
}

func (fixture *pinRotationFixture) rotationEvents() []AuditEvent {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	return slices.Clone(fixture.events)
}

func requirePINRotationCalls(t *testing.T, fixture *pinRotationFixture, logins, logouts int64) {
	t.Helper()
	if got := fixture.module.logins.Load(); got != logins {
		t.Fatalf("physical login calls = %d, want %d", got, logins)
	}
	if got := fixture.module.logouts.Load(); got != logouts {
		t.Fatalf("physical logout calls = %d, want %d", got, logouts)
	}
}

func TestPINRotationFailureKeepsGateAfterCooldown(t *testing.T) {
	fixture := newPINRotationFixture(t, nil)
	owner, ownerSession := fixture.client(t)
	caller, callerSession := fixture.client(t)
	if err := owner.Login(ownerSession, raw.CKU_USER, []byte(testmock.DefaultPIN)); err != nil {
		t.Fatal(err)
	}
	fixture.allowRotation()
	if err := caller.Login(callerSession, raw.CKU_USER, []byte("9999")); !raw.IsError(err, raw.CKR_PIN_INCORRECT) {
		t.Fatalf("failed rotation = %v, want CKR_PIN_INCORRECT", err)
	}
	requirePINRotationCalls(t, fixture, 2, 1)
	if state := fixture.broker.activation.snapshot().State; state != ActivationInactive {
		t.Fatalf("failed rotation activation state = %s, want inactive", state)
	}
	// The short activation cooldown must not reopen the much longer PIN gate.
	for _, wrongPIN := range []string{"9999", "8888", "9999"} {
		fixture.expireCooldown()
		if err := caller.Login(callerSession, raw.CKU_USER, []byte(wrongPIN)); !raw.IsError(err, raw.CKR_PIN_INCORRECT) {
			t.Fatalf("in-interval PIN %q = %v, want CKR_PIN_INCORRECT", wrongPIN, err)
		}
		requirePINRotationCalls(t, fixture, 2, 1)
	}
	// The last HSM-accepted PIN can reactivate without waiting for rotation.
	if err := owner.Login(ownerSession, raw.CKU_USER, []byte(testmock.DefaultPIN)); err != nil {
		t.Fatalf("armed PIN reactivation: %v", err)
	}
	requirePINRotationCalls(t, fixture, 3, 1)
	if _, err := owner.CreateObject(ownerSession, []*raw.Attribute{
		raw.NewAttribute(raw.CKA_CLASS, raw.CKO_DATA),
		raw.NewAttribute(raw.CKA_TOKEN, true),
		raw.NewAttribute(raw.CKA_PRIVATE, true),
	}); err != nil {
		t.Fatalf("reactivating client's private operation: %v", err)
	}
	if err := caller.Login(callerSession, raw.CKU_USER, []byte("9999")); !raw.IsError(err, raw.CKR_PIN_INCORRECT) {
		t.Fatalf("active target mismatch = %v, want CKR_PIN_INCORRECT", err)
	}
	requirePINRotationCalls(t, fixture, 3, 1)
	events := fixture.rotationEvents()
	if len(events) != 1 || events[0].Code == "" {
		t.Fatalf("failed rotation audit = %+v, want one event with failure outcome", events)
	}
}

func TestPINRotationCooldownLongerThanIntervalAvoidsAnotherRotation(t *testing.T) {
	var rotationAuthorizations, activationAuthorizations atomic.Int64
	fixture := newPINRotationFixture(t, func(config *TargetConfig) {
		config.Login.PINRotationInterval = time.Minute
		config.Login.ActivationFailureCooldown = time.Hour
		config.Authorize = func(_ context.Context, request AuthorizationRequest) error {
			switch request.Operation {
			case AuthorizationOperationRotatePIN:
				rotationAuthorizations.Add(1)
			case AuthorizationOperationActivateTarget:
				activationAuthorizations.Add(1)
			}
			return nil
		}
	})
	owner, ownerSession := fixture.client(t)
	caller, callerSession := fixture.client(t)
	if err := owner.Login(ownerSession, raw.CKU_USER, []byte(testmock.DefaultPIN)); err != nil {
		t.Fatal(err)
	}
	fixture.allowRotation()
	if err := caller.Login(callerSession, raw.CKU_USER, []byte("9999")); !raw.IsError(err, raw.CKR_PIN_INCORRECT) {
		t.Fatalf("failed rotation = %v", err)
	}
	requirePINRotationCalls(t, fixture, 2, 1)
	if rotations, activations := rotationAuthorizations.Load(), activationAuthorizations.Load(); rotations != 1 || activations != 2 {
		t.Fatalf("authorization counts after failed rotation = rotate:%d activate:%d, want 1 and 2", rotations, activations)
	}
	// The rotation interval has elapsed, but the longer failure cooldown has
	// not. A mismatch must not start cleanup or logout for an attempt that the
	// activation coordinator would refuse to make.
	fixture.allowRotation()
	if err := caller.Login(callerSession, raw.CKU_USER, []byte("8888")); !raw.IsError(err, raw.CKR_PIN_INCORRECT) {
		t.Fatalf("mismatch during longer cooldown = %v, want CKR_PIN_INCORRECT", err)
	}
	requirePINRotationCalls(t, fixture, 2, 1)
	if rotations, activations := rotationAuthorizations.Load(), activationAuthorizations.Load(); rotations != 1 || activations != 2 {
		t.Fatalf("cooldown asked for rotation authorization: rotate:%d activate:%d", rotations, activations)
	}
	if events := fixture.rotationEvents(); len(events) != 1 {
		t.Fatalf("cooldown audited another rotation: %+v", events)
	}
}

func TestPINRotationArmedPINRejectionClearsGate(t *testing.T) {
	for _, rv := range []uint{
		raw.CKR_PIN_INCORRECT, raw.CKR_PIN_INVALID, raw.CKR_PIN_LEN_RANGE,
		raw.CKR_PIN_EXPIRED, raw.CKR_PIN_LOCKED, raw.CKR_USER_PIN_NOT_INITIALIZED,
	} {
		t.Run(raw.Error(rv).Error(), func(t *testing.T) {
			fixture := newPINRotationFixture(t, nil)
			owner, ownerSession := fixture.client(t)
			caller, callerSession := fixture.client(t)
			if err := owner.Login(ownerSession, raw.CKU_USER, []byte(testmock.DefaultPIN)); err != nil {
				t.Fatal(err)
			}
			fixture.changeTokenPIN(t)
			fixture.allowRotation()
			if err := caller.Login(callerSession, raw.CKU_USER, []byte("9999")); !raw.IsError(err, raw.CKR_PIN_INCORRECT) {
				t.Fatalf("failed rotation = %v", err)
			}
			fixture.expireCooldown()
			if rv != raw.CKR_PIN_INCORRECT {
				fixture.module.failNextLogin(raw.Error(rv))
			}
			if err := owner.Login(ownerSession, raw.CKU_USER, []byte(testmock.DefaultPIN)); !raw.IsError(err, rv) {
				t.Fatalf("HSM rejection of armed PIN = %v, want %v", err, raw.Error(rv))
			}
			requirePINRotationCalls(t, fixture, 3, 1)
			// A definitive rejection proves the armed PIN is obsolete. A new PIN can
			// then activate after only the failure cooldown, inside the rotation interval.
			fixture.expireCooldown()
			if err := caller.Login(callerSession, raw.CKU_USER, []byte("5678")); err != nil {
				t.Fatalf("activation after armed PIN rejection: %v", err)
			}
			requirePINRotationCalls(t, fixture, 4, 1)
			if err := owner.Login(ownerSession, raw.CKU_USER, []byte(testmock.DefaultPIN)); !raw.IsError(err, raw.CKR_PIN_INCORRECT) {
				t.Fatalf("obsolete PIN after re-arm = %v, want CKR_PIN_INCORRECT", err)
			}
			requirePINRotationCalls(t, fixture, 4, 1)
		})
	}
}

func TestPINRotationTransientFailureKeepsGate(t *testing.T) {
	fixture := newPINRotationFixture(t, nil)
	owner, ownerSession := fixture.client(t)
	caller, callerSession := fixture.client(t)
	if err := owner.Login(ownerSession, raw.CKU_USER, []byte(testmock.DefaultPIN)); err != nil {
		t.Fatal(err)
	}
	fixture.changeTokenPIN(t)
	fixture.allowRotation()
	fixture.module.failNextLogin(raw.Error(raw.CKR_DEVICE_ERROR))
	if err := caller.Login(callerSession, raw.CKU_USER, []byte("5678")); !raw.IsError(err, raw.CKR_DEVICE_ERROR) {
		t.Fatalf("transient rotation failure = %v, want CKR_DEVICE_ERROR", err)
	}
	for _, cooldownExpired := range []bool{false, true} {
		if cooldownExpired {
			fixture.expireCooldown()
		}
		if err := caller.Login(callerSession, raw.CKU_USER, []byte("5678")); !raw.IsError(err, raw.CKR_PIN_INCORRECT) {
			t.Fatalf("new PIN inside interval after transient failure (cooldown expired=%t) = %v, want CKR_PIN_INCORRECT", cooldownExpired, err)
		}
		requirePINRotationCalls(t, fixture, 2, 1)
	}
	fixture.allowRotation()
	if err := caller.Login(callerSession, raw.CKU_USER, []byte("5678")); err != nil {
		t.Fatalf("new PIN after next rotation interval: %v", err)
	}
	if got := fixture.module.logins.Load(); got != 3 {
		t.Fatalf("physical login calls = %d, want 3", got)
	}
	events := fixture.rotationEvents()
	if len(events) != 2 || events[0].Code == "" || events[1].Code != "" {
		t.Fatalf("rotation audit = %+v, want failure then success", events)
	}
}

func TestPINRotationArmedPINTransientFailureKeepsGate(t *testing.T) {
	fixture := newPINRotationFixture(t, nil)
	owner, ownerSession := fixture.client(t)
	caller, callerSession := fixture.client(t)
	if err := owner.Login(ownerSession, raw.CKU_USER, []byte(testmock.DefaultPIN)); err != nil {
		t.Fatal(err)
	}
	fixture.allowRotation()
	if err := caller.Login(callerSession, raw.CKU_USER, []byte("9999")); !raw.IsError(err, raw.CKR_PIN_INCORRECT) {
		t.Fatalf("failed rotation = %v", err)
	}
	fixture.expireCooldown()
	fixture.module.failNextLogin(raw.Error(raw.CKR_DEVICE_ERROR))
	if err := owner.Login(ownerSession, raw.CKU_USER, []byte(testmock.DefaultPIN)); !raw.IsError(err, raw.CKR_DEVICE_ERROR) {
		t.Fatalf("armed PIN transient failure = %v, want CKR_DEVICE_ERROR", err)
	}
	fixture.expireCooldown()
	if err := caller.Login(callerSession, raw.CKU_USER, []byte("8888")); !raw.IsError(err, raw.CKR_PIN_INCORRECT) {
		t.Fatalf("mismatch after armed PIN transient failure = %v, want CKR_PIN_INCORRECT", err)
	}
	requirePINRotationCalls(t, fixture, 3, 1)
	if err := owner.Login(ownerSession, raw.CKU_USER, []byte(testmock.DefaultPIN)); err != nil {
		t.Fatalf("armed PIN recovery after transient failure: %v", err)
	}
	requirePINRotationCalls(t, fixture, 4, 1)
}

func TestPINRotationGrantedClientRenewsGrant(t *testing.T) {
	fixture := newPINRotationFixture(t, nil)
	owner, session := fixture.client(t)
	if err := owner.Login(session, raw.CKU_USER, []byte(testmock.DefaultPIN)); err != nil {
		t.Fatal(err)
	}
	fixture.changeTokenPIN(t)
	fixture.allowRotation()
	if err := owner.Login(session, raw.CKU_USER, []byte("5678")); err != nil {
		t.Fatalf("granted client's rotation = %v, want CKR_OK", err)
	}
	requirePINRotationCalls(t, fixture, 2, 1)
	if _, err := owner.CreateObject(session, []*raw.Attribute{
		raw.NewAttribute(raw.CKA_CLASS, raw.CKO_DATA),
		raw.NewAttribute(raw.CKA_TOKEN, true),
		raw.NewAttribute(raw.CKA_PRIVATE, true),
	}); err != nil {
		t.Fatalf("rotation leader's private operation: %v", err)
	}
	if err := owner.Login(session, raw.CKU_USER, []byte("5678")); !raw.IsError(err, raw.CKR_USER_ALREADY_LOGGED_IN) {
		t.Fatalf("repeated login after rotation = %v, want CKR_USER_ALREADY_LOGGED_IN", err)
	}
	events := fixture.rotationEvents()
	if len(events) != 1 || events[0].Code != "" || events[0].Target != "shared-hsm" || events[0].ClientID == "" {
		t.Fatalf("successful rotation audit = %+v", events)
	}
}

func TestPINRotationAuthorizesOnceBeforeLogout(t *testing.T) {
	type observedAuthorization struct {
		operation string
		logouts   int64
	}
	var mu sync.Mutex
	var observed []observedAuthorization
	var fixturePointer atomic.Pointer[pinRotationFixture]
	fixture := newPINRotationFixture(t, func(config *TargetConfig) {
		config.Authorize = func(_ context.Context, request AuthorizationRequest) error {
			if request.Operation == AuthorizationOperationRotatePIN || request.Operation == AuthorizationOperationActivateTarget {
				mu.Lock()
				observed = append(observed, observedAuthorization{request.Operation, fixturePointer.Load().module.logouts.Load()})
				mu.Unlock()
			}
			return nil
		}
	})
	fixturePointer.Store(fixture)
	owner, session := fixture.client(t)
	if err := owner.Login(session, raw.CKU_USER, []byte(testmock.DefaultPIN)); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	observed = nil
	mu.Unlock()
	fixture.changeTokenPIN(t)
	fixture.allowRotation()
	if err := owner.Login(session, raw.CKU_USER, []byte("5678")); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	got := slices.Clone(observed)
	mu.Unlock()
	want := []observedAuthorization{{AuthorizationOperationRotatePIN, 0}, {AuthorizationOperationActivateTarget, 0}}
	if !slices.Equal(got, want) {
		t.Fatalf("rotation authorizations = %+v, want %+v", got, want)
	}
	requirePINRotationCalls(t, fixture, 2, 1)
}

func TestPINRotationAuthorizationDenialPreservesActivation(t *testing.T) {
	for _, deniedOperation := range []string{AuthorizationOperationRotatePIN, AuthorizationOperationActivateTarget} {
		t.Run(deniedOperation, func(t *testing.T) {
			var deny atomic.Bool
			fixture := newPINRotationFixture(t, func(config *TargetConfig) {
				config.Authorize = func(_ context.Context, request AuthorizationRequest) error {
					if deny.Load() && request.Operation == deniedOperation {
						return errors.New("rotation is denied")
					}
					return nil
				}
			})
			owner, session := fixture.client(t)
			if err := owner.Login(session, raw.CKU_USER, []byte(testmock.DefaultPIN)); err != nil {
				t.Fatal(err)
			}
			before := fixture.broker.activation.snapshot()
			fixture.allowRotation()
			deny.Store(true)
			err := owner.Login(session, raw.CKU_USER, []byte("9999"))
			remote, ok := errors.AsType[*RemoteError](err)
			if !ok || remote.Code != "forbidden" {
				t.Fatalf("denied rotation = %v, want forbidden", err)
			}
			requirePINRotationCalls(t, fixture, 1, 0)
			after := fixture.broker.activation.snapshot()
			if after.State != ActivationActive || after.Generation != before.Generation {
				t.Fatalf("denied rotation changed activation: before=%+v after=%+v", before, after)
			}
			if _, err := owner.CreateObject(session, []*raw.Attribute{
				raw.NewAttribute(raw.CKA_CLASS, raw.CKO_DATA),
				raw.NewAttribute(raw.CKA_TOKEN, true),
				raw.NewAttribute(raw.CKA_PRIVATE, true),
			}); err != nil {
				t.Fatalf("denied rotation revoked owner's grant: %v", err)
			}
			events := fixture.rotationEvents()
			if len(events) != 1 || events[0].Code != "forbidden" {
				t.Fatalf("denied rotation audit = %+v, want one forbidden event", events)
			}
		})
	}
}

func TestPINRotationContextSpecificMismatchNeverReachesHSM(t *testing.T) {
	for _, interval := range []time.Duration{0, time.Hour} {
		t.Run(interval.String(), func(t *testing.T) {
			harness := newProxyHarness(t, SessionBudget{MaxPhysicalTotal: 4, MaxPinned: 2}, func(config *TargetConfig) {
				config.Login.Mode = PhysicalLoginClientActivated
				config.Login.PhysicalPIN = nil
				config.Login.VerifyClientPIN = true
				config.Login.PINRotationInterval = interval
				config.Login.Authenticate = func(context.Context, LoginAttempt) error { return nil }
			})
			client := openRemoteRaw(t, harness.target)
			slot := remoteSlot(t, client)
			session := openVirtualSession(t, client, slot, true)
			if err := client.Login(session, raw.CKU_USER, []byte("1234")); err != nil {
				t.Fatal(err)
			}
			key, err := client.CreateObject(session, []*raw.Attribute{
				raw.NewAttribute(raw.CKA_CLASS, raw.CKO_DATA),
				raw.NewAttribute(raw.CKA_TOKEN, true),
				raw.NewAttribute(raw.CKA_PRIVATE, false),
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := client.EncryptInit(session, []*raw.Mechanism{raw.NewMechanism(raw.CKM_AES_CBC, nil)}, key); err != nil {
				t.Fatal(err)
			}
			harness.server.targetsMu.RLock()
			broker := harness.server.targets["mock-hsm"]
			harness.server.targetsMu.RUnlock()
			broker.activation.mu.Lock()
			broker.activation.attemptedAt = time.Now().Add(-2 * time.Hour)
			broker.activation.mu.Unlock()
			if err := client.Login(session, raw.CKU_CONTEXT_SPECIFIC, []byte("9999")); !raw.IsError(err, raw.CKR_PIN_INCORRECT) {
				t.Fatalf("context PIN mismatch = %v, want CKR_PIN_INCORRECT", err)
			}
			if got := diagnostic(t, client, slot, mockDiagLoginCalls); got != 1 {
				t.Fatalf("wrong context PIN reached HSM: %d login calls, want 1", got)
			}
			if got := diagnostic(t, client, slot, mockDiagLogoutCalls); got != 0 {
				t.Fatalf("context-specific login rotated the token: %d logout calls", got)
			}
			if err := client.Login(session, raw.CKU_CONTEXT_SPECIFIC, []byte("1234")); err != nil {
				t.Fatalf("correct context-specific login: %v", err)
			}
			if _, err := client.Encrypt(session, []byte("operation survives rejected context PIN")); err != nil {
				t.Fatalf("operation after context login: %v", err)
			}
		})
	}
}

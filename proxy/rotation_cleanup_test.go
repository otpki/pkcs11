//go:build !windows

package proxy

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/internal/testmock"
	"github.com/otpki/pkcs11/raw"
)

func TestPINRotationClearsOtherClientsOperationsAndPrivateAffinity(t *testing.T) {
	for _, success := range []bool{true, false} {
		name := "failure"
		if success {
			name = "success"
		}
		t.Run(name, func(t *testing.T) {
			source := testmock.Source{Name: t.Name(), Tokens: 1}
			server, address := newTestmockBroker(t, testmockPINTarget(t, source, func(config *TargetConfig) {
				config.Login.PINRotationInterval = time.Hour
				config.Login.ActivationFailureCooldown = time.Nanosecond
			}))
			target := haTarget(address)
			clientA := openRemoteRaw(t, target)
			clientB := openRemoteRaw(t, target)
			rotator := openRemoteRaw(t, target)
			sessionA := openVirtualSession(t, clientA, remoteSlot(t, clientA), true)
			objectSessionA := openVirtualSession(t, clientA, remoteSlot(t, clientA), true)
			sessionB := openVirtualSession(t, clientB, remoteSlot(t, clientB), true)
			rotationSession := openVirtualSession(t, rotator, remoteSlot(t, rotator), true)
			for _, pair := range []struct {
				client  raw.Module
				session raw.SessionHandle
			}{{clientA, sessionA}, {clientB, sessionB}} {
				if err := pair.client.Login(pair.session, raw.CKU_USER, []byte(testmock.DefaultPIN)); err != nil {
					t.Fatal(err)
				}
			}

			_, signingKey, err := clientA.GenerateKeyPair(sessionA,
				[]*raw.Mechanism{raw.NewMechanism(raw.CKM_EC_KEY_PAIR_GEN, nil)},
				[]*raw.Attribute{
					raw.NewAttribute(raw.CKA_TOKEN, true),
					raw.NewAttribute(raw.CKA_PRIVATE, false),
					raw.NewAttribute(raw.CKA_LABEL, "rotation-public-key"),
				},
				[]*raw.Attribute{
					raw.NewAttribute(raw.CKA_TOKEN, true),
					raw.NewAttribute(raw.CKA_PRIVATE, true),
					raw.NewAttribute(raw.CKA_LABEL, "rotation-signing-key"),
				})
			if err != nil {
				t.Fatal(err)
			}
			if err := clientA.SignInit(sessionA, []*raw.Mechanism{raw.NewMechanism(raw.CKM_ECDSA, nil)}, signingKey); err != nil {
				t.Fatal(err)
			}
			privateTemplate := []*raw.Attribute{
				raw.NewAttribute(raw.CKA_CLASS, raw.CKO_DATA),
				raw.NewAttribute(raw.CKA_TOKEN, false),
				raw.NewAttribute(raw.CKA_PRIVATE, true),
			}
			objectA, err := clientA.CreateObject(objectSessionA, privateTemplate)
			if err != nil {
				t.Fatal(err)
			}
			objectB, err := clientB.CreateObject(sessionB, privateTemplate)
			if err != nil {
				t.Fatal(err)
			}
			stats, _ := server.TargetStats("shared-hsm")
			if stats.PinnedSessions != 3 {
				t.Fatalf("pinned sessions before rotation = %d, want 3", stats.PinnedSessions)
			}

			if success {
				admin := testmockAdmin(t, source)
				if err := admin.WithRawSession(context.Background(), pkcs11.RawSessionOptions{ReadWrite: true}, func(module raw.Module, session raw.SessionHandle) error {
					return module.SetPIN(session, []byte(testmock.DefaultPIN), []byte("5678"))
				}); err != nil {
					t.Fatal(err)
				}
			}
			server.targetsMu.RLock()
			broker := server.targets["shared-hsm"]
			server.targetsMu.RUnlock()
			// Make only the first rotation eligible, without timing-sensitive sleeps.
			broker.activation.mu.Lock()
			broker.activation.attemptedAt = time.Now().Add(-2 * time.Hour)
			broker.activation.mu.Unlock()
			err = rotator.Login(rotationSession, raw.CKU_USER, []byte("5678"))
			if success && err != nil {
				t.Fatalf("rotation: %v", err)
			}
			if !success && !raw.IsError(err, raw.CKR_PIN_INCORRECT) {
				t.Fatalf("failed rotation = %v, want CKR_PIN_INCORRECT", err)
			}
			stats, _ = server.TargetStats("shared-hsm")
			if stats.PinnedSessions != 0 {
				t.Fatalf("rotation left pinned sessions: %+v", stats)
			}
			if _, err := clientA.Sign(sessionA, []byte("operation started before rotation")); !raw.IsError(err, raw.CKR_OPERATION_NOT_INITIALIZED) {
				t.Fatalf("Sign after rotation = %v, want CKR_OPERATION_NOT_INITIALIZED", err)
			}
			for _, pair := range []struct {
				client  raw.Module
				session raw.SessionHandle
				object  raw.ObjectHandle
			}{{clientA, objectSessionA, objectA}, {clientB, sessionB, objectB}} {
				if _, err := pair.client.GetObjectSize(pair.session, pair.object); !raw.IsError(err, raw.CKR_OBJECT_HANDLE_INVALID) {
					t.Fatalf("private session object after rotation = %v, want CKR_OBJECT_HANDLE_INVALID", err)
				}
				info, err := pair.client.GetSessionInfo(pair.session)
				if err != nil || info.State != raw.State(raw.CKS_RW_PUBLIC_SESSION) {
					t.Fatalf("other client's login after rotation = %v, %v; want public", info, err)
				}
			}
			currentPIN := testmock.DefaultPIN
			if success {
				currentPIN = "5678"
			}
			if err := clientA.Login(sessionA, raw.CKU_USER, []byte(currentPIN)); err != nil {
				t.Fatalf("other client re-login: %v", err)
			}
			if _, err := clientA.Sign(sessionA, []byte("old operation after re-login")); !raw.IsError(err, raw.CKR_OPERATION_NOT_INITIALIZED) {
				t.Fatalf("Sign after re-login = %v, want CKR_OPERATION_NOT_INITIALIZED", err)
			}
		})
	}
}

func TestPINRotationPreservesPublicSessionObjects(t *testing.T) {
	source := testmock.Source{Name: t.Name(), Tokens: 1}
	server, address := newTestmockBroker(t, testmockPINTarget(t, source, func(config *TargetConfig) {
		config.Login.PINRotationInterval = time.Hour
	}))
	target := haTarget(address)
	owner := openRemoteRaw(t, target)
	rotator := openRemoteRaw(t, target)
	session := openVirtualSession(t, owner, remoteSlot(t, owner), true)
	rotationSession := openVirtualSession(t, rotator, remoteSlot(t, rotator), true)
	if err := owner.Login(session, raw.CKU_USER, []byte(testmock.DefaultPIN)); err != nil {
		t.Fatal(err)
	}
	publicObject, err := owner.CreateObject(session, []*raw.Attribute{
		raw.NewAttribute(raw.CKA_CLASS, raw.CKO_DATA),
		raw.NewAttribute(raw.CKA_TOKEN, false),
		raw.NewAttribute(raw.CKA_PRIVATE, false),
		raw.NewAttribute(raw.CKA_LABEL, "public-object-survives-rotation"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.CreateObject(session, []*raw.Attribute{
		raw.NewAttribute(raw.CKA_CLASS, raw.CKO_DATA),
		raw.NewAttribute(raw.CKA_TOKEN, false),
		raw.NewAttribute(raw.CKA_PRIVATE, true),
	}); err != nil {
		t.Fatal(err)
	}
	if err := owner.DigestInit(session, []*raw.Mechanism{raw.NewMechanism(raw.CKM_SHA256, nil)}); err != nil {
		t.Fatal(err)
	}
	admin := testmockAdmin(t, source)
	if err := admin.WithRawSession(context.Background(), pkcs11.RawSessionOptions{ReadWrite: true}, func(module raw.Module, native raw.SessionHandle) error {
		return module.SetPIN(native, []byte(testmock.DefaultPIN), []byte("5678"))
	}); err != nil {
		t.Fatal(err)
	}
	server.targetsMu.RLock()
	broker := server.targets["shared-hsm"]
	server.targetsMu.RUnlock()
	broker.activation.mu.Lock()
	broker.activation.attemptedAt = time.Now().Add(-2 * time.Hour)
	broker.activation.mu.Unlock()
	if err := rotator.Login(rotationSession, raw.CKU_USER, []byte("5678")); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Digest(session, []byte("operation ended by rotation")); !raw.IsError(err, raw.CKR_OPERATION_NOT_INITIALIZED) {
		t.Fatalf("Digest after rotation = %v, want CKR_OPERATION_NOT_INITIALIZED", err)
	}
	if _, err := owner.GetObjectSize(session, publicObject); err != nil {
		t.Fatalf("public session object after rotation: %v", err)
	}
	stats, _ := server.TargetStats("shared-hsm")
	if stats.PinnedSessions != 1 {
		t.Fatalf("public object affinity = %d, want 1", stats.PinnedSessions)
	}
	if err := owner.DestroyObject(session, publicObject); err != nil {
		t.Fatal(err)
	}
	stats, _ = server.TargetStats("shared-hsm")
	if stats.PinnedSessions != 0 {
		t.Fatalf("private object left affinity after public object was destroyed: %+v", stats)
	}
}

// A PKCS #11 2.x provider cannot cancel operations with C_SessionCancel. A
// successfully closed native session still guarantees that its state is gone.
type rotationCleanupTestModule struct {
	raw.Module
	cancels   atomic.Int64
	closes    atomic.Int64
	failClose atomic.Bool
}

func (module *rotationCleanupTestModule) SessionCancel(raw.SessionHandle, uint) error {
	module.cancels.Add(1)
	return raw.Error(raw.CKR_FUNCTION_NOT_SUPPORTED)
}

func (module *rotationCleanupTestModule) CloseSession(session raw.SessionHandle) error {
	module.closes.Add(1)
	if module.failClose.Swap(false) {
		return raw.Error(raw.CKR_DEVICE_ERROR)
	}
	return module.Module.CloseSession(session)
}

type rotationCleanupTestSource struct {
	name   string
	module *rotationCleanupTestModule
}

func (source rotationCleanupTestSource) OpenModule(context.Context) (raw.Module, error) {
	return source.module, nil
}

func (source rotationCleanupTestSource) RegistryKey() string {
	return "rotation-cleanup-test:" + source.name
}
func (source rotationCleanupTestSource) String() string { return source.RegistryKey() }

func TestPINRotationRecoversUnsupportedCancelOnlyAfterNativeClose(t *testing.T) {
	for _, closeFails := range []bool{false, true} {
		name := "native_close_succeeds"
		if closeFails {
			name = "native_close_fails"
		}
		t.Run(name, func(t *testing.T) {
			module := &rotationCleanupTestModule{Module: testmock.New(t.Name(), 1)}
			source := rotationCleanupTestSource{name: t.Name(), module: module}
			server, address := newTestmockBroker(t, testmockPINTarget(t, source, func(config *TargetConfig) {
				config.Login.PINRotationInterval = time.Hour
			}))
			target := haTarget(address)
			owner := openRemoteRaw(t, target)
			rotator := openRemoteRaw(t, target)
			session := openVirtualSession(t, owner, remoteSlot(t, owner), true)
			rotationSession := openVirtualSession(t, rotator, remoteSlot(t, rotator), true)
			if err := owner.Login(session, raw.CKU_USER, []byte(testmock.DefaultPIN)); err != nil {
				t.Fatal(err)
			}
			if err := owner.DigestInit(session, []*raw.Mechanism{raw.NewMechanism(raw.CKM_SHA256, nil)}); err != nil {
				t.Fatal(err)
			}
			server.targetsMu.RLock()
			broker := server.targets["shared-hsm"]
			server.targetsMu.RUnlock()
			// Use the control lease directly so the mock's PIN changes without
			// the proxy's brokered SetPIN path re-arming the verifier.
			if err := broker.control.Call(context.Background(), "test-out-of-band-pin", func(native raw.Module, handle raw.SessionHandle) error {
				return native.SetPIN(handle, []byte(testmock.DefaultPIN), []byte("5678"))
			}); err != nil {
				t.Fatal(err)
			}
			broker.activation.mu.Lock()
			broker.activation.attemptedAt = time.Now().Add(-2 * time.Hour)
			broker.activation.mu.Unlock()
			beforeClose := module.closes.Load()
			module.failClose.Store(closeFails)
			err := rotator.Login(rotationSession, raw.CKU_USER, []byte("5678"))
			if !closeFails && err != nil {
				t.Fatalf("rotation despite successful fallback close: %v", err)
			}
			if closeFails && !raw.IsError(err, raw.CKR_DEVICE_ERROR) {
				t.Fatalf("rotation with failed native close = %v, want CKR_DEVICE_ERROR", err)
			}
			if module.cancels.Load() != 1 || module.closes.Load() != beforeClose+1 {
				t.Fatalf("cleanup attempts: cancel = %d, closes = %d; want one cancel and one native close", module.cancels.Load(), module.closes.Load()-beforeClose)
			}
			stats, _ := server.TargetStats("shared-hsm")
			if stats.PinnedSessions != 0 {
				t.Fatalf("fallback left pinned sessions: %+v", stats)
			}
			if _, err := owner.Digest(session, []byte("discarded operation")); !raw.IsError(err, raw.CKR_OPERATION_NOT_INITIALIZED) {
				t.Fatalf("old operation after fallback = %v, want CKR_OPERATION_NOT_INITIALIZED", err)
			}
			if !closeFails {
				if _, err := rotator.CreateObject(rotationSession, []*raw.Attribute{
					raw.NewAttribute(raw.CKA_CLASS, raw.CKO_DATA),
					raw.NewAttribute(raw.CKA_TOKEN, true),
					raw.NewAttribute(raw.CKA_PRIVATE, true),
					raw.NewAttribute(raw.CKA_LABEL, "rotation-after-fallback"),
				}); err != nil {
					t.Fatalf("rotator's grant after fallback: %v", err)
				}
			}
		})
	}
}

func TestLogicalLogoutPreservesUnsupportedCancelError(t *testing.T) {
	module := &rotationCleanupTestModule{Module: testmock.New(t.Name(), 1)}
	source := rotationCleanupTestSource{name: t.Name(), module: module}
	server, address := newTestmockBroker(t, testmockPINTarget(t, source, nil))
	client := openRemoteRaw(t, haTarget(address))
	session := openVirtualSession(t, client, remoteSlot(t, client), true)
	if err := client.Login(session, raw.CKU_USER, []byte(testmock.DefaultPIN)); err != nil {
		t.Fatal(err)
	}
	if err := client.DigestInit(session, []*raw.Mechanism{raw.NewMechanism(raw.CKM_SHA256, nil)}); err != nil {
		t.Fatal(err)
	}
	if err := client.Logout(session); !raw.IsError(err, raw.CKR_FUNCTION_NOT_SUPPORTED) {
		t.Fatalf("logical logout = %v, want established CKR_FUNCTION_NOT_SUPPORTED behavior", err)
	}
	stats, _ := server.TargetStats("shared-hsm")
	if stats.PinnedSessions != 0 {
		t.Fatalf("logical logout left pinned session: %+v", stats)
	}
}

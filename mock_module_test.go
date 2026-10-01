//go:build !windows

package pkcs11

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/otpki/pkcs11/raw"
)

func buildMockModule(t *testing.T) string {
	t.Helper()
	compiler := os.Getenv("CC")
	if compiler == "" {
		compiler = "cc"
	}
	if _, err := exec.LookPath(compiler); err != nil {
		t.Skipf("C compiler is unavailable: %v", err)
	}
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "libotpki-pkcs11-mock.so")
	args := []string{"-std=c11", "-fPIC", "-shared", "-pthread", "-I", filepath.Join(root, "raw", "internal", "cryptoki"), filepath.Join(root, "internal", "testmodule", "mock.c"), "-o", output}
	if runtime.GOOS == "darwin" {
		output = filepath.Join(t.TempDir(), "libotpki-pkcs11-mock.dylib")
		args = []string{"-std=c11", "-fPIC", "-dynamiclib", "-pthread", "-I", filepath.Join(root, "raw", "internal", "cryptoki"), filepath.Join(root, "internal", "testmodule", "mock.c"), "-o", output}
	}
	command := exec.Command(compiler, args...)
	if combined, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compile mock module: %v\n%s", err, combined)
	}
	return output
}

var threadAffinityTestVendor = &testVendorModule{definition: VendorDefinition{
	ID:       AdapterFamily("internal-otpki-test"),
	Name:     "OTPKI thread-affinity test module",
	Priority: 10_000,
	Source:   "internal native test fixture",
	Match: VendorMatchSpec{
		Manufacturers: []string{"otpki test"},
	},
	Behavior: VendorBehavior{
		LoginScope:            VendorLoginToken,
		LockSessionToOSThread: true,
		RejectNullOutputProbe: true,
	},
}}

func TestManagedClientAgainstMockModule(t *testing.T) {
	module := buildMockModule(t)
	ctx := context.Background()
	client, err := Open(ctx, Config{
		Module:   LocalModule(module),
		Login:    LoginConfig{Mode: LoginEager},
		PIN:      StaticPIN("1234"),
		Sessions: SessionConfig{Min: 1, Max: 4},
		Vendors:  []VendorModule{threadAffinityTestVendor},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := client.Close(ctx); err != nil {
			t.Errorf("close: %v", err)
		}
	}()

	if got := client.Version(); got != (raw.Version{Major: 2, Minor: 40}) {
		t.Fatalf("interface version = %v", got)
	}
	if got := client.Device().Fingerprint.Token.Label; got != "OTPKI-MOCK" {
		t.Fatalf("token label = %q", got)
	}
	if got := client.Adapter().Name; got != "OTPKI thread-affinity test module" {
		t.Fatalf("adapter = %q", got)
	}
	if report, err := client.Health(ctx, HealthOptions{CheckRandom: true}); err != nil || report.Status == HealthUnhealthy {
		t.Fatalf("health = %#v, %v", report, err)
	}
	if report, err := client.ValidateRuntime(ctx, RuntimeValidationOptions{Refresh: true, CheckRandom: true}); err != nil || report.Level != ValidationOperational || !report.RuntimeProbed {
		t.Fatalf("runtime validation = %#v, %v", report, err)
	}

	const workers = 32
	var wait sync.WaitGroup
	errorsChannel := make(chan error, workers)
	for range workers {
		wait.Go(func() {
			value, err := client.Random(ctx, 64)
			if err != nil {
				errorsChannel <- err
				return
			}
			if len(value) != 64 {
				errorsChannel <- fmt.Errorf("random length = %d", len(value))
			}
		})
	}
	wait.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		t.Error(err)
	}
	if opened := client.SessionStats().ReadOnly.Opened; opened > 4 {
		t.Fatalf("read-only pool opened %d sessions", opened)
	}

	err = client.WithRawSession(ctx, RawSessionOptions{Operation: "mock-output-buffer"}, func(module raw.Module, session raw.SessionHandle) (operationErr error) {
		key, err := module.CreateObject(session, []*raw.Attribute{
			raw.NewAttribute(raw.CKA_CLASS, raw.CKO_SECRET_KEY),
			raw.NewAttribute(raw.CKA_KEY_TYPE, raw.CKK_AES),
			raw.NewAttribute(raw.CKA_TOKEN, false),
		})
		if err != nil {
			return fmt.Errorf("create mock session key: %w", err)
		}
		defer func() { operationErr = errors.Join(operationErr, module.DestroyObject(session, key)) }()

		if err := module.EncryptInit(session, []*raw.Mechanism{raw.NewMechanism(raw.CKM_AES_CBC, nil)}, key); err != nil {
			return err
		}
		plaintext := []byte("output probe compatibility")
		ciphertext, err := module.Encrypt(session, plaintext)
		if err != nil {
			return err
		}
		if string(ciphertext) != string(plaintext) {
			return fmt.Errorf("mock ciphertext = %q", ciphertext)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("real-buffer output compatibility: %v", err)
	}

	err = client.withReadOnlySession(ctx, func(session *sessionLease) error {
		_, signErr := session.Sign(ctx, []byte("not initialized"))
		return signErr
	})
	if !errors.Is(err, raw.Error(raw.CKR_FUNCTION_NOT_SUPPORTED)) {
		t.Fatalf("missing function error = %v", err)
	}
}

const (
	mockDiagnosticLoginCalls  = raw.CKM_VENDOR_DEFINED + 0x7f01
	mockDiagnosticLogoutCalls = raw.CKM_VENDOR_DEFINED + 0x7f02
	mockDiagnosticMaxSessions = raw.CKM_VENDOR_DEFINED + 0x7f03
)

func mockDiagnostic(t *testing.T, client *Client, mechanism uint) uint {
	t.Helper()
	var info raw.MechanismInfo
	err := client.WithRawModule(context.Background(), RawModuleOptions{Operation: "mock-diagnostic"}, func(module raw.Module) error {
		var err error
		info, err = module.GetMechanismInfo(client.Device().Fingerprint.SlotID, raw.MechanismType(mechanism))
		return err
	})
	if err != nil {
		t.Fatalf("mock diagnostic 0x%x: %v", mechanism, err)
	}
	return info.MinKeySize
}

func TestDeactivateCoordinatesOnePhysicalLogout(t *testing.T) {
	module := buildMockModule(t)
	client, err := Open(context.Background(), Config{
		Module:   LocalModule(module),
		Login:    LoginConfig{Mode: LoginEager},
		PIN:      StaticPIN("1234"),
		Sessions: SessionConfig{Min: 1, ReadOnlyMax: 3, ReadWriteMax: 3, MaxTotal: 3},
		Vendors:  []VendorModule{threadAffinityTestVendor},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close(context.Background()) }()

	if got := mockDiagnostic(t, client, mockDiagnosticLoginCalls); got != 1 {
		t.Fatalf("initial physical login calls = %d, want 1", got)
	}
	if _, err := client.Random(context.Background(), 32); err != nil {
		t.Fatal(err)
	}
	if err := client.WithRawSession(context.Background(), RawSessionOptions{ReadWrite: true, Operation: "deactivate-rw"}, func(raw.Module, raw.SessionHandle) error {
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := client.Deactivate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := mockDiagnostic(t, client, mockDiagnosticLogoutCalls); got != 1 {
		t.Fatalf("physical logout calls = %d, want exactly 1", got)
	}
	if _, err := client.Random(context.Background(), 32); err != nil {
		t.Fatal(err)
	}
	if got := mockDiagnostic(t, client, mockDiagnosticLoginCalls); got != 1 {
		t.Fatalf("deactivated client unexpectedly logged in again: %d calls", got)
	}
	if err := client.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := mockDiagnostic(t, client, mockDiagnosticLoginCalls); got != 2 {
		t.Fatalf("physical login calls after explicit reactivation = %d, want 2", got)
	}
}

func TestCombinedSessionBudgetCapsReadOnlyAndReadWritePools(t *testing.T) {
	module := buildMockModule(t)
	client, err := Open(context.Background(), Config{
		Module: LocalModule(module),
		Login:  LoginConfig{Mode: LoginNone},
		Sessions: SessionConfig{
			ReadOnlyMax: 4, ReadWriteMax: 4, MaxTotal: 3,
		},
		Vendors: []VendorModule{threadAffinityTestVendor},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close(context.Background()) }()

	var leases []*RawSessionLease
	for _, readWrite := range []bool{false, true, false} {
		lease, err := client.AcquireRawSession(context.Background(), RawSessionOptions{ReadWrite: readWrite, Operation: "combined-budget"})
		if err != nil {
			t.Fatal(err)
		}
		leases = append(leases, lease)
	}
	defer func() {
		for _, lease := range leases {
			_ = lease.Close(context.Background())
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := client.AcquireRawSession(ctx, RawSessionOptions{ReadWrite: true, Operation: "combined-budget-overflow"}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("fourth session error = %v, want deadline while total budget is full", err)
	}
	stats := client.SessionStats()
	if opened := stats.ReadOnly.Opened + stats.ReadWrite.Opened; opened != 3 {
		t.Fatalf("combined opened sessions = %d, want 3", opened)
	}
	if got := mockDiagnostic(t, client, mockDiagnosticMaxSessions); got > 3 {
		t.Fatalf("native session high-water mark = %d, maximum 3", got)
	}
}

//go:build !windows && integration

package raw

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func buildV32MockModule(t *testing.T) string {
	t.Helper()
	compiler := os.Getenv("CC")
	if compiler == "" {
		compiler = "cc"
	}
	if _, err := exec.LookPath(compiler); err != nil {
		t.Skipf("C compiler is unavailable: %v", err)
	}
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Dir(workingDirectory)
	output := filepath.Join(t.TempDir(), "libotpki-pkcs11-v32-mock.so")
	arguments := []string{"-std=c11", "-fPIC", "-shared", "-I", filepath.Join(workingDirectory, "internal", "cryptoki"), filepath.Join(root, "internal", "testmodule", "mock_v32.c"), "-o", output}
	if runtime.GOOS == "darwin" {
		output = filepath.Join(t.TempDir(), "libotpki-pkcs11-v32-mock.dylib")
		arguments = []string{"-std=c11", "-fPIC", "-dynamiclib", "-I", filepath.Join(workingDirectory, "internal", "cryptoki"), filepath.Join(root, "internal", "testmodule", "mock_v32.c"), "-o", output}
	}
	if combined, err := exec.Command(compiler, arguments...).CombinedOutput(); err != nil {
		t.Fatalf("compile PKCS #11 3.2 mock module: %v\n%s", err, combined)
	}
	return output
}

func assertRetainedMechanism(t *testing.T, module *Ctx, session SessionHandle, operation activeMechanismOperation, want bool) {
	t.Helper()
	module.active.mu.Lock()
	_, got := module.active.values[activeMechanismKey{session: session, operation: operation}]
	module.active.mu.Unlock()
	if got != want {
		t.Fatalf("retained mechanism session=%#x operation=%d = %t, want %t", session, operation, got, want)
	}
}

func TestPKCS1132FunctionTableDispatch(t *testing.T) {
	module, err := Open(buildV32MockModule(t), WithoutLegacyFallback())
	if err != nil {
		t.Fatal(err)
	}
	defer module.Destroy()
	if got := module.Interface(); got.Version != (Version{Major: 3, Minor: 2}) || got.Name != "PKCS 11" {
		t.Fatalf("selected interface = %#v", got)
	}
	if err := module.Initialize(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := module.Finalize(); err != nil {
			t.Errorf("finalize: %v", err)
		}
	}()
	info, err := module.GetInfo()
	if err != nil || info.CryptokiVersion != (Version{Major: 3, Minor: 2}) {
		t.Fatalf("GetInfo = %#v, %v", info, err)
	}
	interfaces, err := module.GetInterfaceList()
	if err != nil || len(interfaces) != 1 || interfaces[0].Version != (Version{Major: 3, Minor: 2}) {
		t.Fatalf("GetInterfaceList = %#v, %v", interfaces, err)
	}
	selected, err := module.GetInterface("PKCS 11", &Version{Major: 3, Minor: 2}, 0)
	if err != nil || selected.Pointer == 0 || selected.Version != (Version{Major: 3, Minor: 2}) {
		t.Fatalf("GetInterface = %#v, %v", selected, err)
	}
	session, err := module.OpenSession(7, CKF_SERIAL_SESSION)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := module.CloseSession(session); err != nil {
			t.Errorf("close session: %v", err)
		}
	}()
	if err := module.LoginUser(session, CKU_USER, []byte("1234"), "alice"); err != nil {
		t.Fatalf("LoginUser: %v", err)
	}
	if err := module.MessageSignInit(session, []*Mechanism{NewMechanism(CKM_SHA256_HMAC, nil)}, 9); err != nil {
		t.Fatalf("MessageSignInit: %v", err)
	}
	assertRetainedMechanism(t, module, session, activeMessageSign, true)
	messageSignature, err := module.SignMessage(session, nil, []byte("abc"))
	if err != nil || !bytes.Equal(messageSignature, []byte{0x32, 'a', 'b', 'c'}) {
		t.Fatalf("SignMessage = %x, %v", messageSignature, err)
	}
	// The PKCS #11 message API permits multiple complete messages between Init
	// and Final, so the initialization mechanism must remain alive here.
	assertRetainedMechanism(t, module, session, activeMessageSign, true)
	if err := module.MessageSignFinal(session); err != nil {
		t.Fatalf("MessageSignFinal: %v", err)
	}
	assertRetainedMechanism(t, module, session, activeMessageSign, false)
	ciphertext, secret, err := module.EncapsulateKey(session, []*Mechanism{NewMechanism(CKM_ML_KEM, nil)}, 11, nil)
	if err != nil || !bytes.Equal(ciphertext, []byte{1, 2, 3, 4}) || secret != 0x1234 {
		t.Fatalf("EncapsulateKey = %x %#x, %v", ciphertext, secret, err)
	}
	secret, err = module.DecapsulateKey(session, []*Mechanism{NewMechanism(CKM_ML_KEM, nil)}, 12, ciphertext, nil)
	if err != nil || secret != 0x5678 {
		t.Fatalf("DecapsulateKey = %#x, %v", secret, err)
	}
	if err := module.VerifySignatureInit(session, []*Mechanism{NewMechanism(CKM_ML_DSA, nil)}, 13, []byte{1, 2, 3}); err != nil {
		t.Fatalf("VerifySignatureInit: %v", err)
	}
	assertRetainedMechanism(t, module, session, activeVerifySignature, true)
	// The mock deliberately reads the signature pointer again during the later
	// verification call. Force collection and allocation churn to catch a raw
	// binding that retained only the address rather than the retained backing data.
	runtime.GC()
	for range 64 {
		_ = make([]byte, 32<<10)
	}
	if err := module.VerifySignature(session, []byte("ok")); err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}
	assertRetainedMechanism(t, module, session, activeVerifySignature, false)

	if err := module.VerifySignatureInit(session, []*Mechanism{NewMechanism(CKM_ML_DSA, nil)}, 13, []byte{1, 2, 3}); err != nil {
		t.Fatalf("VerifySignatureInit multipart: %v", err)
	}
	if err := module.VerifySignatureUpdate(session, []byte("part")); err != nil {
		t.Fatalf("VerifySignatureUpdate: %v", err)
	}
	assertRetainedMechanism(t, module, session, activeVerifySignature, true)
	if err := module.VerifySignatureFinal(session); err != nil {
		t.Fatalf("VerifySignatureFinal: %v", err)
	}
	assertRetainedMechanism(t, module, session, activeVerifySignature, false)
	flags, err := module.GetSessionValidationFlags(session, ValidationFlagsType(CKS_LAST_VALIDATION_OK))
	if err != nil || flags != 0xa5 {
		t.Fatalf("GetSessionValidationFlags = %#x, %v", flags, err)
	}
	async := &AsyncData{Version: 1, Value: make([]byte, 8)}
	if err := module.AsyncComplete(session, "C_Mock", async); err != nil {
		t.Fatalf("AsyncComplete: %v", err)
	}
	if async.Version != 2 || !bytes.Equal(async.Value, []byte{9, 8, 7}) || async.Object != 0x44 || async.AdditionalObject != 0x55 {
		t.Fatalf("AsyncComplete result = %#v", async)
	}
	id, err := module.AsyncGetID(session, "C_Mock")
	if err != nil || id != 42 {
		t.Fatalf("AsyncGetID = %d, %v", id, err)
	}
	if err := module.AsyncJoin(session, "C_Mock", id, []byte{1, 2}); err != nil {
		t.Fatalf("AsyncJoin: %v", err)
	}
	wrapped, err := module.WrapKeyAuthenticated(session, []*Mechanism{NewMechanism(CKM_AES_KEY_WRAP_KWP, nil)}, 14, 15, []byte("aad"))
	if err != nil || !bytes.Equal(wrapped, []byte{6, 5, 4}) {
		t.Fatalf("WrapKeyAuthenticated = %x, %v", wrapped, err)
	}
	unwrapped, err := module.UnwrapKeyAuthenticated(session, []*Mechanism{NewMechanism(CKM_AES_KEY_WRAP_KWP, nil)}, 16, wrapped, nil, []byte("aad"))
	if err != nil || unwrapped != 0x9abc {
		t.Fatalf("UnwrapKeyAuthenticated = %#x, %v", unwrapped, err)
	}
}

func TestMechanismInitializationCannotRaceModuleUnload(t *testing.T) {
	module, err := Open(buildV32MockModule(t), WithoutLegacyFallback())
	if err != nil {
		t.Fatal(err)
	}

	mechanism, err := marshalMechanism(NewMechanism(CKM_AES_GCM, &GCMParams{IV: make([]byte, 12), TagBits: 128}))
	if err != nil {
		module.Destroy()
		t.Fatal(err)
	}

	entered := make(chan struct{})
	continueCall := make(chan struct{})
	initialized := make(chan error, 1)
	go func() {
		initialized <- module.initializeMechanism(0x77, activeEncrypt, mechanism, func() uint {
			close(entered)
			<-continueCall
			return CKR_OK
		})
	}()
	<-entered

	destroyed := make(chan struct{})
	go func() {
		module.Destroy()
		close(destroyed)
	}()

	select {
	case <-destroyed:
		close(continueCall)
		t.Fatal("Destroy returned while mechanism initialization still held the native-library lease")
	case <-time.After(25 * time.Millisecond):
	}

	close(continueCall)
	if err := <-initialized; err != nil {
		t.Fatalf("initialize mechanism: %v", err)
	}
	select {
	case <-destroyed:
	case <-time.After(2 * time.Second):
		t.Fatal("Destroy did not complete after mechanism initialization committed")
	}

	module.active.mu.Lock()
	remaining := len(module.active.values)
	module.active.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("retained mechanisms after Destroy = %d, want 0", remaining)
	}
}

package testmock

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/otpki/pkcs11/raw"
)

func TestModuleLifecycleAndDiscovery(t *testing.T) {
	m := New("demo-hsm", 2)

	if _, err := m.GetSlotList(true); !raw.IsError(err, raw.CKR_CRYPTOKI_NOT_INITIALIZED) {
		t.Fatalf("GetSlotList before init = %v", err)
	}
	if err := m.Initialize(); err != nil {
		t.Fatal(err)
	}
	if err := m.Initialize(); !raw.IsError(err, raw.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
		t.Fatalf("second Initialize = %v", err)
	}
	slots, err := m.GetSlotList(true)
	if err != nil || len(slots) != 2 {
		t.Fatalf("slots = %v, %v", slots, err)
	}
	info, err := m.GetTokenInfo(slots[1])
	if err != nil {
		t.Fatal(err)
	}
	if info.Label != "demo-hsm-token-2" || info.SerialNumber == "" {
		t.Fatalf("token info = %+v", info)
	}
	if _, err := m.GetTokenInfo(raw.SlotID(9)); !raw.IsError(err, raw.CKR_SLOT_ID_INVALID) {
		t.Fatalf("bad slot = %v", err)
	}
	mechs, err := m.GetMechanismList(slots[0])
	if err != nil || len(mechs) == 0 {
		t.Fatalf("mechanisms = %v, %v", mechs, err)
	}
}

func TestModuleSessionsAndLogin(t *testing.T) {
	m := New("demo", 1)
	if err := m.Initialize(); err != nil {
		t.Fatal(err)
	}
	if _, err := m.OpenSession(1, 0); !raw.IsError(err, raw.CKR_SESSION_PARALLEL_NOT_SUPPORTED) {
		t.Fatalf("non-serial session = %v", err)
	}
	s, err := m.OpenSession(1, raw.CKF_SERIAL_SESSION|raw.CKF_RW_SESSION)
	if err != nil {
		t.Fatal(err)
	}
	info, err := m.GetSessionInfo(s)
	if err != nil || info.State != raw.State(raw.CKS_RW_PUBLIC_SESSION) {
		t.Fatalf("session info = %+v, %v", info, err)
	}
	if err := m.Login(s, raw.CKU_USER, []byte("9999")); !raw.IsError(err, raw.CKR_PIN_INCORRECT) {
		t.Fatalf("wrong PIN = %v", err)
	}
	if err := m.Login(s, raw.CKU_USER, []byte(DefaultPIN)); err != nil {
		t.Fatalf("login = %v", err)
	}
	info, _ = m.GetSessionInfo(s)
	if info.State != raw.State(raw.CKS_RW_USER_FUNCTIONS) {
		t.Fatalf("post-login state = %d", info.State)
	}
	if err := m.Login(s, raw.CKU_USER, []byte(DefaultPIN)); !raw.IsError(err, raw.CKR_USER_ALREADY_LOGGED_IN) {
		t.Fatalf("re-login = %v", err)
	}
	if err := m.Logout(s); err != nil {
		t.Fatal(err)
	}
	if err := m.Logout(s); !raw.IsError(err, raw.CKR_USER_NOT_LOGGED_IN) {
		t.Fatalf("double logout = %v", err)
	}
	if err := m.CloseSession(s); err != nil {
		t.Fatal(err)
	}
	if _, err := m.GetSessionInfo(s); !raw.IsError(err, raw.CKR_SESSION_HANDLE_INVALID) {
		t.Fatalf("closed session = %v", err)
	}
}

func TestModuleObjectsDigestAndRandom(t *testing.T) {
	m := New("demo", 1)
	if err := m.Initialize(); err != nil {
		t.Fatal(err)
	}
	s, err := m.OpenSession(1, raw.CKF_SERIAL_SESSION|raw.CKF_RW_SESSION)
	if err != nil {
		t.Fatal(err)
	}

	// The seeded info object is findable.
	objects, err := m.FindAllObjects(s, nil, 16)
	if err != nil || len(objects) == 0 {
		t.Fatalf("FindAllObjects = %v, %v", objects, err)
	}
	attrs, err := m.GetAttributeValue(s, objects[0], []*raw.Attribute{
		{Type: raw.CKA_LABEL},
	})
	if err != nil || string(attrs[0].Value) != "testmode-info" {
		t.Fatalf("seeded object label = %q, %v", attrs[0].Value, err)
	}

	// Create + find by label.
	h, err := m.CreateObject(s, []*raw.Attribute{
		raw.NewAttribute(raw.CKA_CLASS, raw.CKO_DATA),
		raw.NewAttribute(raw.CKA_LABEL, "demo-object"),
		raw.NewAttribute(raw.CKA_VALUE, []byte("hello")),
	})
	if err != nil {
		t.Fatal(err)
	}
	found, err := m.FindAllObjects(s, []*raw.Attribute{raw.NewAttribute(raw.CKA_LABEL, "demo-object")}, 16)
	if err != nil || len(found) != 1 || found[0] != h {
		t.Fatalf("find by label = %v, %v", found, err)
	}

	// Digest.
	if err := m.DigestInit(s, []*raw.Mechanism{raw.NewMechanism(raw.CKM_SHA256, nil)}); err != nil {
		t.Fatal(err)
	}
	sum, err := m.Digest(s, []byte("abc"))
	if err != nil {
		t.Fatal(err)
	}
	if want := sha256.Sum256([]byte("abc")); !bytes.Equal(sum, want[:]) {
		t.Fatalf("digest = %x, want %x", sum, want)
	}

	// Random.
	random, err := m.GenerateRandom(s, 32)
	if err != nil || len(random) != 32 {
		t.Fatalf("random = %d bytes, %v", len(random), err)
	}
}

func TestModuleKeysSignVerifyAndCipher(t *testing.T) {
	m := New("demo", 1)
	if err := m.Initialize(); err != nil {
		t.Fatal(err)
	}
	s, err := m.OpenSession(1, raw.CKF_SERIAL_SESSION|raw.CKF_RW_SESSION)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Login(s, raw.CKU_USER, []byte(DefaultPIN)); err != nil {
		t.Fatal(err)
	}

	// ECDSA roundtrip.
	pub, priv, err := m.GenerateKeyPair(s,
		[]*raw.Mechanism{raw.NewMechanism(raw.CKM_EC_KEY_PAIR_GEN, nil)},
		[]*raw.Attribute{raw.NewAttribute(raw.CKA_LABEL, "ec-pub")},
		[]*raw.Attribute{raw.NewAttribute(raw.CKA_LABEL, "ec-priv")},
	)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("signed through the test module")
	if err := m.SignInit(s, []*raw.Mechanism{raw.NewMechanism(raw.CKM_ECDSA, nil)}, priv); err != nil {
		t.Fatal(err)
	}
	signature, err := m.Sign(s, data)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.VerifyInit(s, []*raw.Mechanism{raw.NewMechanism(raw.CKM_ECDSA, nil)}, pub); err != nil {
		t.Fatal(err)
	}
	if err := m.Verify(s, data, signature); err != nil {
		t.Fatalf("verify own signature = %v", err)
	}
	if err := m.VerifyInit(s, []*raw.Mechanism{raw.NewMechanism(raw.CKM_ECDSA, nil)}, pub); err != nil {
		t.Fatal(err)
	}
	if err := m.Verify(s, []byte("tampered"), signature); !raw.IsError(err, raw.CKR_SIGNATURE_INVALID) {
		t.Fatalf("tampered verify = %v", err)
	}

	// AES-CBC roundtrip.
	aesKey, err := m.GenerateKey(s,
		[]*raw.Mechanism{raw.NewMechanism(raw.CKM_AES_KEY_GEN, nil)},
		[]*raw.Attribute{raw.NewAttribute(raw.CKA_LABEL, "aes-key")},
	)
	if err != nil {
		t.Fatal(err)
	}
	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		t.Fatal(err)
	}
	mech := []*raw.Mechanism{raw.NewMechanism(raw.CKM_AES_CBC, iv)}
	if err := m.EncryptInit(s, mech, aesKey); err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("test fixture plaintext")
	ciphertext, err := m.Encrypt(s, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.DecryptInit(s, mech, aesKey); err != nil {
		t.Fatal(err)
	}
	back, err := m.Decrypt(s, ciphertext)
	if err != nil || !bytes.Equal(back, plaintext) {
		t.Fatalf("roundtrip = %q, %v", back, err)
	}
}

func TestSourceIdentity(t *testing.T) {
	a := Source{Name: "hsm-a", Tokens: 2}
	b := Source{Name: "hsm-a", Tokens: 2}
	c := Source{Name: "hsm-b", Tokens: 2}
	if a.RegistryKey() != b.RegistryKey() {
		t.Fatal("equal sources must share a registry key")
	}
	if a.RegistryKey() == c.RegistryKey() {
		t.Fatal("distinct sources must not share a registry key")
	}
	if _, err := a.OpenModule(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestContainsDefaultPINIgnoresLongerNumbers(t *testing.T) {
	for _, text := range []string{`"checked_at":"2026-10-08T20:38:54.051234034Z"`, `"duration":512345`, ""} {
		if ContainsDefaultPIN(text) {
			t.Errorf("ContainsDefaultPIN(%q) = true, want false", text)
		}
	}
	for _, text := range []string{`"pin":"1234"`, "login with 1234 failed", "PIN1234", "1234"} {
		if !ContainsDefaultPIN(text) {
			t.Errorf("ContainsDefaultPIN(%q) = false, want true", text)
		}
	}
}

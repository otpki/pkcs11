// raw uses the low-level PKCS #11 3.2 binding directly. The managed
// parent package is preferable unless an application must control every handle,
// session flag, template, and Init/Update/Final transition itself.
package main

import (
	"bytes"
	"fmt"
	"log"
	"os"

	"github.com/otpki/pkcs11/raw"
)

func main() {
	defer func() {
		if r := recover(); r != nil {
			log.Fatal(r)
		}
	}()
	run()
}

func run() {
	// raw.Open selects the best available interface (3.2 first) and native
	// backend. Options can require a named interface/version when necessary.
	module, err := raw.Open(os.Getenv("PKCS11_MODULE"))
	check(err)
	defer module.Destroy() // Destroy releases the loaded library after Finalize.

	check(module.Initialize())
	defer func() { check(module.Finalize()) }()
	log.Printf("backend=%s interface=%+v", raw.ActiveNativeBackend(), module.Interface())

	info, err := module.GetInfo()
	check(err)
	interfaces, err := module.GetInterfaceList()
	check(err)
	log.Printf("library=%q interfaces=%d", info.LibraryDescription, len(interfaces))

	// Raw callers must enumerate and select slots themselves.
	slots, err := module.GetSlotList(true)
	check(err)
	if len(slots) == 0 {
		panic("no token-present slots")
	}
	slot := slots[0]
	token, err := module.GetTokenInfo(slot)
	check(err)
	mechanisms, err := module.GetMechanismList(slot)
	check(err)
	log.Printf("slot=%d token=%q mechanisms=%d", slot, token.Label, len(mechanisms))

	// Unlike the managed API, session ownership, login, and cleanup are explicit.
	session, err := module.OpenSession(slot, raw.CKF_SERIAL_SESSION|raw.CKF_RW_SESSION)
	check(err)
	defer func() { check(module.CloseSession(session)) }()
	if pin := os.Getenv("PKCS11_PIN"); pin != "" {
		check(module.Login(session, raw.CKU_USER, []byte(pin)))
		defer func() { check(module.Logout(session)) }()
	}

	randomValue, err := module.GenerateRandom(session, 32)
	check(err)
	check(module.DigestInit(session, []*raw.Mechanism{raw.NewMechanism(raw.CKM_SHA256, nil)}))
	check(module.DigestUpdate(session, []byte("part one, ")))
	check(module.DigestUpdate(session, []byte("part two")))
	digest, err := module.DigestFinal(session)
	check(err)
	log.Printf("random=%x digest=%x", randomValue[:4], digest)

	// Templates are exact CK_ATTRIBUTE lists. This creates a temporary AES key,
	// so the token removes it automatically when the session closes.
	key, err := module.GenerateKey(session,
		[]*raw.Mechanism{raw.NewMechanism(raw.CKM_AES_KEY_GEN, nil)},
		[]*raw.Attribute{
			raw.NewAttribute(raw.CKA_CLASS, raw.CKO_SECRET_KEY),
			raw.NewAttribute(raw.CKA_KEY_TYPE, raw.CKK_AES),
			raw.NewAttribute(raw.CKA_VALUE_LEN, 32),
			raw.NewAttribute(raw.CKA_TOKEN, false),
			raw.NewAttribute(raw.CKA_PRIVATE, true),
			raw.NewAttribute(raw.CKA_SENSITIVE, true),
			raw.NewAttribute(raw.CKA_EXTRACTABLE, false),
			raw.NewAttribute(raw.CKA_ENCRYPT, true),
			raw.NewAttribute(raw.CKA_DECRYPT, true),
			raw.NewAttribute(raw.CKA_LABEL, "raw-example-aes"),
		},
	)
	check(err)
	defer func() { check(module.DestroyObject(session, key)) }()

	iv, err := module.GenerateRandom(session, 12)
	check(err)
	gcm := &raw.GCMParams{IV: iv, AAD: []byte("associated data"), TagBits: 128}
	check(module.EncryptInit(session, []*raw.Mechanism{raw.NewMechanism(raw.CKM_AES_GCM, gcm)}, key))
	ciphertext, err := module.Encrypt(session, []byte("raw plaintext"))
	check(err)
	check(module.DecryptInit(session, []*raw.Mechanism{raw.NewMechanism(raw.CKM_AES_GCM, gcm)}, key))
	plaintext, err := module.Decrypt(session, ciphertext)
	check(err)
	if !bytes.Equal(plaintext, []byte("raw plaintext")) {
		panic("AES-GCM round trip changed the plaintext")
	}

	// FindAllObjects wraps the mandatory Init/Find/Final sequence. Attribute
	// reads use query attributes whose values are nil.
	objects, err := module.FindAllObjects(session, []*raw.Attribute{
		raw.NewAttribute(raw.CKA_LABEL, "raw-example-aes"),
	}, 32)
	check(err)
	attributes, err := module.GetAttributeValue(session, key, []*raw.Attribute{
		raw.NewAttribute(raw.CKA_LABEL, nil),
		raw.NewAttribute(raw.CKA_VALUE_LEN, nil),
	})
	check(err)
	log.Printf("ciphertext=%d objects=%d attributes=%d", len(ciphertext), len(objects), len(attributes))
}

func check(err error) {
	if err != nil {
		panic(fmt.Errorf("raw example failed: %w", err))
	}
}

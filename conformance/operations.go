package conformance

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/raw"
)

func signatureOptionsFromIntent(intent pkcs11.Intent) pkcs11.SignatureOptions {
	return pkcs11.SignatureOptions{
		Algorithm:          intent.Algorithm,
		Hash:               intent.Hash,
		Prehashed:          intent.Prehashed,
		RSAPadding:         intent.RSAPadding,
		PSSSaltLength:      intent.PSSSaltLength,
		Context:            slices.Clone(intent.Context),
		Hedge:              intent.Hedge,
		ExternalMu:         intent.ExternalMu,
		MechanismOverride:  intent.MechanismOverride,
		MechanismParameter: intent.MechanismParameter,
	}
}

var conformanceIdentityCounter atomic.Uint64

func (r *Runner) testRuntime(ctx context.Context, _ Case) (map[string]any, error) {
	options := pkcs11.RuntimeValidationOptions{
		Refresh:     true,
		CheckRandom: r.client.Device().Fingerprint.Token.Flags&raw.CKF_RNG != 0,
		ReadWrite:   true,
	}
	report, err := r.client.ValidateRuntime(ctx, options)
	details := map[string]any{
		"validation_level": report.Level,
		"module_sha256":    report.ModuleSHA256,
		"mechanism_sha256": report.MechanismSHA256,
		"mechanism_count":  len(report.Mechanisms),
		"adapter":          report.Device.Adapter.Family,
		"interface":        fmt.Sprintf("%d.%d", report.Interface.Version.Major, report.Interface.Version.Minor),
	}
	if err != nil {
		return details, err
	}
	if expected := r.profile.Expected.Adapter; expected != "" && report.Device.Adapter.Family != expected {
		return details, fmt.Errorf("conformance: detected adapter %q, expected %q", report.Device.Adapter.Family, expected)
	}
	if minimum := strings.TrimSpace(r.profile.Expected.MinimumInterface); minimum != "" {
		major, minor, parseErr := parseVersion(minimum)
		if parseErr != nil {
			return details, parseErr
		}
		actual := report.Interface.Version
		if actual.Major < major || (actual.Major == major && actual.Minor < minor) {
			return details, fmt.Errorf("conformance: interface %d.%d is below required %d.%d", actual.Major, actual.Minor, major, minor)
		}
	}
	for _, expected := range r.profile.Expected.RequiredMechanisms {
		if !r.client.Capabilities().HasMechanism(uint(expected)) {
			return details, fmt.Errorf("conformance: required mechanism 0x%x is not advertised", uint64(expected))
		}
	}
	return details, nil
}

func parseVersion(value string) (uint8, uint8, error) {
	var major, minor uint8
	if _, err := fmt.Sscanf(value, "%d.%d", &major, &minor); err != nil {
		return 0, 0, fmt.Errorf("conformance: invalid interface version %q", value)
	}
	return major, minor, nil
}

func (r *Runner) testRandom(ctx context.Context, testCase Case) (map[string]any, error) {
	length := max(testCase.MessageBytes, 32)
	first, err := r.client.Random(ctx, length)
	if err != nil {
		return nil, err
	}
	second, err := r.client.Random(ctx, length)
	if err != nil {
		return nil, err
	}
	if len(first) != length || len(second) != length {
		return nil, fmt.Errorf("conformance: random output lengths are %d and %d, expected %d", len(first), len(second), length)
	}
	if bytes.Equal(first, second) {
		return nil, errors.New("conformance: two random outputs were identical")
	}
	return map[string]any{"bytes_per_call": length}, nil
}

func (r *Runner) testSession(ctx context.Context, _ Case) (map[string]any, error) {
	var readOnly, readWrite raw.SessionInfo
	if err := r.withReadOnlySession(ctx, func(session *testSession) error {
		var err error
		readOnly, err = session.GetSessionInfo()
		return err
	}); err != nil {
		return nil, fmt.Errorf("read-only session: %w", err)
	}
	if err := r.withReadWriteSession(ctx, func(session *testSession) error {
		var err error
		readWrite, err = session.GetSessionInfo()
		return err
	}); err != nil {
		return nil, fmt.Errorf("read/write session: %w", err)
	}
	return map[string]any{
		"read_only_state":  readOnly.State,
		"read_write_state": readWrite.State,
		"pool":             r.client.SessionStats(),
	}, nil
}

func (r *Runner) testDigest(ctx context.Context, _ Case) (map[string]any, error) {
	message := []byte("otpki-pkcs11 digest conformance")
	expected := sha256.Sum256(message)
	actual, err := r.client.Digest(ctx, message, pkcs11.DigestOptions{Hash: crypto.SHA256})
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(actual, expected[:]) {
		return nil, errors.New("conformance: token SHA-256 output differs from Go SHA-256")
	}
	return map[string]any{"digest_bytes": len(actual)}, nil
}

func (r *Runner) testConcurrency(ctx context.Context, testCase Case) (map[string]any, error) {
	workers, iterations := testCase.Concurrency, testCase.Iterations
	var wg sync.WaitGroup
	errCh := make(chan error, workers)
	for worker := range workers {
		wg.Go(func() {
			for iteration := range iterations {
				if _, err := r.client.Random(ctx, 32); err != nil {
					errCh <- fmt.Errorf("worker %d iteration %d: %w", worker, iteration, err)
					return
				}
			}
		})
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		return nil, err
	}
	return map[string]any{
		"workers":    workers,
		"iterations": iterations,
		"operations": workers * iterations,
		"pool":       r.client.SessionStats(),
	}, nil
}

func (r *Runner) testGenerate(ctx context.Context, testCase Case) (map[string]any, error) {
	options := r.keyPairOptions(testCase)
	if isSecretAlgorithm(testCase.Algorithm) {
		object, err := r.client.GenerateSecretKey(ctx, r.secretKeyOptions(testCase))
		if err != nil {
			return nil, err
		}
		found, findErr := r.client.Find(ctx, pkcs11.ObjectQuery{ID: object.ID, Limit: 2})
		cleanupErr := r.cleanup(ctx, object)
		if findErr != nil {
			return nil, errorsJoin(findErr, cleanupErr)
		}
		if len(found) != 1 {
			return nil, errorsJoin(fmt.Errorf("conformance: expected one generated object, found %d", len(found)), cleanupErr)
		}
		return map[string]any{"objects": 1, "key_type": object.KeyType}, cleanupErr
	}
	pair, err := r.client.GenerateKeyPair(ctx, options)
	if err != nil {
		return nil, fmt.Errorf("generate %s key pair: %w", testCase.Algorithm, err)
	}
	found, findErr := r.client.Find(ctx, pkcs11.ObjectQuery{ID: pair.Private.ID})
	cleanupErr := r.cleanup(ctx, pair.Private, pair.Public)
	if findErr != nil {
		return nil, errorsJoin(findErr, cleanupErr)
	}
	expectedObjects := 2
	switch {
	case pair.Public.Handle != 0 && pair.Public.Handle == pair.Private.Handle:
		expectedObjects = 1
	case pair.Public.UniqueID != "" && pair.Public.UniqueID == pair.Private.UniqueID:
		expectedObjects = 1
	case pair.Public.Class == pair.Private.Class && bytes.Equal(pair.Public.ID, pair.Private.ID):
		expectedObjects = 1
	}
	if len(found) < expectedObjects {
		return nil, errorsJoin(fmt.Errorf("conformance: expected at least %d generated object(s), found %d", expectedObjects, len(found)), cleanupErr)
	}
	return map[string]any{"objects": len(found), "key_type": pair.Private.KeyType, "single_object_pair": expectedObjects == 1}, cleanupErr
}

func (r *Runner) testSign(ctx context.Context, testCase Case) (map[string]any, error) {
	hash, err := hashByName(testCase.Hash, defaultHash(testCase.Algorithm))
	if err != nil {
		return nil, err
	}
	padding := pkcs11.RSAPaddingPKCS1v15
	if strings.EqualFold(testCase.Variant, "pss") || testCase.Variant == "" && testCase.Algorithm == pkcs11.AlgorithmRSA {
		padding = pkcs11.RSAPaddingPSS
	}
	message := testMessage(testCase.MessageBytes)
	input := message
	var opts crypto.SignerOpts
	intent := pkcs11.Intent{Algorithm: testCase.Algorithm, Hash: hash, Context: []byte(testCase.Context)}

	switch testCase.Algorithm {
	case pkcs11.AlgorithmRSA:
		input, err = hashInput(hash, message)
		if err != nil {
			return nil, err
		}
		intent.Prehashed = true
		if padding == pkcs11.RSAPaddingPSS {
			opts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: hash}
			intent.RSAPadding = pkcs11.RSAPaddingPSS
			intent.PSSSaltLength = hash.Size()
		} else {
			opts = hash
			intent.RSAPadding = pkcs11.RSAPaddingPKCS1v15
		}
	case pkcs11.AlgorithmECDSAP256, pkcs11.AlgorithmECDSAP384, pkcs11.AlgorithmECDSAP521:
		input, err = hashInput(hash, message)
		if err != nil {
			return nil, err
		}
		opts = hash
		intent.Prehashed = true
	case pkcs11.AlgorithmEd25519, pkcs11.AlgorithmEd448:
		opts = crypto.Hash(0)
		intent.Hash = 0
	default:
		pqcOpts := pkcs11.SignatureOptions{Context: []byte(testCase.Context)}
		switch strings.ToLower(testCase.Variant) {
		case "prehash":
			if hash == 0 {
				hash = crypto.SHA512
			}
			input, err = hashInput(hash, message)
			if err != nil {
				return nil, err
			}
			pqcOpts.Hash, pqcOpts.Prehashed = hash, true
			intent.Hash, intent.Prehashed = hash, true
		case "external-mu":
			mu := sha512.Sum512(message)
			input = mu[:]
			pqcOpts.ExternalMu = true
			intent.ExternalMu = true
		default:
			intent.Hash = 0
		}
		opts = pqcOpts
	}

	// Resolve and probe before creating any test objects so a missing
	// capability reports as a skip instead of a failed operation
	signRoute, err := r.client.Resolve(withOperation(intent, pkcs11.OperationSign))
	if err != nil {
		return nil, err
	}
	if err := r.probeParameterizedMechanism(signRoute); err != nil {
		return nil, err
	}

	options := r.keyPairOptions(testCase)
	pair, err := r.client.GenerateKeyPair(ctx, options)
	if err != nil {
		return nil, fmt.Errorf("generate %s key pair: %w", testCase.Algorithm, err)
	}
	cleanup := func(primary error) error {
		return errorsJoin(primary, r.cleanup(ctx, pair.Private, pair.Public))
	}

	signer, err := r.client.Signer(ctx, pkcs11.SignerConfig{
		Private:        pair.Private,
		Public:         pair.Public,
		Algorithm:      testCase.Algorithm,
		DefaultHash:    hash,
		DefaultPadding: padding,
		Context:        []byte(testCase.Context),
	})
	if err != nil {
		return nil, cleanup(fmt.Errorf("create %s signer: %w", testCase.Algorithm, err))
	}

	signature, err := signer.SignContext(ctx, input, opts)
	if err != nil {
		return nil, cleanup(fmt.Errorf("sign with %s: %w", testCase.Algorithm, err))
	}
	if len(signature) == 0 {
		return nil, cleanup(errors.New("conformance: token returned an empty signature"))
	}
	if err := r.client.Verify(ctx, pair.Public, input, signature, signatureOptionsFromIntent(intent)); err != nil {
		return nil, cleanup(fmt.Errorf("verify generated signature: %w", err))
	}
	softwareVerified, err := verifyWithGo(signer.Public(), testCase.Algorithm, hash, padding, input, signature)
	if err != nil {
		return nil, cleanup(fmt.Errorf("verify generated signature with Go: %w", err))
	}
	corrupt := slices.Clone(signature)
	corrupt[len(corrupt)-1] ^= 0x01
	if err := r.client.Verify(ctx, pair.Public, input, corrupt, signatureOptionsFromIntent(intent)); err == nil {
		return nil, cleanup(errors.New("conformance: corrupted signature was accepted"))
	}
	remaining := any(nil)
	if testCase.Algorithm == pkcs11.AlgorithmHSS || testCase.Algorithm == pkcs11.AlgorithmLMS {
		if value, remainingErr := r.client.HSSKeysRemaining(ctx, pair.Private); remainingErr == nil {
			remaining = value
		}
	}
	cleanupErr := cleanup(nil)
	details := map[string]any{
		"message_bytes":   len(message),
		"signature_bytes": len(signature),
		"hash":            hash.String(),
	}
	if softwareVerified {
		details["software_verified"] = true
	}
	if remaining != nil {
		details["hss_keys_remaining"] = remaining
	}
	return details, cleanupErr
}

func (r *Runner) testHMAC(ctx context.Context, testCase Case) (map[string]any, error) {
	object, err := r.client.GenerateSecretKey(ctx, r.secretKeyOptions(testCase))
	if err != nil {
		return nil, err
	}
	message := testMessage(testCase.MessageBytes)
	mac, err := r.client.MAC(ctx, object, message, pkcs11.MACOptions{Algorithm: testCase.Algorithm})
	if err == nil {
		err = r.client.VerifyMAC(ctx, object, message, mac, pkcs11.MACOptions{Algorithm: testCase.Algorithm})
	}
	cleanupErr := r.cleanup(ctx, object)
	if err != nil {
		return nil, errorsJoin(err, cleanupErr)
	}
	return map[string]any{"mac_bytes": len(mac)}, cleanupErr
}

func (r *Runner) testEncrypt(ctx context.Context, testCase Case) (map[string]any, error) {
	if testCase.Algorithm == pkcs11.AlgorithmRSA {
		return r.testRSAEncrypt(ctx, testCase)
	}
	return r.testSymmetricEncrypt(ctx, testCase)
}

func (r *Runner) testSymmetricEncrypt(ctx context.Context, testCase Case) (map[string]any, error) {
	key, err := r.client.GenerateSecretKey(ctx, r.secretKeyOptions(testCase))
	if err != nil {
		return nil, err
	}
	mode := pkcs11.CipherModeGCM
	iv := bytes.Repeat([]byte{0x42}, 12)
	aad := []byte("otpki-conformance-aad")
	switch strings.ToLower(testCase.Variant) {
	case "cbc":
		mode, iv, aad = pkcs11.CipherModeCBC, bytes.Repeat([]byte{0x24}, 16), nil
	case "ctr":
		mode, iv, aad = pkcs11.CipherModeCTR, bytes.Repeat([]byte{0x11}, 16), nil
	case "", "gcm":
	default:
		return nil, errorsJoin(fmt.Errorf("conformance: unknown cipher variant %q", testCase.Variant), r.cleanup(ctx, key))
	}
	plaintext := testMessage(testCase.MessageBytes)
	encrypted, err := r.client.Encrypt(ctx, key, plaintext, pkcs11.CipherOptions{
		Algorithm: testCase.Algorithm,
		Mode:      mode,
		IV:        iv,
		AAD:       aad,
		TagBits:   128,
	})
	if err != nil {
		return nil, errorsJoin(err, r.cleanup(ctx, key))
	}
	recovered, err := r.client.Decrypt(ctx, key, encrypted.Ciphertext, pkcs11.CipherOptions{
		Algorithm: testCase.Algorithm,
		Mode:      mode,
		IV:        encrypted.IV,
		AAD:       aad,
		TagBits:   128,
	})
	cleanupErr := r.cleanup(ctx, key)
	if err != nil {
		return nil, errorsJoin(err, cleanupErr)
	}
	if !bytes.Equal(recovered, plaintext) {
		return nil, errorsJoin(errors.New("conformance: decrypted plaintext differs from input"), cleanupErr)
	}
	return map[string]any{"mode": mode, "plaintext_bytes": len(plaintext), "ciphertext_bytes": len(encrypted.Ciphertext)}, cleanupErr
}

func (r *Runner) testRSAEncrypt(ctx context.Context, testCase Case) (map[string]any, error) {
	padding := pkcs11.RSAPaddingOAEP
	if strings.EqualFold(testCase.Variant, "pkcs1v15") {
		padding = pkcs11.RSAPaddingPKCS1v15
	}
	hash, err := hashByName(testCase.Hash, crypto.SHA256)
	if err != nil {
		return nil, err
	}
	route, err := r.client.Resolve(pkcs11.Intent{Operation: pkcs11.OperationEncrypt, Algorithm: pkcs11.AlgorithmRSA, RSAPadding: padding, Hash: hash})
	if err != nil {
		return nil, err
	}
	if err := r.probeParameterizedMechanism(route); err != nil {
		return nil, err
	}
	pair, err := r.client.GenerateKeyPair(ctx, r.keyPairOptions(testCase))
	if err != nil {
		return nil, err
	}
	plaintext := []byte("otpki-rsa-encryption-conformance")
	encrypted, err := r.client.Encrypt(ctx, pair.Public, plaintext, pkcs11.CipherOptions{
		Algorithm:  pkcs11.AlgorithmRSA,
		RSAPadding: padding,
		Hash:       hash,
	})
	if err != nil {
		return nil, errorsJoin(err, r.cleanup(ctx, pair.Private, pair.Public))
	}
	recovered, err := r.client.Decrypt(ctx, pair.Private, encrypted.Ciphertext, pkcs11.CipherOptions{
		Algorithm:  pkcs11.AlgorithmRSA,
		RSAPadding: padding,
		Hash:       hash,
	})
	cleanupErr := r.cleanup(ctx, pair.Private, pair.Public)
	if err != nil {
		return nil, errorsJoin(err, cleanupErr)
	}
	if !bytes.Equal(recovered, plaintext) {
		return nil, errorsJoin(errors.New("conformance: RSA decrypted plaintext differs from input"), cleanupErr)
	}
	return map[string]any{"padding": padding, "ciphertext_bytes": len(encrypted.Ciphertext)}, cleanupErr
}

func (r *Runner) testWrap(ctx context.Context, _ Case) (map[string]any, error) {
	identity := r.identity("wrap")
	wrapping, err := r.client.GenerateSecretKey(ctx, pkcs11.SecretKeyOptions{Algorithm: pkcs11.AlgorithmAES256, Label: identity + "-kek", ID: []byte(identity + "-kek")})
	if err != nil {
		return nil, err
	}
	targetPolicy := pkcs11.DefaultSecretKeyPolicy()
	targetPolicy.Sensitive = false
	targetPolicy.Extractable = true
	target, err := r.client.GenerateSecretKey(ctx, pkcs11.SecretKeyOptions{Algorithm: pkcs11.AlgorithmAES256, Label: identity + "-target", ID: []byte(identity + "-target"), Policy: &targetPolicy})
	if err != nil {
		return nil, errorsJoin(err, r.cleanup(ctx, wrapping))
	}
	mechanism := raw.NewMechanism(raw.CKM_AES_KEY_WRAP_PAD, nil)
	wrapped, err := r.client.Wrap(ctx, wrapping, target, pkcs11.WrapOptions{Mechanism: mechanism})
	if err != nil {
		return nil, errorsJoin(err, r.cleanup(ctx, target, wrapping))
	}
	unwrappedID := []byte(identity + "-unwrapped")
	attributes := []*raw.Attribute{
		raw.NewAttribute(raw.CKA_CLASS, raw.CKO_SECRET_KEY),
		raw.NewAttribute(raw.CKA_KEY_TYPE, raw.CKK_AES),
		raw.NewAttribute(raw.CKA_TOKEN, true),
		raw.NewAttribute(raw.CKA_PRIVATE, true),
		raw.NewAttribute(raw.CKA_SENSITIVE, false),
		raw.NewAttribute(raw.CKA_EXTRACTABLE, true),
		raw.NewAttribute(raw.CKA_ENCRYPT, true),
		raw.NewAttribute(raw.CKA_DECRYPT, true),
		raw.NewAttribute(raw.CKA_LABEL, identity+"-unwrapped"),
		raw.NewAttribute(raw.CKA_ID, unwrappedID),
	}
	unwrapped, err := r.client.Unwrap(ctx, wrapping, wrapped, pkcs11.UnwrapOptions{
		Mechanism:  mechanism,
		Attributes: attributes,
		Reference:  pkcs11.ObjectRef{Class: raw.CKO_SECRET_KEY, KeyType: raw.CKK_AES, Algorithm: pkcs11.AlgorithmAES256, Label: identity + "-unwrapped", ID: unwrappedID},
	})
	if err != nil {
		return nil, errorsJoin(err, r.cleanup(ctx, target, wrapping))
	}
	originalCiphertext, err := r.encryptCBC(ctx, target)
	if err != nil {
		return nil, errorsJoin(err, r.cleanup(ctx, unwrapped, target, wrapping))
	}
	unwrappedCiphertext, err := r.encryptCBC(ctx, unwrapped)
	cleanupErr := r.cleanup(ctx, unwrapped, target, wrapping)
	if err != nil {
		return nil, errorsJoin(err, cleanupErr)
	}
	if !bytes.Equal(originalCiphertext, unwrappedCiphertext) {
		return nil, errorsJoin(errors.New("conformance: unwrapped key does not reproduce the original ciphertext"), cleanupErr)
	}
	return map[string]any{"wrapped_bytes": len(wrapped)}, cleanupErr
}

func (r *Runner) encryptCBC(ctx context.Context, key pkcs11.ObjectRef) ([]byte, error) {
	iv := bytes.Repeat([]byte{0x55}, 16)
	algorithm := key.Algorithm
	if algorithm == "" {
		algorithm = pkcs11.AlgorithmAES256
	}
	route, err := r.client.Resolve(pkcs11.Intent{Operation: pkcs11.OperationEncrypt, Algorithm: algorithm, CipherMode: pkcs11.CipherModeCBC, IV: iv})
	if err != nil {
		return nil, err
	}
	var ciphertext []byte
	err = r.withSessionOptions(ctx, pkcs11.RawSessionOptions{Operation: "conformance-wrap-compare", ReadWrite: true}, func(session *testSession) error {
		handle, err := findObjectHandle(session, key)
		if err != nil {
			return err
		}
		if err := session.EncryptInit([]*raw.Mechanism{route.Mechanism}, handle); err != nil {
			return err
		}
		ciphertext, err = session.Encrypt(bytes.Repeat([]byte{0x5a}, 32))
		return err
	})
	return ciphertext, err
}

func (r *Runner) testAuthenticatedWrap(ctx context.Context, _ Case) (map[string]any, error) {
	if err := r.requireInterface(raw.Version{Major: 3, Minor: 2}); err != nil {
		return nil, err
	}
	identity := r.identity("authenticated-wrap")
	wrapping, err := r.client.GenerateSecretKey(ctx, pkcs11.SecretKeyOptions{
		Algorithm: pkcs11.AlgorithmAES256,
		Label:     identity + "-kek",
		ID:        []byte(identity + "-kek"),
	})
	if err != nil {
		return nil, err
	}
	targetPolicy := pkcs11.DefaultSecretKeyPolicy()
	targetPolicy.Sensitive = false
	targetPolicy.Extractable = true
	target, err := r.client.GenerateSecretKey(ctx, pkcs11.SecretKeyOptions{
		Algorithm: pkcs11.AlgorithmAES256,
		Label:     identity + "-target",
		ID:        []byte(identity + "-target"),
		Policy:    &targetPolicy,
	})
	if err != nil {
		return nil, errorsJoin(err, r.cleanup(ctx, wrapping))
	}
	mechanism := raw.NewMechanism(raw.CKM_AES_KEY_WRAP_PAD, nil)
	aad := []byte("otpki-pkcs11 authenticated wrap conformance")
	wrapped, err := r.client.Wrap(ctx, wrapping, target, pkcs11.WrapOptions{
		Mechanism:      mechanism,
		AssociatedData: aad,
		Authenticated:  true,
	})
	if err != nil {
		return nil, errorsJoin(err, r.cleanup(ctx, target, wrapping))
	}
	unwrappedID := []byte(identity + "-unwrapped")
	unwrapped, err := r.client.Unwrap(ctx, wrapping, wrapped, pkcs11.UnwrapOptions{
		Mechanism:      mechanism,
		AssociatedData: aad,
		Authenticated:  true,
		Attributes: []*raw.Attribute{
			raw.NewAttribute(raw.CKA_CLASS, raw.CKO_SECRET_KEY),
			raw.NewAttribute(raw.CKA_KEY_TYPE, raw.CKK_AES),
			raw.NewAttribute(raw.CKA_TOKEN, true),
			raw.NewAttribute(raw.CKA_PRIVATE, true),
			raw.NewAttribute(raw.CKA_SENSITIVE, false),
			raw.NewAttribute(raw.CKA_EXTRACTABLE, true),
			raw.NewAttribute(raw.CKA_ENCRYPT, true),
			raw.NewAttribute(raw.CKA_DECRYPT, true),
			raw.NewAttribute(raw.CKA_LABEL, identity+"-unwrapped"),
			raw.NewAttribute(raw.CKA_ID, unwrappedID),
		},
		Reference: pkcs11.ObjectRef{
			Class:     raw.CKO_SECRET_KEY,
			KeyType:   raw.CKK_AES,
			Algorithm: pkcs11.AlgorithmAES256,
			Label:     identity + "-unwrapped",
			ID:        unwrappedID,
		},
	})
	if err != nil {
		return nil, errorsJoin(err, r.cleanup(ctx, target, wrapping))
	}
	originalCiphertext, err := r.encryptCBC(ctx, target)
	if err != nil {
		return nil, errorsJoin(err, r.cleanup(ctx, unwrapped, target, wrapping))
	}
	unwrappedCiphertext, err := r.encryptCBC(ctx, unwrapped)
	cleanupErr := r.cleanup(ctx, unwrapped, target, wrapping)
	if err != nil {
		return nil, errorsJoin(err, cleanupErr)
	}
	if !bytes.Equal(originalCiphertext, unwrappedCiphertext) {
		return nil, errorsJoin(errors.New("conformance: authenticated-unwrapped key differs from original"), cleanupErr)
	}
	return map[string]any{
		"wrapped_bytes": len(wrapped),
		"aad_bytes":     len(aad),
	}, cleanupErr
}

func (r *Runner) testECDH(ctx context.Context, testCase Case) (map[string]any, error) {
	algorithm := testCase.Algorithm
	if algorithm == "" {
		algorithm = pkcs11.AlgorithmECDSAP256
	}
	if algorithm != pkcs11.AlgorithmECDSAP256 && algorithm != pkcs11.AlgorithmECDSAP384 && algorithm != pkcs11.AlgorithmECDSAP521 {
		return nil, fmt.Errorf("conformance: derive-ecdh requires an ECDSA curve, got %s", algorithm)
	}
	leftCase, rightCase := testCase, testCase
	leftCase.Algorithm, rightCase.Algorithm = algorithm, algorithm
	leftCase.Name += "-left"
	rightCase.Name += "-right"
	leftOptions := r.keyPairOptions(leftCase)
	leftOptions.PrivateAttributes = append(leftOptions.PrivateAttributes, raw.NewAttribute(raw.CKA_DERIVE, true))
	left, err := r.client.GenerateKeyPair(ctx, leftOptions)
	if err != nil {
		return nil, err
	}
	rightOptions := r.keyPairOptions(rightCase)
	rightOptions.PrivateAttributes = append(rightOptions.PrivateAttributes, raw.NewAttribute(raw.CKA_DERIVE, true))
	right, err := r.client.GenerateKeyPair(ctx, rightOptions)
	if err != nil {
		return nil, errorsJoin(err, r.cleanup(ctx, left.Private, left.Public))
	}
	cleanupKeys := func(primary error) error {
		return errorsJoin(primary, r.cleanup(ctx, right.Private, right.Public, left.Private, left.Public))
	}
	leftPoint, err := r.ecPoint(ctx, left.Public)
	if err != nil {
		return nil, cleanupKeys(err)
	}
	rightPoint, err := r.ecPoint(ctx, right.Public)
	if err != nil {
		return nil, cleanupKeys(err)
	}
	secretLength := uint(32)
	switch algorithm {
	case pkcs11.AlgorithmECDSAP384:
		secretLength = 48
	case pkcs11.AlgorithmECDSAP521:
		secretLength = 66
	}
	template := []*raw.Attribute{
		raw.NewAttribute(raw.CKA_CLASS, raw.CKO_SECRET_KEY),
		raw.NewAttribute(raw.CKA_KEY_TYPE, raw.CKK_GENERIC_SECRET),
		raw.NewAttribute(raw.CKA_TOKEN, false),
		raw.NewAttribute(raw.CKA_PRIVATE, true),
		raw.NewAttribute(raw.CKA_SENSITIVE, false),
		raw.NewAttribute(raw.CKA_EXTRACTABLE, true),
		raw.NewAttribute(raw.CKA_VALUE_LEN, secretLength),
	}
	var leftSecret, rightSecret []byte
	err = r.withSessionOptions(ctx, pkcs11.RawSessionOptions{Operation: "conformance-ecdh", ReadWrite: true}, func(session *testSession) (operationErr error) {
		leftPrivate, operationErr := findObjectHandle(session, left.Private)
		if operationErr != nil {
			return operationErr
		}
		rightPrivate, operationErr := findObjectHandle(session, right.Private)
		if operationErr != nil {
			return operationErr
		}
		leftHandle, operationErr := session.DeriveKey([]*raw.Mechanism{raw.NewMechanism(raw.CKM_ECDH1_DERIVE, raw.ECDH1DeriveParams{
			KDF:        raw.CKD_NULL,
			PublicData: rightPoint,
		})}, leftPrivate, template)
		if operationErr != nil {
			return operationErr
		}
		defer func() { operationErr = errorsJoin(operationErr, session.DestroyObject(leftHandle)) }()
		rightHandle, operationErr := session.DeriveKey([]*raw.Mechanism{raw.NewMechanism(raw.CKM_ECDH1_DERIVE, raw.ECDH1DeriveParams{
			KDF:        raw.CKD_NULL,
			PublicData: leftPoint,
		})}, rightPrivate, template)
		if operationErr != nil {
			return operationErr
		}
		defer func() { operationErr = errorsJoin(operationErr, session.DestroyObject(rightHandle)) }()
		leftAttrs, operationErr := session.GetAttributeValue(leftHandle, []*raw.Attribute{raw.NewAttribute(raw.CKA_VALUE, nil)})
		if operationErr != nil {
			return operationErr
		}
		rightAttrs, operationErr := session.GetAttributeValue(rightHandle, []*raw.Attribute{raw.NewAttribute(raw.CKA_VALUE, nil)})
		if operationErr != nil {
			return operationErr
		}
		if len(leftAttrs) != 1 || len(rightAttrs) != 1 {
			return errors.New("conformance: ECDH output attributes are incomplete")
		}
		leftSecret = slices.Clone(leftAttrs[0].Value)
		rightSecret = slices.Clone(rightAttrs[0].Value)
		return nil
	})
	cleanupErr := cleanupKeys(nil)
	if err != nil {
		return nil, errorsJoin(err, cleanupErr)
	}
	if len(leftSecret) == 0 || !bytes.Equal(leftSecret, rightSecret) {
		return nil, errorsJoin(errors.New("conformance: ECDH secrets are empty or differ"), cleanupErr)
	}
	return map[string]any{
		"curve":        algorithm,
		"secret_bytes": len(leftSecret),
	}, cleanupErr
}

func (r *Runner) ecPoint(ctx context.Context, object pkcs11.ObjectRef) ([]byte, error) {
	attributes, err := r.client.Attributes(ctx, object, raw.NewAttribute(raw.CKA_EC_POINT, nil))
	if err != nil {
		return nil, err
	}
	if len(attributes) != 1 || len(attributes[0].Value) == 0 {
		return nil, errors.New("conformance: CKA_EC_POINT is empty")
	}
	var point []byte
	if rest, decodeErr := asn1.Unmarshal(attributes[0].Value, &point); decodeErr == nil && len(rest) == 0 && len(point) != 0 {
		return point, nil
	}
	// Some modules return the raw uncompressed point rather than the DER
	// OCTET STRING required for CKA_EC_POINT. Accept it as the ECDH input so
	// the test measures interoperability with the provider actually loaded.
	return slices.Clone(attributes[0].Value), nil
}

func (r *Runner) testImportSecret(ctx context.Context, testCase Case) (map[string]any, error) {
	algorithm := testCase.Algorithm
	if algorithm == "" {
		algorithm = pkcs11.AlgorithmAES256
	}
	var keyBytes int
	switch algorithm {
	case pkcs11.AlgorithmAES128:
		keyBytes = 16
	case pkcs11.AlgorithmAES192:
		keyBytes = 24
	case pkcs11.AlgorithmAES256:
		keyBytes = 32
	default:
		return nil, fmt.Errorf("conformance: import-secret supports AES, got %s", algorithm)
	}
	value := make([]byte, keyBytes)
	if _, err := rand.Read(value); err != nil {
		return nil, err
	}
	identity := r.identity(testCase.Name)
	object := pkcs11.ObjectRef{
		Class:     raw.CKO_SECRET_KEY,
		KeyType:   raw.CKK_AES,
		Algorithm: algorithm,
		Label:     identity,
		ID:        []byte(identity),
	}
	err := r.withSessionOptions(ctx, pkcs11.RawSessionOptions{Operation: "conformance-import-secret", ReadWrite: true}, func(session *testSession) error {
		handle, err := session.CreateObject([]*raw.Attribute{
			raw.NewAttribute(raw.CKA_CLASS, raw.CKO_SECRET_KEY),
			raw.NewAttribute(raw.CKA_KEY_TYPE, raw.CKK_AES),
			raw.NewAttribute(raw.CKA_TOKEN, true),
			raw.NewAttribute(raw.CKA_PRIVATE, true),
			raw.NewAttribute(raw.CKA_SENSITIVE, false),
			raw.NewAttribute(raw.CKA_EXTRACTABLE, true),
			raw.NewAttribute(raw.CKA_ENCRYPT, true),
			raw.NewAttribute(raw.CKA_DECRYPT, true),
			raw.NewAttribute(raw.CKA_LABEL, identity),
			raw.NewAttribute(raw.CKA_ID, object.ID),
			raw.NewAttribute(raw.CKA_VALUE, value),
		})
		if err == nil {
			object.Handle = handle
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	exported, exportErr := r.client.ExportValue(ctx, object)
	if exportErr != nil {
		return nil, errorsJoin(exportErr, r.cleanup(ctx, object))
	}
	if !bytes.Equal(value, exported) {
		return nil, errorsJoin(errors.New("conformance: imported key value differs from exported value"), r.cleanup(ctx, object))
	}
	ciphertext, err := r.encryptCBC(ctx, object)
	cleanupErr := r.cleanup(ctx, object)
	if err != nil {
		return nil, errorsJoin(err, cleanupErr)
	}
	return map[string]any{
		"algorithm":        algorithm,
		"key_bytes":        len(value),
		"ciphertext_bytes": len(ciphertext),
	}, cleanupErr
}

// requireInterface prevents conformance from dispatching through function-table
// members that do not exist in the selected Cryptoki interface. This check must
// happen before creating test objects because an absent versioned entry point is
// a capability result, not an operational failure.
func (r *Runner) requireInterface(version raw.Version) error {
	selected := r.client.Interface().Version
	if selected.AtLeast(version) {
		return nil
	}
	return fmt.Errorf("conformance: PKCS #11 %d.%d interface required; selected %d.%d: %w",
		version.Major, version.Minor, selected.Major, selected.Minor, raw.Error(raw.CKR_FUNCTION_NOT_SUPPORTED))
}

// requireMechanismFlags checks the operation-specific 3.x flags before calling
// a message API. Interface version alone is insufficient: a module can expose a
// 3.x table while implementing only conventional C_Sign/C_Verify operations.
func (r *Runner) requireMechanismFlags(route pkcs11.Route, required uint) error {
	if route.Mechanism == nil {
		return fmt.Errorf("conformance: route has no mechanism: %w", raw.Error(raw.CKR_MECHANISM_INVALID))
	}
	info, ok := r.client.Device().Fingerprint.Mechanisms[raw.MechanismType(route.Mechanism.Mechanism)]
	if ok && info.Flags&required == required {
		return nil
	}
	return fmt.Errorf("conformance: mechanism 0x%x lacks required message flags 0x%x: %w",
		route.Mechanism.Mechanism, required, raw.Error(raw.CKR_FUNCTION_NOT_SUPPORTED))
}

// probeParameterizedMechanism reports a capability gap when a resolved
// mechanism parameter names a digest the token does not advertise. Tokens do
// not say which parameter values they accept so without this check the gap
// shows up later as an operational error like CKR_ARGUMENTS_BAD
func (r *Runner) probeParameterizedMechanism(routes ...pkcs11.Route) error {
	for _, route := range routes {
		if route.Mechanism == nil {
			continue
		}
		for _, mechanism := range parameterDigestMechanisms(route.Mechanism.Parameter) {
			if !r.client.Capabilities().HasMechanism(mechanism) {
				return fmt.Errorf("conformance: mechanism 0x%x parameter mechanism 0x%x is not advertised",
					route.Mechanism.Mechanism, mechanism)
			}
		}
	}
	return nil
}

// parameterDigestMechanisms lists the digest mechanisms named inside a
// mechanism parameter. A CKG_MGF1_* mask function needs the matching CKM_*
// digest on the token even though the CKG value is not a mechanism itself
func parameterDigestMechanisms(parameter any) []uint {
	switch value := parameter.(type) {
	case raw.PSSParams:
		return digestMechanismIDs(value.HashAlg, value.MGF)
	case *raw.PSSParams:
		if value != nil {
			return digestMechanismIDs(value.HashAlg, value.MGF)
		}
	case raw.OAEPParams:
		return digestMechanismIDs(value.HashAlg, value.MGF)
	case *raw.OAEPParams:
		if value != nil {
			return digestMechanismIDs(value.HashAlg, value.MGF)
		}
	}
	return nil
}

func digestMechanismIDs(hashAlg, mgf uint) []uint {
	var mechanisms []uint
	if hashAlg != 0 {
		mechanisms = append(mechanisms, hashAlg)
	}
	if digest, ok := mgfDigestMechanisms[mgf]; ok {
		mechanisms = append(mechanisms, digest)
	}
	return mechanisms
}

var mgfDigestMechanisms = map[uint]uint{
	raw.CKG_MGF1_SHA1:     raw.CKM_SHA_1,
	raw.CKG_MGF1_SHA224:   raw.CKM_SHA224,
	raw.CKG_MGF1_SHA256:   raw.CKM_SHA256,
	raw.CKG_MGF1_SHA384:   raw.CKM_SHA384,
	raw.CKG_MGF1_SHA512:   raw.CKM_SHA512,
	raw.CKG_MGF1_SHA3_224: raw.CKM_SHA3_224,
	raw.CKG_MGF1_SHA3_256: raw.CKM_SHA3_256,
	raw.CKG_MGF1_SHA3_384: raw.CKM_SHA3_384,
	raw.CKG_MGF1_SHA3_512: raw.CKM_SHA3_512,
}

func (r *Runner) testMessageSign(ctx context.Context, testCase Case) (map[string]any, error) {
	if err := r.requireInterface(raw.Version{Major: 3, Minor: 0}); err != nil {
		return nil, err
	}
	if testCase.Algorithm == "" {
		testCase.Algorithm = pkcs11.AlgorithmRSA
	}
	if testCase.Algorithm != pkcs11.AlgorithmRSA {
		return nil, errors.New("conformance: message-sign currently uses RSA")
	}
	if testCase.RSABits == 0 {
		testCase.RSABits = 2048
	}
	hash, err := hashByName(testCase.Hash, crypto.SHA256)
	if err != nil {
		return nil, err
	}
	intent := pkcs11.Intent{
		Algorithm:     pkcs11.AlgorithmRSA,
		Hash:          hash,
		Prehashed:     true,
		RSAPadding:    pkcs11.RSAPaddingPSS,
		PSSSaltLength: hash.Size(),
	}
	signRoute, err := r.client.Resolve(withOperation(intent, pkcs11.OperationSign))
	if err != nil {
		return nil, err
	}
	verifyRoute, err := r.client.Resolve(withOperation(intent, pkcs11.OperationVerify))
	if err != nil {
		return nil, err
	}
	if err := r.probeParameterizedMechanism(signRoute, verifyRoute); err != nil {
		return nil, err
	}
	if err := r.requireMechanismFlags(signRoute, raw.CKF_MESSAGE_SIGN); err != nil {
		return nil, err
	}
	if err := r.requireMechanismFlags(verifyRoute, raw.CKF_MESSAGE_VERIFY); err != nil {
		return nil, err
	}
	pair, err := r.client.GenerateKeyPair(ctx, r.keyPairOptions(testCase))
	if err != nil {
		return nil, err
	}
	cleanup := func(primary error) error { return errorsJoin(primary, r.cleanup(ctx, pair.Private, pair.Public)) }
	softwareSigner, err := r.client.Signer(ctx, pkcs11.SignerConfig{
		Private:        pair.Private,
		Public:         pair.Public,
		Algorithm:      pkcs11.AlgorithmRSA,
		DefaultHash:    hash,
		DefaultPadding: pkcs11.RSAPaddingPSS,
	})
	if err != nil {
		return nil, cleanup(err)
	}
	message := testMessage(testCase.MessageBytes)
	input, err := hashInput(hash, message)
	if err != nil {
		return nil, cleanup(err)
	}
	var signature []byte
	err = r.withSessionOptions(ctx, pkcs11.RawSessionOptions{Operation: "conformance-message-sign", ReadWrite: true}, func(session *testSession) error {
		privateHandle, err := findObjectHandle(session, pair.Private)
		if err != nil {
			return err
		}
		publicHandle, err := findObjectHandle(session, pair.Public)
		if err != nil {
			return err
		}
		if err := session.MessageSignInit([]*raw.Mechanism{signRoute.Mechanism}, privateHandle); err != nil {
			return err
		}
		if signature, err = session.SignMessage(nil, input); err != nil {
			return err
		}
		if err := session.MessageVerifyInit([]*raw.Mechanism{verifyRoute.Mechanism}, publicHandle); err != nil {
			return err
		}
		return session.VerifyMessage(nil, input, signature)
	})
	if err != nil {
		return nil, cleanup(err)
	}
	softwareVerified, err := verifyWithGo(softwareSigner.Public(), pkcs11.AlgorithmRSA, hash, pkcs11.RSAPaddingPSS, input, signature)
	if err != nil {
		return nil, cleanup(fmt.Errorf("verify message signature with Go: %w", err))
	}
	return map[string]any{
		"hash":              hash.String(),
		"signature_bytes":   len(signature),
		"software_verified": softwareVerified,
	}, cleanup(nil)
}

func (r *Runner) testSignatureFirstVerify(ctx context.Context, testCase Case) (map[string]any, error) {
	if err := r.requireInterface(raw.Version{Major: 3, Minor: 2}); err != nil {
		return nil, err
	}
	if testCase.Algorithm == "" {
		testCase.Algorithm = pkcs11.AlgorithmRSA
	}
	if testCase.Algorithm != pkcs11.AlgorithmRSA {
		return nil, errors.New("conformance: signature-first-verify currently uses RSA")
	}
	if testCase.RSABits == 0 {
		testCase.RSABits = 2048
	}
	hash, err := hashByName(testCase.Hash, crypto.SHA256)
	if err != nil {
		return nil, err
	}
	intent := pkcs11.Intent{
		Algorithm:     pkcs11.AlgorithmRSA,
		Hash:          hash,
		Prehashed:     true,
		RSAPadding:    pkcs11.RSAPaddingPSS,
		PSSSaltLength: hash.Size(),
	}
	signRoute, err := r.client.Resolve(withOperation(intent, pkcs11.OperationSign))
	if err != nil {
		return nil, err
	}
	verifyRoute, err := r.client.Resolve(withOperation(intent, pkcs11.OperationVerify))
	if err != nil {
		return nil, err
	}
	if err := r.probeParameterizedMechanism(signRoute, verifyRoute); err != nil {
		return nil, err
	}
	pair, err := r.client.GenerateKeyPair(ctx, r.keyPairOptions(testCase))
	if err != nil {
		return nil, err
	}
	cleanup := func(primary error) error { return errorsJoin(primary, r.cleanup(ctx, pair.Private, pair.Public)) }
	softwareSigner, err := r.client.Signer(ctx, pkcs11.SignerConfig{
		Private:        pair.Private,
		Public:         pair.Public,
		Algorithm:      pkcs11.AlgorithmRSA,
		DefaultHash:    hash,
		DefaultPadding: pkcs11.RSAPaddingPSS,
	})
	if err != nil {
		return nil, cleanup(err)
	}
	input, err := hashInput(hash, testMessage(testCase.MessageBytes))
	if err != nil {
		return nil, cleanup(err)
	}
	var signature []byte
	err = r.withSessionOptions(ctx, pkcs11.RawSessionOptions{Operation: "conformance-signature-first", ReadWrite: true}, func(session *testSession) error {
		privateHandle, err := findObjectHandle(session, pair.Private)
		if err != nil {
			return err
		}
		publicHandle, err := findObjectHandle(session, pair.Public)
		if err != nil {
			return err
		}
		if err := session.SignInit([]*raw.Mechanism{signRoute.Mechanism}, privateHandle); err != nil {
			return err
		}
		if signature, err = session.Sign(input); err != nil {
			return err
		}
		if err := session.VerifySignatureInit([]*raw.Mechanism{verifyRoute.Mechanism}, publicHandle, signature); err != nil {
			return err
		}
		return session.VerifySignature(input)
	})
	if err != nil {
		return nil, cleanup(err)
	}
	softwareVerified, err := verifyWithGo(softwareSigner.Public(), pkcs11.AlgorithmRSA, hash, pkcs11.RSAPaddingPSS, input, signature)
	if err != nil {
		return nil, cleanup(fmt.Errorf("verify signature-first signature with Go: %w", err))
	}
	return map[string]any{
		"hash":              hash.String(),
		"signature_bytes":   len(signature),
		"software_verified": softwareVerified,
	}, cleanup(nil)
}

func withOperation(intent pkcs11.Intent, operation pkcs11.Operation) pkcs11.Intent {
	intent.Operation = operation
	return intent
}

func (r *Runner) testSessionValidation(ctx context.Context, _ Case) (map[string]any, error) {
	if err := r.requireInterface(raw.Version{Major: 3, Minor: 2}); err != nil {
		return nil, err
	}
	var flags raw.Flags
	err := r.withReadOnlySession(ctx, func(session *testSession) error {
		var err error
		flags, err = session.GetSessionValidationFlags(raw.ValidationFlagsType(raw.CKS_LAST_VALIDATION_OK))
		return err
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"validation_type":  fmt.Sprintf("0x%x", raw.CKS_LAST_VALIDATION_OK),
		"validation_flags": fmt.Sprintf("0x%x", uint(flags)),
	}, nil
}

func (r *Runner) testKEM(ctx context.Context, testCase Case) (map[string]any, error) {
	pair, err := r.client.GenerateKeyPair(ctx, r.keyPairOptions(testCase))
	if err != nil {
		return nil, err
	}
	policy := pkcs11.DefaultSecretKeyPolicy()
	policy.Token = true
	policy.Sensitive = false
	policy.Extractable = true
	identity := r.identity("kem")
	encap, err := r.client.Encapsulate(ctx, pair.Public, pkcs11.KEMOptions{
		Algorithm:    testCase.Algorithm,
		Label:        identity + "-encap",
		ID:           []byte(identity + "-encap"),
		SecretPolicy: &policy,
	})
	if err != nil {
		return nil, errorsJoin(err, r.cleanup(ctx, pair.Private, pair.Public))
	}
	decap, err := r.client.Decapsulate(ctx, pair.Private, encap.Ciphertext, pkcs11.KEMOptions{
		Algorithm:    testCase.Algorithm,
		Label:        identity + "-decap",
		ID:           []byte(identity + "-decap"),
		SecretPolicy: &policy,
	})
	if err != nil {
		return nil, errorsJoin(err, r.cleanup(ctx, encap.Secret, pair.Private, pair.Public))
	}
	left, leftErr := r.client.ExportValue(ctx, encap.Secret)
	right, rightErr := r.client.ExportValue(ctx, decap)
	cleanupErr := r.cleanup(ctx, decap, encap.Secret, pair.Private, pair.Public)
	if leftErr != nil || rightErr != nil {
		return nil, errorsJoin(fmt.Errorf("export KEM secrets: %w", errorsJoin(leftErr, rightErr)), cleanupErr)
	}
	if !bytes.Equal(left, right) {
		return nil, errorsJoin(errors.New("conformance: encapsulated and decapsulated secrets differ"), cleanupErr)
	}
	return map[string]any{"ciphertext_bytes": len(encap.Ciphertext), "secret_bytes": len(left)}, cleanupErr
}

func (r *Runner) testObjectLifecycle(ctx context.Context, _ Case) (map[string]any, error) {
	identity := r.identity("object")
	object, err := r.client.GenerateSecretKey(ctx, pkcs11.SecretKeyOptions{Algorithm: pkcs11.AlgorithmAES128, Label: identity, ID: []byte(identity)})
	if err != nil {
		return nil, err
	}
	newLabel := identity + "-renamed"
	if err := r.client.SetAttributes(ctx, object, raw.NewAttribute(raw.CKA_LABEL, newLabel)); err != nil {
		return nil, errorsJoin(err, r.cleanup(ctx, object))
	}
	object.Label = newLabel
	found, err := r.client.Find(ctx, pkcs11.ObjectQuery{ID: object.ID, Label: newLabel, Limit: 2})
	if err != nil || len(found) != 1 {
		if err == nil {
			err = fmt.Errorf("conformance: renamed object search returned %d objects", len(found))
		}
		return nil, errorsJoin(err, r.cleanup(ctx, object))
	}
	copyID := []byte(identity + "-copy")
	copyLabel := identity + "-copy"
	var copyHandle raw.ObjectHandle
	err = r.withSessionOptions(ctx, pkcs11.RawSessionOptions{Operation: "conformance-copy-object", ReadWrite: true}, func(session *testSession) error {
		handle, err := findObjectHandle(session, object)
		if err != nil {
			return err
		}
		copyHandle, err = session.CopyObject(handle, []*raw.Attribute{
			raw.NewAttribute(raw.CKA_LABEL, copyLabel),
			raw.NewAttribute(raw.CKA_ID, copyID),
		})
		return err
	})
	copyRef := pkcs11.ObjectRef{Handle: copyHandle, Class: raw.CKO_SECRET_KEY, KeyType: raw.CKK_AES, Algorithm: pkcs11.AlgorithmAES128, Label: copyLabel, ID: copyID}
	cleanupErr := r.cleanup(ctx, copyRef, object)
	if err != nil {
		return nil, errorsJoin(err, cleanupErr)
	}
	return map[string]any{"renamed": true, "copied": true}, cleanupErr
}

func (r *Runner) testCertificate(ctx context.Context, testCase Case) (map[string]any, error) {
	if testCase.Algorithm == "" {
		testCase.Algorithm = pkcs11.AlgorithmRSA
	}
	if testCase.Algorithm != pkcs11.AlgorithmRSA {
		return nil, errors.New("conformance: certificate test currently uses RSA")
	}
	options := r.keyPairOptions(testCase)
	if options.RSABits == 0 {
		options.RSABits = 2048
	}
	signer, pair, err := r.client.GenerateSigner(ctx, options, pkcs11.SignerConfig{DefaultHash: crypto.SHA256, DefaultPadding: pkcs11.RSAPaddingPKCS1v15})
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return nil, errorsJoin(err, r.cleanup(ctx, pair.Private, pair.Public))
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "otpki-pkcs11 conformance"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.SHA256WithRSA,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		return nil, errorsJoin(err, r.cleanup(ctx, pair.Private, pair.Public))
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, errorsJoin(err, r.cleanup(ctx, pair.Private, pair.Public))
	}
	imported, err := r.client.ImportCertificateForKey(ctx, certificate, pair.Private, pkcs11.CertificateImportOptions{})
	if err != nil {
		return nil, errorsJoin(err, r.cleanup(ctx, pair.Private, pair.Public))
	}
	found, findErr := r.client.FindCertificateForKey(ctx, pair.Private)
	cleanupErr := r.cleanup(ctx, imported.Object, pair.Private, pair.Public)
	if findErr != nil {
		return nil, errorsJoin(findErr, cleanupErr)
	}
	if !bytes.Equal(found.Certificate.Raw, certificate.Raw) {
		return nil, errorsJoin(errors.New("conformance: imported certificate differs from source"), cleanupErr)
	}
	return map[string]any{"certificate_bytes": len(certificate.Raw)}, cleanupErr
}

func (r *Runner) testIdleRecovery(ctx context.Context, testCase Case) (map[string]any, error) {
	if testCase.IdleFor <= 0 {
		return nil, errors.New("conformance: idle-recovery requires idle_for")
	}
	if testCase.Algorithm == "" {
		testCase.Algorithm = pkcs11.AlgorithmRSA
	}
	pair, err := r.client.GenerateKeyPair(ctx, r.keyPairOptions(testCase))
	if err != nil {
		return nil, err
	}
	signer, err := r.client.Signer(ctx, pkcs11.SignerConfig{
		Private:        pair.Private,
		Public:         pair.Public,
		Algorithm:      pkcs11.AlgorithmRSA,
		DefaultHash:    crypto.SHA256,
		DefaultPadding: pkcs11.RSAPaddingPSS,
	})
	if err != nil {
		return nil, errorsJoin(err, r.cleanup(ctx, pair.Private, pair.Public))
	}
	message := testMessage(testCase.MessageBytes)
	digest := sha256.Sum256(message)
	intent := pkcs11.Intent{
		Operation:     pkcs11.OperationSign,
		Algorithm:     pkcs11.AlgorithmRSA,
		Hash:          crypto.SHA256,
		Prehashed:     true,
		RSAPadding:    pkcs11.RSAPaddingPSS,
		PSSSaltLength: crypto.SHA256.Size(),
	}
	route, err := r.client.Resolve(intent)
	if err != nil {
		return nil, errorsJoin(err, r.cleanup(ctx, pair.Private, pair.Public))
	}
	var attempts atomic.Int32
	var before, after []byte
	err = r.withSessionOptions(ctx, pkcs11.RawSessionOptions{
		Operation:  "conformance-idle-recovery",
		ReadWrite:  true,
		Idempotent: true,
	}, func(session *testSession) error {
		attempt := attempts.Add(1)
		handle, err := findObjectHandle(session, pair.Private)
		if err != nil {
			return err
		}
		sign := func() ([]byte, error) {
			if err := session.SignInit([]*raw.Mechanism{route.Mechanism}, handle); err != nil {
				return nil, err
			}
			return session.Sign(digest[:])
		}
		if attempt == 1 {
			before, err = sign()
			if err != nil {
				return err
			}
			timer := time.NewTimer(testCase.IdleFor)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
			}
		}
		after, err = sign()
		return err
	})
	cleanupCtx := ctx //nolint:contextcheck // Deferred cleanup intentionally detaches when ctx is already canceled.
	cleanupCancel := func() {}
	if ctx.Err() != nil {
		cleanupCtx, cleanupCancel = context.WithTimeout(context.Background(), 30*time.Second)
	}
	defer cleanupCancel()
	cleanupErr := r.cleanup(cleanupCtx, pair.Private, pair.Public)
	if err != nil {
		return nil, errorsJoin(fmt.Errorf("sign after %s idle: %w", testCase.IdleFor, err), cleanupErr)
	}
	publicKey, ok := signer.Public().(*rsa.PublicKey)
	if !ok {
		return nil, errorsJoin(errors.New("conformance: RSA signer public key has unexpected type"), cleanupErr)
	}
	for name, signature := range map[string][]byte{"before": before, "after": after} {
		if len(signature) == 0 {
			return nil, errorsJoin(fmt.Errorf("conformance: %s-idle signature is empty", name), cleanupErr)
		}
		if verifyErr := rsa.VerifyPSS(publicKey, crypto.SHA256, digest[:], signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}); verifyErr != nil {
			return nil, errorsJoin(fmt.Errorf("verify %s-idle signature: %w", name, verifyErr), cleanupErr)
		}
	}
	recoveryTriggered := attempts.Load() > 1
	if testCase.ExpectRecovery != nil && recoveryTriggered != *testCase.ExpectRecovery {
		return nil, errorsJoin(fmt.Errorf("conformance: recovery_triggered=%t, expected %t", recoveryTriggered, *testCase.ExpectRecovery), cleanupErr)
	}
	return map[string]any{
		"idle_for":               testCase.IdleFor.String(),
		"before_signature_bytes": len(before),
		"after_signature_bytes":  len(after),
		"attempts":               attempts.Load(),
		"recovery_triggered":     recoveryTriggered,
		"pool":                   r.client.SessionStats(),
	}, cleanupErr
}

func (r *Runner) keyPairOptions(testCase Case) pkcs11.KeyPairOptions {
	identity := r.identity(testCase.Name)
	options := pkcs11.KeyPairOptions{
		Algorithm:    testCase.Algorithm,
		Label:        identity,
		ID:           []byte(identity),
		RSABits:      testCase.RSABits,
		ParameterSet: uint(testCase.ParameterSet),
	}
	options.PublicAttributes = testCase.PublicAttributes
	options.PrivateAttributes = testCase.PrivateAttributes
	if testCase.HSS != nil {
		hss := &pkcs11.HSSParameters{Levels: testCase.HSS.Levels}
		for _, value := range testCase.HSS.LMSTypes {
			hss.LMSTypes = append(hss.LMSTypes, uint(value))
		}
		for _, value := range testCase.HSS.LMOTSTypes {
			hss.LMOTSTypes = append(hss.LMOTSTypes, uint(value))
		}
		options.HSS = hss
	}
	return options
}

func (r *Runner) secretKeyOptions(testCase Case) pkcs11.SecretKeyOptions {
	identity := r.identity(testCase.Name)
	return pkcs11.SecretKeyOptions{
		Algorithm: testCase.Algorithm,
		Label:     identity,
		ID:        []byte(identity),
	}
}

func (r *Runner) identity(name string) string {
	prefix := r.profile.Suite.Prefix
	if prefix == "" {
		prefix = "otpki"
	}
	prefix = strings.Map(func(value rune) rune {
		if value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' || value == '-' || value == '_' {
			return value
		}
		return '-'
	}, prefix)
	prefix = strings.Trim(prefix, "-_")
	if prefix == "" {
		prefix = "otpki"
	}
	if len(prefix) > 8 {
		prefix = prefix[:8]
	}
	sequence := conformanceIdentityCounter.Add(1)
	digest := sha256.Sum256(fmt.Appendf(nil, "%s\x00%s\x00%d\x00%d", prefix, name, time.Now().UnixNano(), sequence))
	// Keep the base identity to 21 bytes so suffixes such as "-unwrapped"
	// remain within the conservative 31-byte label limit of older HSMs.
	return fmt.Sprintf("%s-%x", prefix, digest[:6])
}

func verifyWithGo(public crypto.PublicKey, algorithm pkcs11.Algorithm, hash crypto.Hash, padding pkcs11.RSAPadding, input, signature []byte) (bool, error) {
	switch key := public.(type) {
	case *rsa.PublicKey:
		if hash == 0 {
			return false, nil
		}
		if padding == pkcs11.RSAPaddingPSS {
			return true, rsa.VerifyPSS(key, hash, input, signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: hash})
		}
		return true, rsa.VerifyPKCS1v15(key, hash, input, signature)
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(key, input, signature) {
			return true, errors.New("ECDSA signature is invalid")
		}
		return true, nil
	case ed25519.PublicKey:
		if algorithm != pkcs11.AlgorithmEd25519 || hash != 0 {
			return false, nil
		}
		if !ed25519.Verify(key, input, signature) {
			return true, errors.New("Ed25519 signature is invalid")
		}
		return true, nil
	default:
		return false, nil
	}
}

func (r *Runner) cleanup(ctx context.Context, objects ...pkcs11.ObjectRef) error {
	if !r.profile.Suite.Cleanup {
		return nil
	}
	var errs []error
	seen := make(map[string]struct{}, len(objects))
	for _, object := range objects {
		if object.Handle == 0 && object.ID == nil && object.Label == "" && object.UniqueID == "" {
			continue
		}
		key := fmt.Sprintf("%x/%x/%x/%s/%x", object.Handle, object.Class, object.KeyType, object.UniqueID, object.ID)
		if object.UniqueID == "" && object.ID == nil && object.Label != "" {
			key = fmt.Sprintf("label/%x/%x/%s", object.Class, object.KeyType, object.Label)
		}
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		if err := r.client.Destroy(ctx, object); err != nil {
			errs = append(errs, fmt.Errorf("destroy %s/%x: %w", object.Label, object.ID, err))
		}
	}
	return errorsJoin(nil, errs...)
}

func findObjectHandle(session *testSession, object pkcs11.ObjectRef) (raw.ObjectHandle, error) {
	if object.ID == nil && object.Label == "" && object.UniqueID == "" {
		if object.Handle == 0 {
			return 0, errors.New("conformance: object has no handle or stable locator")
		}
		return object.Handle, nil
	}
	attributes := make([]*raw.Attribute, 0, 5)
	if object.Class != 0 {
		attributes = append(attributes, raw.NewAttribute(raw.CKA_CLASS, object.Class))
	}
	if object.KeyType != 0 {
		attributes = append(attributes, raw.NewAttribute(raw.CKA_KEY_TYPE, object.KeyType))
	}
	if object.UniqueID != "" {
		attributes = append(attributes, raw.NewAttribute(raw.CKA_UNIQUE_ID, object.UniqueID))
	}
	if object.ID != nil {
		attributes = append(attributes, raw.NewAttribute(raw.CKA_ID, object.ID))
	} else if object.Label != "" {
		attributes = append(attributes, raw.NewAttribute(raw.CKA_LABEL, object.Label))
	}
	handles, err := session.FindAllObjects(attributes, 8)
	if err != nil {
		return 0, err
	}
	if len(handles) != 1 {
		return 0, fmt.Errorf("conformance: locator matched %d objects", len(handles))
	}
	return handles[0], nil
}

func testMessage(length int) []byte {
	if length <= 0 {
		length = 128
	}
	seed := []byte("otpki-pkcs11 conformance message ")
	result := make([]byte, length)
	for offset := 0; offset < len(result); offset += len(seed) {
		copy(result[offset:], seed)
	}
	return result
}

func isSecretAlgorithm(algorithm pkcs11.Algorithm) bool {
	switch algorithm {
	case pkcs11.AlgorithmAES128, pkcs11.AlgorithmAES192, pkcs11.AlgorithmAES256,
		pkcs11.AlgorithmHMACSHA256, pkcs11.AlgorithmHMACSHA384, pkcs11.AlgorithmHMACSHA512:
		return true
	default:
		return false
	}
}

func defaultHash(algorithm pkcs11.Algorithm) crypto.Hash {
	switch algorithm {
	case pkcs11.AlgorithmECDSAP384:
		return crypto.SHA384
	case pkcs11.AlgorithmECDSAP521:
		return crypto.SHA512
	case pkcs11.AlgorithmRSA, pkcs11.AlgorithmECDSAP256:
		return crypto.SHA256
	default:
		return 0
	}
}

package conformance

import (
	"bytes"
	"context"
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hkdf"
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

func (r *Runner) testDigest(ctx context.Context, testCase Case) (map[string]any, error) {
	hash, err := hashByName(testCase.Hash, crypto.SHA256)
	if err != nil {
		return nil, err
	}
	if !hash.Available() {
		return nil, fmt.Errorf("conformance: hash %v is unavailable in this Go build: %w", hash, raw.Error(raw.CKR_FUNCTION_NOT_SUPPORTED))
	}
	message := []byte("otpki-pkcs11 digest conformance")
	expected, err := hashInput(hash, message)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", err, raw.Error(raw.CKR_FUNCTION_NOT_SUPPORTED))
	}
	actual, err := r.client.Digest(ctx, message, pkcs11.DigestOptions{Hash: hash})
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(actual, expected) {
		return nil, fmt.Errorf("conformance: token %v output differs from the Go digest", hash)
	}
	return map[string]any{"hash": hash.String(), "digest_bytes": len(actual)}, nil
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
	// tokenHashed marks combined mechanisms where the token digests the message
	// internally, so the Go oracle must verify over the digest rather than the
	// input the token received.
	tokenHashed := false
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
		if strings.EqualFold(testCase.Variant, "token-hash") {
			// The combined mechanism digests the message inside the token.
			opts = pkcs11.SignatureOptions{Hash: hash}
			tokenHashed = true
		} else {
			input, err = hashInput(hash, message)
			if err != nil {
				return nil, err
			}
			opts = hash
			intent.Prehashed = true
		}
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
	// The Go oracle verifies over a digest, so when the token hashed the
	// message internally the software-side input becomes the computed digest.
	softwareInput := input
	if tokenHashed {
		if softwareInput, err = hashInput(hash, message); err != nil {
			return nil, cleanup(err)
		}
	}
	softwareVerified, err := verifyWithGo(signer.Public(), testCase.Algorithm, hash, padding, softwareInput, signature)
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
	case "ccm":
		// CCM requires a 7-13 byte nonce.
		mode, iv = pkcs11.CipherModeCCM, bytes.Repeat([]byte{0x59}, 12)
	case "cts":
		mode, iv, aad = pkcs11.CipherModeCTS, bytes.Repeat([]byte{0x61}, 16), nil
	case "ofb":
		mode, iv, aad = pkcs11.CipherModeOFB, bytes.Repeat([]byte{0x62}, 16), nil
	case "cfb128", "cfb":
		mode, iv, aad = pkcs11.CipherModeCFB, bytes.Repeat([]byte{0x63}, 16), nil
	case "cfb8":
		mode, iv, aad = pkcs11.CipherModeCFB8, bytes.Repeat([]byte{0x64}, 16), nil
	case "cfb1":
		mode, iv, aad = pkcs11.CipherModeCFB1, bytes.Repeat([]byte{0x65}, 16), nil
	case "ecb":
		// ECB carries no IV and no padding; the plaintext must align to a
		// block boundary, which the default testMessage length already does.
		mode, iv, aad = pkcs11.CipherModeECB, nil, nil
	case "chacha20-poly1305":
		mode = pkcs11.CipherModeChaCha20Poly1305
	case "chacha20":
		mode, iv, aad = pkcs11.CipherModeChaCha20, bytes.Repeat([]byte{0x33}, 16), nil
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

func (r *Runner) testWrap(ctx context.Context, testCase Case) (map[string]any, error) {
	mechanismID := raw.CKM_AES_KEY_WRAP_PAD
	switch strings.ToLower(testCase.Variant) {
	case "", "pad":
	case "kwp":
		mechanismID = raw.CKM_AES_KEY_WRAP_KWP
	case "pkcs7":
		mechanismID = raw.CKM_AES_KEY_WRAP_PKCS7
	default:
		return nil, fmt.Errorf("conformance: unknown wrap variant %q", testCase.Variant)
	}
	if err := r.requireAdvertisedMechanism(mechanismID, raw.CKF_WRAP|raw.CKF_UNWRAP); err != nil {
		return nil, err
	}
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
	mechanism := raw.NewMechanism(mechanismID, nil)
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

// keyDerivationHashMechanism maps a case variant to a CKM_*_KEY_DERIVATION
// mechanism and the digest it performs on the base key value
func keyDerivationHashMechanism(variant string) (uint, crypto.Hash, error) {
	switch strings.ToLower(strings.TrimSpace(variant)) {
	case "sha1":
		return raw.CKM_SHA1_KEY_DERIVATION, crypto.SHA1, nil
	case "sha224":
		return raw.CKM_SHA224_KEY_DERIVATION, crypto.SHA224, nil
	case "sha256":
		return raw.CKM_SHA256_KEY_DERIVATION, crypto.SHA256, nil
	case "sha384":
		return raw.CKM_SHA384_KEY_DERIVATION, crypto.SHA384, nil
	case "sha512":
		return raw.CKM_SHA512_KEY_DERIVATION, crypto.SHA512, nil
	case "sha512-224":
		return raw.CKM_SHA512_224_KEY_DERIVATION, crypto.SHA512_224, nil
	case "sha512-256":
		return raw.CKM_SHA512_256_KEY_DERIVATION, crypto.SHA512_256, nil
	case "sha3-224":
		return raw.CKM_SHA3_224_KEY_DERIVATION, crypto.SHA3_224, nil
	case "sha3-256":
		return raw.CKM_SHA3_256_KEY_DERIVATION, crypto.SHA3_256, nil
	case "sha3-384":
		return raw.CKM_SHA3_384_KEY_DERIVATION, crypto.SHA3_384, nil
	case "sha3-512":
		return raw.CKM_SHA3_512_KEY_DERIVATION, crypto.SHA3_512, nil
	default:
		return 0, 0, fmt.Errorf("conformance: unknown derive-hash variant %q", variant)
	}
}

// testDeriveHash derives a key by hashing the base key value and compares the
// result with the equivalent software digest
func (r *Runner) testDeriveHash(ctx context.Context, testCase Case) (map[string]any, error) {
	mechanism, hash, err := keyDerivationHashMechanism(testCase.Variant)
	if err != nil {
		return nil, err
	}
	if err := r.requireAdvertisedMechanism(mechanism, raw.CKF_DERIVE); err != nil {
		return nil, err
	}
	if !hash.Available() {
		return nil, fmt.Errorf("conformance: hash %v is unavailable in this Go build: %w", hash, raw.Error(raw.CKR_FUNCTION_NOT_SUPPORTED))
	}
	identity := r.identity(testCase.Name)
	ikm := testMessage(64)
	base := pkcs11.ObjectRef{Class: raw.CKO_SECRET_KEY, KeyType: raw.CKK_GENERIC_SECRET, Label: identity + "-base", ID: []byte(identity + "-base")}
	var derived []byte
	err = r.withSessionOptions(ctx, pkcs11.RawSessionOptions{Operation: "conformance-derive-hash", ReadWrite: true}, func(session *testSession) (operationErr error) {
		baseHandle, err := session.CreateObject([]*raw.Attribute{
			raw.NewAttribute(raw.CKA_CLASS, raw.CKO_SECRET_KEY),
			raw.NewAttribute(raw.CKA_KEY_TYPE, raw.CKK_GENERIC_SECRET),
			raw.NewAttribute(raw.CKA_TOKEN, true),
			raw.NewAttribute(raw.CKA_PRIVATE, true),
			raw.NewAttribute(raw.CKA_SENSITIVE, false),
			raw.NewAttribute(raw.CKA_EXTRACTABLE, true),
			raw.NewAttribute(raw.CKA_DERIVE, true),
			raw.NewAttribute(raw.CKA_LABEL, base.Label),
			raw.NewAttribute(raw.CKA_ID, base.ID),
			raw.NewAttribute(raw.CKA_VALUE, ikm),
		})
		if err != nil {
			return err
		}
		base.Handle = baseHandle
		derivedHandle, err := session.DeriveKey([]*raw.Mechanism{raw.NewMechanism(mechanism, nil)}, baseHandle, []*raw.Attribute{
			raw.NewAttribute(raw.CKA_CLASS, raw.CKO_SECRET_KEY),
			raw.NewAttribute(raw.CKA_KEY_TYPE, raw.CKK_GENERIC_SECRET),
			raw.NewAttribute(raw.CKA_TOKEN, false),
			raw.NewAttribute(raw.CKA_PRIVATE, true),
			raw.NewAttribute(raw.CKA_SENSITIVE, false),
			raw.NewAttribute(raw.CKA_EXTRACTABLE, true),
			raw.NewAttribute(raw.CKA_VALUE_LEN, uint(hash.Size())),
		})
		if err != nil {
			return err
		}
		defer func() { operationErr = errorsJoin(operationErr, session.DestroyObject(derivedHandle)) }()
		attrs, err := session.GetAttributeValue(derivedHandle, []*raw.Attribute{raw.NewAttribute(raw.CKA_VALUE, nil)})
		if err != nil {
			return err
		}
		if len(attrs) != 1 || len(attrs[0].Value) == 0 {
			return errors.New("conformance: derived key has no CKA_VALUE")
		}
		derived = slices.Clone(attrs[0].Value)
		return nil
	})
	cleanupErr := r.cleanup(ctx, base)
	if err != nil {
		return nil, errorsJoin(err, cleanupErr)
	}
	digest := hash.New()
	_, _ = digest.Write(ikm)
	if !bytes.Equal(derived, digest.Sum(nil)) {
		return nil, errorsJoin(errors.New("conformance: derived key differs from the software digest of the base key"), cleanupErr)
	}
	return map[string]any{"hash": hash.String(), "secret_bytes": len(derived)}, cleanupErr
}

// digestMechanismForHash maps a Go hash to the CKM digest mechanism HKDF uses
// as its PRF selector
func digestMechanismForHash(hash crypto.Hash) (uint, error) {
	switch hash {
	case crypto.SHA1:
		return raw.CKM_SHA_1, nil
	case crypto.SHA256:
		return raw.CKM_SHA256, nil
	case crypto.SHA384:
		return raw.CKM_SHA384, nil
	case crypto.SHA512:
		return raw.CKM_SHA512, nil
	case crypto.SHA3_224:
		return raw.CKM_SHA3_224, nil
	case crypto.SHA3_256:
		return raw.CKM_SHA3_256, nil
	case crypto.SHA3_384:
		return raw.CKM_SHA3_384, nil
	case crypto.SHA3_512:
		return raw.CKM_SHA3_512, nil
	default:
		return 0, fmt.Errorf("conformance: no digest mechanism for hash %v", hash)
	}
}

// testDeriveHKDF runs CKM_HKDF_DERIVE with a known input key and compares the
// derived secret with the Go standard library HKDF
func (r *Runner) testDeriveHKDF(ctx context.Context, testCase Case) (map[string]any, error) {
	if err := r.requireInterface(raw.Version{Major: 3, Minor: 0}); err != nil {
		return nil, err
	}
	if err := r.requireAdvertisedMechanism(raw.CKM_HKDF_DERIVE, raw.CKF_DERIVE); err != nil {
		return nil, err
	}
	hash, err := hashByName(testCase.Hash, crypto.SHA256)
	if err != nil {
		return nil, err
	}
	prf, err := digestMechanismForHash(hash)
	if err != nil {
		return nil, err
	}
	if !hash.Available() {
		return nil, fmt.Errorf("conformance: hash %v is unavailable in this Go build: %w", hash, raw.Error(raw.CKR_FUNCTION_NOT_SUPPORTED))
	}
	identity := r.identity(testCase.Name)
	ikm := testMessage(48)
	salt := testMessage(20)
	info := []byte("otpki-conformance-hkdf")
	base := pkcs11.ObjectRef{Class: raw.CKO_SECRET_KEY, KeyType: raw.CKK_HKDF, Label: identity + "-base", ID: []byte(identity + "-base")}
	var derived []byte
	err = r.withSessionOptions(ctx, pkcs11.RawSessionOptions{Operation: "conformance-derive-hkdf", ReadWrite: true}, func(session *testSession) (operationErr error) {
		baseHandle, err := session.CreateObject([]*raw.Attribute{
			raw.NewAttribute(raw.CKA_CLASS, raw.CKO_SECRET_KEY),
			raw.NewAttribute(raw.CKA_KEY_TYPE, raw.CKK_HKDF),
			raw.NewAttribute(raw.CKA_TOKEN, true),
			raw.NewAttribute(raw.CKA_PRIVATE, true),
			raw.NewAttribute(raw.CKA_SENSITIVE, false),
			raw.NewAttribute(raw.CKA_EXTRACTABLE, true),
			raw.NewAttribute(raw.CKA_DERIVE, true),
			raw.NewAttribute(raw.CKA_LABEL, base.Label),
			raw.NewAttribute(raw.CKA_ID, base.ID),
			raw.NewAttribute(raw.CKA_VALUE, ikm),
		})
		if err != nil {
			return err
		}
		base.Handle = baseHandle
		derivedHandle, err := session.DeriveKey([]*raw.Mechanism{raw.NewMechanism(raw.CKM_HKDF_DERIVE, raw.HKDFParams{
			Extract:          true,
			Expand:           true,
			PRFHashMechanism: prf,
			SaltType:         raw.CKF_HKDF_SALT_DATA,
			Salt:             salt,
			Info:             info,
		})}, baseHandle, []*raw.Attribute{
			raw.NewAttribute(raw.CKA_CLASS, raw.CKO_SECRET_KEY),
			raw.NewAttribute(raw.CKA_KEY_TYPE, raw.CKK_GENERIC_SECRET),
			raw.NewAttribute(raw.CKA_TOKEN, false),
			raw.NewAttribute(raw.CKA_PRIVATE, true),
			raw.NewAttribute(raw.CKA_SENSITIVE, false),
			raw.NewAttribute(raw.CKA_EXTRACTABLE, true),
			raw.NewAttribute(raw.CKA_VALUE_LEN, uint(hash.Size())),
		})
		if err != nil {
			return err
		}
		defer func() { operationErr = errorsJoin(operationErr, session.DestroyObject(derivedHandle)) }()
		attrs, err := session.GetAttributeValue(derivedHandle, []*raw.Attribute{raw.NewAttribute(raw.CKA_VALUE, nil)})
		if err != nil {
			return err
		}
		if len(attrs) != 1 || len(attrs[0].Value) == 0 {
			return errors.New("conformance: derived HKDF key has no CKA_VALUE")
		}
		derived = slices.Clone(attrs[0].Value)
		return nil
	})
	cleanupErr := r.cleanup(ctx, base)
	if err != nil {
		return nil, errorsJoin(err, cleanupErr)
	}
	expected, hkdfErr := hkdf.Key(hash.New, ikm, salt, string(info), hash.Size())
	if hkdfErr != nil {
		return nil, errorsJoin(fmt.Errorf("conformance: software HKDF failed: %w", hkdfErr), cleanupErr)
	}
	if !bytes.Equal(derived, expected) {
		return nil, errorsJoin(errors.New("conformance: derived HKDF key differs from the RFC 5869 software result"), cleanupErr)
	}
	return map[string]any{"hash": hash.String(), "secret_bytes": len(derived), "software_verified": true}, cleanupErr
}

// testDeriveIKE runs CKM_IKE_PRF_DERIVE in data-as-key mode, which produces a
// fresh key from the two nonces without referencing other key objects
func (r *Runner) testDeriveIKE(ctx context.Context, testCase Case) (map[string]any, error) {
	if err := r.requireInterface(raw.Version{Major: 3, Minor: 0}); err != nil {
		return nil, err
	}
	if err := r.requireAdvertisedMechanism(raw.CKM_IKE_PRF_DERIVE, raw.CKF_DERIVE); err != nil {
		return nil, err
	}
	// the PRF runs inside the provider so the HMAC mechanism must exist too
	if err := r.requireAdvertisedMechanism(raw.CKM_SHA256_HMAC, 0); err != nil {
		return nil, err
	}
	identity := r.identity(testCase.Name)
	ni := testMessage(32)
	nr := bytes.Repeat([]byte{0x6e}, 24)
	base := pkcs11.ObjectRef{Class: raw.CKO_SECRET_KEY, KeyType: raw.CKK_GENERIC_SECRET, Label: identity + "-base", ID: []byte(identity + "-base")}
	var derivedLength int
	err := r.withSessionOptions(ctx, pkcs11.RawSessionOptions{Operation: "conformance-derive-ike", ReadWrite: true}, func(session *testSession) (operationErr error) {
		baseHandle, err := session.CreateObject([]*raw.Attribute{
			raw.NewAttribute(raw.CKA_CLASS, raw.CKO_SECRET_KEY),
			raw.NewAttribute(raw.CKA_KEY_TYPE, raw.CKK_GENERIC_SECRET),
			raw.NewAttribute(raw.CKA_TOKEN, true),
			raw.NewAttribute(raw.CKA_PRIVATE, true),
			raw.NewAttribute(raw.CKA_DERIVE, true),
			raw.NewAttribute(raw.CKA_LABEL, base.Label),
			raw.NewAttribute(raw.CKA_ID, base.ID),
			raw.NewAttribute(raw.CKA_VALUE, testMessage(48)),
		})
		if err != nil {
			return err
		}
		base.Handle = baseHandle
		derivedHandle, err := session.DeriveKey([]*raw.Mechanism{raw.NewMechanism(raw.CKM_IKE_PRF_DERIVE, raw.IKEPRFDeriveParams{
			PRFMechanism: raw.CKM_SHA256_HMAC,
			DataAsKey:    true,
			Ni:           ni,
			Nr:           nr,
		})}, baseHandle, []*raw.Attribute{
			raw.NewAttribute(raw.CKA_CLASS, raw.CKO_SECRET_KEY),
			raw.NewAttribute(raw.CKA_KEY_TYPE, raw.CKK_GENERIC_SECRET),
			raw.NewAttribute(raw.CKA_TOKEN, false),
			raw.NewAttribute(raw.CKA_PRIVATE, true),
			raw.NewAttribute(raw.CKA_SENSITIVE, false),
			raw.NewAttribute(raw.CKA_EXTRACTABLE, true),
			raw.NewAttribute(raw.CKA_VALUE_LEN, uint(32)),
		})
		if err != nil {
			return err
		}
		defer func() { operationErr = errorsJoin(operationErr, session.DestroyObject(derivedHandle)) }()
		attrs, err := session.GetAttributeValue(derivedHandle, []*raw.Attribute{raw.NewAttribute(raw.CKA_VALUE, nil)})
		if err != nil {
			return err
		}
		if len(attrs) != 1 || len(attrs[0].Value) == 0 {
			return errors.New("conformance: derived IKE key has no CKA_VALUE")
		}
		derivedLength = len(attrs[0].Value)
		return nil
	})
	cleanupErr := r.cleanup(ctx, base)
	if err != nil {
		return nil, errorsJoin(err, cleanupErr)
	}
	return map[string]any{"secret_bytes": derivedLength}, cleanupErr
}

// testTrustObject creates and removes a PKCS #11 trust object. No token in the
// test fleet advertises CKO_TRUST support today so the case exercises the typed
// object path and capability-skips cleanly everywhere else
func (r *Runner) testTrustObject(ctx context.Context, _ Case) (map[string]any, error) {
	identity := r.identity("trust")
	err := r.withSessionOptions(ctx, pkcs11.RawSessionOptions{Operation: "conformance-trust-object", ReadWrite: true}, func(session *testSession) (operationErr error) {
		handle, err := session.CreateObject([]*raw.Attribute{
			raw.NewAttribute(raw.CKA_CLASS, raw.CKO_TRUST),
			raw.NewAttribute(raw.CKA_TOKEN, true),
			raw.NewAttribute(raw.CKA_PRIVATE, false),
			raw.NewAttribute(raw.CKA_MODIFIABLE, true),
			raw.NewAttribute(raw.CKA_LABEL, identity),
			raw.NewAttribute(raw.CKA_ISSUER, []byte("otpki-conformance-issuer")),
			raw.NewAttribute(raw.CKA_SERIAL_NUMBER, []byte{0x01}),
			raw.NewAttribute(raw.CKA_HASH_OF_CERTIFICATE, testMessage(20)),
			raw.NewAttribute(raw.CKA_TRUST_SERVER_AUTH, raw.CKT_TRUST_ANCHOR),
			raw.NewAttribute(raw.CKA_TRUST_CLIENT_AUTH, raw.CKT_NOT_TRUSTED),
		})
		if err != nil {
			return fmt.Errorf("conformance: trust objects are not supported: %w", err)
		}
		defer func() { operationErr = errorsJoin(operationErr, session.DestroyObject(handle)) }()
		attrs, err := session.GetAttributeValue(handle, []*raw.Attribute{raw.NewAttribute(raw.CKA_TRUST_SERVER_AUTH, nil)})
		if err != nil {
			return err
		}
		if len(attrs) != 1 {
			return errors.New("conformance: trust object did not retain CKA_TRUST_SERVER_AUTH")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"created": true}, nil
}

// testValidationObject creates and removes a PKCS #11 3.2 validation object.
// No token in the test fleet supports CKO_VALIDATION today
func (r *Runner) testValidationObject(ctx context.Context, _ Case) (map[string]any, error) {
	if err := r.requireInterface(raw.Version{Major: 3, Minor: 2}); err != nil {
		return nil, err
	}
	identity := r.identity("validation")
	err := r.withSessionOptions(ctx, pkcs11.RawSessionOptions{Operation: "conformance-validation-object", ReadWrite: true}, func(session *testSession) (operationErr error) {
		handle, err := session.CreateObject([]*raw.Attribute{
			raw.NewAttribute(raw.CKA_CLASS, raw.CKO_VALIDATION),
			raw.NewAttribute(raw.CKA_TOKEN, true),
			raw.NewAttribute(raw.CKA_PRIVATE, false),
			raw.NewAttribute(raw.CKA_MODIFIABLE, true),
			raw.NewAttribute(raw.CKA_LABEL, identity),
			raw.NewAttribute(raw.CKA_VALIDATION_TYPE, raw.CKV_TYPE_SOFTWARE),
			raw.NewAttribute(raw.CKA_VALIDATION_VERSION, []byte{3, 2}),
			raw.NewAttribute(raw.CKA_VALIDATION_LEVEL, uint(0)),
			raw.NewAttribute(raw.CKA_VALIDATION_AUTHORITY_TYPE, raw.CKV_AUTHORITY_TYPE_NIST_CMVP),
			raw.NewAttribute(raw.CKA_VALIDATION_MODULE_ID, []byte("otpki-conformance")),
		})
		if err != nil {
			return fmt.Errorf("conformance: validation objects are not supported: %w", err)
		}
		defer func() { operationErr = errorsJoin(operationErr, session.DestroyObject(handle)) }()
		return nil
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"created": true}, nil
}

// testMessageAEAD exercises the PKCS #11 3.0 single-shot message encryption and
// decryption functions with an AEAD mechanism, including the tag the provider
// writes back through the message parameter
func (r *Runner) testMessageAEAD(ctx context.Context, testCase Case) (map[string]any, error) {
	if err := r.requireInterface(raw.Version{Major: 3, Minor: 0}); err != nil {
		return nil, err
	}
	variant := strings.ToLower(strings.TrimSpace(testCase.Variant))
	if variant == "" {
		variant = "chacha20-poly1305"
	}
	var mechanism uint
	keyCase := testCase
	switch variant {
	case "chacha20-poly1305":
		mechanism = raw.CKM_CHACHA20_POLY1305
		if keyCase.Algorithm == "" {
			keyCase.Algorithm = pkcs11.AlgorithmChaCha20
		}
	case "gcm":
		mechanism = raw.CKM_AES_GCM
		if keyCase.Algorithm == "" {
			keyCase.Algorithm = pkcs11.AlgorithmAES256
		}
	default:
		return nil, fmt.Errorf("conformance: unknown message-aead variant %q", testCase.Variant)
	}
	if err := r.requireAdvertisedMechanism(mechanism, raw.CKF_MESSAGE_ENCRYPT|raw.CKF_MESSAGE_DECRYPT); err != nil {
		return nil, err
	}
	key, err := r.client.GenerateSecretKey(ctx, r.secretKeyOptions(keyCase))
	if err != nil {
		return nil, err
	}
	nonce := bytes.Repeat([]byte{0x77}, 12)
	aad := []byte("otpki-conformance-message-aad")
	plaintext := testMessage(testCase.MessageBytes)
	var ciphertext, tag, recovered []byte
	err = r.withSessionOptions(ctx, pkcs11.RawSessionOptions{Operation: "conformance-message-aead", ReadWrite: true}, func(session *testSession) error {
		handle, err := findObjectHandle(session, key)
		if err != nil {
			return err
		}
		// Message operations take the AEAD parameter per message, not at init.
		// The tag lands in the parameter struct when the call returns.
		var encryptParameter, decryptParameter any
		var encryptParams *raw.ChaCha20Poly1305MsgParams
		var encryptGCMParams *raw.GCMMessageParams
		switch variant {
		case "chacha20-poly1305":
			encryptParams = &raw.ChaCha20Poly1305MsgParams{Nonce: nonce}
			encryptParameter = encryptParams
		default:
			encryptGCMParams = &raw.GCMMessageParams{IV: nonce, IVGenerator: raw.CKG_NO_GENERATE, TagBits: 128}
			encryptParameter = encryptGCMParams
		}
		if err := session.MessageEncryptInit([]*raw.Mechanism{raw.NewMechanism(mechanism, nil)}, handle); err != nil {
			return err
		}
		if ciphertext, err = session.EncryptMessage(encryptParameter, aad, plaintext); err != nil {
			_ = session.MessageEncryptFinal() // release the active operation so the pooled session stays usable
			return err
		}
		if err := session.MessageEncryptFinal(); err != nil {
			return fmt.Errorf("conformance: message encrypt final: %w", err)
		}
		switch variant {
		case "chacha20-poly1305":
			tag = slices.Clone(encryptParams.Tag)
			decryptParameter = &raw.ChaCha20Poly1305MsgParams{Nonce: nonce, Tag: tag}
		default:
			tag = slices.Clone(encryptGCMParams.Tag)
			decryptParameter = &raw.GCMMessageParams{IV: nonce, IVGenerator: raw.CKG_NO_GENERATE, Tag: tag, TagBits: 128}
		}
		if err := session.MessageDecryptInit([]*raw.Mechanism{raw.NewMechanism(mechanism, nil)}, handle); err != nil {
			return err
		}
		if recovered, err = session.DecryptMessage(decryptParameter, aad, ciphertext); err != nil {
			_ = session.MessageDecryptFinal()
			return err
		}
		return session.MessageDecryptFinal()
	})
	cleanupErr := r.cleanup(ctx, key)
	if err != nil {
		return nil, errorsJoin(err, cleanupErr)
	}
	if len(tag) != 16 {
		return nil, errorsJoin(fmt.Errorf("conformance: message tag has %d bytes, want 16", len(tag)), cleanupErr)
	}
	if !bytes.Equal(recovered, plaintext) {
		return nil, errorsJoin(errors.New("conformance: message decrypt output differs from input"), cleanupErr)
	}
	return map[string]any{"variant": variant, "ciphertext_bytes": len(ciphertext), "tag_bytes": len(tag)}, cleanupErr
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

// requireAdvertisedMechanism reports a capability gap when the token does not
// advertise the mechanism with all of the required operation flags
func (r *Runner) requireAdvertisedMechanism(mechanism, flags uint) error {
	info, ok := r.client.Device().Fingerprint.Mechanisms[raw.MechanismType(mechanism)]
	if !ok || info.Flags&flags != flags {
		return fmt.Errorf("conformance: mechanism 0x%x is not advertised with flags 0x%x: %w",
			mechanism, flags, raw.Error(raw.CKR_MECHANISM_INVALID))
	}
	return nil
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
	case *dsa.PublicKey:
		if !dsaVerifyASN1(key, input, signature) {
			return true, errors.New("DSA signature is invalid")
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
	case pkcs11.AlgorithmAES128, pkcs11.AlgorithmAES192, pkcs11.AlgorithmAES256, pkcs11.AlgorithmChaCha20,
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

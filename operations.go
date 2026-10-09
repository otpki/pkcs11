package pkcs11

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"slices"

	"github.com/otpki/pkcs11/raw"
)

// DigestOptions selects a token-side message digest. A zero Hash defaults to
// SHA-256. MechanismOverride is reserved for mechanisms that are not represented
// by crypto.Hash; ordinary applications should leave it nil.
type DigestOptions struct {
	// Hash selects the token digest mechanism. Zero defaults to SHA-256.
	Hash crypto.Hash
	// MechanismOverride selects an exact CKM_* identifier instead of Hash.
	MechanismOverride *uint
	// MechanismParameter is passed to the selected mechanism for expert or vendor use.
	MechanismParameter any
}

// CipherOptions describes one single-part encryption or decryption operation.
// Algorithm defaults to the algorithm recorded on the key reference. AES-GCM
// encryption generates a 12-byte IV with the token RNG when IV is empty and the
// selected vendor does not generate its own IV.
type CipherOptions struct {
	// Algorithm defaults to key.Algorithm. RSA and AES are supported by the common API.
	Algorithm Algorithm
	// Mode selects the AES mode and defaults to GCM.
	Mode CipherMode
	// RSAPadding selects RSA OAEP, PKCS #1 v1.5, or the raw primitive.
	RSAPadding RSAPadding
	// Hash selects the OAEP digest and MGF digest. Zero resolves to SHA-256.
	Hash crypto.Hash
	// OAEPLabel is the optional RSA-OAEP label and is not encrypted.
	OAEPLabel []byte
	// IV is the AES IV or CTR counter block. Encrypt may generate it for GCM.
	IV []byte
	// AAD is authenticated by GCM but is not included in the ciphertext.
	AAD []byte
	// TagBits is the GCM authentication-tag length. Zero resolves to 128.
	TagBits uint

	// MechanismOverride bypasses automatic mechanism routing.
	MechanismOverride *uint
	// MechanismParameter replaces the driver's typed mechanism parameter.
	MechanismParameter any
}

// EncryptionResult contains the ciphertext and the IV used for the operation.
// IV is returned separately for standard routes and vendor modules that write a
// generated IV back through the mechanism parameter. A module whose native
// format embeds the IV in Ciphertext may leave IV empty in FinalizeEncryption.
type EncryptionResult struct {
	// Ciphertext contains the complete provider output, including an appended GCM tag.
	Ciphertext []byte
	// IV is the IV that must be supplied to Decrypt. It may be empty when a vendor
	// format embeds the generated IV in Ciphertext.
	IV []byte
}

// MACOptions selects a token-side MAC mechanism. Algorithm defaults to the
// algorithm recorded on the key reference and should normally be one of the
// AlgorithmHMAC* values.
type MACOptions struct {
	// Algorithm defaults to key.Algorithm and must resolve to an HMAC algorithm.
	Algorithm Algorithm

	// MechanismOverride selects an exact MAC mechanism.
	MechanismOverride *uint
	// MechanismParameter is passed through for truncated or vendor MAC variants.
	MechanismParameter any
}

// Digest hashes data inside the selected token. It uses a managed read-only
// session and may safely retry after replacement of an expired idle session.
func (c *Client) Digest(ctx context.Context, data []byte, options DigestOptions) ([]byte, error) {
	mechanism, err := digestMechanism(options.Hash)
	if err != nil {
		return nil, err
	}
	if options.MechanismOverride != nil {
		mechanism = *options.MechanismOverride
	}
	var digest []byte
	err = c.withSession(ctx, sessionOptions{Operation: "digest", Idempotent: true}, func(session *sessionLease) error {
		if err := session.DigestInit(ctx, []*raw.Mechanism{raw.NewMechanism(mechanism, options.MechanismParameter)}); err != nil {
			return err
		}
		digest, err = session.Digest(ctx, data)
		return err
	})
	return digest, err
}

func cipherAlgorithm(key ObjectRef, requested Algorithm) (Algorithm, error) {
	if requested != "" {
		return requested, nil
	}
	if key.Algorithm != "" {
		return key.Algorithm, nil
	}
	if key.KeyType == raw.CKK_RSA {
		return AlgorithmRSA, nil
	}
	return "", errors.New("pkcs11: cipher algorithm is required when the object reference does not identify it")
}

// prepareCipherIntent resolves public defaults before mechanism routing. The IV
// is copied so a caller cannot mutate the parameter while an HSM call is in flight.
func (c *Client) prepareCipherIntent(ctx context.Context, operation Operation, key ObjectRef, options CipherOptions) (Intent, []byte, error) {
	algorithm, err := cipherAlgorithm(key, options.Algorithm)
	if err != nil {
		return Intent{}, nil, err
	}
	iv := slices.Clone(options.IV)
	if algorithm == AlgorithmAES128 || algorithm == AlgorithmAES192 || algorithm == AlgorithmAES256 {
		mode := options.Mode
		if mode == "" {
			mode = CipherModeGCM
		}
		switch mode {
		case CipherModeGCM:
			cipherBehavior := c.currentDevice().plan.cipher
			if len(iv) == 0 && operation == OperationEncrypt && cipherBehavior.gcmIVMode == VendorGCMIVCaller {
				iv, err = c.Random(ctx, cipherBehavior.gcmIVSize)
				if err != nil {
					return Intent{}, nil, fmt.Errorf("pkcs11: generate AES-GCM IV: %w", err)
				}
			}
			if len(iv) == 0 && operation == OperationDecrypt && cipherBehavior.gcmIVMode != VendorGCMIVCiphertextPrefix {
				return Intent{}, nil, errors.New("pkcs11: AES-GCM decryption requires the IV returned by Encrypt")
			}
		case CipherModeCBC, CipherModeCTR, CipherModeCTS, CipherModeOFB,
			CipherModeCFB, CipherModeCFB8, CipherModeCFB1:
			if len(iv) != 16 {
				return Intent{}, nil, fmt.Errorf("pkcs11: AES-%s requires a 16-byte IV/counter", mode)
			}
		case CipherModeECB:
			if len(iv) != 0 {
				return Intent{}, nil, errors.New("pkcs11: AES-ECB does not take an IV")
			}
		case CipherModeCCM:
			if len(iv) < 7 || len(iv) > 13 {
				return Intent{}, nil, errors.New("pkcs11: AES-CCM requires a 7-to-13-byte nonce in IV")
			}
			if options.TagBits != 0 && (options.TagBits%16 != 0 || options.TagBits < 32 || options.TagBits > 128) {
				return Intent{}, nil, errors.New("pkcs11: AES-CCM tag length must be an even number of bytes between 4 and 16")
			}
		default:
			return Intent{}, nil, fmt.Errorf("pkcs11: unsupported AES cipher mode %q", mode)
		}
		options.Mode = mode
	}
	if algorithm == AlgorithmChaCha20 {
		mode := options.Mode
		if mode == "" {
			mode = CipherModeChaCha20Poly1305
		}
		switch mode {
		case CipherModeChaCha20Poly1305:
			// The nonce always travels in the mechanism parameter, so the driver
			// can safely generate one here regardless of vendor IV behavior.
			if len(iv) == 0 && operation == OperationEncrypt {
				iv, err = c.Random(ctx, 12)
				if err != nil {
					return Intent{}, nil, fmt.Errorf("pkcs11: generate ChaCha20-Poly1305 nonce: %w", err)
				}
			}
			if len(iv) != 12 {
				return Intent{}, nil, errors.New("pkcs11: ChaCha20-Poly1305 requires a 12-byte nonce")
			}
		case CipherModeChaCha20:
			if len(iv) != 16 {
				return Intent{}, nil, errors.New("pkcs11: ChaCha20 requires a 16-byte counter and nonce IV")
			}
		default:
			return Intent{}, nil, fmt.Errorf("pkcs11: unsupported ChaCha20 cipher mode %q", mode)
		}
		options.Mode = mode
	}
	return Intent{
		Operation:          operation,
		Algorithm:          algorithm,
		Hash:               options.Hash,
		RSAPadding:         options.RSAPadding,
		OAEPLabel:          options.OAEPLabel,
		CipherMode:         options.Mode,
		IV:                 iv,
		AAD:                options.AAD,
		TagBits:            options.TagBits,
		MechanismOverride:  options.MechanismOverride,
		MechanismParameter: options.MechanismParameter,
	}, iv, nil
}

// retainGCMParameter ensures the route owns a pointer to its GCM parameter. Some
// modules write a generated IV back into CK_GCM_PARAMS, so Encrypt must retain the
// same object until the native call has completed.
func retainGCMParameter(route *Route) *raw.GCMParams {
	if route == nil || route.Mechanism == nil {
		return nil
	}
	switch parameter := route.Mechanism.Parameter.(type) {
	case raw.GCMParams:
		copied := parameter
		route.Mechanism.Parameter = &copied
		return &copied
	case *raw.GCMParams:
		return parameter
	default:
		return nil
	}
}

func mechanismDescription(mechanism *raw.Mechanism) string {
	if mechanism == nil {
		return "<nil>"
	}
	switch parameters := mechanism.Parameter.(type) {
	case raw.OAEPParams:
		return fmt.Sprintf(
			"0x%x OAEP(hash=0x%x mgf=0x%x source=0x%x label=%dB)",
			mechanism.Mechanism, parameters.HashAlg, parameters.MGF, parameters.Source, len(parameters.SourceData),
		)
	case *raw.OAEPParams:
		if parameters == nil {
			return fmt.Sprintf("0x%x OAEP(<nil>)", mechanism.Mechanism)
		}
		return fmt.Sprintf(
			"0x%x OAEP(hash=0x%x mgf=0x%x source=0x%x label=%dB)",
			mechanism.Mechanism, parameters.HashAlg, parameters.MGF, parameters.Source, len(parameters.SourceData),
		)
	case nil:
		return fmt.Sprintf("0x%x", mechanism.Mechanism)
	default:
		return fmt.Sprintf("0x%x parameter=%T", mechanism.Mechanism, mechanism.Parameter)
	}
}

// Encrypt performs one managed single-part encryption operation. For AES-GCM,
// use the returned IV with Decrypt; the driver generates it when appropriate.
func (c *Client) Encrypt(ctx context.Context, key ObjectRef, plaintext []byte, options CipherOptions) (EncryptionResult, error) {
	intent, iv, err := c.prepareCipherIntent(ctx, OperationEncrypt, key, options)
	if err != nil {
		return EncryptionResult{}, err
	}
	route, err := c.Resolve(intent)
	if err != nil {
		return EncryptionResult{}, err
	}
	if ccm, ok := route.Mechanism.Parameter.(raw.CCMParams); ok {
		ccm.DataLen = uint(len(plaintext))
		route.Mechanism.Parameter = ccm
	}
	gcm := retainGCMParameter(&route)
	var ciphertext []byte
	err = c.withSession(ctx, sessionOptions{Operation: "encrypt"}, func(session *sessionLease) error {
		handle, err := resolveObject(ctx, session, key)
		if err != nil {
			return err
		}
		if err := session.EncryptInit(ctx, []*raw.Mechanism{route.Mechanism}, handle); err != nil {
			return fmt.Errorf("pkcs11: encrypt init with %s: %w", mechanismDescription(route.Mechanism), err)
		}
		ciphertext, err = session.Encrypt(ctx, plaintext)
		if err != nil {
			return fmt.Errorf("pkcs11: encrypt with %s: %w", mechanismDescription(route.Mechanism), err)
		}
		return nil
	})
	if err != nil {
		return EncryptionResult{}, err
	}
	if gcm != nil && len(gcm.IV) != 0 {
		// Prefer a provider-generated IV written back through CK_GCM_PARAMS over the
		// pre-call value retained by prepareCipherIntent.
		iv = append(iv[:0], gcm.IV...)
	}
	result := EncryptionResult{Ciphertext: ciphertext, IV: iv}
	device := c.currentDevice()
	if device.vendor != nil {
		result, err = device.vendor.FinalizeEncryption(
			VendorCipherContext{Device: cloneDevice(device), Route: route}, result,
		)
		if err != nil {
			return EncryptionResult{}, err
		}
	}
	return result, nil
}

// Decrypt performs one managed single-part decryption operation. RSA defaults
// to OAEP with SHA-256; AES defaults to GCM.
func (c *Client) Decrypt(ctx context.Context, key ObjectRef, ciphertext []byte, options CipherOptions) ([]byte, error) {
	intent, _, err := c.prepareCipherIntent(ctx, OperationDecrypt, key, options)
	if err != nil {
		return nil, err
	}
	route, err := c.Resolve(intent)
	if err != nil {
		return nil, err
	}
	if ccm, ok := route.Mechanism.Parameter.(raw.CCMParams); ok {
		macLen := int(ccm.MACLen)
		if macLen == 0 {
			macLen = 16
		}
		ccm.DataLen = uint(max(len(ciphertext)-macLen, 0))
		route.Mechanism.Parameter = ccm
	}
	var plaintext []byte
	err = c.withSession(ctx, sessionOptions{Operation: "decrypt", Idempotent: true}, func(session *sessionLease) error {
		handle, err := resolveObject(ctx, session, key)
		if err != nil {
			return err
		}
		if err := session.DecryptInit(ctx, []*raw.Mechanism{route.Mechanism}, handle); err != nil {
			return fmt.Errorf("pkcs11: decrypt init with %s: %w", mechanismDescription(route.Mechanism), err)
		}
		plaintext, err = session.Decrypt(ctx, ciphertext)
		if err != nil {
			return fmt.Errorf("pkcs11: decrypt with %s: %w", mechanismDescription(route.Mechanism), err)
		}
		return nil
	})
	return plaintext, err
}

func macAlgorithm(key ObjectRef, requested Algorithm) (Algorithm, error) {
	algorithm := requested
	if algorithm == "" {
		algorithm = key.Algorithm
	}
	switch algorithm {
	case AlgorithmHMACSHA256, AlgorithmHMACSHA384, AlgorithmHMACSHA512,
		AlgorithmAES128, AlgorithmAES192, AlgorithmAES256:
		return algorithm, nil
	default:
		return "", fmt.Errorf("pkcs11: MAC requires an HMAC or AES-CMAC algorithm, got %q", algorithm)
	}
}

// MAC computes an HMAC inside the token.
func (c *Client) MAC(ctx context.Context, key ObjectRef, data []byte, options MACOptions) ([]byte, error) {
	algorithm, err := macAlgorithm(key, options.Algorithm)
	if err != nil {
		return nil, err
	}
	route, err := c.Resolve(Intent{Operation: OperationSign, Algorithm: algorithm, MechanismOverride: options.MechanismOverride, MechanismParameter: options.MechanismParameter})
	if err != nil {
		return nil, err
	}
	var mac []byte
	err = c.withSession(ctx, sessionOptions{Operation: "mac", Idempotent: true}, func(session *sessionLease) error {
		handle, err := resolveObject(ctx, session, key)
		if err != nil {
			return err
		}
		if err := session.SignInit(ctx, []*raw.Mechanism{route.Mechanism}, handle); err != nil {
			return err
		}
		mac, err = session.Sign(ctx, data)
		return err
	})
	return mac, err
}

// VerifyMAC verifies an HMAC inside the token. A mismatched MAC is returned as
// raw.CKR_SIGNATURE_INVALID so callers can use errors.Is with raw.Error.
func (c *Client) VerifyMAC(ctx context.Context, key ObjectRef, data, mac []byte, options MACOptions) error {
	algorithm, err := macAlgorithm(key, options.Algorithm)
	if err != nil {
		return err
	}
	route, err := c.Resolve(Intent{Operation: OperationVerify, Algorithm: algorithm, MechanismOverride: options.MechanismOverride, MechanismParameter: options.MechanismParameter})
	if err != nil {
		return err
	}
	return c.withSession(ctx, sessionOptions{Operation: "verify-mac", Idempotent: true}, func(session *sessionLease) error {
		handle, err := resolveObject(ctx, session, key)
		if err != nil {
			return err
		}
		if err := session.VerifyInit(ctx, []*raw.Mechanism{route.Mechanism}, handle); err != nil {
			return err
		}
		return session.Verify(ctx, data, mac)
	})
}

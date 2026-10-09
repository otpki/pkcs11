package conformance

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/dsa"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"

	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/raw"
)

// domainParams decodes a hex-encoded DSA/DH domain parameter set.
func domainParams(prime, subprime, base string) *pkcs11.DomainParameters {
	decode := func(value string) *big.Int {
		bytes, err := hex.DecodeString(value)
		if err != nil {
			panic("conformance: invalid embedded domain parameter hex")
		}
		return new(big.Int).SetBytes(bytes)
	}
	params := &pkcs11.DomainParameters{Prime: decode(prime), Base: decode(base)}
	if subprime != "" {
		params.Subprime = decode(subprime)
	}
	return params
}

// ffdhe2048 returns the RFC 7919 Appendix A.1 group used for finite-field DH
// and, with q=(p-1)/2 and g=4, as a valid DSA parameter set. Kryoptic only
// accepts well-known FFDH groups, so an embedded known group is required for
// the conformance fleet.
func ffdhe2048() *pkcs11.DomainParameters {
	return domainParams(
		"ffffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d3695a9e13641"+
			"146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4617ad3df1ed5d5fd"+
			"65612433f51f5f066ed0856365553ded1af3b557135e7f57c935984f0c70e0e68b77"+
			"e2a689daf3efe8721df158a136ade73530acca4f483a797abc0ab182b324fb61d108"+
			"a94bb2c8e3fbb96adab760d7f4681d4f42a3de394df4ae56ede76372bb190b07a7c8"+
			"ee0a6d709e02fce1cdf7e2ecc03404cd28342f619172fe9ce98583ff8e4f1232eef2"+
			"8183c3fe3b1b4c6fad733bb5fcbc2ec22005c58ef1837d1683b2c6f34a26c1b2effa"+
			"886b423861285c97ffffffffffffffff",
		"",
		"02",
	)
}

// dsa2048 returns a generated FIPS 186-4 DSA parameter set (L=2048, N=256).
// Safe-prime parameters of the form q=(p-1)/2 are rejected by OpenSSL-based
// providers, which only accept the FIPS subprime sizes 160, 224, and 256 bits.
// N=256 keeps the subprime at least as wide as the SHA-256 digest: OpenSSL
// reduces the digest mod q while Go's crypto/dsa applies the FIPS truncation
// to N bits, so a narrower q would verify differently between the two.
func dsa2048() *pkcs11.DomainParameters {
	return domainParams(
		"febfa725b97e92bed698c1e9a7964e5c482dfa5e610dbedc4cfbe5153763851b2051"+
			"000fa38d6c5501efcbb03e2604a3c9fcee265c8736a7bcc7cb0f71e84d76eca695d9"+
			"3340a9db7490371ffba2ceb4fd3967e81373072c15ecb3b657436bbbfa3eeb14ece9"+
			"5d8f88be82b14d594a618c9ed26cd3536eb344ff340b471d6ee90955765f5980bf82"+
			"4733256860cf7ee23c0384ee273b8caabf8bbada4b8d67938414edfe63a00747eb0c"+
			"bef078fb3ccbffca4a5d70b210eea28e401761d521a9a695d93af712aad1e0fb7c4e"+
			"37a67892e79437efb158990eeb099b55c899847150bfa05cb3e4aa3eaa54295c4b2"+
			"beb816c004a3574b3f1fe105d344eafff24f5",
		"dc1ca83fc1f7ec5ce1a9cdb23732c15403f7752343cd3b17f653b39816f8343f",
		"3272c66b672f4c29521a44a6949606064b30efc91d91e1558ba11f8e722ce8e29e9c"+
			"f83c790e5fd1935332741639747a1f6a515ec40df346cefaabc5f996f6cdebccd91"+
			"be0f3af8753e9b5a754d7e4b3faba26e89bc062867a6eeb976d251abcb38d56c6a48"+
			"c071d21c2f406c47fb64dbb7320c2b473cc3d9d90ae48b9bb29232c1952b65e69ef0"+
			"063a03fffc01512ab3f73c8b5ff747f1c0acfa43abeea35c6a80878d3728cc7b2ea4"+
			"f45f7284094b8837a86ed1db38c1f63adfaa29b223bd8476e2a650ba253cece6881b"+
			"1e4dd0643d2cecbc0abfa3ee0bd597cbc6e0f0f4fd2c3d0c26fb4c3f73218a700364"+
			"228453c825cbea29647a7fe60cc8f6dfc1a44",
	)
}

// createSecretObject imports a session secret with a known CKA_VALUE so the
// conformance result can be checked against a software oracle. Extra
// attributes replace same-type defaults, so callers can override the object
// class for non-secret-key families such as CKO_OTP_KEY.
func createSecretObject(session *testSession, identity string, keyType uint, value []byte, extra ...*raw.Attribute) (raw.ObjectHandle, error) {
	template := []*raw.Attribute{
		raw.NewAttribute(raw.CKA_CLASS, raw.CKO_SECRET_KEY),
		raw.NewAttribute(raw.CKA_KEY_TYPE, keyType),
		raw.NewAttribute(raw.CKA_TOKEN, true),
		raw.NewAttribute(raw.CKA_PRIVATE, true),
		raw.NewAttribute(raw.CKA_SENSITIVE, false),
		raw.NewAttribute(raw.CKA_EXTRACTABLE, true),
		raw.NewAttribute(raw.CKA_LABEL, identity),
		raw.NewAttribute(raw.CKA_ID, []byte(identity)),
		raw.NewAttribute(raw.CKA_VALUE, value),
	}
	for _, override := range extra {
		replaced := false
		for i, attribute := range template {
			if attribute.Type == override.Type {
				template[i] = override
				replaced = true
				break
			}
		}
		if !replaced {
			template = append(template, override)
		}
	}
	return session.CreateObject(template)
}

// readSecretValue returns CKA_VALUE of an object created with extractable
// templates.
func readSecretValue(session *testSession, handle raw.ObjectHandle) ([]byte, error) {
	attrs, err := session.GetAttributeValue(handle, []*raw.Attribute{raw.NewAttribute(raw.CKA_VALUE, nil)})
	if err != nil {
		return nil, err
	}
	if len(attrs) != 1 || len(attrs[0].Value) == 0 {
		return nil, errors.New("conformance: object has no CKA_VALUE")
	}
	return slices.Clone(attrs[0].Value), nil
}

// aesCMAC computes RFC 4493 CMAC-AES in software so token output can be
// compared byte for byte.
func aesCMAC(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	double := func(in []byte) []byte {
		out := make([]byte, 16)
		var carry byte
		for i := 15; i >= 0; i-- {
			out[i] = in[i]<<1 | carry
			carry = in[i] >> 7
		}
		if carry != 0 {
			out[15] ^= 0x87
		}
		return out
	}
	l := make([]byte, 16)
	block.Encrypt(l, l)
	k1, k2 := double(l), double(double(l))
	var tail []byte
	switch {
	case len(data) > 0 && len(data)%16 == 0:
		tail = slices.Clone(data[len(data)-16:])
		for i := range tail {
			tail[i] ^= k1[i]
		}
		data = data[:len(data)-16]
	default:
		padded := make([]byte, 16)
		copy(padded, data[len(data)-len(data)%16:])
		padded[len(data)%16] = 0x80
		for i := range padded {
			padded[i] ^= k2[i]
		}
		tail = padded
		data = data[:len(data)-len(data)%16]
	}
	x := make([]byte, 16)
	for len(data) > 0 {
		for i := range x {
			x[i] ^= data[i]
		}
		block.Encrypt(x, x)
		data = data[16:]
	}
	for i := range x {
		x[i] ^= tail[i]
	}
	block.Encrypt(x, x)
	return x, nil
}

// tlsPRF implements the TLS P_hash expansion: HMAC(secret, A(i)||seed) where
// A(0)=seed and A(i)=HMAC(secret, A(i-1)).
func tlsPRF(secret, seed []byte, outLen int) []byte {
	mac := hmac.New(crypto.SHA256.New, secret)
	a := seed
	var out []byte
	for len(out) < outLen {
		mac.Reset()
		_, _ = mac.Write(a)
		a = mac.Sum(nil)
		mac.Reset()
		_, _ = mac.Write(a)
		_, _ = mac.Write(seed)
		out = append(out, mac.Sum(nil)...)
	}
	return out[:outLen]
}

// hotpOracle computes an RFC 4226 HOTP code, selecting the HMAC hash from the
// secret length exactly as Kryoptic does: 20 bytes SHA-1, 32 SHA-256, 64
// SHA-512.
func hotpOracle(secret []byte, counter uint64, digits int) (string, error) {
	var hash crypto.Hash
	switch len(secret) {
	case 20:
		hash = crypto.SHA1
	case 32:
		hash = crypto.SHA256
	case 64:
		hash = crypto.SHA512
	default:
		return "", fmt.Errorf("conformance: HOTP secret length %d unsupported", len(secret))
	}
	mac := hmac.New(hash.New, secret)
	var counterBytes [8]byte
	binary.BigEndian.PutUint64(counterBytes[:], counter)
	_, _ = mac.Write(counterBytes[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	modulus := uint32(1)
	for range digits {
		modulus *= 10
	}
	return fmt.Sprintf("%0*d", digits, value%modulus), nil
}

// hmacMechanism maps a digest mechanism to its combined HMAC mechanism.
// dsaVerifyASN1 verifies a DER-encoded DSA signature with crypto/dsa, which only
// exposes the raw (r, s) form.
func dsaVerifyASN1(public *dsa.PublicKey, digest, signature []byte) bool {
	var pair struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(signature, &pair); err != nil {
		return false
	}
	return dsa.Verify(public, digest, pair.R, pair.S)
}

func hmacMechanism(digest uint) (uint, error) {
	switch digest {
	case raw.CKM_SHA_1:
		return raw.CKM_SHA_1_HMAC, nil
	case raw.CKM_SHA224:
		return raw.CKM_SHA224_HMAC, nil
	case raw.CKM_SHA256:
		return raw.CKM_SHA256_HMAC, nil
	case raw.CKM_SHA384:
		return raw.CKM_SHA384_HMAC, nil
	case raw.CKM_SHA512:
		return raw.CKM_SHA512_HMAC, nil
	case raw.CKM_SHA512_224:
		return raw.CKM_SHA512_224_HMAC, nil
	case raw.CKM_SHA512_256:
		return raw.CKM_SHA512_256_HMAC, nil
	case raw.CKM_SHA3_256:
		return raw.CKM_SHA3_256_HMAC, nil
	case raw.CKM_SHA3_384:
		return raw.CKM_SHA3_384_HMAC, nil
	case raw.CKM_SHA3_512:
		return raw.CKM_SHA3_512_HMAC, nil
	default:
		return 0, fmt.Errorf("conformance: no HMAC mechanism for digest 0x%x: %w", digest, raw.Error(raw.CKR_MECHANISM_INVALID))
	}
}

// testDSA exercises the full DSA path: domain parameters on the public
// template, key-pair generation, DER signature conversion, token verify, a Go
// oracle check, and a corrupted-signature rejection.
func (r *Runner) testDSA(ctx context.Context, testCase Case) (map[string]any, error) {
	hash, err := hashByName(testCase.Hash, crypto.SHA256)
	if err != nil {
		return nil, err
	}
	if err := r.requireAdvertisedMechanism(raw.CKM_DSA_KEY_PAIR_GEN, raw.CKF_GENERATE_KEY_PAIR); err != nil {
		return nil, err
	}
	// The token-hash variant signs the complete message through the combined
	// CKM_DSA_SHA* mechanisms; the default variant feeds a prehashed digest to
	// raw CKM_DSA.
	tokenHash := strings.EqualFold(testCase.Variant, "token-hash")
	intent := pkcs11.Intent{Algorithm: pkcs11.AlgorithmDSA, Hash: hash, Prehashed: !tokenHash}
	if _, err := r.client.Resolve(withOperation(intent, pkcs11.OperationSign)); err != nil {
		return nil, err
	}
	identity := r.identity(testCase.Name)
	params := dsa2048()
	pair, err := r.client.GenerateKeyPair(ctx, pkcs11.KeyPairOptions{
		Algorithm:        pkcs11.AlgorithmDSA,
		Label:            identity,
		ID:               []byte(identity),
		DomainParameters: params,
	})
	if err != nil {
		return nil, fmt.Errorf("generate dsa key pair: %w", err)
	}
	cleanup := func(primary error) error {
		return errorsJoin(primary, r.cleanup(ctx, pair.Private, pair.Public))
	}
	message := testMessage(testCase.MessageBytes)
	digest, err := hashInput(hash, message)
	if err != nil {
		return nil, cleanup(err)
	}
	input := digest
	var opts crypto.SignerOpts = hash
	if tokenHash {
		input = message
		opts = pkcs11.SignatureOptions{Hash: hash}
	}
	signer, err := r.client.Signer(ctx, pkcs11.SignerConfig{
		Private:     pair.Private,
		Public:      pair.Public,
		Algorithm:   pkcs11.AlgorithmDSA,
		DefaultHash: hash,
	})
	if err != nil {
		return nil, cleanup(fmt.Errorf("create dsa signer: %w", err))
	}
	signature, err := signer.SignContext(ctx, input, opts)
	if err != nil {
		return nil, cleanup(fmt.Errorf("dsa sign: %w", err))
	}
	verifyOptions := pkcs11.SignatureOptions{Algorithm: pkcs11.AlgorithmDSA, Hash: hash, Prehashed: !tokenHash}
	if err := r.client.Verify(ctx, pair.Public, input, signature, verifyOptions); err != nil {
		return nil, cleanup(fmt.Errorf("dsa verify: %w", err))
	}
	public, ok := signer.Public().(*dsa.PublicKey)
	if !ok {
		return nil, cleanup(errors.New("conformance: DSA public key did not load as *dsa.PublicKey"))
	}
	if !dsaVerifyASN1(public, digest, signature) {
		return nil, cleanup(errors.New("conformance: Go rejected the token DSA signature"))
	}
	corrupt := slices.Clone(signature)
	corrupt[len(corrupt)-1] ^= 0x01
	if err := r.client.Verify(ctx, pair.Public, input, corrupt, verifyOptions); err == nil {
		return nil, cleanup(errors.New("conformance: corrupted DSA signature was accepted"))
	}
	return map[string]any{"hash": hash.String(), "signature_bytes": len(signature)}, cleanup(nil)
}

// testParameterGen runs a domain-parameter generation mechanism and then uses
// the produced CKO_DOMAIN_PARAMETERS attributes for a full keygen operation.
func (r *Runner) testParameterGen(ctx context.Context, testCase Case) (map[string]any, error) {
	var mechanism uint
	var parameter any
	var template []*raw.Attribute
	identity := r.identity(testCase.Name)
	// Domain-parameter objects accept only a minimal template: CKA_CLASS,
	// CKA_KEY_TYPE, and the requested prime size. Tokens such as SoftHSM reject
	// storage attributes on CKO_DOMAIN_PARAMETERS.
	base := []*raw.Attribute{
		raw.NewAttribute(raw.CKA_CLASS, raw.CKO_DOMAIN_PARAMETERS),
		raw.NewAttribute(raw.CKA_PRIME_BITS, uint(2048)),
	}
	switch testCase.Variant {
	case "dsa":
		mechanism = raw.CKM_DSA_PARAMETER_GEN
		parameter = raw.DSAParameterGenParams{Hash: raw.CKM_SHA256}
		template = append(slices.Clone(base), raw.NewAttribute(raw.CKA_KEY_TYPE, raw.CKK_DSA))
	case "dh":
		mechanism = raw.CKM_DH_PKCS_PARAMETER_GEN
		template = append(slices.Clone(base), raw.NewAttribute(raw.CKA_KEY_TYPE, raw.CKK_DH))
	default:
		return nil, fmt.Errorf("conformance: unknown param-gen variant %q", testCase.Variant)
	}
	if err := r.requireAdvertisedMechanism(mechanism, raw.CKF_GENERATE); err != nil {
		return nil, err
	}
	var params pkcs11.DomainParameters
	err := r.withSessionOptions(ctx, pkcs11.RawSessionOptions{Operation: "conformance-param-gen", ReadWrite: true}, func(session *testSession) error {
		handle, err := session.GenerateKey([]*raw.Mechanism{raw.NewMechanism(mechanism, parameter)}, template)
		if err != nil {
			return err
		}
		queries := []*raw.Attribute{
			raw.NewAttribute(raw.CKA_PRIME, nil),
			raw.NewAttribute(raw.CKA_BASE, nil),
		}
		if testCase.Variant == "dsa" {
			queries = append(queries, raw.NewAttribute(raw.CKA_SUBPRIME, nil))
		}
		attrs, err := session.GetAttributeValue(handle, queries)
		destroyErr := session.DestroyObject(handle)
		if err != nil {
			return errorsJoin(err, destroyErr)
		}
		for _, attribute := range attrs {
			switch attribute.Type {
			case raw.CKA_PRIME:
				params.Prime = new(big.Int).SetBytes(attribute.Value)
			case raw.CKA_SUBPRIME:
				params.Subprime = new(big.Int).SetBytes(attribute.Value)
			case raw.CKA_BASE:
				params.Base = new(big.Int).SetBytes(attribute.Value)
			}
		}
		return destroyErr
	})
	if err != nil {
		return nil, err
	}
	if params.Prime == nil || params.Prime.Sign() == 0 || params.Base == nil || params.Base.Sign() == 0 {
		return nil, errors.New("conformance: generated domain parameters are incomplete")
	}
	if testCase.Variant == "dsa" && params.Subprime == nil {
		return nil, errors.New("conformance: generated DSA parameters lack CKA_SUBPRIME")
	}
	algorithm := pkcs11.AlgorithmDH
	if testCase.Variant == "dsa" {
		algorithm = pkcs11.AlgorithmDSA
	}
	pair, err := r.client.GenerateKeyPair(ctx, pkcs11.KeyPairOptions{
		Algorithm:        algorithm,
		Label:            identity,
		ID:               []byte(identity),
		DomainParameters: &params,
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"prime_bits": params.Prime.BitLen()}, r.cleanup(ctx, pair.Private, pair.Public)
}

// testDH runs a classic finite-field DH agreement over the ffdhe2048 group and
// confirms both parties derive identical secrets.
func (r *Runner) testDH(ctx context.Context, testCase Case) (map[string]any, error) {
	if err := r.requireAdvertisedMechanism(raw.CKM_DH_PKCS_KEY_PAIR_GEN, raw.CKF_GENERATE_KEY_PAIR); err != nil {
		return nil, err
	}
	if err := r.requireAdvertisedMechanism(raw.CKM_DH_PKCS_DERIVE, raw.CKF_DERIVE); err != nil {
		return nil, err
	}
	params := ffdhe2048()
	keygen := func(name string) (pkcs11.KeyPair, error) {
		identity := r.identity(testCase.Name + name)
		return r.client.GenerateKeyPair(ctx, pkcs11.KeyPairOptions{
			Algorithm:        pkcs11.AlgorithmDH,
			Label:            identity,
			ID:               []byte(identity),
			DomainParameters: params,
			PrivateAttributes: []*raw.Attribute{
				raw.NewAttribute(raw.CKA_DERIVE, true),
			},
		})
	}
	left, err := keygen("-left")
	if err != nil {
		return nil, err
	}
	right, err := keygen("-right")
	if err != nil {
		return nil, errorsJoin(err, r.cleanup(ctx, left.Private, left.Public))
	}
	cleanupKeys := func(primary error) error {
		return errorsJoin(primary, r.cleanup(ctx, right.Private, right.Public, left.Private, left.Public))
	}
	publicValue := func(object pkcs11.ObjectRef) ([]byte, error) {
		attrs, err := r.client.Attributes(ctx, object, raw.NewAttribute(raw.CKA_VALUE, nil))
		if err != nil {
			return nil, err
		}
		if len(attrs) != 1 || len(attrs[0].Value) == 0 {
			return nil, errors.New("conformance: DH public key has no CKA_VALUE")
		}
		return slices.Clone(attrs[0].Value), nil
	}
	leftPublic, err := publicValue(left.Public)
	if err != nil {
		return nil, cleanupKeys(err)
	}
	rightPublic, err := publicValue(right.Public)
	if err != nil {
		return nil, cleanupKeys(err)
	}
	var leftSecret, rightSecret []byte
	err = r.withSessionOptions(ctx, pkcs11.RawSessionOptions{Operation: "conformance-dh", ReadWrite: true}, func(session *testSession) (operationErr error) {
		leftPrivate, err := findObjectHandle(session, left.Private)
		if err != nil {
			return err
		}
		rightPrivate, err := findObjectHandle(session, right.Private)
		if err != nil {
			return err
		}
		template := []*raw.Attribute{
			raw.NewAttribute(raw.CKA_CLASS, raw.CKO_SECRET_KEY),
			raw.NewAttribute(raw.CKA_KEY_TYPE, raw.CKK_GENERIC_SECRET),
			raw.NewAttribute(raw.CKA_TOKEN, false),
			raw.NewAttribute(raw.CKA_SENSITIVE, false),
			raw.NewAttribute(raw.CKA_EXTRACTABLE, true),
			raw.NewAttribute(raw.CKA_VALUE_LEN, uint(256)),
		}
		leftHandle, err := session.DeriveKey([]*raw.Mechanism{raw.NewMechanism(raw.CKM_DH_PKCS_DERIVE, rightPublic)}, leftPrivate, template)
		if err != nil {
			return err
		}
		defer func() { operationErr = errorsJoin(operationErr, session.DestroyObject(leftHandle)) }()
		rightHandle, err := session.DeriveKey([]*raw.Mechanism{raw.NewMechanism(raw.CKM_DH_PKCS_DERIVE, leftPublic)}, rightPrivate, template)
		if err != nil {
			return err
		}
		defer func() { operationErr = errorsJoin(operationErr, session.DestroyObject(rightHandle)) }()
		if leftSecret, err = readSecretValue(session, leftHandle); err != nil {
			return err
		}
		rightSecret, err = readSecretValue(session, rightHandle)
		return err
	})
	cleanupErr := cleanupKeys(nil)
	if err != nil {
		return nil, errorsJoin(err, cleanupErr)
	}
	if len(leftSecret) == 0 || !bytes.Equal(leftSecret, rightSecret) {
		return nil, errorsJoin(errors.New("conformance: DH shared secrets are empty or differ"), cleanupErr)
	}
	return map[string]any{"group": "ffdhe2048", "secret_bytes": len(leftSecret)}, cleanupErr
}

// testMontgomery runs X25519/X448 key agreement, validating the token result
// against crypto/ecdh for X25519 and comparing both directions for X448.
func (r *Runner) testMontgomery(ctx context.Context, testCase Case) (map[string]any, error) {
	algorithm := testCase.Algorithm
	if algorithm == "" {
		algorithm = pkcs11.AlgorithmX25519
	}
	if algorithm != pkcs11.AlgorithmX25519 && algorithm != pkcs11.AlgorithmX448 {
		return nil, fmt.Errorf("conformance: derive-montgomery requires a Montgomery algorithm, got %s", algorithm)
	}
	if err := r.requireAdvertisedMechanism(raw.CKM_EC_MONTGOMERY_KEY_PAIR_GEN, raw.CKF_GENERATE_KEY_PAIR); err != nil {
		return nil, err
	}
	if err := r.requireAdvertisedMechanism(raw.CKM_ECDH1_DERIVE, raw.CKF_DERIVE); err != nil {
		return nil, err
	}
	keygen := func(name string) (pkcs11.KeyPair, error) {
		identity := r.identity(testCase.Name + name)
		return r.client.GenerateKeyPair(ctx, pkcs11.KeyPairOptions{
			Algorithm: algorithm,
			Label:     identity,
			ID:        []byte(identity),
			PrivateAttributes: []*raw.Attribute{
				raw.NewAttribute(raw.CKA_DERIVE, true),
			},
		})
	}
	token, err := keygen("")
	if err != nil {
		return nil, err
	}
	cleanupKeys := func(primary error) error {
		return errorsJoin(primary, r.cleanup(ctx, token.Private, token.Public))
	}
	tokenPoint, err := r.ecPoint(ctx, token.Public)
	if err != nil {
		return nil, cleanupKeys(err)
	}
	var tokenSecret []byte
	var expectedSecret []byte
	err = r.withSessionOptions(ctx, pkcs11.RawSessionOptions{Operation: "conformance-montgomery", ReadWrite: true}, func(session *testSession) (operationErr error) {
		tokenPrivate, err := findObjectHandle(session, token.Private)
		if err != nil {
			return err
		}
		template := []*raw.Attribute{
			raw.NewAttribute(raw.CKA_CLASS, raw.CKO_SECRET_KEY),
			raw.NewAttribute(raw.CKA_KEY_TYPE, raw.CKK_GENERIC_SECRET),
			raw.NewAttribute(raw.CKA_TOKEN, false),
			raw.NewAttribute(raw.CKA_SENSITIVE, false),
			raw.NewAttribute(raw.CKA_EXTRACTABLE, true),
		}
		if algorithm == pkcs11.AlgorithmX25519 {
			// Generate the peer on the Go side so the token output can be
			// checked against crypto/ecdh rather than only against itself.
			ephemeral, err := ecdh.X25519().GenerateKey(bytes.NewReader(testMessage(64)))
			if err != nil {
				return err
			}
			expectedSecret, err = ephemeral.ECDH(func() *ecdh.PublicKey {
				public, convErr := ecdh.X25519().NewPublicKey(tokenPoint)
				if convErr != nil {
					err = convErr
				}
				return public
			}())
			if err != nil {
				return err
			}
			peer := ephemeral.PublicKey().Bytes()
			handle, err := session.DeriveKey([]*raw.Mechanism{raw.NewMechanism(raw.CKM_ECDH1_DERIVE, raw.ECDH1DeriveParams{
				KDF:        raw.CKD_NULL,
				PublicData: peer,
			})}, tokenPrivate, template)
			if err != nil {
				return err
			}
			defer func() { operationErr = errorsJoin(operationErr, session.DestroyObject(handle)) }()
			tokenSecret, err = readSecretValue(session, handle)
			return err
		}
		peer, err := keygen("-peer")
		if err != nil {
			return err
		}
		defer func() { operationErr = errorsJoin(operationErr, r.cleanup(ctx, peer.Private, peer.Public)) }()
		peerPoint, err := r.ecPoint(ctx, peer.Public)
		if err != nil {
			return err
		}
		peerPrivate, err := findObjectHandle(session, peer.Private)
		if err != nil {
			return err
		}
		leftHandle, err := session.DeriveKey([]*raw.Mechanism{raw.NewMechanism(raw.CKM_ECDH1_DERIVE, raw.ECDH1DeriveParams{
			KDF:        raw.CKD_NULL,
			PublicData: peerPoint,
		})}, tokenPrivate, template)
		if err != nil {
			return err
		}
		defer func() { operationErr = errorsJoin(operationErr, session.DestroyObject(leftHandle)) }()
		rightHandle, err := session.DeriveKey([]*raw.Mechanism{raw.NewMechanism(raw.CKM_ECDH1_DERIVE, raw.ECDH1DeriveParams{
			KDF:        raw.CKD_NULL,
			PublicData: tokenPoint,
		})}, peerPrivate, template)
		if err != nil {
			return err
		}
		defer func() { operationErr = errorsJoin(operationErr, session.DestroyObject(rightHandle)) }()
		if tokenSecret, err = readSecretValue(session, leftHandle); err != nil {
			return err
		}
		expectedSecret, err = readSecretValue(session, rightHandle)
		return err
	})
	cleanupErr := cleanupKeys(nil)
	if err != nil {
		return nil, errorsJoin(err, cleanupErr)
	}
	if len(tokenSecret) == 0 || !bytes.Equal(tokenSecret, expectedSecret) {
		return nil, errorsJoin(errors.New("conformance: Montgomery shared secret is empty or differs from the reference"), cleanupErr)
	}
	return map[string]any{"algorithm": algorithm, "secret_bytes": len(tokenSecret), "software_verified": algorithm == pkcs11.AlgorithmX25519}, cleanupErr
}

// testMAC covers AES-CMAC and truncated *_HMAC_GENERAL signing mechanisms.
// Both produce outputs checked against software oracles over an imported key.
func (r *Runner) testMAC(ctx context.Context, testCase Case) (map[string]any, error) {
	identity := r.identity(testCase.Name)
	message := testMessage(testCase.MessageBytes)
	var mechanism uint
	var parameter any
	var keyType uint
	var keyValue []byte
	var expected []byte
	var err error
	switch testCase.Variant {
	case "", "aes-cmac":
		mechanism = raw.CKM_AES_CMAC
		keyType = raw.CKK_AES
		keyValue = testMessage(16)
		expected, err = aesCMAC(keyValue, message)
	case "aes-cmac-general":
		mechanism = raw.CKM_AES_CMAC_GENERAL
		keyType = raw.CKK_AES
		keyValue = testMessage(16)
		parameter = uint(10)
		var full []byte
		full, err = aesCMAC(keyValue, message)
		expected = full[:10]
	case "hmac-sha256-general", "hmac-sha384-general", "hmac-sha512-general":
		variant := map[string]struct {
			mechanism uint
			hash      crypto.Hash
		}{
			"hmac-sha256-general": {raw.CKM_SHA256_HMAC_GENERAL, crypto.SHA256},
			"hmac-sha384-general": {raw.CKM_SHA384_HMAC_GENERAL, crypto.SHA384},
			"hmac-sha512-general": {raw.CKM_SHA512_HMAC_GENERAL, crypto.SHA512},
		}[testCase.Variant]
		mechanism = variant.mechanism
		keyType = raw.CKK_GENERIC_SECRET
		keyValue = testMessage(48)
		parameter = uint(12)
		mac := hmac.New(variant.hash.New, keyValue)
		_, _ = mac.Write(message)
		expected = mac.Sum(nil)[:12]
	default:
		return nil, fmt.Errorf("conformance: unknown mac variant %q", testCase.Variant)
	}
	if err != nil {
		return nil, err
	}
	if err := r.requireAdvertisedMechanism(mechanism, raw.CKF_SIGN); err != nil {
		return nil, err
	}
	err = r.withSessionOptions(ctx, pkcs11.RawSessionOptions{Operation: "conformance-mac", ReadWrite: true}, func(session *testSession) (operationErr error) {
		handle, err := createSecretObject(session, identity, keyType, keyValue,
			raw.NewAttribute(raw.CKA_SIGN, true), raw.NewAttribute(raw.CKA_VERIFY, true))
		if err != nil {
			return err
		}
		defer func() { operationErr = errorsJoin(operationErr, session.DestroyObject(handle)) }()
		if err := session.SignInit([]*raw.Mechanism{raw.NewMechanism(mechanism, parameter)}, handle); err != nil {
			return err
		}
		signature, err := session.Sign(message)
		if err != nil {
			return err
		}
		if !bytes.Equal(signature, expected) {
			return fmt.Errorf("conformance: token MAC %x differs from software oracle %x", signature, expected)
		}
		if err := session.VerifyInit([]*raw.Mechanism{raw.NewMechanism(mechanism, parameter)}, handle); err != nil {
			return err
		}
		if err := session.Verify(message, signature); err != nil {
			return fmt.Errorf("conformance: token rejected its own MAC: %w", err)
		}
		corrupt := slices.Clone(message)
		corrupt[0] ^= 0xff
		if err := session.VerifyInit([]*raw.Mechanism{raw.NewMechanism(mechanism, parameter)}, handle); err != nil {
			return err
		}
		if err := session.Verify(corrupt, signature); err == nil {
			return errors.New("conformance: token accepted a MAC over modified data")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"mechanism": mechanism, "mac_bytes": len(expected)}, nil
}

// testDeriveEncrypt covers the *_ENCRYPT_DATA family: a key derived by
// encrypting caller data under the base key. The result is compared against a
// software AES computation.
func (r *Runner) testDeriveEncrypt(ctx context.Context, testCase Case) (map[string]any, error) {
	identity := r.identity(testCase.Name)
	baseKey := testMessage(16)
	data := testMessage(32)
	var mechanism uint
	var parameter any
	var expected []byte
	switch testCase.Variant {
	case "", "aes-cbc":
		mechanism = raw.CKM_AES_CBC_ENCRYPT_DATA
		var iv [16]byte
		copy(iv[:], testMessage(16))
		parameter = raw.AESCBCEncryptDataParams{IV: iv, Data: data}
		block, err := aes.NewCipher(baseKey)
		if err != nil {
			return nil, err
		}
		expected = make([]byte, len(data))
		cipher.NewCBCEncrypter(block, iv[:]).CryptBlocks(expected, data)
	case "aes-ecb":
		mechanism = raw.CKM_AES_ECB_ENCRYPT_DATA
		parameter = raw.KeyDerivationStringData{Data: data}
		block, err := aes.NewCipher(baseKey)
		if err != nil {
			return nil, err
		}
		expected = make([]byte, len(data))
		for i := 0; i < len(data); i += 16 {
			block.Encrypt(expected[i:], data[i:])
		}
	default:
		return nil, fmt.Errorf("conformance: unknown derive-encrypt variant %q", testCase.Variant)
	}
	if err := r.requireAdvertisedMechanism(mechanism, raw.CKF_DERIVE); err != nil {
		return nil, err
	}
	var derived []byte
	err := r.withSessionOptions(ctx, pkcs11.RawSessionOptions{Operation: "conformance-derive-encrypt", ReadWrite: true}, func(session *testSession) (operationErr error) {
		baseHandle, err := createSecretObject(session, identity+"-base", raw.CKK_AES, baseKey, raw.NewAttribute(raw.CKA_DERIVE, true))
		if err != nil {
			return err
		}
		defer func() { operationErr = errorsJoin(operationErr, session.DestroyObject(baseHandle)) }()
		derivedHandle, err := session.DeriveKey([]*raw.Mechanism{raw.NewMechanism(mechanism, parameter)}, baseHandle, []*raw.Attribute{
			raw.NewAttribute(raw.CKA_CLASS, raw.CKO_SECRET_KEY),
			raw.NewAttribute(raw.CKA_KEY_TYPE, raw.CKK_AES),
			raw.NewAttribute(raw.CKA_TOKEN, false),
			raw.NewAttribute(raw.CKA_SENSITIVE, false),
			raw.NewAttribute(raw.CKA_EXTRACTABLE, true),
			raw.NewAttribute(raw.CKA_VALUE_LEN, uint(32)),
		})
		if err != nil {
			return err
		}
		defer func() { operationErr = errorsJoin(operationErr, session.DestroyObject(derivedHandle)) }()
		derived, err = readSecretValue(session, derivedHandle)
		return err
	})
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(derived, expected[:len(derived)]) {
		return nil, errors.New("conformance: encrypt-data derived key differs from the software cipher")
	}
	return map[string]any{"mechanism": mechanism, "derived_bytes": len(derived)}, nil
}

// testDeriveConcatenate covers the CKM_CONCATENATE_* and CKM_XOR_BASE_AND_DATA
// simple derivations with byte-exact software oracles.
func (r *Runner) testDeriveConcatenate(ctx context.Context, testCase Case) (map[string]any, error) {
	identity := r.identity(testCase.Name)
	baseKey := testMessage(24)
	data := testMessage(16)
	variant := testCase.Variant
	if variant == "" {
		variant = "base-data"
	}
	var mechanism uint
	var parameter any
	var expected []byte
	var other []byte
	switch variant {
	case "base-data":
		mechanism = raw.CKM_CONCATENATE_BASE_AND_DATA
		parameter = raw.KeyDerivationStringData{Data: data}
		expected = append(slices.Clone(baseKey), data...)
	case "data-base":
		mechanism = raw.CKM_CONCATENATE_DATA_AND_BASE
		parameter = raw.KeyDerivationStringData{Data: data}
		expected = append(slices.Clone(data), baseKey...)
	case "base-key":
		mechanism = raw.CKM_CONCATENATE_BASE_AND_KEY
		other = testMessage(16)
		expected = append(slices.Clone(baseKey), other...)
	case "xor":
		mechanism = raw.CKM_XOR_BASE_AND_DATA
		parameter = raw.KeyDerivationStringData{Data: data}
		// The data string is applied to the left of the base key; the result
		// keeps the base-key length, with trailing bytes unchanged when the
		// data is shorter.
		expected = slices.Clone(baseKey)
		for i := 0; i < len(expected) && i < len(data); i++ {
			expected[i] ^= data[i]
		}
	default:
		return nil, fmt.Errorf("conformance: unknown derive-concatenate variant %q", variant)
	}
	if err := r.requireAdvertisedMechanism(mechanism, raw.CKF_DERIVE); err != nil {
		return nil, err
	}
	var derived []byte
	err := r.withSessionOptions(ctx, pkcs11.RawSessionOptions{Operation: "conformance-derive-concatenate", ReadWrite: true}, func(session *testSession) (operationErr error) {
		baseHandle, err := createSecretObject(session, identity+"-base", raw.CKK_GENERIC_SECRET, baseKey, raw.NewAttribute(raw.CKA_DERIVE, true))
		if err != nil {
			return err
		}
		defer func() { operationErr = errorsJoin(operationErr, session.DestroyObject(baseHandle)) }()
		if variant == "base-key" {
			otherHandle, err := createSecretObject(session, identity+"-other", raw.CKK_GENERIC_SECRET, other, raw.NewAttribute(raw.CKA_DERIVE, true))
			if err != nil {
				return err
			}
			defer func() { operationErr = errorsJoin(operationErr, session.DestroyObject(otherHandle)) }()
			parameter = uint(otherHandle)
		}
		// CKM_XOR_BASE_AND_DATA emits only min(len(base), len(data)) bytes; the
		// concatenate variants emit the full concatenation.
		valueLen := uint(24)
		if variant == "xor" {
			valueLen = uint(len(data))
		}
		derivedHandle, err := session.DeriveKey([]*raw.Mechanism{raw.NewMechanism(mechanism, parameter)}, baseHandle, []*raw.Attribute{
			raw.NewAttribute(raw.CKA_CLASS, raw.CKO_SECRET_KEY),
			raw.NewAttribute(raw.CKA_KEY_TYPE, raw.CKK_GENERIC_SECRET),
			raw.NewAttribute(raw.CKA_TOKEN, false),
			raw.NewAttribute(raw.CKA_SENSITIVE, false),
			raw.NewAttribute(raw.CKA_EXTRACTABLE, true),
			raw.NewAttribute(raw.CKA_VALUE_LEN, valueLen),
		})
		if err != nil {
			return err
		}
		defer func() { operationErr = errorsJoin(operationErr, session.DestroyObject(derivedHandle)) }()
		derived, err = readSecretValue(session, derivedHandle)
		return err
	})
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(derived, expected[:len(derived)]) {
		return nil, errors.New("conformance: simple derived key differs from the software oracle")
	}
	return map[string]any{"mechanism": mechanism, "derived_bytes": len(derived)}, nil
}

// testDeriveExtract runs CKM_EXTRACT_KEY_FROM_KEY with a bit offset, matching
// the token's big-endian bit-slice semantics.
func (r *Runner) testDeriveExtract(ctx context.Context, testCase Case) (map[string]any, error) {
	if err := r.requireAdvertisedMechanism(raw.CKM_EXTRACT_KEY_FROM_KEY, raw.CKF_DERIVE); err != nil {
		return nil, err
	}
	identity := r.identity(testCase.Name)
	baseKey := testMessage(32)
	bitOffset := uint(13)
	keyLen := 24
	expected := make([]byte, keyLen)
	shift := bitOffset % 8
	baseByte := (bitOffset - shift) / 8
	for i := range keyLen {
		first := baseKey[(int(baseByte)+i)%len(baseKey)] << shift
		var second byte
		if shift != 0 {
			second = baseKey[(int(baseByte)+i+1)%len(baseKey)] >> (8 - shift)
		}
		expected[i] = first | second
	}
	var derived []byte
	err := r.withSessionOptions(ctx, pkcs11.RawSessionOptions{Operation: "conformance-derive-extract", ReadWrite: true}, func(session *testSession) (operationErr error) {
		baseHandle, err := createSecretObject(session, identity+"-base", raw.CKK_GENERIC_SECRET, baseKey, raw.NewAttribute(raw.CKA_DERIVE, true))
		if err != nil {
			return err
		}
		defer func() { operationErr = errorsJoin(operationErr, session.DestroyObject(baseHandle)) }()
		derivedHandle, err := session.DeriveKey([]*raw.Mechanism{raw.NewMechanism(raw.CKM_EXTRACT_KEY_FROM_KEY, bitOffset)}, baseHandle, []*raw.Attribute{
			raw.NewAttribute(raw.CKA_CLASS, raw.CKO_SECRET_KEY),
			raw.NewAttribute(raw.CKA_KEY_TYPE, raw.CKK_GENERIC_SECRET),
			raw.NewAttribute(raw.CKA_TOKEN, false),
			raw.NewAttribute(raw.CKA_SENSITIVE, false),
			raw.NewAttribute(raw.CKA_EXTRACTABLE, true),
			raw.NewAttribute(raw.CKA_VALUE_LEN, uint(keyLen)),
		})
		if err != nil {
			return err
		}
		defer func() { operationErr = errorsJoin(operationErr, session.DestroyObject(derivedHandle)) }()
		derived, err = readSecretValue(session, derivedHandle)
		return err
	})
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(derived, expected) {
		return nil, errors.New("conformance: extracted key differs from the software bit-slice oracle")
	}
	return map[string]any{"derived_bytes": len(derived)}, nil
}

// testRSAAESWrap wraps an AES target under RSA-OAEP with an ephemeral AES key
// via CKM_RSA_AES_KEY_WRAP, exercising the nested OAEP parameter marshal.
func (r *Runner) testRSAAESWrap(ctx context.Context, _ Case) (map[string]any, error) {
	if err := r.requireAdvertisedMechanism(raw.CKM_RSA_AES_KEY_WRAP, raw.CKF_WRAP); err != nil {
		return nil, err
	}
	identity := r.identity("rsa-aes-wrap")
	pair, err := r.client.GenerateKeyPair(ctx, pkcs11.KeyPairOptions{
		Algorithm: pkcs11.AlgorithmRSA,
		RSABits:   2048,
		Label:     identity,
		ID:        []byte(identity),
		PublicAttributes: []*raw.Attribute{
			raw.NewAttribute(raw.CKA_WRAP, true),
		},
		PrivateAttributes: []*raw.Attribute{
			raw.NewAttribute(raw.CKA_UNWRAP, true),
		},
	})
	if err != nil {
		return nil, err
	}
	cleanup := func(primary error) error {
		return errorsJoin(primary, r.cleanup(ctx, pair.Private, pair.Public))
	}
	targetKey := testMessage(32)
	var wrapped []byte
	err = r.withSessionOptions(ctx, pkcs11.RawSessionOptions{Operation: "conformance-rsa-aes-wrap", ReadWrite: true}, func(session *testSession) (operationErr error) {
		target, err := createSecretObject(session, identity+"-target", raw.CKK_AES, targetKey, raw.NewAttribute(raw.CKA_EXTRACTABLE, true))
		if err != nil {
			return err
		}
		defer func() { operationErr = errorsJoin(operationErr, session.DestroyObject(target)) }()
		wrapping, err := findObjectHandle(session, pair.Public)
		if err != nil {
			return err
		}
		mechanisms := []*raw.Mechanism{raw.NewMechanism(raw.CKM_RSA_AES_KEY_WRAP, raw.RSAAESKeyWrapParams{
			AESKeyBits: 128,
			OAEPParams: &raw.OAEPParams{HashAlg: raw.CKM_SHA256, MGF: raw.CKG_MGF1_SHA256, Source: raw.CKZ_DATA_SPECIFIED},
		})}
		wrapped, err = session.WrapKey(mechanisms, wrapping, target)
		if err != nil {
			return err
		}
		unwrapping, err := findObjectHandle(session, pair.Private)
		if err != nil {
			return err
		}
		unwrapped, err := session.UnwrapKey(mechanisms, unwrapping, wrapped, []*raw.Attribute{
			raw.NewAttribute(raw.CKA_CLASS, raw.CKO_SECRET_KEY),
			raw.NewAttribute(raw.CKA_KEY_TYPE, raw.CKK_AES),
			raw.NewAttribute(raw.CKA_TOKEN, false),
			raw.NewAttribute(raw.CKA_SENSITIVE, false),
			raw.NewAttribute(raw.CKA_EXTRACTABLE, true),
		})
		if err != nil {
			return err
		}
		defer func() { operationErr = errorsJoin(operationErr, session.DestroyObject(unwrapped)) }()
		value, err := readSecretValue(session, unwrapped)
		if err != nil {
			return err
		}
		if !bytes.Equal(value, targetKey) {
			return errors.New("conformance: unwrapped AES key differs from the original")
		}
		return nil
	})
	if err != nil {
		return nil, errorsJoin(err, cleanup(nil))
	}
	return map[string]any{"wrapped_bytes": len(wrapped)}, cleanup(nil)
}

// testDeriveSP800 runs the SP800-108 counter and feedback KDFs with a byte-
// exact oracle: K(i) = PRF(base, i||label||0x00||context||L_bits) for counter
// mode and K(i) = PRF(base, K(i-1)||label||0x00||context||L_bits) for feedback.
func (r *Runner) testDeriveSP800(ctx context.Context, testCase Case) (map[string]any, error) {
	variant := testCase.Variant
	if variant == "" {
		variant = "counter"
	}
	var mechanism uint
	var parameter any
	baseKey := testMessage(48)
	label := []byte("otpki-sp800-label")
	contextData := []byte("otpki-sp800-context")
	fixedInput := append(append(slices.Clone(label), 0x00), contextData...)
	keyLen := 32
	switch variant {
	case "counter":
		mechanism = raw.CKM_SP800_108_COUNTER_KDF
		parameter = raw.SP800108KDFParams{
			PRFType: raw.CKM_SHA256_HMAC,
			DataParams: []raw.SP800108DataParam{
				{Type: raw.CK_SP800_108_ITERATION_VARIABLE, Value: raw.SP800108CounterFormat{WidthInBits: 32}},
				{Type: raw.CK_SP800_108_BYTE_ARRAY, Value: fixedInput},
				{Type: raw.CK_SP800_108_DKM_LENGTH, Value: raw.SP800108DKMLengthFormat{Method: raw.CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS, WidthInBits: 32}},
			},
		}
	case "feedback":
		mechanism = raw.CKM_SP800_108_FEEDBACK_KDF
		parameter = raw.SP800108FeedbackKDFParams{
			PRFType: raw.CKM_SHA256_HMAC,
			DataParams: []raw.SP800108DataParam{
				{Type: raw.CK_SP800_108_ITERATION_VARIABLE},
				{Type: raw.CK_SP800_108_BYTE_ARRAY, Value: fixedInput},
				{Type: raw.CK_SP800_108_DKM_LENGTH, Value: raw.SP800108DKMLengthFormat{Method: raw.CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS, WidthInBits: 32}},
			},
			IV: bytes.Repeat([]byte{0x5a}, 16),
		}
	default:
		return nil, fmt.Errorf("conformance: unknown derive-sp800 variant %q", variant)
	}
	if err := r.requireAdvertisedMechanism(mechanism, raw.CKF_DERIVE); err != nil {
		return nil, err
	}
	if err := r.requireAdvertisedMechanism(raw.CKM_SHA256_HMAC, 0); err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, baseKey)
	var expected []byte
	var previous []byte
	for len(expected) < keyLen {
		mac.Reset()
		switch variant {
		case "counter":
			var counter [4]byte
			binary.BigEndian.PutUint32(counter[:], uint32(len(expected)/32+1))
			_, _ = mac.Write(counter[:])
		case "feedback":
			if len(previous) == 0 {
				feedback, ok := parameter.(raw.SP800108FeedbackKDFParams)
				if !ok {
					return nil, fmt.Errorf("conformance: feedback variant parameter is %T, not SP800108FeedbackKDFParams", parameter)
				}
				_, _ = mac.Write(feedback.IV)
			} else {
				_, _ = mac.Write(previous)
			}
		}
		_, _ = mac.Write(fixedInput)
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(keyLen*8))
		_, _ = mac.Write(length[:])
		previous = mac.Sum(nil)
		expected = append(expected, previous...)
	}
	expected = expected[:keyLen]
	identity := r.identity(testCase.Name)
	var derived []byte
	err := r.withSessionOptions(ctx, pkcs11.RawSessionOptions{Operation: "conformance-derive-sp800", ReadWrite: true}, func(session *testSession) (operationErr error) {
		baseHandle, err := createSecretObject(session, identity+"-base", raw.CKK_GENERIC_SECRET, baseKey, raw.NewAttribute(raw.CKA_DERIVE, true))
		if err != nil {
			return err
		}
		defer func() { operationErr = errorsJoin(operationErr, session.DestroyObject(baseHandle)) }()
		derivedHandle, err := session.DeriveKey([]*raw.Mechanism{raw.NewMechanism(mechanism, parameter)}, baseHandle, []*raw.Attribute{
			raw.NewAttribute(raw.CKA_CLASS, raw.CKO_SECRET_KEY),
			raw.NewAttribute(raw.CKA_KEY_TYPE, raw.CKK_GENERIC_SECRET),
			raw.NewAttribute(raw.CKA_TOKEN, false),
			raw.NewAttribute(raw.CKA_SENSITIVE, false),
			raw.NewAttribute(raw.CKA_EXTRACTABLE, true),
			raw.NewAttribute(raw.CKA_VALUE_LEN, uint(keyLen)),
		})
		if err != nil {
			return err
		}
		defer func() { operationErr = errorsJoin(operationErr, session.DestroyObject(derivedHandle)) }()
		derived, err = readSecretValue(session, derivedHandle)
		return err
	})
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(derived, expected) {
		return nil, errors.New("conformance: SP800-108 output differs from the software oracle")
	}
	return map[string]any{"mechanism": mechanism, "derived_bytes": len(derived)}, nil
}

// testDeriveTLS covers the TLS KDF family: the generic labeled CKM_TLS_KDF,
// the TLS 1.2 master-secret derivations, and the key-material expansion that
// writes nested output handles.
func (r *Runner) testDeriveTLS(ctx context.Context, testCase Case) (map[string]any, error) {
	variant := testCase.Variant
	if variant == "" {
		variant = "kdf"
	}
	mechanism := map[string]uint{
		"kdf":      raw.CKM_TLS_KDF,
		"tls12":    raw.CKM_TLS12_KDF,
		"master":   raw.CKM_TLS12_MASTER_KEY_DERIVE,
		"extended": raw.CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE,
		"key-mat":  raw.CKM_TLS12_KEY_AND_MAC_DERIVE,
	}[variant]
	if mechanism == 0 {
		return nil, fmt.Errorf("conformance: unknown derive-tls variant %q", variant)
	}
	if err := r.requireAdvertisedMechanism(mechanism, raw.CKF_DERIVE); err != nil {
		return nil, err
	}
	identity := r.identity(testCase.Name)
	secret := testMessage(48)
	// The premaster's first two bytes become the returned CK_VERSION.
	secret[0], secret[1] = 0x03, 0x03
	clientRandom := testMessage(32)
	serverRandom := bytes.Repeat([]byte{0x71}, 32)
	sessionHash := sha256.Sum256(testMessage(64))
	label := []byte("otpki-tls-label")
	contextData := []byte("otpki-tls-context")
	keyLen := 48
	var parameter any
	var expected []byte
	var versionCheck *raw.Version
	var material *raw.TLS12KeyMaterial
	switch variant {
	case "kdf", "tls12":
		parameter = raw.TLSKDFParams{
			PRFMechanism: raw.CKM_SHA256,
			Label:        label,
			ClientRandom: clientRandom,
			ServerRandom: serverRandom,
			ContextData:  contextData,
		}
		expected = tlsPRF(secret, append(append(append(slices.Clone(label), clientRandom...), serverRandom...), contextData...), keyLen)
	case "master":
		version := &raw.Version{}
		versionCheck = version
		parameter = raw.TLS12MasterKeyDeriveParams{ClientRandom: clientRandom, ServerRandom: serverRandom, Version: version, PRFHashMechanism: raw.CKM_SHA256}
		expected = tlsPRF(secret, append(append([]byte("master secret"), clientRandom...), serverRandom...), 48)
	case "extended":
		version := &raw.Version{}
		versionCheck = version
		parameter = raw.TLS12ExtendedMasterKeyDeriveParams{SessionHash: sessionHash[:], Version: version, PRFHashMechanism: raw.CKM_SHA256}
		expected = tlsPRF(secret, append([]byte("extended master secret"), sessionHash[:]...), 48)
	case "key-mat":
		material = &raw.TLS12KeyMaterial{}
		parameter = raw.TLS12KeyMatParams{
			MACSizeBits:      256,
			KeySizeBits:      128,
			IVSizeBits:       128,
			ClientRandom:     clientRandom,
			ServerRandom:     serverRandom,
			KeyMaterial:      material,
			PRFHashMechanism: raw.CKM_SHA256,
		}
	}
	// The derived object's CKA_VALUE_LEN is the master secret length except for
	// key-material derivation, where it must match KeySizeBits/8 because the
	// returned key objects are the write keys.
	derivedValueLen := uint(keyLen)
	if variant == "key-mat" {
		derivedValueLen = 128 / 8
	}
	var derived []byte
	var keyMaterialValues [][]byte
	err := r.withSessionOptions(ctx, pkcs11.RawSessionOptions{Operation: "conformance-derive-tls", ReadWrite: true}, func(session *testSession) (operationErr error) {
		// The premaster must be a session object: providers only echo the
		// negotiated version out of ephemeral premaster secrets.
		baseHandle, err := createSecretObject(session, identity+"-base", raw.CKK_GENERIC_SECRET, secret,
			raw.NewAttribute(raw.CKA_DERIVE, true),
			raw.NewAttribute(raw.CKA_TOKEN, false))
		if err != nil {
			return err
		}
		defer func() { operationErr = errorsJoin(operationErr, session.DestroyObject(baseHandle)) }()
		derivedHandle, err := session.DeriveKey([]*raw.Mechanism{raw.NewMechanism(mechanism, parameter)}, baseHandle, []*raw.Attribute{
			raw.NewAttribute(raw.CKA_CLASS, raw.CKO_SECRET_KEY),
			raw.NewAttribute(raw.CKA_KEY_TYPE, raw.CKK_GENERIC_SECRET),
			raw.NewAttribute(raw.CKA_TOKEN, false),
			raw.NewAttribute(raw.CKA_SENSITIVE, false),
			raw.NewAttribute(raw.CKA_EXTRACTABLE, true),
			raw.NewAttribute(raw.CKA_VALUE_LEN, derivedValueLen),
		})
		if err != nil {
			return err
		}
		// Key-material expansion returns objects only through
		// pReturnedKeyMaterial; providers leave the derive handle unwritten.
		if derivedHandle != 0 {
			defer func() { operationErr = errorsJoin(operationErr, session.DestroyObject(derivedHandle)) }()
		}
		if expected != nil {
			if derived, err = readSecretValue(session, derivedHandle); err != nil {
				return err
			}
		}
		if material != nil {
			for _, handle := range []raw.ObjectHandle{material.ClientMACSecret, material.ServerMACSecret, material.ClientKey, material.ServerKey} {
				if handle == 0 {
					continue
				}
				value, err := readSecretValue(session, handle)
				if err != nil {
					operationErr = errorsJoin(operationErr, err)
				} else {
					keyMaterialValues = append(keyMaterialValues, value)
				}
				operationErr = errorsJoin(operationErr, session.DestroyObject(handle))
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	details := map[string]any{"mechanism": mechanism}
	if expected != nil {
		if !bytes.Equal(derived, expected) {
			return nil, errors.New("conformance: TLS derivation differs from the TLS P_hash oracle")
		}
		details["secret_bytes"] = len(derived)
		details["software_verified"] = true
	}
	if versionCheck != nil {
		if versionCheck.Major != 3 || versionCheck.Minor != 3 {
			return nil, fmt.Errorf("conformance: TLS version output is %d.%d, expected 3.3", versionCheck.Major, versionCheck.Minor)
		}
		details["version_synced"] = true
	}
	if material != nil {
		if material.ClientMACSecret == 0 || material.ServerMACSecret == 0 || material.ClientKey == 0 || material.ServerKey == 0 {
			return nil, errors.New("conformance: TLS key material derivation did not return all object handles")
		}
		if len(material.IVClient) != 16 || len(material.IVServer) != 16 {
			return nil, fmt.Errorf("conformance: TLS key material IVs are %d/%d bytes, expected 16", len(material.IVClient), len(material.IVServer))
		}
		block := tlsPRF(secret, append(append([]byte("key expansion"), serverRandom...), clientRandom...), 128)
		parts := [][]byte{block[0:32], block[32:64], block[64:80], block[80:96]}
		for index, value := range keyMaterialValues {
			if index >= len(parts) || !bytes.Equal(value, parts[index]) {
				return nil, errors.New("conformance: TLS key material objects differ from the P_hash oracle")
			}
		}
		if len(keyMaterialValues) != len(parts) {
			return nil, errors.New("conformance: TLS key material derivation did not return readable key objects")
		}
		if !bytes.Equal(material.IVClient, block[96:112]) || !bytes.Equal(material.IVServer, block[112:128]) {
			return nil, errors.New("conformance: TLS key material IVs differ from the P_hash oracle")
		}
		details["objects"] = 4
		details["software_verified"] = true
	}
	return details, nil
}

// testTLSMAC signs data with CKM_TLS_MAC, the TLS finished-label MAC, and
// verifies against the P_hash oracle.
func (r *Runner) testTLSMAC(ctx context.Context, testCase Case) (map[string]any, error) {
	if err := r.requireAdvertisedMechanism(raw.CKM_TLS_MAC, raw.CKF_SIGN); err != nil {
		return nil, err
	}
	serverOrClient := uint(2)
	finished := []byte("client finished")
	if testCase.Variant == "server" {
		serverOrClient = 1
		finished = []byte("server finished")
	}
	identity := r.identity(testCase.Name)
	secret := testMessage(48)
	data := testMessage(testCase.MessageBytes)
	const macLen = 12
	expected := tlsPRF(secret, append(slices.Clone(finished), data...), macLen)
	err := r.withSessionOptions(ctx, pkcs11.RawSessionOptions{Operation: "conformance-tls-mac", ReadWrite: true}, func(session *testSession) (operationErr error) {
		// CKA_DERIVE is required as well: providers drive the TLS PRF through
		// an internal derive-capable MAC operation on this key.
		handle, err := createSecretObject(session, identity, raw.CKK_GENERIC_SECRET, secret,
			raw.NewAttribute(raw.CKA_SIGN, true), raw.NewAttribute(raw.CKA_VERIFY, true),
			raw.NewAttribute(raw.CKA_DERIVE, true))
		if err != nil {
			return err
		}
		defer func() { operationErr = errorsJoin(operationErr, session.DestroyObject(handle)) }()
		params := raw.TLSMACParams{PRFHashMechanism: raw.CKM_SHA256, MACLength: macLen, ServerOrClient: serverOrClient}
		if err := session.SignInit([]*raw.Mechanism{raw.NewMechanism(raw.CKM_TLS_MAC, params)}, handle); err != nil {
			return err
		}
		mac, err := session.Sign(data)
		if err != nil {
			return err
		}
		if !bytes.Equal(mac, expected) {
			return errors.New("conformance: TLS MAC differs from the P_hash oracle")
		}
		if err := session.VerifyInit([]*raw.Mechanism{raw.NewMechanism(raw.CKM_TLS_MAC, params)}, handle); err != nil {
			return err
		}
		if err := session.Verify(data, mac); err != nil {
			return fmt.Errorf("conformance: token rejected its own TLS MAC: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"mac_bytes": macLen, "software_verified": true}, nil
}

// testHOTP creates a CKO_OTP_KEY, signs the empty string, decodes the
// CK_OTP_SIGNATURE_INFO trailer, and checks the digits against RFC 4226.
func (r *Runner) testHOTP(ctx context.Context, _ Case) (map[string]any, error) {
	if err := r.requireAdvertisedMechanism(raw.CKM_HOTP, raw.CKF_SIGN); err != nil {
		return nil, err
	}
	identity := r.identity("hotp")
	secret := testMessage(20)
	const digits = 6
	var counter uint64 = 7
	err := r.withSessionOptions(ctx, pkcs11.RawSessionOptions{Operation: "conformance-hotp", ReadWrite: true}, func(session *testSession) (operationErr error) {
		var counterBytes [8]byte
		binary.BigEndian.PutUint64(counterBytes[:], counter)
		handle, err := createSecretObject(session, identity, raw.CKK_HOTP, secret,
			raw.NewAttribute(raw.CKA_CLASS, raw.CKO_OTP_KEY),
			raw.NewAttribute(raw.CKA_OTP_COUNTER, counterBytes[:]),
			raw.NewAttribute(raw.CKA_OTP_COUNTER_REQUIREMENT, raw.CK_OTP_PARAM_OPTIONAL),
			raw.NewAttribute(raw.CKA_OTP_LENGTH, uint(digits)),
			raw.NewAttribute(raw.CKA_SIGN, true), raw.NewAttribute(raw.CKA_VERIFY, true))
		if err != nil {
			return err
		}
		defer func() { operationErr = errorsJoin(operationErr, session.DestroyObject(handle)) }()
		// CKM_HOTP signs the empty input through C_SignFinal: C_Sign requires
		// a non-NULL pData argument, and C_SignUpdate rejects payload bytes.
		// Passing the counter as a mechanism parameter keeps the stored
		// counter unmodified so the verify pass reads the same moving factor.
		params := raw.OTPParams{Params: []raw.OTPParam{{Type: raw.CK_OTP_COUNTER, Value: counterBytes[:]}}}
		if err := session.SignInit([]*raw.Mechanism{raw.NewMechanism(raw.CKM_HOTP, params)}, handle); err != nil {
			return err
		}
		blob, err := session.SignFinal()
		if err != nil {
			return err
		}
		if len(blob) < digits {
			return fmt.Errorf("conformance: HOTP signature blob is %d bytes", len(blob))
		}
		otp := string(blob[len(blob)-digits:])
		expected, err := hotpOracle(secret, counter, digits)
		if err != nil {
			return err
		}
		if otp != expected {
			return fmt.Errorf("conformance: HOTP %q differs from the RFC 4226 oracle %q", otp, expected)
		}
		if err := session.VerifyInit([]*raw.Mechanism{raw.NewMechanism(raw.CKM_HOTP, params)}, handle); err != nil {
			return err
		}
		if err := session.VerifyFinal([]byte(otp)); err != nil {
			return fmt.Errorf("conformance: token rejected its own HOTP value: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"digits": digits, "software_verified": true}, nil
}

// testPBKDF2 generates a key through CKM_PKCS5_PBKD2 and compares it with the
// Go standard library PBKDF2.
func (r *Runner) testPBKDF2(ctx context.Context, _ Case) (map[string]any, error) {
	if err := r.requireAdvertisedMechanism(raw.CKM_PKCS5_PBKD2, raw.CKF_GENERATE); err != nil {
		return nil, err
	}
	identity := r.identity("pbkdf2")
	password := []byte("otpki-conformance-password")
	salt := testMessage(16)
	const iterations = 1000
	const keyLen = 32
	expected, err := pbkdf2.Key(sha256.New, string(password), salt, iterations, keyLen)
	if err != nil {
		return nil, fmt.Errorf("conformance: software PBKDF2 failed: %w", err)
	}
	var derived []byte
	err = r.withSessionOptions(ctx, pkcs11.RawSessionOptions{Operation: "conformance-pbkdf2", ReadWrite: true}, func(session *testSession) (operationErr error) {
		handle, err := session.GenerateKey([]*raw.Mechanism{raw.NewMechanism(raw.CKM_PKCS5_PBKD2, raw.PBKDF2Params{
			SaltSource: raw.CKZ_SALT_SPECIFIED,
			Salt:       salt,
			Iterations: iterations,
			PRF:        raw.CKP_PKCS5_PBKD2_HMAC_SHA256,
			Password:   password,
		})}, []*raw.Attribute{
			raw.NewAttribute(raw.CKA_CLASS, raw.CKO_SECRET_KEY),
			raw.NewAttribute(raw.CKA_KEY_TYPE, raw.CKK_GENERIC_SECRET),
			raw.NewAttribute(raw.CKA_TOKEN, false),
			raw.NewAttribute(raw.CKA_SENSITIVE, false),
			raw.NewAttribute(raw.CKA_EXTRACTABLE, true),
			raw.NewAttribute(raw.CKA_VALUE_LEN, uint(keyLen)),
			raw.NewAttribute(raw.CKA_LABEL, identity),
			raw.NewAttribute(raw.CKA_ID, []byte(identity)),
		})
		if err != nil {
			return err
		}
		defer func() { operationErr = errorsJoin(operationErr, session.DestroyObject(handle)) }()
		derived, err = readSecretValue(session, handle)
		return err
	})
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(derived, expected) {
		return nil, errors.New("conformance: PBKDF2 output differs from the software oracle")
	}
	return map[string]any{"derived_bytes": len(derived), "software_verified": true}, nil
}

// testPubKeyFromPriv derives a public-key object from a private key via
// CKM_PUB_KEY_FROM_PRIV_KEY and confirms it verifies token signatures.
func (r *Runner) testPubKeyFromPriv(ctx context.Context, testCase Case) (map[string]any, error) {
	if err := r.requireAdvertisedMechanism(raw.CKM_PUB_KEY_FROM_PRIV_KEY, raw.CKF_DERIVE); err != nil {
		return nil, err
	}
	algorithm := testCase.Algorithm
	variant := testCase.Variant
	if algorithm == "" && variant == "" {
		algorithm = pkcs11.AlgorithmECDSAP256
		variant = "ecdsa"
	}
	pair, err := r.client.GenerateKeyPair(ctx, r.keyPairOptions(testCase))
	if err != nil {
		return nil, err
	}
	cleanup := func(primary error) error {
		return errorsJoin(primary, r.cleanup(ctx, pair.Private, pair.Public))
	}
	var ecParams []byte
	if variant != "rsa" {
		if attrs, attrErr := r.client.Attributes(ctx, pair.Public, raw.NewAttribute(raw.CKA_EC_PARAMS, nil)); attrErr == nil && len(attrs) == 1 {
			ecParams = attrs[0].Value
		}
	}
	err = r.withSessionOptions(ctx, pkcs11.RawSessionOptions{Operation: "conformance-pub-from-priv", ReadWrite: true}, func(session *testSession) (operationErr error) {
		privateHandle, err := findObjectHandle(session, pair.Private)
		if err != nil {
			return err
		}
		// RSA public objects derive modulus and exponent from the private
		// object itself; EC objects need the curve parameters in the template.
		// CKA_DESTROYABLE defaults to false on derived public keys, so request
		// it explicitly to allow cleanup.
		template := []*raw.Attribute{
			raw.NewAttribute(raw.CKA_CLASS, raw.CKO_PUBLIC_KEY),
			raw.NewAttribute(raw.CKA_TOKEN, false),
			raw.NewAttribute(raw.CKA_VERIFY, true),
			raw.NewAttribute(raw.CKA_DESTROYABLE, true),
		}
		if variant == "rsa" {
			template = append(template, raw.NewAttribute(raw.CKA_KEY_TYPE, raw.CKK_RSA))
		} else {
			template = append(template,
				raw.NewAttribute(raw.CKA_KEY_TYPE, raw.CKK_EC),
				raw.NewAttribute(raw.CKA_EC_PARAMS, ecParams))
		}
		publicHandle, err := session.DeriveKey([]*raw.Mechanism{raw.NewMechanism(raw.CKM_PUB_KEY_FROM_PRIV_KEY, nil)}, privateHandle, template)
		if err != nil {
			return fmt.Errorf("conformance: pub-key-from-priv derive: %w", err)
		}
		defer func() { operationErr = errorsJoin(operationErr, session.DestroyObject(publicHandle)) }()
		message := testMessage(testCase.MessageBytes)
		var signMechanism uint
		var signInput []byte
		if variant == "rsa" {
			signMechanism = raw.CKM_SHA256_RSA_PKCS
			signInput = message
		} else {
			signMechanism = raw.CKM_ECDSA
			digest := sha256.Sum256(message)
			signInput = digest[:]
		}
		if err := session.SignInit([]*raw.Mechanism{raw.NewMechanism(signMechanism, nil)}, privateHandle); err != nil {
			return fmt.Errorf("conformance: pub-key-from-priv sign init: %w", err)
		}
		signature, err := session.Sign(signInput)
		if err != nil {
			return fmt.Errorf("conformance: pub-key-from-priv sign: %w", err)
		}
		if err := session.VerifyInit([]*raw.Mechanism{raw.NewMechanism(signMechanism, nil)}, publicHandle); err != nil {
			return fmt.Errorf("conformance: pub-key-from-priv verify init: %w", err)
		}
		if err := session.Verify(signInput, signature); err != nil {
			return errors.New("conformance: derived public key failed to verify a token signature")
		}
		return nil
	})
	if err != nil {
		return nil, errorsJoin(err, cleanup(nil))
	}
	return map[string]any{"algorithm": algorithm}, cleanup(nil)
}

// testHMACKeyGen exercises the CKM_SHA*_KEY_GEN mechanisms that create typed
// HMAC keys, then MACs and verifies with the generated key.
func (r *Runner) testHMACKeyGen(ctx context.Context, testCase Case) (map[string]any, error) {
	variant := testCase.Variant
	if variant == "" {
		variant = "sha256"
	}
	mechanism, keyType, hash, err := func() (uint, uint, crypto.Hash, error) {
		switch variant {
		case "sha256":
			return raw.CKM_SHA256_KEY_GEN, raw.CKK_SHA256_HMAC, crypto.SHA256, nil
		case "sha384":
			return raw.CKM_SHA384_KEY_GEN, raw.CKK_SHA384_HMAC, crypto.SHA384, nil
		case "sha512":
			return raw.CKM_SHA512_KEY_GEN, raw.CKK_SHA512_HMAC, crypto.SHA512, nil
		case "sha512-224":
			return raw.CKM_SHA512_224_KEY_GEN, raw.CKK_SHA512_224_HMAC, crypto.SHA512_224, nil
		case "sha512-256":
			return raw.CKM_SHA512_256_KEY_GEN, raw.CKK_SHA512_256_HMAC, crypto.SHA512_256, nil
		default:
			return 0, 0, 0, fmt.Errorf("conformance: unknown hmac-keygen variant %q", variant)
		}
	}()
	if err != nil {
		return nil, err
	}
	if err := r.requireAdvertisedMechanism(mechanism, raw.CKF_GENERATE); err != nil {
		return nil, err
	}
	hmacMech, err := hmacMechanism(map[crypto.Hash]uint{
		crypto.SHA256: raw.CKM_SHA256, crypto.SHA384: raw.CKM_SHA384, crypto.SHA512: raw.CKM_SHA512,
		crypto.SHA512_224: raw.CKM_SHA512_224, crypto.SHA512_256: raw.CKM_SHA512_256,
	}[hash])
	if err != nil {
		return nil, err
	}
	identity := r.identity(testCase.Name)
	message := testMessage(testCase.MessageBytes)
	err = r.withSessionOptions(ctx, pkcs11.RawSessionOptions{Operation: "conformance-hmac-keygen", ReadWrite: true}, func(session *testSession) (operationErr error) {
		// CKA_VALUE_LEN is required by key generation: it selects the secret
		// length the token creates.
		handle, err := session.GenerateKey([]*raw.Mechanism{raw.NewMechanism(mechanism, nil)}, []*raw.Attribute{
			raw.NewAttribute(raw.CKA_CLASS, raw.CKO_SECRET_KEY),
			raw.NewAttribute(raw.CKA_KEY_TYPE, keyType),
			raw.NewAttribute(raw.CKA_TOKEN, false),
			raw.NewAttribute(raw.CKA_SENSITIVE, false),
			raw.NewAttribute(raw.CKA_EXTRACTABLE, true),
			raw.NewAttribute(raw.CKA_SIGN, true),
			raw.NewAttribute(raw.CKA_VERIFY, true),
			raw.NewAttribute(raw.CKA_VALUE_LEN, uint(hash.Size())),
			raw.NewAttribute(raw.CKA_LABEL, identity),
			raw.NewAttribute(raw.CKA_ID, []byte(identity)),
		})
		if err != nil {
			return err
		}
		defer func() { operationErr = errorsJoin(operationErr, session.DestroyObject(handle)) }()
		keyValue, err := readSecretValue(session, handle)
		if err != nil {
			return err
		}
		if err := session.SignInit([]*raw.Mechanism{raw.NewMechanism(hmacMech, nil)}, handle); err != nil {
			return err
		}
		mac, err := session.Sign(message)
		if err != nil {
			return err
		}
		expected := hmac.New(hash.New, keyValue)
		_, _ = expected.Write(message)
		if !bytes.Equal(mac, expected.Sum(nil)) {
			return errors.New("conformance: generated HMAC key produced a MAC that differs from the software oracle")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"hash": hash.String(), "software_verified": true}, nil
}

// testDES runs single-DES and triple-DES CBC against crypto/des oracles.
func (r *Runner) testDES(ctx context.Context, testCase Case) (map[string]any, error) {
	variant := testCase.Variant
	if variant == "" {
		variant = "des3-cbc"
	}
	var mechanism, keyType uint
	var keyBytes int
	switch variant {
	case "des-cbc":
		mechanism, keyType, keyBytes = raw.CKM_DES_CBC, raw.CKK_DES, 8
	case "des3-cbc":
		mechanism, keyType, keyBytes = raw.CKM_DES3_CBC, raw.CKK_DES3, 24
	default:
		return nil, fmt.Errorf("conformance: unknown des variant %q", variant)
	}
	if err := r.requireAdvertisedMechanism(mechanism, raw.CKF_ENCRYPT); err != nil {
		return nil, err
	}
	identity := r.identity(testCase.Name)
	key := testMessage(keyBytes)
	iv := bytes.Repeat([]byte{0x17}, 8)
	plaintext := testMessage(48)
	var expected []byte
	{
		var block cipher.Block
		var err error
		if variant == "des-cbc" {
			block, err = des.NewCipher(key)
		} else {
			block, err = des.NewTripleDESCipher(key)
		}
		if err != nil {
			return nil, err
		}
		expected = make([]byte, len(plaintext))
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(expected, plaintext)
	}
	err := r.withSessionOptions(ctx, pkcs11.RawSessionOptions{Operation: "conformance-des", ReadWrite: true}, func(session *testSession) (operationErr error) {
		handle, err := createSecretObject(session, identity, keyType, key,
			raw.NewAttribute(raw.CKA_ENCRYPT, true), raw.NewAttribute(raw.CKA_DECRYPT, true))
		if err != nil {
			return err
		}
		defer func() { operationErr = errorsJoin(operationErr, session.DestroyObject(handle)) }()
		if err := session.EncryptInit([]*raw.Mechanism{raw.NewMechanism(mechanism, iv)}, handle); err != nil {
			return err
		}
		ciphertext, err := session.Encrypt(plaintext)
		if err != nil {
			return err
		}
		if !bytes.Equal(ciphertext, expected) {
			return errors.New("conformance: DES ciphertext differs from the software oracle")
		}
		if err := session.DecryptInit([]*raw.Mechanism{raw.NewMechanism(mechanism, iv)}, handle); err != nil {
			return err
		}
		recovered, err := session.Decrypt(ciphertext)
		if err != nil {
			return err
		}
		if !bytes.Equal(recovered, plaintext) {
			return errors.New("conformance: DES decrypt round-trip failed")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"mechanism": mechanism, "ciphertext_bytes": len(expected), "software_verified": true}, nil
}

// testTokenPrehash exercises the CKM_HASH_ML_DSA_* mechanisms where the token
// performs the prehash internally.
func (r *Runner) testTokenPrehash(ctx context.Context, testCase Case) (map[string]any, error) {
	mechanism, err := pqcHashMechanismForCase(testCase)
	if err != nil {
		return nil, err
	}
	if err := r.requireAdvertisedMechanism(mechanism, raw.CKF_SIGN); err != nil {
		return nil, err
	}
	pair, err := r.client.GenerateKeyPair(ctx, r.keyPairOptions(testCase))
	if err != nil {
		return nil, err
	}
	cleanup := func(primary error) error {
		return errorsJoin(primary, r.cleanup(ctx, pair.Private, pair.Public))
	}
	err = r.withSessionOptions(ctx, pkcs11.RawSessionOptions{Operation: "conformance-token-prehash", ReadWrite: true}, func(session *testSession) (operationErr error) {
		privateHandle, err := findObjectHandle(session, pair.Private)
		if err != nil {
			return err
		}
		publicHandle, err := findObjectHandle(session, pair.Public)
		if err != nil {
			return err
		}
		message := testMessage(testCase.MessageBytes)
		params := raw.SignAdditionalContext{Hedge: raw.HedgeMode(raw.CKH_HEDGE_PREFERRED)}
		if err := session.SignInit([]*raw.Mechanism{raw.NewMechanism(mechanism, params)}, privateHandle); err != nil {
			return err
		}
		signature, err := session.Sign(message)
		if err != nil {
			return err
		}
		if len(signature) == 0 {
			return errors.New("conformance: token returned an empty token-prehash signature")
		}
		if err := session.VerifyInit([]*raw.Mechanism{raw.NewMechanism(mechanism, params)}, publicHandle); err != nil {
			return err
		}
		if err := session.Verify(message, signature); err != nil {
			return fmt.Errorf("conformance: token rejected its own prehash signature: %w", err)
		}
		corrupt := slices.Clone(signature)
		corrupt[len(corrupt)-1] ^= 0x01
		if err := session.VerifyInit([]*raw.Mechanism{raw.NewMechanism(mechanism, params)}, publicHandle); err != nil {
			return err
		}
		if err := session.Verify(message, corrupt); err == nil {
			return errors.New("conformance: corrupted token-prehash signature was accepted")
		}
		return nil
	})
	if err != nil {
		return nil, errorsJoin(err, cleanup(nil))
	}
	return map[string]any{"mechanism": mechanism}, cleanup(nil)
}

// pqcHashMechanismForCase maps a case to its token-side prehash mechanism.
func pqcHashMechanismForCase(testCase Case) (uint, error) {
	slh := false
	switch testCase.Algorithm {
	case pkcs11.AlgorithmMLDSA44, pkcs11.AlgorithmMLDSA65, pkcs11.AlgorithmMLDSA87:
	case pkcs11.AlgorithmSLHDSASHA2128S, pkcs11.AlgorithmSLHDSASHA2128F,
		pkcs11.AlgorithmSLHDSASHA2192S, pkcs11.AlgorithmSLHDSASHA2192F,
		pkcs11.AlgorithmSLHDSASHA2256S, pkcs11.AlgorithmSLHDSASHA2256F,
		pkcs11.AlgorithmSLHDSASHAKE128S, pkcs11.AlgorithmSLHDSASHAKE128F,
		pkcs11.AlgorithmSLHDSASHAKE192S, pkcs11.AlgorithmSLHDSASHAKE192F,
		pkcs11.AlgorithmSLHDSASHAKE256S, pkcs11.AlgorithmSLHDSASHAKE256F:
		slh = true
	default:
		return 0, fmt.Errorf("conformance: token-prehash requires an ML-DSA or SLH-DSA algorithm, got %s", testCase.Algorithm)
	}
	// SHAKE is not a crypto.Hash, so the XOF mechanisms are keyed by name.
	name := strings.ToLower(strings.TrimSpace(testCase.Hash))
	if name == "" {
		name = "sha512"
	}
	var mechanism uint
	if slh {
		switch name {
		case "sha224", "sha-224":
			mechanism = raw.CKM_HASH_SLH_DSA_SHA224
		case "sha256", "sha-256":
			mechanism = raw.CKM_HASH_SLH_DSA_SHA256
		case "sha384", "sha-384":
			mechanism = raw.CKM_HASH_SLH_DSA_SHA384
		case "sha512", "sha-512":
			mechanism = raw.CKM_HASH_SLH_DSA_SHA512
		case "sha3-224":
			mechanism = raw.CKM_HASH_SLH_DSA_SHA3_224
		case "sha3-256":
			mechanism = raw.CKM_HASH_SLH_DSA_SHA3_256
		case "sha3-384":
			mechanism = raw.CKM_HASH_SLH_DSA_SHA3_384
		case "sha3-512":
			mechanism = raw.CKM_HASH_SLH_DSA_SHA3_512
		case "shake128":
			mechanism = raw.CKM_HASH_SLH_DSA_SHAKE128
		case "shake256":
			mechanism = raw.CKM_HASH_SLH_DSA_SHAKE256
		default:
			return 0, fmt.Errorf("conformance: unsupported SLH-DSA prehash %q", testCase.Hash)
		}
		return mechanism, nil
	}
	switch name {
	case "sha224", "sha-224":
		mechanism = raw.CKM_HASH_ML_DSA_SHA224
	case "sha256", "sha-256":
		mechanism = raw.CKM_HASH_ML_DSA_SHA256
	case "sha384", "sha-384":
		mechanism = raw.CKM_HASH_ML_DSA_SHA384
	case "sha512", "sha-512":
		mechanism = raw.CKM_HASH_ML_DSA_SHA512
	case "sha3-224":
		mechanism = raw.CKM_HASH_ML_DSA_SHA3_224
	case "sha3-256":
		mechanism = raw.CKM_HASH_ML_DSA_SHA3_256
	case "sha3-384":
		mechanism = raw.CKM_HASH_ML_DSA_SHA3_384
	case "sha3-512":
		mechanism = raw.CKM_HASH_ML_DSA_SHA3_512
	case "shake128":
		mechanism = raw.CKM_HASH_ML_DSA_SHAKE128
	case "shake256":
		mechanism = raw.CKM_HASH_ML_DSA_SHAKE256
	default:
		return 0, fmt.Errorf("conformance: unsupported ML-DSA prehash %q", testCase.Hash)
	}
	return mechanism, nil
}

// testIKE1PRF runs CKM_IKE1_PRF_DERIVE: SKEYID-style
// prf(base, [prev||]gxy||CKYi||CKYr||keyNumber) with a byte-exact oracle.
func (r *Runner) testIKE1PRF(ctx context.Context, _ Case) (map[string]any, error) {
	if err := r.requireAdvertisedMechanism(raw.CKM_IKE1_PRF_DERIVE, raw.CKF_DERIVE); err != nil {
		return nil, err
	}
	if err := r.requireAdvertisedMechanism(raw.CKM_SHA256_HMAC, 0); err != nil {
		return nil, err
	}
	identity := r.identity("ike1-prf")
	baseKey := testMessage(32)
	gxy := testMessage(48)
	ckyi := bytes.Repeat([]byte{0x49}, 8)
	ckyr := bytes.Repeat([]byte{0x52}, 8)
	keyNumber := byte(1)
	const keyLen = 20
	mac := hmac.New(sha256.New, baseKey)
	_, _ = mac.Write(gxy)
	_, _ = mac.Write(ckyi)
	_, _ = mac.Write(ckyr)
	_, _ = mac.Write([]byte{keyNumber})
	expected := mac.Sum(nil)[:keyLen]
	var derived []byte
	err := r.withSessionOptions(ctx, pkcs11.RawSessionOptions{Operation: "conformance-ike1-prf", ReadWrite: true}, func(session *testSession) (operationErr error) {
		baseHandle, err := createSecretObject(session, identity+"-base", raw.CKK_SHA256_HMAC, baseKey, raw.NewAttribute(raw.CKA_DERIVE, true))
		if err != nil {
			return err
		}
		defer func() { operationErr = errorsJoin(operationErr, session.DestroyObject(baseHandle)) }()
		gxyHandle, err := createSecretObject(session, identity+"-gxy", raw.CKK_GENERIC_SECRET, gxy)
		if err != nil {
			return err
		}
		defer func() { operationErr = errorsJoin(operationErr, session.DestroyObject(gxyHandle)) }()
		derivedHandle, err := session.DeriveKey([]*raw.Mechanism{raw.NewMechanism(raw.CKM_IKE1_PRF_DERIVE, raw.IKE1PRFDerivParams{
			PRFMechanism: raw.CKM_SHA256_HMAC,
			KeyGxy:       gxyHandle,
			CKYi:         ckyi,
			CKYr:         ckyr,
			KeyNumber:    keyNumber,
		})}, baseHandle, []*raw.Attribute{
			raw.NewAttribute(raw.CKA_CLASS, raw.CKO_SECRET_KEY),
			raw.NewAttribute(raw.CKA_KEY_TYPE, raw.CKK_GENERIC_SECRET),
			raw.NewAttribute(raw.CKA_TOKEN, false),
			raw.NewAttribute(raw.CKA_SENSITIVE, false),
			raw.NewAttribute(raw.CKA_EXTRACTABLE, true),
			raw.NewAttribute(raw.CKA_VALUE_LEN, uint(keyLen)),
		})
		if err != nil {
			return err
		}
		defer func() { operationErr = errorsJoin(operationErr, session.DestroyObject(derivedHandle)) }()
		derived, err = readSecretValue(session, derivedHandle)
		return err
	})
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(derived, expected) {
		return nil, errors.New("conformance: IKE1 PRF output differs from the software oracle")
	}
	return map[string]any{"derived_bytes": len(derived), "software_verified": true}, nil
}

// testIKE2PRFPlus runs CKM_IKE2_PRF_PLUS_DERIVE, the RFC 7296 prf+ expansion.
func (r *Runner) testIKE2PRFPlus(ctx context.Context, _ Case) (map[string]any, error) {
	if err := r.requireAdvertisedMechanism(raw.CKM_IKE2_PRF_PLUS_DERIVE, raw.CKF_DERIVE); err != nil {
		return nil, err
	}
	if err := r.requireAdvertisedMechanism(raw.CKM_SHA256_HMAC, 0); err != nil {
		return nil, err
	}
	identity := r.identity("ike2-prf-plus")
	baseKey := testMessage(32)
	seed := testMessage(24)
	const keyLen = 44
	mac := hmac.New(sha256.New, baseKey)
	var expected, previous []byte
	for counter := byte(1); len(expected) < keyLen; counter++ {
		mac.Reset()
		_, _ = mac.Write(previous)
		_, _ = mac.Write(seed)
		_, _ = mac.Write([]byte{counter})
		previous = mac.Sum(nil)
		expected = append(expected, previous...)
	}
	expected = expected[:keyLen]
	var derived []byte
	err := r.withSessionOptions(ctx, pkcs11.RawSessionOptions{Operation: "conformance-ike2-prf-plus", ReadWrite: true}, func(session *testSession) (operationErr error) {
		baseHandle, err := createSecretObject(session, identity+"-base", raw.CKK_SHA256_HMAC, baseKey, raw.NewAttribute(raw.CKA_DERIVE, true))
		if err != nil {
			return err
		}
		defer func() { operationErr = errorsJoin(operationErr, session.DestroyObject(baseHandle)) }()
		derivedHandle, err := session.DeriveKey([]*raw.Mechanism{raw.NewMechanism(raw.CKM_IKE2_PRF_PLUS_DERIVE, raw.IKE2PRFPlusDeriveParams{
			PRFMechanism: raw.CKM_SHA256_HMAC,
			SeedData:     seed,
		})}, baseHandle, []*raw.Attribute{
			raw.NewAttribute(raw.CKA_CLASS, raw.CKO_SECRET_KEY),
			raw.NewAttribute(raw.CKA_KEY_TYPE, raw.CKK_GENERIC_SECRET),
			raw.NewAttribute(raw.CKA_TOKEN, false),
			raw.NewAttribute(raw.CKA_SENSITIVE, false),
			raw.NewAttribute(raw.CKA_EXTRACTABLE, true),
			raw.NewAttribute(raw.CKA_VALUE_LEN, uint(keyLen)),
		})
		if err != nil {
			return err
		}
		defer func() { operationErr = errorsJoin(operationErr, session.DestroyObject(derivedHandle)) }()
		derived, err = readSecretValue(session, derivedHandle)
		return err
	})
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(derived, expected) {
		return nil, errors.New("conformance: IKE2 PRF+ output differs from the software oracle")
	}
	return map[string]any{"derived_bytes": len(derived), "software_verified": true}, nil
}

// testIKE1Extended runs CKM_IKE1_EXTENDED_DERIVE, the RFC 2409 Appendix B
// expansion K1 = prf(K, [gxy][extra]), Kn = prf(K, K(n-1)[gxy][extra]).
func (r *Runner) testIKE1Extended(ctx context.Context, _ Case) (map[string]any, error) {
	if err := r.requireAdvertisedMechanism(raw.CKM_IKE1_EXTENDED_DERIVE, raw.CKF_DERIVE); err != nil {
		return nil, err
	}
	if err := r.requireAdvertisedMechanism(raw.CKM_SHA256_HMAC, 0); err != nil {
		return nil, err
	}
	identity := r.identity("ike1-extended")
	baseKey := testMessage(32)
	gxy := testMessage(48)
	extra := testMessage(16)
	const keyLen = 50
	mac := hmac.New(sha256.New, baseKey)
	var expected, previous []byte
	for block := 0; len(expected) < keyLen; block++ {
		mac.Reset()
		if block != 0 {
			_, _ = mac.Write(previous)
		}
		_, _ = mac.Write(gxy)
		_, _ = mac.Write(extra)
		previous = mac.Sum(nil)
		expected = append(expected, previous...)
	}
	expected = expected[:keyLen]
	var derived []byte
	err := r.withSessionOptions(ctx, pkcs11.RawSessionOptions{Operation: "conformance-ike1-extended", ReadWrite: true}, func(session *testSession) (operationErr error) {
		baseHandle, err := createSecretObject(session, identity+"-base", raw.CKK_SHA256_HMAC, baseKey, raw.NewAttribute(raw.CKA_DERIVE, true))
		if err != nil {
			return err
		}
		defer func() { operationErr = errorsJoin(operationErr, session.DestroyObject(baseHandle)) }()
		gxyHandle, err := createSecretObject(session, identity+"-gxy", raw.CKK_GENERIC_SECRET, gxy)
		if err != nil {
			return err
		}
		defer func() { operationErr = errorsJoin(operationErr, session.DestroyObject(gxyHandle)) }()
		derivedHandle, err := session.DeriveKey([]*raw.Mechanism{raw.NewMechanism(raw.CKM_IKE1_EXTENDED_DERIVE, raw.IKE1ExtendedDeriveParams{
			PRFMechanism: raw.CKM_SHA256_HMAC,
			HasKeyGxy:    true,
			KeyGxy:       gxyHandle,
			ExtraData:    extra,
		})}, baseHandle, []*raw.Attribute{
			raw.NewAttribute(raw.CKA_CLASS, raw.CKO_SECRET_KEY),
			raw.NewAttribute(raw.CKA_KEY_TYPE, raw.CKK_GENERIC_SECRET),
			raw.NewAttribute(raw.CKA_TOKEN, false),
			raw.NewAttribute(raw.CKA_SENSITIVE, false),
			raw.NewAttribute(raw.CKA_EXTRACTABLE, true),
			raw.NewAttribute(raw.CKA_VALUE_LEN, uint(keyLen)),
		})
		if err != nil {
			return err
		}
		defer func() { operationErr = errorsJoin(operationErr, session.DestroyObject(derivedHandle)) }()
		derived, err = readSecretValue(session, derivedHandle)
		return err
	})
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(derived, expected) {
		return nil, errors.New("conformance: IKE1 extended output differs from the software oracle")
	}
	return map[string]any{"derived_bytes": len(derived), "software_verified": true}, nil
}

// testProfileObject creates a CKO_PROFILE advertisement object. No fleet token
// supports it today, so the case demonstrates a clean capability skip.
func (r *Runner) testProfileObject(ctx context.Context, _ Case) (map[string]any, error) {
	identity := r.identity("profile")
	err := r.withSessionOptions(ctx, pkcs11.RawSessionOptions{Operation: "conformance-profile-object", ReadWrite: true}, func(session *testSession) (operationErr error) {
		handle, err := session.CreateObject([]*raw.Attribute{
			raw.NewAttribute(raw.CKA_CLASS, raw.CKO_PROFILE),
			raw.NewAttribute(raw.CKA_TOKEN, true),
			raw.NewAttribute(raw.CKA_PRIVATE, false),
			raw.NewAttribute(raw.CKA_LABEL, identity),
			raw.NewAttribute(raw.CKA_PROFILE_ID, raw.CKP_BASELINE_PROVIDER),
		})
		if err != nil {
			return fmt.Errorf("conformance: profile objects are not supported: %w", err)
		}
		defer func() { operationErr = errorsJoin(operationErr, session.DestroyObject(handle)) }()
		return nil
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"created": true}, nil
}

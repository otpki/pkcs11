package conformance

import (
	"context"
	"crypto"
	_ "crypto/sha1" // Register crypto.SHA1 for legacy OAEP conformance cases.
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/raw"
)

type Runner struct {
	profile    Profile
	client     *pkcs11.Client
	extensions extensionRegistry
}

// Test runs a conformance plan as ordinary Go subtests.
func Test(t *testing.T, profile Profile, options ...RunOption) {
	t.Helper()
	config, extensions, err := resolveRunConfig(options)
	if err != nil {
		t.Fatal(err)
	}
	if profile.Module == "" && config.module == nil {
		t.Skip("PKCS11_MODULE is not configured")
	}
	if expected := os.Getenv("CONFORMANCE_EXPECT_BACKEND"); expected != "" && expected != string(raw.ActiveNativeBackend()) {
		t.Fatalf("native backend = %q, want %q", raw.ActiveNativeBackend(), expected)
	}
	if err := profile.Validate(config.extensions...); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), profile.suiteTimeout())
	defer cancel()
	clientConfig, err := profile.clientConfig(config.vendors, config.module)
	if err != nil {
		t.Fatal(err)
	}
	client, err := pkcs11.Open(ctx, clientConfig)
	if err != nil {
		t.Fatalf("open module: %v", err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			t.Errorf("close module: %v", err)
		}
	}()

	runner := &Runner{profile: profile, client: client, extensions: extensions}
	for _, configured := range profile.Cases {
		testCase := profile.normalizedCase(configured)
		t.Run(testCase.Name, func(t *testing.T) {
			runner.testCase(t, ctx, testCase)
		})
	}
}

func (r *Runner) testCase(t *testing.T, parent context.Context, testCase Case) {
	t.Helper()
	if testCase.Notes != "" {
		t.Log(testCase.Notes)
	}
	if testCase.Requirement == Disabled {
		t.Skip("disabled")
	}

	ctx, cancel := context.WithTimeout(parent, r.profile.caseTimeout())
	defer cancel()
	details, err := r.execute(ctx, testCase)
	if len(details) != 0 {
		t.Logf("details: %v", details)
	}
	if ctx.Err() != nil && err == nil {
		err = ctx.Err()
	}

	switch testCase.Requirement {
	case Forbidden:
		switch {
		case err == nil:
			t.Error("operation unexpectedly succeeded but is forbidden")
		case IsUnsupported(err):
			t.Logf("unsupported as required: %v", err)
		default:
			t.Errorf("forbidden operation failed for a non-capability reason: %v", err)
		}
	case Optional:
		if IsUnsupported(err) {
			t.Skip(err)
		}
		if err != nil {
			t.Error(err)
		}
	default:
		if err != nil {
			t.Error(err)
		}
	}
}

func (r *Runner) execute(ctx context.Context, testCase Case) (map[string]any, error) {
	switch strings.ToLower(testCase.Kind) {
	case "runtime":
		return r.testRuntime(ctx, testCase)
	case "random":
		return r.testRandom(ctx, testCase)
	case "session":
		return r.testSession(ctx, testCase)
	case "digest":
		return r.testDigest(ctx, testCase)
	case "concurrency":
		return r.testConcurrency(ctx, testCase)
	case "generate":
		return r.testGenerate(ctx, testCase)
	case "sign":
		return r.testSign(ctx, testCase)
	case "hmac":
		return r.testHMAC(ctx, testCase)
	case "encrypt":
		return r.testEncrypt(ctx, testCase)
	case "wrap":
		return r.testWrap(ctx, testCase)
	case "authenticated-wrap":
		return r.testAuthenticatedWrap(ctx, testCase)
	case "derive-ecdh":
		return r.testECDH(ctx, testCase)
	case "import-secret":
		return r.testImportSecret(ctx, testCase)
	case "message-sign":
		return r.testMessageSign(ctx, testCase)
	case "signature-first-verify":
		return r.testSignatureFirstVerify(ctx, testCase)
	case "session-validation":
		return r.testSessionValidation(ctx, testCase)
	case "kem":
		return r.testKEM(ctx, testCase)
	case "object-lifecycle":
		return r.testObjectLifecycle(ctx, testCase)
	case "certificate":
		return r.testCertificate(ctx, testCase)
	case "idle-recovery":
		return r.testIdleRecovery(ctx, testCase)
	default:
		kind := strings.ToLower(strings.TrimSpace(testCase.Kind))
		if extension := r.extensions.byKind[kind]; extension != nil {
			return extension.Execute(ctx, ExtensionContext{
				Client: r.client, Cleanup: r.profile.Suite.Cleanup, Prefix: r.profile.Suite.Prefix, identity: r.identity,
			}, testCase)
		}
		return nil, fmt.Errorf("conformance: unknown case kind %q", testCase.Kind)
	}
}

// IsUnsupported distinguishes a missing capability from an operational error.
func IsUnsupported(err error) bool {
	if err == nil {
		return false
	}
	for _, value := range []uint{raw.CKR_FUNCTION_NOT_SUPPORTED, raw.CKR_MECHANISM_INVALID, raw.CKR_CURVE_NOT_SUPPORTED} {
		if raw.IsError(err, value) {
			return true
		}
	}
	message := strings.ToLower(err.Error())
	for _, fragment := range []string{
		"not supported", "unsupported algorithm", "no route", "route is unavailable", "not advertised",
		"does not expose",
		"has neither standard mechanism", "does not define key-type alias", "does not define parameter-set alias",
		"requires vendor mechanism alias", "has no usable alias", "has no generation path", "requires a vendor",
		"is not a key-pair algorithm", "is not a secret-key algorithm",
	} {
		if strings.Contains(message, fragment) {
			return true
		}
	}
	return false
}

func hashByName(name string, fallback crypto.Hash) (crypto.Hash, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "default":
		return fallback, nil
	case "sha1", "sha-1":
		return crypto.SHA1, nil
	case "sha256", "sha-256":
		return crypto.SHA256, nil
	case "sha384", "sha-384":
		return crypto.SHA384, nil
	case "sha512", "sha-512":
		return crypto.SHA512, nil
	case "none", "direct":
		return 0, nil
	default:
		return 0, fmt.Errorf("conformance: unsupported hash name %q", name)
	}
}

func hashInput(hash crypto.Hash, data []byte) ([]byte, error) {
	if hash == 0 {
		return append([]byte(nil), data...), nil
	}
	if !hash.Available() {
		return nil, fmt.Errorf("conformance: hash %v is unavailable in this Go build", hash)
	}
	h := hash.New()
	_, _ = h.Write(data)
	return h.Sum(nil), nil
}

func errorsJoin(primary error, additional ...error) error {
	return errors.Join(append([]error{primary}, additional...)...)
}

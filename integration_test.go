package pkcs11

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/otpki/pkcs11/raw"
)

// TestIntegration exercises a real module only when PKCS11_MODULE is set.
// Mutation is separately gated because generated keys are token objects.
func TestIntegration(t *testing.T) {
	modulePath := strings.TrimSpace(os.Getenv("PKCS11_MODULE"))
	if modulePath == "" {
		t.Skip("PKCS11_MODULE is not set")
	}

	config := Config{
		Module: LocalModule(modulePath),
		Token: TokenSelector{
			Label:        os.Getenv("PKCS11_TOKEN_LABEL"),
			SerialNumber: os.Getenv("PKCS11_TOKEN_SERIAL"),
		},
		Login: LoginConfig{Mode: LoginNone},
	}
	if pin := os.Getenv("PKCS11_PIN"); pin != "" {
		config.Login.Mode = LoginLazy
		config.PIN = StaticPIN(pin)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	client, err := Open(ctx, config)
	if err != nil {
		t.Fatalf("open module: %v", err)
	}
	t.Cleanup(func() {
		if err := client.Close(ctx); err != nil {
			t.Errorf("close module: %v", err)
		}
	})

	report, err := client.Health(ctx, HealthOptions{
		CheckRandom: client.Device().Fingerprint.Token.Flags&raw.CKF_RNG != 0,
	})
	if err != nil {
		t.Fatalf("health check (%s): %v", report.Status, err)
	}
	if report.Status == HealthUnhealthy {
		t.Fatalf("health status: %s", report.Status)
	}
	validation, validationErr := client.ValidateRuntime(ctx, RuntimeValidationOptions{Refresh: true, CheckRandom: client.Device().Fingerprint.Token.Flags&raw.CKF_RNG != 0})
	if validationErr != nil {
		t.Fatalf("runtime validation (%s): %v", validation.Level, validationErr)
	}

	if os.Getenv("PKCS11_INTEGRATION_WRITE") != "1" {
		return
	}
	algorithmNames := splitIntegrationAlgorithms(os.Getenv("PKCS11_INTEGRATION_ALGORITHMS"))
	if len(algorithmNames) == 0 {
		algorithmNames = []string{string(AlgorithmRSA)}
	}
	for _, name := range algorithmNames {
		algorithm := Algorithm(name)
		t.Run(name, func(t *testing.T) {
			testIntegrationGenerateAndDestroy(ctx, t, client, algorithm)
		})
	}
}

func splitIntegrationAlgorithms(value string) []string {
	var result []string
	for item := range strings.SplitSeq(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			result = append(result, item)
		}
	}
	return result
}

func testIntegrationGenerateAndDestroy(ctx context.Context, t *testing.T, client *Client, algorithm Algorithm) {
	t.Helper()
	spec, ok := algorithmSpecs[algorithm]
	if !ok {
		t.Fatalf("unknown algorithm %q", algorithm)
	}
	if algorithm == AlgorithmHSS || algorithm == AlgorithmXMSS || algorithm == AlgorithmXMSSMT {
		t.Fatalf("%s requires device-specific stateful-signature parameters; use a dedicated hardware test", algorithm)
	}

	identity := fmt.Sprintf("otpki-pkcs11-integration-%s-%d", algorithm, time.Now().UnixNano())
	if spec.Secret {
		options := SecretKeyOptions{Algorithm: algorithm, Label: identity, ID: []byte(identity)}
		object, err := client.GenerateSecretKey(ctx, options)
		if err != nil {
			t.Fatalf("generate secret key: %v", err)
		}
		if err := client.Destroy(ctx, object); err != nil {
			t.Fatalf("destroy secret key: %v", err)
		}
		return
	}
	if !spec.KeyPair {
		t.Fatalf("algorithm %s has no integration generation path", algorithm)
	}
	options := KeyPairOptions{Algorithm: algorithm, Label: identity, ID: []byte(identity)}
	pair, err := client.GenerateKeyPair(ctx, options)
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	if err := client.Destroy(ctx, pair.Private); err != nil {
		t.Errorf("destroy private key: %v", err)
	}
	if err := client.Destroy(ctx, pair.Public); err != nil {
		t.Errorf("destroy public key: %v", err)
	}
}

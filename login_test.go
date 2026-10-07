package pkcs11

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/otpki/pkcs11/internal/testmock"
	"github.com/otpki/pkcs11/raw"
)

// Closing a client's last session logs the application out.
func TestClientLogsInAgainAfterItsLastSessionCloses(t *testing.T) {
	for _, test := range []struct {
		name             string
		sessions         SessionConfig
		closeLastSession func(context.Context, *testing.T, *Client)
	}{
		{
			name: "failed key generation",
			closeLastSession: func(ctx context.Context, t *testing.T, client *Client) {
				t.Helper()
				if _, err := client.GenerateKeyPair(ctx, rejectedKeyPair()); !raw.IsError(err, raw.CKR_KEY_SIZE_RANGE) {
					t.Fatalf("GenerateKeyPair(RSA-1024) = %v, want CKR_KEY_SIZE_RANGE", err)
				}
			},
		},
		{
			name:             "idle timeout",
			sessions:         SessionConfig{IdleTimeout: time.Millisecond},
			closeLastSession: func(context.Context, *testing.T, *Client) { time.Sleep(10 * time.Millisecond) },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			client := openLoginTestClient(t, testmockSource(t), test.sessions)
			if err := createPrivateObject(ctx, client); err != nil {
				t.Fatalf("first session: %v", err)
			}
			test.closeLastSession(ctx, t, client)
			if err := createPrivateObject(ctx, client); err != nil {
				t.Fatalf("session after the last one closed: %v", err)
			}
		})
	}
}

// A failed write on a logged-out application discards the client's idle
// sessions. Those sessions lost the login too.
func TestNotLoggedInWriteForcesLoginOnNextCall(t *testing.T) {
	ctx := context.Background()
	source := testmockSource(t)
	client := openLoginTestClient(t, source, SessionConfig{Min: 2})
	if err := client.Activate(ctx); err != nil {
		t.Fatal(err)
	}
	// Login state belongs to the application. Another client's logout therefore ends it.
	if err := openLoginTestClient(t, source, SessionConfig{}).Deactivate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := createPrivateObject(ctx, client); !raw.IsError(err, raw.CKR_USER_NOT_LOGGED_IN) {
		t.Fatalf("write after the logout = %v, want CKR_USER_NOT_LOGGED_IN", err)
	}
	if err := createPrivateObject(ctx, client); err != nil {
		t.Fatalf("write after the failed one: %v", err)
	}
}

// rejectedKeyPair asks for a 1024-bit RSA modulus, below the test module's
// minimum. The failed generation discards its session.
func rejectedKeyPair() KeyPairOptions {
	return KeyPairOptions{
		Algorithm:        AlgorithmRSA,
		PublicAttributes: []*raw.Attribute{raw.NewAttribute(raw.CKA_MODULUS_BITS, uint(1024))},
	}
}

func testmockSource(t *testing.T) testmock.SharedSource {
	t.Helper()
	return testmock.SharedSource{Name: t.Name(), Module: testmock.New(t.Name(), 1)}
}

func openLoginTestClient(t *testing.T, source ModuleSource, sessions SessionConfig) *Client {
	t.Helper()
	ctx := context.Background()
	client, err := Open(ctx, Config{
		Module:   source,
		PIN:      StaticPIN(testmock.DefaultPIN),
		Login:    LoginConfig{Mode: LoginLazy},
		Sessions: sessions,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close(ctx) })
	return client
}

// createPrivateObject needs a logged-in read/write session. It fails on a
// session in the public state.
func createPrivateObject(ctx context.Context, client *Client) error {
	return client.WithRawSession(ctx, RawSessionOptions{ReadWrite: true}, func(module raw.Module, session raw.SessionHandle) error {
		info, err := module.GetSessionInfo(session)
		if err != nil {
			return err
		}
		var stateErr error
		if info.State != raw.State(raw.CKS_RW_USER_FUNCTIONS) {
			stateErr = fmt.Errorf("session state = %d, want CKS_RW_USER_FUNCTIONS", info.State)
		}
		_, createErr := module.CreateObject(session, []*raw.Attribute{
			raw.NewAttribute(raw.CKA_CLASS, raw.CKO_DATA),
			raw.NewAttribute(raw.CKA_PRIVATE, true),
		})
		return errors.Join(stateErr, createErr)
	})
}

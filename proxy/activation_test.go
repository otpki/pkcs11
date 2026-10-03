package proxy

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/raw"
)

func TestLoginPolicyResolvePhysicalMode(t *testing.T) {
	protectedToken := raw.TokenInfo{Flags: raw.CKF_PROTECTED_AUTHENTICATION_PATH}
	ordinaryToken := raw.TokenInfo{}

	tests := []struct {
		name    string
		policy  LoginPolicy
		token   raw.TokenInfo
		want    PhysicalLoginMode
		wantErr bool
	}{
		{
			name:   "infer server managed",
			policy: LoginPolicy{PhysicalPIN: pkcs11.StaticPIN("1234")},
			token:  ordinaryToken,
			want:   PhysicalLoginServerManaged,
		},
		{
			name:   "infer protected path",
			policy: LoginPolicy{},
			token:  protectedToken,
			want:   PhysicalLoginProtectedPath,
		},
		{
			name:   "explicit client activated",
			policy: LoginPolicy{Mode: PhysicalLoginClientActivated},
			token:  ordinaryToken,
			want:   PhysicalLoginClientActivated,
		},
		{
			name:    "missing explicit client mode",
			policy:  LoginPolicy{},
			token:   ordinaryToken,
			wantErr: true,
		},
		{
			name:    "client mode rejects stored PIN",
			policy:  LoginPolicy{Mode: PhysicalLoginClientActivated, PhysicalPIN: pkcs11.StaticPIN("1234")},
			token:   ordinaryToken,
			wantErr: true,
		},
		{
			name:    "client mode rejects eager login",
			policy:  LoginPolicy{Mode: PhysicalLoginClientActivated, EagerPhysicalLogin: true},
			token:   ordinaryToken,
			wantErr: true,
		},
		{
			name:    "server mode requires PIN",
			policy:  LoginPolicy{Mode: PhysicalLoginServerManaged},
			token:   ordinaryToken,
			wantErr: true,
		},
		{
			name:    "protected path requires token flag",
			policy:  LoginPolicy{Mode: PhysicalLoginProtectedPath},
			token:   ordinaryToken,
			wantErr: true,
		},
		{
			name:    "protected path rejects stored PIN",
			policy:  LoginPolicy{Mode: PhysicalLoginProtectedPath, PhysicalPIN: pkcs11.StaticPIN("1234")},
			token:   protectedToken,
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := test.policy.resolvePhysicalMode(test.token)
			if test.wantErr {
				if err == nil {
					t.Fatalf("resolvePhysicalMode() = %q, nil; want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolvePhysicalMode(): %v", err)
			}
			if got != test.want {
				t.Fatalf("resolvePhysicalMode() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestRequestFingerprintDoesNotRetainCredentialValues(t *testing.T) {
	first := request{
		Method: "Login",
		Auth:   []byte("workload-token-one"),
		Arguments: []wireValue{
			{Kind: valueUint, Uint: 7},
			{Kind: valueUint, Uint: uint64(raw.CKU_USER)},
			{Kind: valueBytes, Bytes: []byte("1234")},
		},
	}
	second := first
	second.Auth = []byte("different-workload-token")
	second.Arguments = []wireValue{
		{Kind: valueUint, Uint: 99},
		{Kind: valueUint, Uint: uint64(raw.CKU_SO)},
		{Kind: valueBytes, Bytes: []byte("different-pin")},
	}

	firstFingerprint := requestFingerprint(first)
	secondFingerprint := requestFingerprint(second)
	if firstFingerprint != secondFingerprint {
		t.Fatal("request fingerprint changed with authentication or PIN values")
	}

	second.Method = "SetPIN"
	differentMethod := requestFingerprint(second)
	if firstFingerprint == differentMethod {
		t.Fatal("request fingerprint did not distinguish a different operation")
	}

	second.Method = "Login"
	second.Arguments[2] = wireValue{Kind: valueString, String: "different-shape"}
	differentShape := requestFingerprint(second)
	if firstFingerprint == differentShape {
		t.Fatal("request fingerprint did not distinguish a different argument schema")
	}
}

func TestActivationAuthorizationDenialDoesNotClaimLeadershipOrStartCooldown(t *testing.T) {
	coordinator := newActivationCoordinator()
	var activationCalls int

	_, err := coordinator.ensure(
		context.Background(),
		"denied-principal",
		time.Minute,
		func() error { return errors.New("forbidden") },
		func() error {
			activationCalls++
			return nil
		},
		nil,
	)
	if err == nil || err.Error() != "forbidden" {
		t.Fatalf("denied activation = %v, want forbidden", err)
	}
	if activationCalls != 0 {
		t.Fatalf("denied caller performed %d activation calls, want 0", activationCalls)
	}

	generation, err := coordinator.ensure(
		context.Background(),
		"authorized-principal",
		time.Minute,
		func() error { return nil },
		func() error {
			activationCalls++
			return nil
		},
		nil,
	)
	if err != nil {
		t.Fatalf("authorized activation: %v", err)
	}
	if generation == 0 {
		t.Fatal("authorized activation returned zero generation")
	}
	if activationCalls != 1 {
		t.Fatalf("authorized caller performed %d activation calls, want 1", activationCalls)
	}
}

func TestActivationFollowersRecontendAfterLeaderAuthorizationDenial(t *testing.T) {
	coordinator := newActivationCoordinator()
	deniedEntered := make(chan struct{})
	releaseDenied := make(chan struct{})
	deniedDone := make(chan error, 1)
	go func() {
		_, err := coordinator.ensure(
			context.Background(),
			"denied-principal",
			time.Minute,
			func() error {
				close(deniedEntered)
				<-releaseDenied
				return errors.New("forbidden")
			},
			func() error { return errors.New("denied leader reached HSM") },
			nil,
		)
		deniedDone <- err
	}()
	<-deniedEntered

	type result struct {
		generation uint64
		err        error
	}
	authorizedDone := make(chan result, 1)
	go func() {
		generation, err := coordinator.ensure(
			context.Background(),
			"authorized-principal",
			time.Minute,
			func() error { return nil },
			func() error { return nil },
			nil,
		)
		authorizedDone <- result{generation: generation, err: err}
	}()

	close(releaseDenied)
	if err := <-deniedDone; err == nil || err.Error() != "forbidden" {
		t.Fatalf("denied leader result = %v, want forbidden", err)
	}
	select {
	case got := <-authorizedDone:
		if got.err != nil {
			t.Fatalf("authorized follower activation: %v", got.err)
		}
		if got.generation == 0 {
			t.Fatal("authorized follower returned zero generation")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("authorized follower did not re-contend after denied leader")
	}
}

func TestActivationInvalidationWhileLeaderRunsFailsClosed(t *testing.T) {
	coordinator := newActivationCoordinator()
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)

	go func() {
		_, err := coordinator.ensure(
			context.Background(),
			"principal",
			0,
			nil,
			func() error {
				close(entered)
				<-release
				return nil
			},
			nil,
		)
		done <- err
	}()
	<-entered
	coordinator.invalidate(true)
	close(release)

	select {
	case err := <-done:
		if !raw.IsError(err, raw.CKR_USER_NOT_LOGGED_IN) {
			t.Fatalf("invalidated activation = %v, want CKR_USER_NOT_LOGGED_IN", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("invalidated activation did not finish")
	}
	status := coordinator.snapshot()
	if status.State != ActivationInactive {
		t.Fatalf("activation state = %q, want inactive", status.State)
	}
}

func TestBrokerRejectsPINOnNestedManagedClientConfig(t *testing.T) {
	_, err := newBrokerTarget(context.Background(), TargetConfig{
		ID:       "nested-pin",
		Revision: "revision-1",
		Client: pkcs11.Config{
			PIN: pkcs11.StaticPIN("must-not-be-stored-here"),
		},
		Login: LoginPolicy{
			Mode:         PhysicalLoginClientActivated,
			Authenticate: func(context.Context, LoginAttempt) error { return nil },
		},
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "TargetConfig.Client.PIN") {
		t.Fatalf("nested client PIN validation = %v, want explicit rejection", err)
	}
}

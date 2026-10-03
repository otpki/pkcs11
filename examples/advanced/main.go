// advanced demonstrates operational controls and raw escape
// hatches. Use these only when the ordinary Client methods do not model a need.
package main

import (
	"context"
	"crypto"
	"fmt"
	"log"
	"os"
	"time"

	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/raw"
	"github.com/otpki/pkcs11/vendors/all"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	observer := logObserver{}
	client, err := pkcs11.Open(ctx, pkcs11.Config{
		Module:  pkcs11.LocalModule(os.Getenv("PKCS11_MODULE")),
		Token:   pkcs11.TokenSelector{Label: os.Getenv("PKCS11_TOKEN_LABEL")},
		Vendors: all.Modules(),
		PIN:     pkcs11.StaticPIN(os.Getenv("PKCS11_PIN")),
		// Manual mode is useful when application lifecycle controls activation.
		Login: pkcs11.LoginConfig{Mode: pkcs11.LoginManual},
		Sessions: pkcs11.SessionConfig{
			Min: 1, MaxTotal: 4, ReadOnlyMax: 4, ReadWriteMax: 2,
			IdleTimeout: 2 * time.Minute, MaxOperations: 10_000,
		},
		Retry: pkcs11.RetryPolicy{MaxAttempts: 2, InitialBackoff: 25 * time.Millisecond},
		Cache: pkcs11.CacheConfig{ObjectTTL: time.Minute, AttributeTTL: 10 * time.Second},
		Hooks: pkcs11.Hooks{Metrics: observer, Audit: observer, Tracer: observer},
	})
	check(err)
	defer func() { check(client.Close(ctx)) }()

	// Activate warms minimum pool capacity and performs the configured login.
	check(client.Activate(ctx))
	log.Printf("login-scope=%s pools=%+v", client.LoginScope(), client.SessionStats())

	// Runtime validation inventories mechanisms and performs only requested,
	// non-destructive probes. The callback can validate one existing key too.
	report, err := client.ValidateRuntime(ctx, pkcs11.RuntimeValidationOptions{
		Refresh:     true, // Also demonstrates explicit rediscovery before probing.
		CheckRandom: true,
		ReadWrite:   true,
		CryptographicProbe: func(ctx context.Context, client *pkcs11.Client) error {
			_, err := client.Digest(ctx, []byte("validation probe"), pkcs11.DigestOptions{Hash: crypto.SHA256})
			return err
		},
	})
	check(err)
	log.Printf("validation=%s mechanisms=%d warnings=%d", report.Level, len(report.Mechanisms), len(report.Warnings))
	if seed := os.Getenv("PKCS11_RNG_SEED"); seed != "" {
		// Seeding supplements the token RNG; it does not replace GenerateRandom.
		// Many production HSMs intentionally reject caller-provided seed material.
		check(client.SeedRandom(ctx, []byte(seed)))
	}

	// WithRawModule protects lifecycle and observability while exposing exact
	// non-session Cryptoki calls. Never retain the module after the callback.
	check(client.WithRawModule(ctx, pkcs11.RawModuleOptions{Operation: "example-get-info"}, func(module raw.Module) error {
		info, err := module.GetInfo()
		if err == nil {
			log.Printf("raw library=%q version=%d.%d", info.LibraryDescription, info.LibraryVersion.Major, info.LibraryVersion.Minor)
		}
		return err
	}))

	// WithRawSession is the usual escape hatch. Mark a callback idempotent only
	// when replaying the entire sequence after an ambiguous failure is safe.
	check(client.WithRawSession(ctx, pkcs11.RawSessionOptions{
		Operation: "example-multipart-digest", Idempotent: true,
	}, func(module raw.Module, session raw.SessionHandle) error {
		if err := module.DigestInit(session, []*raw.Mechanism{raw.NewMechanism(raw.CKM_SHA256, nil)}); err != nil {
			return err
		}
		if err := module.DigestUpdate(session, []byte("part one, ")); err != nil {
			return err
		}
		digest, err := module.DigestFinal(session)
		log.Printf("multipart digest=%x", digest)
		return err
	}))

	// A lease preserves one physical session across several calls. This is for
	// multipart protocols, session objects, or provider operations requiring
	// affinity. Always close it promptly so the pool regains capacity.
	lease, err := client.AcquireRawSession(ctx, pkcs11.RawSessionOptions{ReadWrite: true, Operation: "example-lease"})
	check(err)
	defer func() { check(lease.Close(ctx)) }()
	check(lease.Call(ctx, "example-random", func(module raw.Module, session raw.SessionHandle) error {
		value, err := module.GenerateRandom(session, 16)
		log.Printf("leased-session=%d random=%x", lease.Handle(), value)
		return err
	}))

	// Slot watchers use C_WaitForSlotEvent when available and polling otherwise.
	watchCtx, stopWatch := context.WithCancel(ctx)
	events := client.WatchSlotEvents(watchCtx, pkcs11.WatchConfig{PollInterval: time.Second, Refresh: true})
	stopWatch()
	for event := range events {
		log.Printf("slot event kind=%s slot=%d error=%s", event.Kind, event.SlotID, event.Error)
	}

	// Deactivate logs out and drains pools without unloading the shared module.
	check(client.Deactivate(ctx))
}

// One small type can implement all three optional observability interfaces.
// OperationEvent intentionally contains metadata only, never plaintext or PINs.
type logObserver struct{}

func (logObserver) ObservePKCS11(_ context.Context, event pkcs11.OperationEvent) {
	log.Printf("metric operation=%s duration=%s error=%v", event.Operation, event.Duration, event.Err)
}

func (logObserver) AuditPKCS11(_ context.Context, event pkcs11.OperationEvent) {
	log.Printf("audit operation=%s slot=%d", event.Operation, event.SlotID)
}

func (logObserver) StartPKCS11(ctx context.Context, event pkcs11.OperationEvent) (context.Context, pkcs11.Span) {
	log.Printf("trace start operation=%s", event.Operation)
	return ctx, logSpan{operation: event.Operation}
}

type logSpan struct{ operation string }

func (span logSpan) End(err error) {
	log.Printf("trace end operation=%s error=%v", span.operation, err)
}

func check(err error) {
	if err != nil {
		log.Fatal(fmt.Errorf("advanced example failed: %w", err))
	}
}

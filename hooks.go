package pkcs11

import (
	"context"
	"time"

	"github.com/otpki/pkcs11/raw"
)

// OperationEvent contains non-secret metadata about one driver operation.
// Parameters, PINs, plaintext, ciphertext, wrapped keys, and key material are
// deliberately never included.
type OperationEvent struct {
	// Operation is the stable logical/native operation name, such as C_Sign or
	// generate-key-pair.
	Operation string
	// ModulePath identifies the loaded native library. It may contain sensitive
	// host-layout information and should be handled accordingly by integrations.
	ModulePath string
	// Vendor is the display name of the automatically selected adapter.
	Vendor string
	// SlotID identifies the selected token-bearing slot.
	SlotID raw.SlotID
	// Session is zero for module-level operations and the managed native handle
	// for session-bound operations. It is diagnostic only and must not be reused.
	Session raw.SessionHandle
	// ReadWrite reports whether the managed session was opened read/write.
	ReadWrite bool
	// Attempt is the one-based managed retry attempt, or zero for module calls
	// that are not executed through the session retry loop.
	Attempt int
	// Started and Duration are populated by Hooks.begin.
	Started  time.Time
	Duration time.Duration
	// Err is the final operation error, including nil on success.
	Err error
}

// Metrics receives counters and timings for managed operations without secret payloads.
type Metrics interface {
	ObservePKCS11(context.Context, OperationEvent)
}

// Auditor receives security-relevant operation metadata without PINs or key material.
type Auditor interface {
	AuditPKCS11(context.Context, OperationEvent)
}

// Span is the minimal tracing span used by the driver.
type Span interface {
	End(error)
}

// Tracer starts spans around managed PKCS #11 operations.
type Tracer interface {
	StartPKCS11(context.Context, OperationEvent) (context.Context, Span)
}

// Hooks groups optional metrics, audit, and tracing integrations.
type Hooks struct {
	// Metrics receives the completed event after tracing has ended.
	Metrics Metrics
	// Audit receives the completed event last, after metrics observation.
	Audit Auditor
	// Tracer can replace the operation context and is invoked before the native
	// call. The returned context is also passed to Metrics and Audit.
	Tracer Tracer
}

// begin starts configured instrumentation and returns a completion callback.
// The caller must invoke the callback exactly once, normally with defer, so the
// duration and final error are consistent across tracing, metrics, and auditing.
func (h Hooks) begin(ctx context.Context, event OperationEvent) (context.Context, func(error)) {
	event.Started = time.Now()
	var span Span
	if h.Tracer != nil {
		ctx, span = h.Tracer.StartPKCS11(ctx, event)
	}
	return ctx, func(err error) {
		// Every sink receives the same completed value copy. No sink can mutate
		// what a later sink observes through the event itself.
		event.Duration = time.Since(event.Started)
		event.Err = err
		// End the span before emitting metrics and audit data so integrations that
		// export synchronously observe a completed trace.
		if span != nil {
			span.End(err)
		}
		if h.Metrics != nil {
			h.Metrics.ObservePKCS11(ctx, event)
		}
		if h.Audit != nil {
			h.Audit.AuditPKCS11(ctx, event)
		}
	}
}

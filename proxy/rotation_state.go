package proxy

import (
	"context"
	"errors"

	"github.com/otpki/pkcs11/raw"
)

// clearPINRotationState invalidates every logical grant and ends all operations
// that would otherwise survive the token-wide logout. The caller must hold the
// target's maintenanceLock for writing, which drains native request execution.
// Do not take a client's authMu here: a queued request can already hold it while
// waiting for that same maintenance lock.
func (target *brokerTarget) clearPINRotationState(ctx context.Context) error {
	target.clientsMu.Lock()
	clients := make([]*logicalClient, 0, len(target.clients))
	for _, client := range target.clients {
		clients = append(clients, client)
	}
	target.clientsMu.Unlock()

	for _, client := range clients {
		client.stateMu.Lock()
		client.grants = make(map[string]loginGrant)
		client.stateMu.Unlock()
	}
	var errs []error
	for _, client := range clients {
		if err := client.cleanupLoginStateWithRecovery(ctx, target, true); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// cleanupLoginState removes private handles and operation state for logical
// logout or a token-wide PIN rotation. The caller excludes ordinary requests
// with either client.authMu or target.maintenanceLock. Session locks additionally
// protect against the idle reaper and a concurrent logical-client destruction.
func (client *logicalClient) cleanupLoginState(ctx context.Context, target *brokerTarget) error {
	return client.cleanupLoginStateWithRecovery(ctx, target, false)
}

// Rotation can complete cleanup by closing a native session when cancellation
// or private-object destruction is unsupported. Logical logout retains its
// established behavior of reporting the original cleanup failure.
func (client *logicalClient) cleanupLoginStateWithRecovery(ctx context.Context, target *brokerTarget, allowDiscardRecovery bool) error {
	privateSessionObjects := client.takePrivateObjects()

	client.sessionsMu.Lock()
	sessions := make([]*virtualSession, 0, len(client.sessions))
	for _, session := range client.sessions {
		sessions = append(sessions, session)
	}
	client.sessionsMu.Unlock()
	var errs []error
	for _, session := range sessions {
		session.mu.Lock()
		session.touch()

		// Take the lifetime write lock before canceling operations or destroying
		// private session objects. Cross-session users hold the corresponding read
		// lock, so logout waits for their native calls to finish rather than
		// invalidating an object handle underneath them.
		session.lifetime.Lock()
		lease := session.lease
		if lease == nil {
			session.lifetime.Unlock()
			session.mu.Unlock()
			continue
		}

		// Cancel active operations and destroy private session objects while
		// preserving public session objects. Rotation runs this cleanup before
		// the physical logout, while logical logout leaves the shared token active.
		flags := cancelFlagsForOperations(session.operations)
		var cleanupErr error
		if flags != 0 {
			cleanupErr = lease.Call(ctx, "proxy-logical-logout-cancel", func(module raw.Module, native raw.SessionHandle) error {
				return module.SessionCancel(native, flags)
			})
		}
		if cleanupErr == nil {
			for _, object := range privateSessionObjects[session.handle] {
				err := lease.Call(ctx, "proxy-logical-logout-destroy-private-session-object", func(module raw.Module, native raw.SessionHandle) error {
					return module.DestroyObject(native, object)
				})
				if err != nil && !raw.IsError(err, raw.CKR_OBJECT_HANDLE_INVALID) {
					cleanupErr = errors.Join(cleanupErr, err)
				}
			}
		}

		if cleanupErr != nil {
			// The native session's post-logout state is uncertain. Detach it while
			// the lifetime lock is held, then invalidate every remaining affine
			// handle owned by the discarded native session.
			session.clearOperationsLocked()
			session.affineObjects.Store(0)
			session.lease = nil
			if session.pinnedCounted {
				session.pinnedCounted = false
				target.releasePinned()
			}
			lease.MarkBroken()
			closeErr := lease.Close(ctx)
			session.lifetime.Unlock()
			client.removeAffineObjects(session.handle)
			// MarkBroken forces Close to close the native session rather than
			// pool it. Its result confirms that the old operation and private
			// objects cannot survive; a native close failure must still surface.
			if !allowDiscardRecovery {
				errs = append(errs, errors.Join(cleanupErr, closeErr))
			} else if closeErr != nil {
				// The failed fallback, rather than missing cancellation support,
				// is the reason rotation cannot confirm complete cleanup.
				errs = append(errs, errors.Join(closeErr, cleanupErr))
			}
			session.mu.Unlock()
			continue
		}

		session.clearOperationsLocked()
		if count := int64(len(privateSessionObjects[session.handle])); count > 0 {
			for {
				current := session.affineObjects.Load()
				next := max(current-count, 0)
				if session.affineObjects.CompareAndSwap(current, next) {
					break
				}
			}
		}
		session.lifetime.Unlock()
		if err := session.releaseIfIdle(ctx, target); err != nil {
			errs = append(errs, err)
		}
		session.mu.Unlock()
	}
	return errors.Join(errs...)
}

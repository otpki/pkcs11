package pkcs11

import (
	"context"
	"errors"
	"sync"
)

var errSessionLimiterClosed = errors.New("pkcs11: session limiter is closed")

// sessionLimiter caps native sessions across all pools for one Client. Closing it wakes waiters
// while existing holders can still release their permits.
type sessionLimiter struct {
	sem       chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

func newSessionLimiter(limit int) *sessionLimiter {
	if limit < 1 {
		limit = 1
	}
	return &sessionLimiter{sem: make(chan struct{}, limit), done: make(chan struct{})}
}

//nolint:contextcheck // Nil callers intentionally fall back to a detached context.
func (l *sessionLimiter) acquire(ctx context.Context) error {
	if l == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-l.done:
		return errSessionLimiterClosed
	default:
	}
	select {
	case <-l.done:
		return errSessionLimiterClosed
	case <-ctx.Done():
		return ctx.Err()
	case l.sem <- struct{}{}:
		// close may race with the send. Return the permit before reporting closure
		// so the limiter's accounting remains exact during a concurrent drain.
		select {
		case <-l.done:
			<-l.sem
			return errSessionLimiterClosed
		default:
			return nil
		}
	}
}

func (l *sessionLimiter) release() {
	if l == nil {
		return
	}
	select {
	case <-l.sem:
	default:
		panic("pkcs11: session limiter release without acquisition")
	}
}

func (l *sessionLimiter) close() {
	if l != nil {
		l.closeOnce.Do(func() { close(l.done) })
	}
}

func (l *sessionLimiter) used() int {
	if l == nil {
		return 0
	}
	return len(l.sem)
}

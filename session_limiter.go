package pkcs11

import (
	"context"
	"errors"
	"slices"
	"sync"
)

var errSessionLimiterClosed = errors.New("pkcs11: session limiter is closed")

// sessionLimiter caps native sessions across all pools for one Client. Closing it wakes waiters
// while existing holders can still release their permits.
type sessionLimiter struct {
	sem       chan struct{}
	done      chan struct{}
	closeOnce sync.Once

	// pools hold the idle sessions whose permits a waiter may reclaim.
	mu    sync.Mutex
	pools []*sessionPool
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

// tryAcquire takes a permit if one is free. A nil limiter imposes no budget.
func (l *sessionLimiter) tryAcquire() bool {
	if l == nil {
		return true
	}
	select {
	case <-l.done:
		return false
	default:
	}
	select {
	case l.sem <- struct{}{}:
		select {
		case <-l.done:
			<-l.sem
			return false
		default:
			return true
		}
	default:
		return false
	}
}

// acquireOrTake waits for a free permit or for a session returned to idle, whichever comes
// first. It reports taken with the session, or holds one permit when taken is false.
func (l *sessionLimiter) acquireOrTake(ctx context.Context, idle <-chan pooledSession) (pooledSession, bool, error) {
	select {
	case <-l.done:
		return pooledSession{}, false, errSessionLimiterClosed
	case <-ctx.Done():
		return pooledSession{}, false, ctx.Err()
	case item := <-idle:
		return item, true, nil
	case l.sem <- struct{}{}:
		select {
		case <-l.done:
			<-l.sem
			return pooledSession{}, false, errSessionLimiterClosed
		default:
			return pooledSession{}, false, nil
		}
	}
}

// register records a pool whose idle sessions hold permits of this limiter.
func (l *sessionLimiter) register(pool *sessionPool) {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.pools = append(l.pools, pool)
	l.mu.Unlock()
}

// reclaimIdle closes one idle session of a pool other than except, which returns its permit.
// Nothing else would: an idle session keeps its permit until that pool is used again.
func (l *sessionLimiter) reclaimIdle(ctx context.Context, except *sessionPool) bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	pools := slices.Clone(l.pools)
	l.mu.Unlock()
	for _, pool := range pools {
		if pool == except {
			continue
		}
		select {
		case item := <-pool.idle:
			_ = pool.closeHandle(ctx, item)
			return true
		default:
		}
	}
	return false
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
